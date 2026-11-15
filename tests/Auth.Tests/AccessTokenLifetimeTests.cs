using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using Auth.Core.Contracts;
using Auth.Infrastructure.Data;
using Auth.Tests.Fixtures;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Tests;

/// <summary>
/// Access tokens expire 15 minutes after issue with no configuration override, and refresh tokens
/// keep working with the shorter access lifetime. Uses RecordingAuthFactory, which does not override
/// Jwt:ExpiresMinutes, so these tests see the service default.
/// </summary>
public sealed class AccessTokenLifetimeTests : IClassFixture<RecordingAuthFactory>, IAsyncLifetime
{
    private static readonly TimeSpan ExpectedLifetime = TimeSpan.FromMinutes(15);
    private readonly RecordingAuthFactory _factory;

    public AccessTokenLifetimeTests(RecordingAuthFactory factory) => _factory = factory;

    public Task InitializeAsync() => _factory.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task AccessToken_ExpiresFifteenMinutesAfterIssue()
    {
        var auth = await LoginAsync();

        var token = new JwtSecurityTokenHandler().ReadJwtToken(auth.AccessToken);
        var issuedAt = long.Parse(token.Claims.Single(c => c.Type == "iat").Value);
        var expiresAt = long.Parse(token.Claims.Single(c => c.Type == "exp").Value);

        Assert.Equal(ExpectedLifetime.TotalSeconds, expiresAt - issuedAt);
    }

    [Fact]
    public async Task RefreshToken_StillRotates_AfterShortAccessLifetime()
    {
        var client = _factory.CreateClient();
        var auth = await LoginAsync();

        var refreshed = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(auth.RefreshToken));

        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        var body = await refreshed.Content.ReadFromJsonAsync<AuthResponse>();
        Assert.NotNull(body);
        Assert.NotEqual(auth.RefreshToken, body!.RefreshToken);
        Assert.False(string.IsNullOrWhiteSpace(body.AccessToken));
    }

    private async Task<AuthResponse> LoginAsync()
    {
        var client = _factory.CreateClient();
        var email = $"life{Guid.NewGuid():N}@test.com";
        await client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, "SecureP@ss123", "Lifetime"));
        await using (var scope = _factory.Services.CreateAsyncScope())
            await AccountHelpers.VerifyEmailAsync(scope.ServiceProvider.GetRequiredService<AuthDbContext>(), email);

        var login = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, "SecureP@ss123"));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        return (await login.Content.ReadFromJsonAsync<AuthResponse>())!;
    }
}
