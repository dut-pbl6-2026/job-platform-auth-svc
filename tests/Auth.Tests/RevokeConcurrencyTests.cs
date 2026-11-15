using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Auth.Core.Contracts;
using Auth.Core.Entities;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Auth.Tests.Fixtures;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SharedKernel;

namespace Auth.Tests;

/// <summary>
/// Refresh-token revocations from logout, logout-all and reset-password under concurrency, against the real
/// Postgres container. The race is made deterministic: a save interceptor runs the winning request after the
/// losing request has loaded its rows and before the losing save, so the losing save hits the concurrency token.
/// </summary>
[Collection(PostgresCollection.Name)]
public class RevokeConcurrencyTests : IAsyncLifetime
{
    private const string OldPassword = "OldP@ssw0rd1";
    private const string NewPassword = "NewP@ssw0rd1";

    private readonly PostgresFixture _fixture;

    public RevokeConcurrencyTests(PostgresFixture fixture) => _fixture = fixture;

    public Task InitializeAsync() => _fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private static JwtOptions Jwt => new()
    {
        Secret = "unit-test-signing-key-0123456789abcdef",
        Issuer = "job-platform",
        Audience = "job-platform",
        ExpiresMinutes = 60
    };

    private static IConfiguration Config => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?> { ["WEB_URL"] = "http://localhost:5173" })
        .Build();

    private static JwtTokenService Tokens() => new(Options.Create(Jwt));

    private AuthDbContext CreateDb(params IInterceptor[] interceptors) => new(
        new DbContextOptionsBuilder<AuthDbContext>()
            .UseNpgsql(_fixture.ConnectionString)
            .AddInterceptors(interceptors)
            .Options);

    private static AuthService Service(AuthDbContext db) =>
        new(db, new PasswordHasherService(), Tokens(), NullLogger<AuthService>.Instance,
            Config, new Mock<ITokenRevocationStore>().Object);

    /// <summary>A verified user with one active session. Returns the user id and the session's refresh token.</summary>
    private async Task<(Guid UserId, string Refresh)> SeedUserWithSessionAsync(string email)
    {
        var refresh = Tokens().GenerateRefreshToken();
        await using var db = CreateDb();
        db.Users.Add(new User(email, new PasswordHasherService().Hash(OldPassword), "Race User"));
        await db.SaveChangesAsync();
        await AccountHelpers.VerifyEmailAsync(db, email);
        var user = await db.Users.SingleAsync(u => u.Email == email);
        db.RefreshTokens.Add(new RefreshToken(user.Id, Tokens().HashToken(refresh), DateTime.UtcNow.AddDays(7)));
        await db.SaveChangesAsync();
        return (user.Id, refresh);
    }

    [Fact]
    public async Task Logout_TwoConcurrentLogoutsOfSameToken_BothSucceedAndTokenIsRevoked()
    {
        var (userId, refresh) = await SeedUserWithSessionAsync("logout@race.test");

        // The losing logout has loaded the token; the winning logout revokes it before the losing save.
        await using var loser = CreateDb(new BeforeFirstSave(async () =>
        {
            await using var winner = CreateDb();
            Assert.True((await Service(winner).LogoutAsync(userId, refresh)).IsSuccess);
        }));

        var lost = await Service(loser).LogoutAsync(userId, refresh);

        Assert.True(lost.IsSuccess);
        await using var check = CreateDb();
        var token = await check.RefreshTokens.SingleAsync(t => t.TokenHash == Tokens().HashToken(refresh));
        Assert.True(token.IsRevoked);
    }

    [Fact]
    public async Task LogoutAll_LosingConcurrentRotation_RetriesAndRevokesEverySession()
    {
        var (userId, refresh) = await SeedUserWithSessionAsync("logoutall@race.test");

        // A refresh rotates the session after logout-all has loaded it. The logout-all save then conflicts.
        await using var loser = CreateDb(new BeforeFirstSave(async () =>
        {
            await using var refresher = CreateDb();
            Assert.True((await Service(refresher).RefreshAsync(refresh)).IsSuccess);
        }));

        var res = await Service(loser).LogoutAsync(userId, refreshToken: null);

        Assert.True(res.IsSuccess, res.Error);
        await using var check = CreateDb();
        var tokens = await check.RefreshTokens.Where(t => t.UserId == userId).ToListAsync();
        Assert.Equal(2, tokens.Count);
        Assert.All(tokens, t => Assert.True(t.IsRevoked));
    }

    [Fact]
    public async Task ResetPassword_RacingRefresh_ChangesPasswordAndRejectsOldRefreshToken()
    {
        var (userId, refresh) = await SeedUserWithSessionAsync("reset@race.test");
        var resetToken = Tokens().GenerateRefreshToken();
        await using (var seed = CreateDb())
        {
            seed.PasswordResetTokens.Add(new PasswordResetToken(userId, Tokens().HashToken(resetToken), DateTime.UtcNow.AddMinutes(15)));
            await seed.SaveChangesAsync();
        }

        // A refresh rotates the session after the reset has loaded it. The reset's first save conflicts and rolls back.
        await using var resetDb = CreateDb(new BeforeFirstSave(async () =>
        {
            await using var refresher = CreateDb();
            Assert.True((await Service(refresher).RefreshAsync(refresh)).IsSuccess);
        }));

        var reset = await Service(resetDb).ResetPasswordAsync(new ResetPasswordRequest(resetToken, NewPassword));

        Assert.True(reset.IsSuccess, reset.Error);
        var hasher = new PasswordHasherService();
        await using (var check = CreateDb())
        {
            var user = await check.Users.SingleAsync(u => u.Id == userId);
            Assert.True(hasher.Verify(NewPassword, user.PasswordHash));
            Assert.False(hasher.Verify(OldPassword, user.PasswordHash));
            Assert.True((await check.PasswordResetTokens.SingleAsync()).IsUsed);
            var tokens = await check.RefreshTokens.Where(t => t.UserId == userId).ToListAsync();
            Assert.All(tokens, t => Assert.True(t.IsRevoked));
        }

        await using var afterCheck = CreateDb();
        var oldRefresh = await Service(afterCheck).RefreshAsync(refresh);
        Assert.False(oldRefresh.IsSuccess);
    }

    /// <summary>Runs an action once, just before the first save of the context it is attached to.</summary>
    private sealed class BeforeFirstSave(Func<Task> action) : SaveChangesInterceptor
    {
        private Func<Task>? _action = action;

        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
            DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            var pending = Interlocked.Exchange(ref _action, null);
            if (pending != null) await pending();
            return result;
        }
    }
}

/// <summary>Logout through the HTTP API, with two requests racing on the same refresh token.</summary>
public sealed class LogoutEndpointConcurrencyTests : IClassFixture<RecordingAuthFactory>, IAsyncLifetime
{
    private const string Password = "SecureP@ss123";
    private readonly RecordingAuthFactory _factory;

    public LogoutEndpointConcurrencyTests(RecordingAuthFactory factory) => _factory = factory;

    public Task InitializeAsync() => _factory.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Logout_TwoConcurrentRequestsWithSameRefreshToken_BothReturn204()
    {
        var client = _factory.CreateClient();
        var email = $"race{Guid.NewGuid():N}@test.com";
        await client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, Password, "Race"));
        await using (var scope = _factory.Services.CreateAsyncScope())
            await AccountHelpers.VerifyEmailAsync(scope.ServiceProvider.GetRequiredService<AuthDbContext>(), email);
        var login = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, Password));
        var auth = (await login.Content.ReadFromJsonAsync<AuthResponse>())!;

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", auth.AccessToken);
        var body = new LogoutRequest(auth.RefreshToken);
        var responses = await Task.WhenAll(
            client.PostAsJsonAsync("/api/auth/logout", body),
            client.PostAsJsonAsync("/api/auth/logout", body));

        Assert.All(responses, r => Assert.Equal(HttpStatusCode.NoContent, r.StatusCode));
    }
}
