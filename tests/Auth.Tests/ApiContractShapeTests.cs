using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Auth.Core.Contracts;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Auth.Tests.Fixtures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Tests;

/// <summary>
/// Schema checks on live responses: property names and nesting that clients depend on.
/// Separate factory from <see cref="RegistrationFlowTests"/> so rate-limit buckets stay independent.
/// </summary>
public sealed class ApiContractShapeTests : IClassFixture<RecordingAuthFactory>, IAsyncLifetime
{
    private const string Password = "SecureP@ss123";
    private readonly RecordingAuthFactory _factory;

    public ApiContractShapeTests(RecordingAuthFactory factory) => _factory = factory;

    public Task InitializeAsync() => _factory.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private static async Task<JsonElement> ReadAsync(HttpResponseMessage res)
    {
        using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }

    private static string[] Keys(JsonElement obj) => obj.EnumerateObject().Select(p => p.Name).ToArray();

    /// <summary>Registers, activates through the emailed link, and returns the email.</summary>
    private async Task<string> RegisterAndVerifyAsync(HttpClient client, string prefix)
    {
        var email = $"{prefix}{Guid.NewGuid():N}@test.com";
        await client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, Password, "Shape User"));
        await _factory.DeliverPendingEmailsAsync();
        var token = RecordingEmailSender.TokenFrom(_factory.Emails.Single("EmailVerification").Link!);
        await client.PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest(token));
        return email;
    }

    [Fact]
    public async Task Register_Returns202WithMessageOnly()
    {
        var email = $"shape{Guid.NewGuid():N}@test.com";
        var res = await _factory.CreateClient().PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, Password, "Shape"));

        Assert.Equal(HttpStatusCode.Accepted, res.StatusCode);
        Assert.Equal(["message"], Keys(await ReadAsync(res)));
    }

    [Fact]
    public async Task VerifyEmail_Returns200WithMessageOnly()
    {
        var client = _factory.CreateClient();
        await client.PostAsJsonAsync("/api/auth/register", new RegisterRequest($"ver{Guid.NewGuid():N}@test.com", Password, "Ver"));
        await _factory.DeliverPendingEmailsAsync();
        var token = RecordingEmailSender.TokenFrom(_factory.Emails.Single("EmailVerification").Link!);

        var res = await client.PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest(token));

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal(["message"], Keys(await ReadAsync(res)));
    }

    [Fact]
    public async Task Login_Returns200WithTokensAndUser()
    {
        var client = _factory.CreateClient();
        var email = await RegisterAndVerifyAsync(client, "login");

        var res = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, Password));

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var body = await ReadAsync(res);
        Assert.Equal(["accessToken", "refreshToken", "user"], Keys(body));
        Assert.Equal(["id", "email", "fullName", "role", "companyId"], Keys(body.GetProperty("user")));
    }

    [Fact]
    public async Task Refresh_Returns200WithSameShape()
    {
        var client = _factory.CreateClient();
        var email = await RegisterAndVerifyAsync(client, "refresh");
        var login = await ReadAsync(await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, Password)));

        var res = await client.PostAsJsonAsync("/api/auth/refresh", new RefreshRequest(login.GetProperty("refreshToken").GetString()!));

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var body = await ReadAsync(res);
        Assert.Equal(["accessToken", "refreshToken", "user"], Keys(body));
        Assert.Equal(["id", "email", "fullName", "role", "companyId"], Keys(body.GetProperty("user")));
    }

    [Fact]
    public async Task ForgotAndReset_ReturnMessageOnlyShapes()
    {
        var client = _factory.CreateClient();
        var email = await RegisterAndVerifyAsync(client, "reset");

        var forgot = await client.PostAsJsonAsync("/api/auth/forgot-password", new ForgotPasswordRequest(email));
        Assert.Equal(HttpStatusCode.OK, forgot.StatusCode);
        Assert.Equal(["message"], Keys(await ReadAsync(forgot)));

        await _factory.DeliverPendingEmailsAsync();
        var token = Uri.UnescapeDataString(_factory.Emails.Single("PasswordReset").Link!.Split("token=")[1]);
        var reset = await client.PostAsJsonAsync("/api/auth/reset-password", new ResetPasswordRequest(token, "NewSecure456"));
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
        Assert.Equal(["message"], Keys(await ReadAsync(reset)));
    }

    [Fact]
    public async Task AdminStats_ReturnsUsersJobsApplicationsSections()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var admin = new Auth.Core.Entities.User($"admin{Guid.NewGuid():N}@test.com", "unused-hash", "Admin", "Admin");
        admin.VerifyEmail();
        db.Users.Add(admin);
        await db.SaveChangesAsync();
        var token = scope.ServiceProvider.GetRequiredService<JwtTokenService>()
            .GenerateAccessToken(admin.Id, admin.Email, "Admin");

        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var res = await client.GetAsync("/api/admin/stats");
        var raw = await res.Content.ReadAsStringAsync();

        Assert.True(res.StatusCode == HttpStatusCode.OK, $"{res.StatusCode}: {raw}");
        var body = await ReadAsync(res);
        // Camel-cased by the default JSON options; the C# records use PascalCase.
        Assert.Equal(["users", "jobs", "applications"], Keys(body));
        foreach (var section in new[] { "users", "jobs", "applications" })
            Assert.Contains("status", Keys(body.GetProperty(section)));
    }
}
