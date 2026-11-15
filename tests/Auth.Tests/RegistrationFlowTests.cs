using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Auth.Core.Contracts;
using Auth.Infrastructure.Data;
using Auth.Tests.Fixtures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Tests;

/// <summary>
/// Registration enumeration hardening and the emailed verification flow, end to end through HTTP.
/// Kept to fewer than 10 registrations per class to stay inside the register rate-limit bucket.
/// </summary>
public sealed class RegistrationFlowTests : IClassFixture<RecordingAuthFactory>, IAsyncLifetime
{
    private const string Password = "SecureP@ss123";
    private readonly RecordingAuthFactory _factory;

    public RegistrationFlowTests(RecordingAuthFactory factory) => _factory = factory;

    public Task InitializeAsync() => _factory.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private HttpClient Client() => _factory.CreateClient();

    private static string UniqueEmail(string prefix) => $"{prefix}{Guid.NewGuid():N}@test.com";

    private async Task<HttpResponseMessage> RegisterAsync(HttpClient client, string email) =>
        await client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, Password, "Flow User"));

    [Fact]
    public async Task Register_UnknownAndKnownEmail_ReturnIdenticalStatusAndBody()
    {
        var client = Client();
        var known = UniqueEmail("known");
        await RegisterAsync(client, known);

        var newRes = await RegisterAsync(client, UniqueEmail("new"));
        var dupRes = await RegisterAsync(client, known);

        Assert.Equal(HttpStatusCode.Accepted, newRes.StatusCode);
        Assert.Equal(newRes.StatusCode, dupRes.StatusCode);
        Assert.Equal(await newRes.Content.ReadAsStringAsync(), await dupRes.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Register_NewEmail_CreatesPendingAccountAndMailsLink()
    {
        var email = UniqueEmail("pending");
        await RegisterAsync(Client(), email);

        var sent = _factory.Emails.Single("EmailVerification");
        Assert.Equal(email, sent.Email);
        Assert.Contains("/verify-email?token=", sent.Link);
        await using var scope = _factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        Assert.False((await db.Users.SingleAsync(u => u.Email == email)).IsEmailVerified);
    }

    [Fact]
    public async Task Register_DuplicateEmail_MailsOwnerNoticeAndSendsNoLink()
    {
        var client = Client();
        var email = UniqueEmail("owner");
        await RegisterAsync(client, email);
        _factory.Emails.Clear();

        await RegisterAsync(client, email);

        Assert.Equal(["DuplicateRegistrationNotice"], _factory.Emails.Sent.Select(e => e.Kind));
    }

    [Fact]
    public async Task UnverifiedLogin_IsRefusedWithSameResponseAsWrongPassword()
    {
        var client = Client();
        var email = UniqueEmail("unverified");
        await RegisterAsync(client, email);

        var unverified = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, Password));
        var wrongPassword = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, "Wrong-pass1"));

        Assert.Equal(HttpStatusCode.Unauthorized, unverified.StatusCode);
        Assert.Equal(wrongPassword.StatusCode, unverified.StatusCode);
        Assert.Equal(await wrongPassword.Content.ReadAsStringAsync(), await unverified.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task VerifyLink_ActivatesAccount_ThenLoginSucceeds_AndLinkIsSingleUse()
    {
        var client = Client();
        var email = UniqueEmail("activate");
        await RegisterAsync(client, email);
        var token = RecordingEmailSender.TokenFrom(_factory.Emails.Single("EmailVerification").Link!);

        var verify = await client.PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest(token));
        var reuse = await client.PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest(token));
        var login = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, Password));

        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, reuse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    [Fact]
    public async Task VerifyEmail_UnknownToken_Returns400()
    {
        var res = await Client().PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest("not-a-real-token"));

        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task InternalUserEmail_WithoutToken_Returns401()
    {
        var res = await Client().GetAsync($"/api/internal/users/{Guid.NewGuid()}/email");

        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task InternalUserEmail_WrongToken_Returns401()
    {
        var client = Client();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "wrong-token");

        var res = await client.GetAsync($"/api/internal/users/{Guid.NewGuid()}/email");

        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task InternalUserEmail_UnknownId_Returns404()
    {
        var client = Client();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", RecordingAuthFactory.InternalToken);

        var res = await client.GetAsync($"/api/internal/users/{Guid.NewGuid()}/email");

        Assert.Equal(HttpStatusCode.NotFound, res.StatusCode);
    }

    [Fact]
    public async Task InternalUserEmail_WithToken_ReturnsEmailForKnownId()
    {
        var client = Client();
        var email = UniqueEmail("internal");
        await RegisterAsync(client, email);
        Guid userId;
        await using (var scope = _factory.Services.CreateAsyncScope())
            userId = (await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Users.SingleAsync(u => u.Email == email)).Id;

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", RecordingAuthFactory.InternalToken);
        var res = await client.GetAsync($"/api/internal/users/{userId}/email");

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        using var json = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
        Assert.Equal(["userId", "email"], json.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(userId, json.RootElement.GetProperty("userId").GetGuid());
        Assert.Equal(email, json.RootElement.GetProperty("email").GetString());
    }
}
