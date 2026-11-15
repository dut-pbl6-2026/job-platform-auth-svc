using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Auth.Core.Contracts;
using Auth.Core.Entities;
using Auth.Infrastructure.Data;
using Auth.Tests.Fixtures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Tests;

/// <summary>
/// Resend-verification and refresh over HTTP against the real container. Resend calls in this class total
/// five, the per-IP limit of 5 per hour, so add no resend call here: the 429 check lives in
/// <see cref="ResendVerificationRateLimitTests"/> with its own host.
/// </summary>
public sealed class ResendVerificationEndpointTests : IClassFixture<RecordingAuthFactory>, IAsyncLifetime
{
    private const string Password = "SecureP@ss123";
    private readonly RecordingAuthFactory _factory;

    public ResendVerificationEndpointTests(RecordingAuthFactory factory) => _factory = factory;

    public Task InitializeAsync() => _factory.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private static string UniqueEmail(string prefix) => $"{prefix}{Guid.NewGuid():N}@test.com";

    private async Task<string> RegisterAsync(HttpClient client, string prefix)
    {
        var email = UniqueEmail(prefix);
        var res = await client.PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, Password, "Resend User"));
        Assert.Equal(HttpStatusCode.Accepted, res.StatusCode);
        return email;
    }

    private static async Task<HttpResponseMessage> ResendAsync(HttpClient client, string email) =>
        await client.PostAsJsonAsync("/api/auth/resend-verification", new ResendVerificationRequest(email));

    private async Task<int> OutboxCountAsync(string email)
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        return await db.EmailOutboxMessages.CountAsync(m => m.Recipient == email);
    }

    [Fact]
    public async Task Resend_UnknownVerifiedAndUnverified_ReturnIdentical202Bodies()
    {
        var client = _factory.CreateClient();
        var unverified = await RegisterAsync(client, "pending");
        var verified = await RegisterAsync(client, "verified");
        await using (var scope = _factory.Services.CreateAsyncScope())
            await AccountHelpers.VerifyEmailAsync(scope.ServiceProvider.GetRequiredService<AuthDbContext>(), verified);

        var unknownRes = await ResendAsync(client, UniqueEmail("ghost"));
        var verifiedRes = await ResendAsync(client, verified);
        var unverifiedRes = await ResendAsync(client, unverified);

        Assert.Equal(HttpStatusCode.Accepted, unknownRes.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, verifiedRes.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, unverifiedRes.StatusCode);
        var unknownBody = await unknownRes.Content.ReadAsStringAsync();
        Assert.Equal(unknownBody, await verifiedRes.Content.ReadAsStringAsync());
        Assert.Equal(unknownBody, await unverifiedRes.Content.ReadAsStringAsync());

        using var doc = JsonDocument.Parse(unknownBody);
        Assert.Equal(new[] { "message" }, doc.RootElement.EnumerateObject().Select(p => p.Name).ToArray());
    }

    [Fact]
    public async Task Resend_UnverifiedAccount_QueuesExactlyOneOutboxRow()
    {
        var client = _factory.CreateClient();
        var email = await RegisterAsync(client, "queue");
        await _factory.DeliverPendingEmailsAsync();
        var before = await OutboxCountAsync(email);

        var res = await ResendAsync(client, email);

        Assert.Equal(HttpStatusCode.Accepted, res.StatusCode);
        Assert.Equal(before + 1, await OutboxCountAsync(email));
        await using var scope = _factory.Services.CreateAsyncScope();
        var row = await scope.ServiceProvider.GetRequiredService<AuthDbContext>().EmailOutboxMessages
            .Where(m => m.Recipient == email).OrderByDescending(m => m.CreatedAt).FirstAsync();
        Assert.Equal(EmailKind.EmailVerification, row.Kind);
        Assert.StartsWith("http://localhost:5173/verify-email?token=", row.Link);
    }

    [Fact]
    public async Task Resend_AfterLinkExpired_NewLinkVerifiesAndOldLinkDoesNot()
    {
        var client = _factory.CreateClient();
        var email = await RegisterAsync(client, "expired");
        await _factory.DeliverPendingEmailsAsync();
        var oldToken = RecordingEmailSender.TokenFrom(_factory.Emails.Single("EmailVerification").Link!);

        // Expire the first link in the database, as if it were clicked after its 24 hours.
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var userId = (await db.Users.SingleAsync(u => u.Email == email)).Id;
            await db.EmailVerificationTokens.Where(t => t.UserId == userId)
                .ExecuteUpdateAsync(s => s.SetProperty(t => t.ExpiresAt, DateTime.UtcNow.AddMinutes(-1)));
        }
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest(oldToken))).StatusCode);

        Assert.Equal(HttpStatusCode.Accepted, (await ResendAsync(client, email)).StatusCode);
        await _factory.DeliverPendingEmailsAsync();
        var newToken = RecordingEmailSender.TokenFrom(_factory.Emails.Sent.Last(e => e.Kind == "EmailVerification").Link!);

        Assert.NotEqual(oldToken, newToken);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest(newToken))).StatusCode);
    }

    [Fact]
    public async Task Refresh_InvalidToken_Returns401WithEmptyBody()
    {
        var res = await _factory.CreateClient().PostAsJsonAsync("/api/auth/refresh", new RefreshRequest("not-a-real-token"));

        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        Assert.Equal("", await res.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Refresh_TwoConcurrentRequestsWithSameToken_ExactlyOneSucceeds()
    {
        var client = _factory.CreateClient();
        var email = await RegisterAsync(client, "race");
        await _factory.DeliverPendingEmailsAsync();
        var verifyToken = RecordingEmailSender.TokenFrom(_factory.Emails.Single("EmailVerification").Link!);
        await client.PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest(verifyToken));
        var login = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, Password));
        var auth = await login.Content.ReadFromJsonAsync<AuthResponse>();
        var body = new RefreshRequest(auth!.RefreshToken);

        var responses = await Task.WhenAll(
            client.PostAsJsonAsync("/api/auth/refresh", body),
            client.PostAsJsonAsync("/api/auth/refresh", body));

        var statuses = responses.Select(r => r.StatusCode).ToArray();
        Assert.Equal(1, statuses.Count(s => s == HttpStatusCode.OK));
        Assert.Equal(1, statuses.Count(s => s == HttpStatusCode.Unauthorized));
    }
}

/// <summary>Per-IP limit of 5 resends per hour on its own host, so the budget starts full.</summary>
public sealed class ResendVerificationRateLimitTests : IClassFixture<RecordingAuthFactory>, IAsyncLifetime
{
    private readonly RecordingAuthFactory _factory;

    public ResendVerificationRateLimitTests(RecordingAuthFactory factory) => _factory = factory;

    public Task InitializeAsync() => _factory.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Resend_SixthFromOneIp_Returns429()
    {
        var client = _factory.CreateClient();
        HttpStatusCode? sixth = null;
        for (var i = 0; i < 6; i++)
        {
            var res = await client.PostAsJsonAsync("/api/auth/resend-verification", new ResendVerificationRequest($"rl{i}@test.com"));
            if (i < 5)
                Assert.Equal(HttpStatusCode.Accepted, res.StatusCode);
            else
                sixth = res.StatusCode;
        }
        Assert.Equal(HttpStatusCode.TooManyRequests, sixth);
    }
}
