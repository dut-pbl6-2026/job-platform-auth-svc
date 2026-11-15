using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Auth.Core.Contracts;
using Auth.Core.Entities;
using Auth.Api.Endpoints;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Data;
using Auth.Tests.Fixtures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Tests;

/// <summary>
/// Company self-serve sign-up, verification and the job-svc link-company call, end to end through HTTP
/// (AUTH-01-10 to AUTH-01-12, AUTH-01-14). Each test starts with an empty per-IP sign-up bucket.
/// </summary>
public sealed class CompanySignUpEndpointTests : IClassFixture<CompanySignUpHost>, IAsyncLifetime
{
    private const string Password = "SecureP@ss123";
    private const string Accepted = "Check your email to continue the company sign-up.";
    private const string Processed = "Your sign-up has been processed.";
    private readonly CompanySignUpHost _host;

    public CompanySignUpEndpointTests(CompanySignUpHost host) => _host = host;

    public Task InitializeAsync() => _host.Reset();

    public Task DisposeAsync() => Task.CompletedTask;

    private RecordingAuthFactory Factory => _host.Factory;

    private HttpClient Client() => Factory.CreateClient();

    private static string UniqueEmail(string domain) => $"founder{Guid.NewGuid():N}@{domain}";

    private static object SignUpBody(string email, string companyName = "Acme Labs", string? taxCode = "0101234567") =>
        new { companyName, taxCode, email, password = Password, fullName = "Founder Name" };

    private async Task<HttpResponseMessage> SignUpAsync(string email, string companyName = "Acme Labs", string? taxCode = "0101234567") =>
        await Client().PostAsJsonAsync("/api/auth/register-company", SignUpBody(email, companyName, taxCode));

    private static async Task<string> MessageOf(HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("message").GetString()!;

    private static async Task<string?> ErrorCodeOf(HttpResponseMessage response) =>
        (await response.Content.ReadFromJsonAsync<JsonElement>()).TryGetProperty("errorCode", out var code)
            ? code.GetString()
            : null;

    private string LinkFor(string email) =>
        Factory.Emails.Sent.Single(e => e.Email == email && e.Kind == "CompanySignUpVerification").Link!;

    // ---- sign-up ---------------------------------------------------------------------------

    [Fact]
    public async Task SignUp_ReturnsTheSame202Body_ForEveryOutcome()
    {
        Factory.CompanyDirectory.AddVerifiedCompany("corp.example", "Corp Verified");
        Factory.CompanyDirectory.TakeName("Taken Name");
        var existing = UniqueEmail("existing.example");
        await using (var scope = Factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            db.Users.Add(new User(existing, "hash", "Existing", "User"));
            await db.SaveChangesAsync();
        }

        var newCompany = UniqueEmail("new.example");
        var domainMatch = UniqueEmail("corp.example");
        var nameTaken = UniqueEmail("other.example");
        var emailTaken = existing;
        var responses = new[]
        {
            await SignUpAsync(newCompany, "Fresh Co"),
            await SignUpAsync(domainMatch, "Ignored Name"),
            await SignUpAsync(nameTaken, "Taken Name"),
            await SignUpAsync(emailTaken, "Fresh Two"),
        };

        foreach (var res in responses)
        {
            Assert.Equal(HttpStatusCode.Accepted, res.StatusCode);
            Assert.Null(res.Headers.Location);
            Assert.Equal(Accepted, await MessageOf(res));
        }
        Assert.Equal(
            await responses[0].Content.ReadAsStringAsync(),
            await responses[3].Content.ReadAsStringAsync());

        await Factory.DeliverPendingEmailsAsync();
        Assert.Equal("CompanySignUpVerification", Factory.Emails.Sent.Single(e => e.Email == newCompany).Kind);
        Assert.Equal("CompanySignUpVerification", Factory.Emails.Sent.Single(e => e.Email == domainMatch).Kind);
        // The notice goes only to the address in the request, has no link, and nobody else gets a mail.
        foreach (var address in new[] { nameTaken, emailTaken })
        {
            var notice = Factory.Emails.Sent.Single(e => e.Email == address);
            Assert.Equal("CompanySignUpNotice", notice.Kind);
            Assert.Null(notice.Link);
        }
        Assert.Equal(4, Factory.Emails.Sent.Count);
    }

    [Fact]
    public async Task SignUp_FreeProvider_Returns422_WorkEmailRequired()
    {
        var res = await SignUpAsync("someone@gmail.com");

        Assert.Equal(HttpStatusCode.UnprocessableEntity, res.StatusCode);
        Assert.Equal("WORK_EMAIL_REQUIRED", await ErrorCodeOf(res));
    }

    [Fact]
    public async Task SignUp_LookupFailure_Returns503_AndStoresNothing()
    {
        Factory.CompanyDirectory.Unavailable = true;
        var email = UniqueEmail("acme.example");

        var res = await SignUpAsync(email);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, res.StatusCode);
        await using var scope = Factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        Assert.Empty(await db.PendingCompanySignups.ToListAsync());
        Assert.Empty(await db.EmailOutboxMessages.ToListAsync());
    }

    [Fact]
    public async Task SignUp_WeakPassword_Returns400Validation()
    {
        var res = await Client().PostAsJsonAsync("/api/auth/register-company",
            new { companyName = "Acme", taxCode = (string?)null, email = UniqueEmail("acme.example"), password = "weak", fullName = "F" });

        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task SignUp_IsLimitedTo5PerIpPerHour_WhateverTheOutcome()
    {
        Factory.CompanyDirectory.TakeName("Taken Name");
        var existing = UniqueEmail("limit.example");
        await using (var scope = Factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            db.Users.Add(new User(existing, "hash", "Existing", "User"));
            await db.SaveChangesAsync();
        }

        var statuses = new List<HttpStatusCode>
        {
            (await SignUpAsync(UniqueEmail("a.example"), "Fresh A")).StatusCode,
            (await SignUpAsync(UniqueEmail("gmail.com"))).StatusCode,
            (await SignUpAsync(UniqueEmail("b.example"), "Taken Name")).StatusCode,
            (await SignUpAsync(existing, "Fresh B")).StatusCode,
        };
        Factory.CompanyDirectory.Unavailable = true;
        statuses.Add((await SignUpAsync(UniqueEmail("c.example"), "Fresh C")).StatusCode);
        Factory.CompanyDirectory.Unavailable = false;

        Assert.Equal(
            new[] { HttpStatusCode.Accepted, HttpStatusCode.UnprocessableEntity, HttpStatusCode.Accepted, HttpStatusCode.Accepted, HttpStatusCode.ServiceUnavailable },
            statuses);
        // The sixth request in the hour is refused before any lookup, whatever its outcome would have been.
        var sixth = await SignUpAsync(UniqueEmail("d.example"), "Fresh D");
        Assert.Equal(HttpStatusCode.TooManyRequests, sixth.StatusCode);
    }

    // ---- verification -----------------------------------------------------------------------

    [Fact]
    public async Task Verify_NewCompany_ReturnsTheFixedMessage_AndTheFounderCanLogIn()
    {
        var email = UniqueEmail("acme.example");
        await SignUpAsync(email);
        await Factory.DeliverPendingEmailsAsync();

        var res = await Client().PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest(RecordingEmailSender.TokenFrom(LinkFor(email))));

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal(Processed, await MessageOf(res));
        var login = await Client().PostAsJsonAsync("/api/auth/login", new LoginRequest(email, Password));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    [Fact]
    public async Task Verify_DomainMatch_ReturnsTheSameFixedMessage_AndTheRequesterCanLogIn()
    {
        Factory.CompanyDirectory.AddVerifiedCompany("join.example", "Join Co");
        var email = UniqueEmail("join.example");
        await SignUpAsync(email);
        await Factory.DeliverPendingEmailsAsync();

        var res = await Client().PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest(RecordingEmailSender.TokenFrom(LinkFor(email))));

        Assert.Equal(Processed, await MessageOf(res));
        Assert.Equal(HttpStatusCode.OK, (await Client().PostAsJsonAsync("/api/auth/login", new LoginRequest(email, Password))).StatusCode);
    }

    [Fact]
    public async Task Verify_NameTakenSinceSignUp_ReturnsTheSameFixedMessage_AndSendsTheNotice()
    {
        var email = UniqueEmail("acme.example");
        await SignUpAsync(email, "Race Co");
        await Factory.DeliverPendingEmailsAsync();
        var token = RecordingEmailSender.TokenFrom(LinkFor(email));
        Factory.CompanyDirectory.TakeName("Race Co");

        var res = await Client().PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest(token));
        await Factory.DeliverPendingEmailsAsync();

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal(Processed, await MessageOf(res));
        Assert.Equal("CompanySignUpNotice", Factory.Emails.Sent.Last(e => e.Email == email).Kind);
    }

    [Fact]
    public async Task Verify_BadOrReusedToken_Returns422_VerificationTokenInvalid()
    {
        var email = UniqueEmail("acme.example");
        await SignUpAsync(email);
        await Factory.DeliverPendingEmailsAsync();
        var token = RecordingEmailSender.TokenFrom(LinkFor(email));
        var client = Client();

        var unknown = await client.PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest("not-a-real-token"));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, unknown.StatusCode);
        Assert.Equal("VERIFICATION_TOKEN_INVALID", await ErrorCodeOf(unknown));

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest(token))).StatusCode);
        var reused = await client.PostAsJsonAsync("/api/auth/verify-email", new VerifyEmailRequest(token));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, reused.StatusCode);
    }

    // ---- link-company (job-svc to auth-svc) ---------------------------------------------------

    [Fact]
    public async Task LinkCompany_RequiresTheJobCallerToken_IsIdempotentForOneCompany_AndRefusesAnother()
    {
        Guid userId;
        await using (var scope = Factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var user = new User(UniqueEmail("joiner.example"), "hash", "Joiner", "User");
            db.Users.Add(user);
            await db.SaveChangesAsync();
            userId = user.Id;
        }
        var companyA = Guid.NewGuid();
        var companyB = Guid.NewGuid();

        foreach (var token in new[] { null, RecordingAuthFactory.NotifInternalToken, RecordingAuthFactory.OutboundJobToken, RecordingAuthFactory.LegacySharedToken })
        {
            var denied = await LinkCompanyAsync(userId, companyA, token);
            Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        }

        var linked = await LinkCompanyAsync(userId, companyA, RecordingAuthFactory.JobCallerInternalToken);
        Assert.Equal(HttpStatusCode.NoContent, linked.StatusCode);
        var again = await LinkCompanyAsync(userId, companyA, RecordingAuthFactory.JobCallerInternalToken);
        Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);
        var other = await LinkCompanyAsync(userId, companyB, RecordingAuthFactory.JobCallerInternalToken);
        Assert.Equal(HttpStatusCode.Conflict, other.StatusCode);
        Assert.Equal("ACCOUNT_ALREADY_HAS_COMPANY", await ErrorCodeOf(other));

        await using var check = Factory.Services.CreateAsyncScope();
        var stored = await check.ServiceProvider.GetRequiredService<AuthDbContext>().Users.AsNoTracking().SingleAsync(u => u.Id == userId);
        Assert.Equal("Recruiter", stored.Role);
        Assert.Equal(companyA, stored.CompanyId);
    }

    [Fact]
    public async Task LinkCompany_UnknownUser_Returns404()
    {
        var res = await LinkCompanyAsync(Guid.NewGuid(), Guid.NewGuid(), RecordingAuthFactory.JobCallerInternalToken);

        Assert.Equal(HttpStatusCode.NotFound, res.StatusCode);
    }

    private async Task<HttpResponseMessage> LinkCompanyAsync(Guid userId, Guid companyId, string? bearer)
    {
        var client = Client();
        if (bearer is not null)
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return await client.PostAsJsonAsync($"/api/internal/users/{userId}/link-company", new LinkCompanyRequest(companyId));
    }
}
