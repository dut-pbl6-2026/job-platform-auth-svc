using System.Net;
using Auth.Core.Contracts;
using Auth.Core.Entities;
using Auth.Core.Interfaces;
using Auth.Core.Security;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Auth.Tests.Fixtures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SharedKernel;

namespace Auth.Tests;

/// <summary>
/// Company self-serve sign-up and verification against a real database and a fake job-svc
/// (AUTH-01-10, AUTH-01-11, AUTH-01-12, backlog A13).
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class CompanySignUpServiceTests : IAsyncLifetime
{
    private const string Password = "SecureP@ss123";
    private const string CompanyName = "Acme Labs";
    private const string TaxCode = "0101234567";
    private readonly PostgresFixture _fixture;
    private readonly FakeCompanyDirectory _directory = new();

    public CompanySignUpServiceTests(PostgresFixture fixture) => _fixture = fixture;

    public async Task InitializeAsync()
    {
        await _fixture.ResetAsync();
        _directory.Reset();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    // ---- sign-up -------------------------------------------------------------------------

    [Fact]
    public async Task FreeProvider_IsRejectedBeforeAnyLookup_AndStoresNothing()
    {
        using var db = _fixture.CreateDbContext();

        var status = await Service(db).RegisterAsync(SignUp("founder@gmail.com"));

        Assert.Equal(CompanySignUpStatus.WorkEmailRequired, status);
        Assert.Equal(0, _directory.DomainLookups + _directory.AvailabilityLookups);
        Assert.Empty(await db.PendingCompanySignups.ToListAsync());
        Assert.Empty(await db.EmailOutboxMessages.ToListAsync());
    }

    [Fact]
    public async Task NewCompany_StoresPendingSignUpAndQueuesOnlyTheVerificationLink()
    {
        using var db = _fixture.CreateDbContext();

        var status = await Service(db).RegisterAsync(SignUp("founder@acme.example"));

        Assert.Equal(CompanySignUpStatus.Accepted, status);
        Assert.Equal(1, _directory.DomainLookups);
        Assert.Equal(1, _directory.AvailabilityLookups);
        var pending = await db.PendingCompanySignups.SingleAsync();
        Assert.Equal(CompanyName, pending.CompanyName);
        Assert.Equal(TaxCode, pending.TaxCode);
        Assert.NotEqual(Password, pending.PasswordHash);
        var mail = await db.EmailOutboxMessages.SingleAsync();
        Assert.Equal(EmailKind.CompanySignUpVerification, mail.Kind);
        Assert.Contains("/verify-email?token=", mail.Link);
        Assert.Empty(await db.Users.ToListAsync());
    }

    [Fact]
    public async Task DomainMatched_IgnoresTakenName_AndStillQueuesVerification()
    {
        _directory.AddVerifiedCompany("acme.example", CompanyName);
        using var db = _fixture.CreateDbContext();

        var status = await Service(db).RegisterAsync(SignUp("second@acme.example"));

        Assert.Equal(CompanySignUpStatus.Accepted, status);
        Assert.Single(await db.PendingCompanySignups.ToListAsync());
        Assert.Equal(EmailKind.CompanySignUpVerification, (await db.EmailOutboxMessages.SingleAsync()).Kind);
    }

    [Fact]
    public async Task NameTaken_QueuesNoticeOnly_AndDeletesEarlierPendingSignUp()
    {
        using var db = _fixture.CreateDbContext();
        var svc = Service(db);
        await svc.RegisterAsync(SignUp("founder@acme.example"));
        _directory.TakeName(CompanyName);

        var status = await svc.RegisterAsync(SignUp("founder@acme.example"));

        Assert.Equal(CompanySignUpStatus.Accepted, status);
        Assert.Empty(await db.PendingCompanySignups.ToListAsync());
        var kinds = await db.EmailOutboxMessages.Select(m => m.Kind).ToListAsync();
        Assert.Contains(EmailKind.CompanySignUpNotice, kinds);
        var notice = await db.EmailOutboxMessages.Where(m => m.Kind == EmailKind.CompanySignUpNotice).SingleAsync();
        Assert.Null(notice.Link);
    }

    [Fact]
    public async Task TaxCodeTaken_QueuesNotice()
    {
        _directory.TakeTaxCode(TaxCode);
        using var db = _fixture.CreateDbContext();

        await Service(db).RegisterAsync(SignUp("founder@acme.example"));

        Assert.Empty(await db.PendingCompanySignups.ToListAsync());
        Assert.Equal(EmailKind.CompanySignUpNotice, (await db.EmailOutboxMessages.SingleAsync()).Kind);
    }

    [Fact]
    public async Task ExistingAccount_QueuesNoticeAndDoesNotStoreSignUp()
    {
        using var db = _fixture.CreateDbContext();
        db.Users.Add(new User("taken@acme.example", "hash", "Existing", "User"));
        await db.SaveChangesAsync();

        var status = await Service(db).RegisterAsync(SignUp("taken@acme.example"));

        Assert.Equal(CompanySignUpStatus.Accepted, status);
        Assert.Empty(await db.PendingCompanySignups.ToListAsync());
        Assert.Equal(EmailKind.CompanySignUpNotice, (await db.EmailOutboxMessages.SingleAsync()).Kind);
    }

    [Fact]
    public async Task LookupFailure_Returns_Unavailable_AndStoresNothing_EvenForAnExistingAccount()
    {
        using var db = _fixture.CreateDbContext();
        db.Users.Add(new User("taken@acme.example", "hash", "Existing", "User"));
        await db.SaveChangesAsync();
        _directory.Unavailable = true;

        var status = await Service(db).RegisterAsync(SignUp("taken@acme.example"));

        Assert.Equal(CompanySignUpStatus.Unavailable, status);
        Assert.Empty(await db.PendingCompanySignups.ToListAsync());
        Assert.Empty(await db.EmailOutboxMessages.ToListAsync());
    }

    [Fact]
    public async Task WeakPassword_IsRejectedBeforeAnyLookup()
    {
        using var db = _fixture.CreateDbContext();

        var status = await Service(db).RegisterAsync(new RegisterCompanyRequest(CompanyName, TaxCode, "f@acme.example", "weak", "Founder"));

        Assert.Equal(CompanySignUpStatus.WeakPassword, status);
        Assert.Equal(0, _directory.DomainLookups + _directory.AvailabilityLookups);
    }

    [Fact]
    public async Task NewerAttempt_ReplacesEarlierPending_SoOnlyTheNewestLinkWorks()
    {
        using var db = _fixture.CreateDbContext();
        var svc = Service(db);
        await svc.RegisterAsync(SignUp("founder@acme.example"));
        var firstToken = RecordingEmailSender.TokenFrom((await db.EmailOutboxMessages.SingleAsync()).Link!);
        await svc.RegisterAsync(SignUp("founder@acme.example"));

        Assert.Single(await db.PendingCompanySignups.ToListAsync());
        Assert.Equal(CompanyVerifyOutcome.NotCompanyToken, await svc.VerifyAsync(firstToken));
    }

    [Fact]
    public async Task EveryLookupRunsOnce_NoMatterTheOutcome()
    {
        _directory.TakeName(CompanyName);
        using var db = _fixture.CreateDbContext();
        await Service(db).RegisterAsync(SignUp("founder@acme.example"));

        Assert.Equal(1, _directory.DomainLookups);
        Assert.Equal(1, _directory.AvailabilityLookups);
    }

    // ---- verification --------------------------------------------------------------------

    [Fact]
    public async Task Verify_NewCompany_CreatesActiveRecruiterWithCompany_AndTheLinkIsSingleUse()
    {
        using var db = _fixture.CreateDbContext();
        var svc = Service(db);
        var token = await SignUpAndGetTokenAsync(db, svc, "founder@acme.example");

        var first = await svc.VerifyAsync(token);
        var second = await svc.VerifyAsync(token);

        Assert.Equal(CompanyVerifyOutcome.Processed, first);
        Assert.Equal(CompanyVerifyOutcome.NotCompanyToken, second);
        var user = await db.Users.SingleAsync(u => u.Email == "founder@acme.example");
        Assert.True(user.IsActive);
        Assert.True(user.IsEmailVerified);
        Assert.Equal("Recruiter", user.Role);
        var company = Assert.Single(_directory.CompaniesCreated);
        Assert.Equal(user.Id, company.CreatedBy);
        Assert.Equal(company.Id, user.CompanyId);
        Assert.Equal("acme.example", company.EmailDomain);
        Assert.Empty(_directory.JoinRequests);
        Assert.Empty(await db.PendingCompanySignups.ToListAsync());
    }

    [Fact]
    public async Task Verify_DomainMatched_CreatesJoinRequest_AndNeverCreatesACompany()
    {
        _directory.AddVerifiedCompany("acme.example", "Existing Co");
        using var db = _fixture.CreateDbContext();
        var svc = Service(db);
        var token = await SignUpAndGetTokenAsync(db, svc, "founder@acme.example");

        var outcome = await svc.VerifyAsync(token);

        Assert.Equal(CompanyVerifyOutcome.Processed, outcome);
        Assert.Empty(_directory.CompaniesCreated);
        var join = Assert.Single(_directory.JoinRequests);
        var user = await db.Users.SingleAsync(u => u.Email == "founder@acme.example");
        Assert.Equal(user.Id, join.UserId);
        Assert.True(user.IsActive);
        Assert.Equal("User", user.Role);
        Assert.Null(user.CompanyId);
    }

    [Fact]
    public async Task Verify_NameTakenSinceSignUp_SendsNotice_CreatesNothing_AndDeletesPending()
    {
        using var db = _fixture.CreateDbContext();
        var svc = Service(db);
        var token = await SignUpAndGetTokenAsync(db, svc, "founder@acme.example");
        _directory.TakeName(CompanyName);

        var outcome = await svc.VerifyAsync(token);

        Assert.Equal(CompanyVerifyOutcome.Processed, outcome);
        Assert.Empty(await db.Users.ToListAsync());
        Assert.Empty(_directory.CompaniesCreated);
        Assert.Empty(await db.PendingCompanySignups.ToListAsync());
        Assert.Equal(EmailKind.CompanySignUpNotice, (await db.EmailOutboxMessages.OrderByDescending(m => m.CreatedAt).FirstAsync()).Kind);
    }

    [Fact]
    public async Task Verify_EmailGainedAnAccountSinceSignUp_SendsNotice_AndCreatesNoSecondAccount()
    {
        using var db = _fixture.CreateDbContext();
        var svc = Service(db);
        var token = await SignUpAndGetTokenAsync(db, svc, "founder@acme.example");
        db.Users.Add(new User("founder@acme.example", "hash", "Personal", "User"));
        await db.SaveChangesAsync();

        var outcome = await svc.VerifyAsync(token);

        Assert.Equal(CompanyVerifyOutcome.Processed, outcome);
        Assert.Equal(1, await db.Users.CountAsync());
        Assert.Empty(_directory.CompaniesCreated);
        Assert.Empty(await db.PendingCompanySignups.ToListAsync());
    }

    [Fact]
    public async Task Verify_JobFailsOnCreate_RemovesUser_RestoresLink_AndTheSameLinkWorksAgain()
    {
        using var db = _fixture.CreateDbContext();
        var svc = Service(db);
        var token = await SignUpAndGetTokenAsync(db, svc, "founder@acme.example");
        _directory.UnavailableCreatesRemaining = 1;

        var failed = await svc.VerifyAsync(token);

        Assert.Equal(CompanyVerifyOutcome.Unavailable, failed);
        Assert.Empty(await db.Users.ToListAsync());
        Assert.Single(await db.PendingCompanySignups.ToListAsync());

        var retried = await svc.VerifyAsync(token);

        Assert.Equal(CompanyVerifyOutcome.Processed, retried);
        var user = await db.Users.SingleAsync();
        Assert.True(user.IsActive);
        Assert.Equal(user.CompanyId, Assert.Single(_directory.CompaniesCreated).Id);
    }

    [Fact]
    public async Task Verify_JobFailsOnJoinRequest_RemovesUser_AndRestoresLink()
    {
        _directory.AddVerifiedCompany("acme.example", "Existing Co");
        using var db = _fixture.CreateDbContext();
        var svc = Service(db);
        var token = await SignUpAndGetTokenAsync(db, svc, "founder@acme.example");
        _directory.UnavailableCreatesRemaining = 1;

        Assert.Equal(CompanyVerifyOutcome.Unavailable, await svc.VerifyAsync(token));
        Assert.Empty(await db.Users.ToListAsync());
        Assert.Single(await db.PendingCompanySignups.ToListAsync());

        Assert.Equal(CompanyVerifyOutcome.Processed, await svc.VerifyAsync(token));
        Assert.Single(_directory.JoinRequests);
    }

    [Fact]
    public async Task Verify_CompanyTakenBetweenLookupAndCreate_SendsNotice_AndRemovesUser()
    {
        using var db = _fixture.CreateDbContext();
        var svc = Service(db);
        var token = await SignUpAndGetTokenAsync(db, svc, "founder@acme.example");
        // The lookup passes, then another request takes the name before the create.
        _directory.BeforeCreate = () =>
        {
            _directory.TakeName(CompanyName);
            return Task.CompletedTask;
        };

        var outcome = await svc.VerifyAsync(token);

        Assert.Equal(CompanyVerifyOutcome.Processed, outcome);
        Assert.Empty(await db.Users.ToListAsync());
        Assert.Empty(await db.PendingCompanySignups.ToListAsync());
        Assert.Empty(_directory.CompaniesCreated);
    }

    [Fact]
    public async Task Verify_LookupUnavailable_LeavesTheLinkAndCreatesNothing()
    {
        using var db = _fixture.CreateDbContext();
        var svc = Service(db);
        var token = await SignUpAndGetTokenAsync(db, svc, "founder@acme.example");
        _directory.Unavailable = true;

        Assert.Equal(CompanyVerifyOutcome.Unavailable, await svc.VerifyAsync(token));
        Assert.Single(await db.PendingCompanySignups.ToListAsync());
        Assert.Empty(await db.Users.ToListAsync());

        _directory.Unavailable = false;
        Assert.Equal(CompanyVerifyOutcome.Processed, await svc.VerifyAsync(token));
    }

    [Fact]
    public async Task Verify_ExpiredLink_IsInvalidAndRemovesTheRow()
    {
        using var db = _fixture.CreateDbContext();
        var svc = Service(db);
        var token = await SignUpAndGetTokenAsync(db, svc, "founder@acme.example");
        await db.PendingCompanySignups.ExecuteUpdateAsync(s => s.SetProperty(p => p.ExpiresAt, DateTime.UtcNow.AddMinutes(-1)));

        Assert.Equal(CompanyVerifyOutcome.Invalid, await svc.VerifyAsync(token));
        Assert.Empty(await db.PendingCompanySignups.ToListAsync());
        Assert.Empty(await db.Users.ToListAsync());
    }

    [Fact]
    public async Task Verify_ConcurrentSecondUse_CreatesOneCompany_AndTheLoserGetsInvalid()
    {
        using var db = _fixture.CreateDbContext();
        var svc = Service(db);
        var token = await SignUpAndGetTokenAsync(db, svc, "founder@acme.example");

        // While the first use is between its lookup and its claim, a second use of the same link completes.
        CompanyVerifyOutcome? nested = null;
        var fired = false;
        _directory.BeforeAvailability = async () =>
        {
            if (fired) return;
            fired = true;
            using var inner = _fixture.CreateDbContext();
            nested = await Service(inner).VerifyAsync(token);
        };

        var outer = await svc.VerifyAsync(token);

        Assert.Equal(CompanyVerifyOutcome.Processed, nested);
        Assert.Equal(CompanyVerifyOutcome.Invalid, outer);
        Assert.Single(_directory.CompaniesCreated);
        Assert.Equal(1, await db.Users.CountAsync());
    }

    [Fact]
    public async Task Verify_UnknownToken_IsNotACompanyToken()
    {
        using var db = _fixture.CreateDbContext();
        Assert.Equal(CompanyVerifyOutcome.NotCompanyToken, await Service(db).VerifyAsync("not-a-real-token"));
    }

    [Fact]
    public async Task Verify_FailedJobCall_LeavesNoInactiveUserBehind()
    {
        using var db = _fixture.CreateDbContext();
        var svc = Service(db);
        var token = await SignUpAndGetTokenAsync(db, svc, "founder@acme.example");
        _directory.UnavailableCreatesRemaining = 1;

        await svc.VerifyAsync(token);

        Assert.False(await db.Users.AnyAsync(u => !u.IsActive));
    }

    // ---- helpers -----------------------------------------------------------------------

    private async Task<string> SignUpAndGetTokenAsync(AuthDbContext db, ICompanySignUpService svc, string email)
    {
        await svc.RegisterAsync(SignUp(email));
        var mail = await db.EmailOutboxMessages.Where(m => m.Kind == EmailKind.CompanySignUpVerification).SingleAsync();
        return RecordingEmailSender.TokenFrom(mail.Link!);
    }

    private static RegisterCompanyRequest SignUp(string email) =>
        new(CompanyName, TaxCode, email, Password, "Founder Name");

    private CompanySignUpService Service(AuthDbContext db)
    {
        var jwt = new JwtTokenService(Options.Create(new JwtOptions
        {
            Issuer = "job-platform",
            Audience = "job-platform",
            ExpiresMinutes = 60,
        }), TestSigningKeys.Keys);
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["WEB_URL"] = "http://localhost:5173" })
            .Build();
        return new CompanySignUpService(db, new PasswordHasherService(), jwt, _directory, new WorkEmailPolicy(), cfg,
            NullLogger<CompanySignUpService>.Instance);
    }
}
