using Auth.Core.Contracts;
using Auth.Core.Entities;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Auth.Tests.Fixtures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SharedKernel;

namespace Auth.Tests;

/// <summary>SRS AUTH-01-06 / AUTH-01-09: recruiter registration with an invite code.</summary>
[Collection(PostgresCollection.Name)]
public class InviteCodeRegistrationTests : IAsyncLifetime
{
    private const string Password = "SecureP@ss123";
    private static readonly Guid CompanyA = Guid.NewGuid();
    private static readonly Guid CompanyB = Guid.NewGuid();
    private readonly PostgresFixture _fixture;

    public InviteCodeRegistrationTests(PostgresFixture fixture) => _fixture = fixture;

    public Task InitializeAsync() => _fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Recruiter_WithoutCode_FailsBeforeAnyJobCall()
    {
        var fake = new FakeInviteCodeClient();
        using var db = _fixture.CreateDbContext();
        var result = await Service(db, fake).RegisterAsync(Request("r1@b.com", "Recruiter"));

        Assert.False(result.IsSuccess);
        Assert.Equal(InviteCodeErrors.Missing, result.Error);
        Assert.Equal(0, fake.CheckCalls);
        Assert.Empty(await db.Users.ToListAsync());
    }

    [Fact]
    public async Task Recruiter_InvalidCode_FailsWithoutCreatingUser()
    {
        var fake = new FakeInviteCodeClient();
        using var db = _fixture.CreateDbContext();
        var result = await Service(db, fake).RegisterAsync(Request("r2@b.com", "Recruiter", inviteCode: "BAD"));

        Assert.False(result.IsSuccess);
        Assert.Equal(InviteCodeErrors.Invalid, result.Error);
        Assert.Equal(0, fake.RedeemCalls);
        Assert.Empty(await db.Users.ToListAsync());
    }

    [Fact]
    public async Task Recruiter_ValidCode_CreatesUserInCodesCompanyAndRedeemsOnce()
    {
        var fake = new FakeInviteCodeClient();
        var code = fake.Add("CODE-ONE", CompanyA, "r3@b.com");
        using var db = _fixture.CreateDbContext();

        // The client-sent companyId is ignored: the company comes from the code.
        var result = await Service(db, fake).RegisterAsync(
            Request("r3@b.com", "Recruiter", inviteCode: code, companyId: CompanyB));

        Assert.True(result.IsSuccess);
        var user = await db.Users.SingleAsync(u => u.Email == "r3@b.com");
        Assert.Equal("Recruiter", user.Role);
        Assert.Equal(CompanyA, user.CompanyId);
        Assert.Equal(1, fake.RedeemCalls);
        Assert.Empty(fake.Released);
    }

    [Fact]
    public async Task Recruiter_SecondUseOfSameCode_IsRejected()
    {
        var fake = new FakeInviteCodeClient();
        var code = fake.Add("CODE-TWO", CompanyA, "first@b.com");
        using var db = _fixture.CreateDbContext();
        var svc = Service(db, fake);

        Assert.True((await svc.RegisterAsync(Request("first@b.com", "Recruiter", inviteCode: code))).IsSuccess);
        var second = await svc.RegisterAsync(Request("second@b.com", "Recruiter", inviteCode: code));

        Assert.False(second.IsSuccess);
        Assert.Equal(InviteCodeErrors.Invalid, second.Error);
        Assert.Equal(1, await db.Users.CountAsync());
    }

    [Fact]
    public async Task Duplicate_WithValidCode_NoticeSucceedsAndCodeIsNotConsumed()
    {
        var fake = new FakeInviteCodeClient();
        var code = fake.Add("CODE-THREE", CompanyA, "dup@b.com");
        using var db = _fixture.CreateDbContext();
        db.Users.Add(new User("dup@b.com", "hash", "Existing", "User", null));
        await db.SaveChangesAsync();

        var result = await Service(db, fake).RegisterAsync(Request("dup@b.com", "Recruiter", inviteCode: code));

        Assert.True(result.IsSuccess);
        Assert.Equal(0, fake.RedeemCalls);
        Assert.Equal(1, await db.Users.CountAsync());
        Assert.Single(await db.EmailOutboxMessages.Where(m => m.Kind == EmailKind.DuplicateRegistrationNotice).ToListAsync());
    }

    [Fact]
    public async Task RaceOnEmail_AfterRedeem_ReleasesCodeAndReturnsDuplicatePath()
    {
        var fake = new FakeInviteCodeClient();
        var code = fake.Add("CODE-FOUR", CompanyA, "race@b.com");
        // Simulate a concurrent registration for the same email that commits right after the duplicate check.
        fake.OnRedeem = () =>
        {
            using var other = _fixture.CreateDbContext();
            other.Users.Add(new User("race@b.com", "hash", "Other", "User", null));
            other.SaveChanges();
        };
        using var db = _fixture.CreateDbContext();

        var result = await Service(db, fake).RegisterAsync(Request("race@b.com", "Recruiter", inviteCode: code));

        Assert.True(result.IsSuccess);
        Assert.Equal(new[] { fake.LastRedeemedId }, fake.Released);
        Assert.Equal(1, await db.Users.CountAsync(u => u.Email == "race@b.com"));
    }

    [Fact]
    public async Task JobUnavailable_FailsClosed()
    {
        var fake = new FakeInviteCodeClient { Unavailable = true };
        using var db = _fixture.CreateDbContext();
        var result = await Service(db, fake).RegisterAsync(Request("r5@b.com", "Recruiter", inviteCode: "ANY"));

        Assert.False(result.IsSuccess);
        Assert.Equal(InviteCodeErrors.Unavailable, result.Error);
        Assert.Empty(await db.Users.ToListAsync());
    }

    [Fact]
    public async Task UserRole_IgnoresInviteCodeAndNeverCallsJobs()
    {
        var fake = new FakeInviteCodeClient();
        using var db = _fixture.CreateDbContext();
        var result = await Service(db, fake).RegisterAsync(Request("u@b.com", "User", companyId: CompanyA));

        Assert.True(result.IsSuccess);
        Assert.Equal(0, fake.CheckCalls);
        Assert.Equal(0, fake.RedeemCalls);
        Assert.Null((await db.Users.SingleAsync()).CompanyId);
    }

    [Fact]
    public async Task Recruiter_CodePresentedWithAnotherAddress_IsRejectedLikeAnyBadCode()
    {
        var fake = new FakeInviteCodeClient();
        var code = fake.Add("CODE-BOUND", CompanyA, "bound@b.com");
        using var db = _fixture.CreateDbContext();

        var result = await Service(db, fake).RegisterAsync(Request("someone-else@b.com", "Recruiter", inviteCode: code));

        Assert.False(result.IsSuccess);
        Assert.Equal(InviteCodeErrors.Invalid, result.Error);
        Assert.Equal(new[] { "someone-else@b.com" }, fake.EmailsChecked);
        Assert.Equal(0, fake.RedeemCalls);
        Assert.Empty(await db.Users.ToListAsync());
    }

    [Fact]
    public async Task Recruiter_ValidCode_IsActiveAtOnce_AndGetsNoVerificationMail()
    {
        var fake = new FakeInviteCodeClient();
        var code = fake.Add("CODE-ACTIVE", CompanyA, "active@b.com");
        using var db = _fixture.CreateDbContext();

        var result = await Service(db, fake).RegisterAsync(Request("active@b.com", "Recruiter", inviteCode: code));

        Assert.True(result.IsSuccess);
        var user = await db.Users.SingleAsync();
        Assert.True(user.IsActive);
        Assert.True(user.IsEmailVerified);
        Assert.Empty(await db.EmailVerificationTokens.ToListAsync());
        Assert.Empty(await db.EmailOutboxMessages.ToListAsync());
        Assert.Equal(new[] { "active@b.com" }, fake.EmailsRedeemed);
    }

    private static AuthService Service(AuthDbContext db, IInviteCodeClient client)
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
        return new AuthService(db, new PasswordHasherService(), jwt,
            NullLogger<AuthService>.Instance, cfg, new Mock<ITokenRevocationStore>().Object, client);
    }

    private static RegisterRequest Request(string email, string role, string? inviteCode = null, Guid? companyId = null) =>
        new(email, Password, "Test User", role, companyId, inviteCode);

    private sealed class FakeInviteCodeClient : IInviteCodeClient
    {
        private readonly Dictionary<string, (Guid CompanyId, Guid Id, string Email)> _codes = new();
        private readonly HashSet<string> _used = new();

        public int CheckCalls { get; private set; }
        public int RedeemCalls { get; private set; }
        public List<Guid> Released { get; } = new();
        public List<string> EmailsChecked { get; } = new();
        public List<string> EmailsRedeemed { get; } = new();
        public bool Unavailable { get; init; }
        public Action? OnRedeem { get; set; }
        public Guid LastRedeemedId { get; private set; }

        /// <summary>Registers a code bound to one address in the fake and returns it.</summary>
        public string Add(string code, Guid companyId, string email)
        {
            _codes[code] = (companyId, Guid.NewGuid(), email);
            return code;
        }

        public Task<InviteCodeCheckResult?> CheckAsync(string code, string email, CancellationToken ct = default)
        {
            CheckCalls++;
            EmailsChecked.Add(email);
            if (Unavailable)
                throw new InviteCodeServiceUnavailableException("down");
            return Task.FromResult(TryUsable(code, email, out var v) ? new InviteCodeCheckResult(v.CompanyId, "Co") : null);
        }

        public Task<InviteCodeRedeemResult?> RedeemAsync(string code, string email, CancellationToken ct = default)
        {
            RedeemCalls++;
            EmailsRedeemed.Add(email);
            if (Unavailable)
                throw new InviteCodeServiceUnavailableException("down");
            if (!TryUsable(code, email, out var v))
                return Task.FromResult<InviteCodeRedeemResult?>(null);
            _used.Add(code);
            LastRedeemedId = v.Id;
            OnRedeem?.Invoke();
            return Task.FromResult<InviteCodeRedeemResult?>(new InviteCodeRedeemResult(v.Id, v.CompanyId));
        }

        public Task<bool> ReleaseAsync(Guid inviteCodeId, CancellationToken ct = default)
        {
            Released.Add(inviteCodeId);
            return Task.FromResult(true);
        }

        /// <summary>A code works once, and only with the address it was issued to (AUTH-01-15).</summary>
        private bool TryUsable(string code, string email, out (Guid CompanyId, Guid Id, string Email) value)
        {
            if (_codes.TryGetValue(code, out value) && !_used.Contains(code) && value.Email == email)
                return true;
            value = default;
            return false;
        }
    }
}
