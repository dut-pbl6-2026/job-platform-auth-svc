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

/// <summary>
/// Unit-level checks for the enumeration and token policies. Timing defenses are verified by
/// counting calls on the hasher and email abstractions, never by measuring elapsed time.
/// </summary>
[Collection(PostgresCollection.Name)]
public class EnumerationHardeningTests : IAsyncLifetime
{
    private readonly PostgresFixture _fixture;

    public EnumerationHardeningTests(PostgresFixture fixture) => _fixture = fixture;

    public Task InitializeAsync() => _fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private static JwtOptions Jwt => new()
    {
        Issuer = "job-platform",
        Audience = "job-platform",
        ExpiresMinutes = 60
    };

    private static IConfiguration Config => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?> { ["WEB_URL"] = "http://localhost:5173" })
        .Build();

    private AuthDbContext CreateDb() => _fixture.CreateDbContext();

    private static JwtTokenService Tokens() => new(Options.Create(Jwt), TestSigningKeys.Keys);

    private AuthService Service(AuthDbContext db, IPasswordHasher? hasher = null, ITokenRevocationStore? revocation = null) =>
        new(db, hasher ?? new PasswordHasherService(), Tokens(), NullLogger<AuthService>.Instance,
            Config, revocation ?? new Mock<ITokenRevocationStore>().Object);

    private static Mock<IPasswordHasher> FakeHasher(string dummy = "dummy-hash")
    {
        var hasher = new Mock<IPasswordHasher>();
        hasher.Setup(h => h.DummyHash).Returns(dummy);
        hasher.Setup(h => h.Hash(It.IsAny<string>())).Returns("stored-hash");
        hasher.Setup(h => h.Verify(It.IsAny<string>(), It.IsAny<string>())).Returns(false);
        return hasher;
    }

    // ── Timing defense: hasher call count ───────────────────────────────

    [Fact]
    public async Task Login_UnknownEmail_StillVerifiesAgainstDummyHash()
    {
        using var db = CreateDb();
        var hasher = FakeHasher();

        var res = await Service(db, hasher.Object).LoginAsync(new LoginRequest("nobody@b.com", "SecureP@ss123"));

        Assert.False(res.IsSuccess);
        hasher.Verify(h => h.Verify("SecureP@ss123", "dummy-hash"), Times.Once);
    }

    [Fact]
    public async Task Login_KnownEmail_VerifiesAgainstStoredHashExactlyOnce()
    {
        using var db = CreateDb();
        db.Users.Add(new User("known@b.com", "stored-hash", "Known"));
        await db.SaveChangesAsync();
        await AccountHelpers.VerifyEmailAsync(db, "known@b.com");
        var hasher = FakeHasher();

        await Service(db, hasher.Object).LoginAsync(new LoginRequest("known@b.com", "SecureP@ss123"));

        hasher.Verify(h => h.Verify("SecureP@ss123", "stored-hash"), Times.Once);
        hasher.Verify(h => h.Verify(It.IsAny<string>(), "dummy-hash"), Times.Never);
    }

    [Fact]
    public async Task Login_UnverifiedAccount_IsRefusedAfterPasswordCheckWithSameResponseAsBadCredentials()
    {
        using var db = CreateDb();
        db.Users.Add(new User("pending@b.com", "stored-hash", "Pending"));
        await db.SaveChangesAsync();
        var hasher = FakeHasher();
        hasher.Setup(h => h.Verify("SecureP@ss123", "stored-hash")).Returns(true);
        var svc = Service(db, hasher.Object);

        var pending = await svc.LoginAsync(new LoginRequest("pending@b.com", "SecureP@ss123"));
        var badPassword = await svc.LoginAsync(new LoginRequest("pending@b.com", "wrong"));

        Assert.False(pending.IsSuccess);
        Assert.Equal("Invalid credentials", pending.Error);
        Assert.Equal(badPassword.Error, pending.Error);
        hasher.Verify(h => h.Verify("SecureP@ss123", "stored-hash"), Times.Once);
    }

    [Fact]
    public async Task Register_NewAndDuplicate_BothHashOnce()
    {
        using var db = CreateDb();
        var hasher = FakeHasher();
        var svc = Service(db, hasher.Object);

        await svc.RegisterAsync(new RegisterRequest("h1@b.com", "SecureP@ss123", "One"));
        await svc.RegisterAsync(new RegisterRequest("h1@b.com", "SecureP@ss123", "Two"));

        hasher.Verify(h => h.Hash("SecureP@ss123"), Times.Exactly(2));
    }

    [Fact]
    public async Task ForgotPassword_UnknownEmail_QueuesOneNoticeAndNoToken()
    {
        using var db = CreateDb();

        var res = await Service(db).ForgotPasswordAsync(new ForgotPasswordRequest("ghost@b.com"));

        Assert.True(res.IsSuccess);
        var queued = await db.EmailOutboxMessages.SingleAsync();
        Assert.Equal(EmailKind.UnknownAccountResetNotice, queued.Kind);
        Assert.Null(queued.Link);
        Assert.Equal(0, await db.PasswordResetTokens.CountAsync());
    }

    [Fact]
    public async Task ForgotPassword_KnownEmail_QueuesOneResetLinkAndStoresToken()
    {
        using var db = CreateDb();
        db.Users.Add(new User("real@b.com", "stored-hash", "Real"));
        await db.SaveChangesAsync();

        await Service(db).ForgotPasswordAsync(new ForgotPasswordRequest("real@b.com"));

        var queued = await db.EmailOutboxMessages.SingleAsync();
        Assert.Equal(EmailKind.PasswordReset, queued.Kind);
        Assert.StartsWith("http://localhost:5173/reset-password?token=", queued.Link);
        Assert.Equal(queued.LinkExpiresAt, (await db.PasswordResetTokens.SingleAsync()).ExpiresAt);
    }

    // ── Verification token policy ───────────────────────────────────────

    [Theory]
    [InlineData(-1, true)]
    [InlineData(0, false)]
    [InlineData(1, false)]
    public void VerificationToken_IsUsableOnlyBeforeExpiry(int minutesFromExpiry, bool expected)
    {
        var expiresAt = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var token = new EmailVerificationToken(Guid.NewGuid(), "hash", expiresAt);

        Assert.Equal(expected, token.IsUsableAt(expiresAt.AddMinutes(minutesFromExpiry)));
    }

    [Fact]
    public void VerificationToken_UsedTokenIsNotUsable()
    {
        var expiresAt = DateTime.UtcNow.AddHours(1);
        var token = new EmailVerificationToken(Guid.NewGuid(), "hash", expiresAt);
        token.MarkUsed();

        Assert.False(token.IsUsableAt(DateTime.UtcNow));
    }

    [Fact]
    public void VerificationToken_LifetimeIsOneDay()
    {
        Assert.Equal(TimeSpan.FromHours(24), EmailVerificationToken.Lifetime);
    }

    [Fact]
    public async Task VerifyEmail_ExpiredToken_IsRejected()
    {
        using var db = CreateDb();
        var user = new User("exp@b.com", "stored-hash", "Exp");
        db.Users.Add(user);
        var plain = Tokens().GenerateRefreshToken();
        db.EmailVerificationTokens.Add(new EmailVerificationToken(user.Id, Tokens().HashToken(plain), DateTime.UtcNow.AddMinutes(-1)));
        await db.SaveChangesAsync();

        var res = await Service(db).VerifyEmailAsync(plain);

        Assert.False(res.IsSuccess);
        Assert.False((await db.Users.SingleAsync()).IsEmailVerified);
    }

    [Fact]
    public async Task VerifyEmail_PasswordResetToken_CannotActivateAccount()
    {
        using var db = CreateDb();
        var user = new User("cross@b.com", "stored-hash", "Cross");
        db.Users.Add(user);
        var plain = Tokens().GenerateRefreshToken();
        db.PasswordResetTokens.Add(new PasswordResetToken(user.Id, Tokens().HashToken(plain), DateTime.UtcNow.AddMinutes(15)));
        await db.SaveChangesAsync();

        var res = await Service(db).VerifyEmailAsync(plain);

        Assert.False(res.IsSuccess);
        Assert.False((await db.Users.SingleAsync()).IsEmailVerified);
    }

    // ── Revocation on credential change ─────────────────────────────────

    [Fact]
    public async Task ResetPassword_RevokesAccessTokensThroughRevocationStore()
    {
        using var db = CreateDb();
        var user = new User("rst@b.com", "stored-hash", "Rst");
        db.Users.Add(user);
        var plain = Tokens().GenerateRefreshToken();
        db.PasswordResetTokens.Add(new PasswordResetToken(user.Id, Tokens().HashToken(plain), DateTime.UtcNow.AddMinutes(15)));
        await db.SaveChangesAsync();
        var revocation = new Mock<ITokenRevocationStore>();

        var res = await Service(db, revocation: revocation.Object).ResetPasswordAsync(new ResetPasswordRequest(plain, "NewSecure456"));

        Assert.True(res.IsSuccess);
        revocation.Verify(r => r.RevokeUserTokensAsync(user.Id, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Logout_AllSessions_RevokesAccessTokensThroughRevocationStore()
    {
        using var db = CreateDb();
        var user = new User("out@b.com", "stored-hash", "Out");
        db.Users.Add(user);
        await db.SaveChangesAsync();
        var revocation = new Mock<ITokenRevocationStore>();

        var res = await Service(db, revocation: revocation.Object).LogoutAsync(user.Id, refreshToken: null);

        Assert.True(res.IsSuccess);
        revocation.Verify(r => r.RevokeUserTokensAsync(user.Id, It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── Hasher ──────────────────────────────────────────────────────────

    [Fact]
    public void DummyHash_IsValidAtWorkFactor12AndMatchesNoGuessedPassword()
    {
        var hasher = new PasswordHasherService();

        Assert.Contains("$12$", hasher.DummyHash);
        Assert.False(hasher.Verify("SecureP@ss123", hasher.DummyHash));
        Assert.False(hasher.Verify("", hasher.DummyHash));
    }
}
