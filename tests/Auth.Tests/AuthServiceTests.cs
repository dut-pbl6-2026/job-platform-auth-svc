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

[Collection(PostgresCollection.Name)]
public class AuthServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _fixture;

    public AuthServiceTests(PostgresFixture fixture)
    {
        _fixture = fixture;
    }

    public Task InitializeAsync() => _fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private static JwtOptions JwtOptions => new()
    {
        Secret = "unit-test-signing-key-0123456789abcdef",
        Issuer = "job-platform",
        Audience = "job-platform",
        ExpiresMinutes = 60
    };

    private AuthDbContext CreateDb() => _fixture.CreateDbContext();

    private AuthService CreateService(AuthDbContext db, IInviteCodeClient? inviteCodes = null, IPasswordHasher? hasher = null, ITokenRevocationStore? revocationStore = null)
    {
        hasher ??= new PasswordHasherService();
        var jwt = new JwtTokenService(Options.Create(JwtOptions));
        revocationStore ??= new Mock<ITokenRevocationStore>().Object;
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["WEB_URL"] = "http://localhost:5173" }).Build();
        return new AuthService(db, hasher, jwt, NullLogger<AuthService>.Instance, cfg, revocationStore, inviteCodes);
    }


    [Fact]
    public async Task Register_Success_PersistsUser()
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        var req = new RegisterRequest("a@b.com", "SecureP@ss123", "Hoai Nguyen");
        var res = await svc.RegisterAsync(req);
        Assert.True(res.IsSuccess);
        var user = await db.Users.FirstAsync(u => u.Email == "a@b.com");
        Assert.Equal("Hoai Nguyen", user.FullName);
        Assert.Equal("User", user.Role);
        Assert.Contains("$12$", user.PasswordHash);
        Assert.False(user.IsEmailVerified);
        Assert.Equal(1, await db.EmailVerificationTokens.CountAsync(t => t.UserId == user.Id));
    }

    [Fact]
    public async Task Register_NewEmail_QueuesOneVerificationLinkWithToken()
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        await svc.RegisterAsync(new RegisterRequest("link@b.com", "SecureP@ss123", "Link"));

        var queued = await db.EmailOutboxMessages.SingleAsync();
        Assert.Equal(EmailKind.EmailVerification, queued.Kind);
        Assert.Equal("link@b.com", queued.Recipient);
        Assert.StartsWith("http://localhost:5173/verify-email?token=", queued.Link);
        Assert.NotNull(queued.LinkExpiresAt);
        Assert.Null(queued.SentAt);
    }

    [Fact]
    public async Task Register_DuplicateEmail_SucceedsWithNoticeAndNoAccountChange()
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        await svc.RegisterAsync(new RegisterRequest("dup@b.com", "SecureP@ss123", "A"));
        var before = await db.Users.AsNoTracking().SingleAsync(u => u.Email == "dup@b.com");

        var second = await svc.RegisterAsync(new RegisterRequest("dup@b.com", "OtherP@ss999", "B"));

        Assert.True(second.IsSuccess);
        var after = await db.Users.AsNoTracking().SingleAsync(u => u.Email == "dup@b.com");
        Assert.Equal(before.PasswordHash, after.PasswordHash);
        Assert.Equal("A", after.FullName);
        Assert.Equal(1, await db.Users.CountAsync(u => u.Email == "dup@b.com"));
        var notices = await db.EmailOutboxMessages.Where(m => m.Kind == EmailKind.DuplicateRegistrationNotice).ToListAsync();
        Assert.Equal("dup@b.com", Assert.Single(notices).Recipient);
        Assert.Null(Assert.Single(notices).Link);
    }

    [Fact]
    public async Task Register_HashesPasswordOnceOnBothNewAndDuplicatePaths()
    {
        using var db = CreateDb();
        var hasher = new Mock<IPasswordHasher>();
        hasher.Setup(h => h.Hash(It.IsAny<string>())).Returns("hash");
        hasher.Setup(h => h.DummyHash).Returns("dummy");
        var svc = CreateService(db, hasher: hasher.Object);

        await svc.RegisterAsync(new RegisterRequest("hc@b.com", "SecureP@ss123", "New"));
        hasher.Verify(h => h.Hash("SecureP@ss123"), Times.Once);

        await svc.RegisterAsync(new RegisterRequest("hc@b.com", "SecureP@ss123", "Dup"));
        hasher.Verify(h => h.Hash("SecureP@ss123"), Times.Exactly(2));
    }

    [Theory]
    [InlineData("short1A", "Password must be at least 8 characters with 1 uppercase and 1 digit")]
    [InlineData("noupper123", "Password must be at least 8 characters with 1 uppercase and 1 digit")]
    [InlineData("NoDigitAA", "Password must be at least 8 characters with 1 uppercase and 1 digit")]
    public async Task Register_WeakPassword_Fails(string pwd, string expectedError)
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        var res = await svc.RegisterAsync(new RegisterRequest("weak@b.com", pwd, "Weak"));
        Assert.False(res.IsSuccess);
        Assert.Equal(expectedError, res.Error);
    }

    [Fact]
    public async Task Register_InvalidRole_Fails()
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        var res = await svc.RegisterAsync(new RegisterRequest("r@b.com", "SecureP@ss123", "R", "SuperUser"));
        Assert.False(res.IsSuccess);
        Assert.Equal("Invalid role", res.Error);
    }

    [Fact]
    public async Task Register_AdminRole_Fails()
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        var res = await svc.RegisterAsync(new RegisterRequest("admin@b.com", "SecureP@ss123", "Admin", "Admin"));
        Assert.False(res.IsSuccess);
        Assert.Equal("Invalid role", res.Error);
    }

    [Fact]
    public async Task Login_Success_ReturnsTokensAndPersistsRefresh()
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        await svc.RegisterAsync(new RegisterRequest("login@b.com", "SecureP@ss123", "Login User"));
        await AccountHelpers.VerifyEmailAsync(db, "login@b.com");
        var res = await svc.LoginAsync(new LoginRequest("login@b.com", "SecureP@ss123"));
        Assert.True(res.IsSuccess);
        Assert.NotNull(res.Value);
        Assert.False(string.IsNullOrWhiteSpace(res.Value!.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(res.Value.RefreshToken));
        Assert.Equal("login@b.com", res.Value.User.Email);
        var rt = await db.RefreshTokens.FirstAsync();
        Assert.Equal(64, rt.TokenHash.Length);
        var user = await db.Users.FirstAsync(u => u.Email == "login@b.com");
        Assert.NotNull(user.LastLoginAt);
    }

    [Fact]
    public async Task Login_WrongPassword_Unauthorized()
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        await svc.RegisterAsync(new RegisterRequest("wp@b.com", "SecureP@ss123", "WP"));
        var res = await svc.LoginAsync(new LoginRequest("wp@b.com", "wrong"));
        Assert.False(res.IsSuccess);
        Assert.Equal("Invalid credentials", res.Error);
    }

    [Fact]
    public async Task Login_NonExistentEmail_Unauthorized()
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        var res = await svc.LoginAsync(new LoginRequest("no@b.com", "SecureP@ss123"));
        Assert.False(res.IsSuccess);
        Assert.Equal("Invalid credentials", res.Error);
    }

    [Fact]
    public async Task Login_RememberMe_30DaysExpiry()
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        await svc.RegisterAsync(new RegisterRequest("rm@b.com", "SecureP@ss123", "RM"));
        await AccountHelpers.VerifyEmailAsync(db, "rm@b.com");
        await svc.LoginAsync(new LoginRequest("rm@b.com", "SecureP@ss123", true));
        var rt = await db.RefreshTokens.FirstAsync();
        Assert.True(rt.ExpiresAt > DateTime.UtcNow.AddDays(29));
    }

    [Fact]
    public async Task Email_Lowercased()
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        await svc.RegisterAsync(new RegisterRequest("UPPER@B.COM", "SecureP@ss123", "Upper"));
        await AccountHelpers.VerifyEmailAsync(db, "upper@b.com");
        var user = await db.Users.FirstAsync(u => u.Id != Guid.Empty);
        Assert.Equal("upper@b.com", user.Email);
        var login = await svc.LoginAsync(new LoginRequest("upper@b.com", "SecureP@ss123"));
        Assert.True(login.IsSuccess);
        var loginUpper = await svc.LoginAsync(new LoginRequest("UPPER@B.COM", "SecureP@ss123"));
        Assert.True(loginUpper.IsSuccess);
    }
}
