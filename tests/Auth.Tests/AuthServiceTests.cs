using Auth.Core.Contracts;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SharedKernel;

namespace Auth.Tests;

public class AuthServiceTests
{
    private static JwtOptions JwtOptions => new()
    {
        Secret = "dev-jwt-secret-change-me-32chars-min",
        Issuer = "job-platform",
        Audience = "job-platform",
        ExpiresMinutes = 60
    };

    private AuthDbContext CreateDb()
    {
        var opt = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new AuthDbContext(opt);
    }

    private AuthService CreateService(AuthDbContext db)
    {
        var hasher = new PasswordHasherService();
        var jwt = new JwtTokenService(Options.Create(JwtOptions));
        return new AuthService(db, hasher, jwt, NullLogger<AuthService>.Instance);
    }

    [Fact]
    public async Task Register_Success_PersistsUser()
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        var req = new RegisterRequest("a@b.com", "SecureP@ss123", "Hoai Nguyen");
        var res = await svc.RegisterAsync(req);
        Assert.True(res.IsSuccess);
        Assert.NotEqual(Guid.Empty, res.Value);
        var user = await db.Users.FirstAsync(u => u.Email == "a@b.com");
        Assert.Equal("Hoai Nguyen", user.FullName);
        Assert.Equal("User", user.Role);
        Assert.Contains("$12$", user.PasswordHash);
    }

    [Fact]
    public async Task Register_DuplicateEmail_Conflict()
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        await svc.RegisterAsync(new RegisterRequest("dup@b.com", "SecureP@ss123", "A"));
        var second = await svc.RegisterAsync(new RegisterRequest("dup@b.com", "SecureP@ss123", "B"));
        Assert.False(second.IsSuccess);
        Assert.Equal("Email exists", second.Error);
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
    public async Task Login_Success_ReturnsTokensAndPersistsRefresh()
    {
        using var db = CreateDb();
        var svc = CreateService(db);
        await svc.RegisterAsync(new RegisterRequest("login@b.com", "SecureP@ss123", "Login User"));
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
        var user = await db.Users.FirstAsync(u => u.Id != Guid.Empty);
        Assert.Equal("upper@b.com", user.Email);
        var login = await svc.LoginAsync(new LoginRequest("upper@b.com", "SecureP@ss123"));
        Assert.True(login.IsSuccess);
        var loginUpper = await svc.LoginAsync(new LoginRequest("UPPER@B.COM", "SecureP@ss123"));
        Assert.True(loginUpper.IsSuccess);
    }
}
