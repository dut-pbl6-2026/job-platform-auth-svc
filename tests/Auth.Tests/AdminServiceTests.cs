using Auth.Core.Entities;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Services;
using Auth.Tests.Fixtures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Auth.Tests;

[Collection(PostgresCollection.Name)]
public class AdminServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _fixture;
    private readonly FakeTokenRevocationStore _revocationStore = new();

    public AdminServiceTests(PostgresFixture fixture)
    {
        _fixture = fixture;
    }

    public Task InitializeAsync() => _fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private AdminService CreateService(Auth.Infrastructure.Data.AuthDbContext db) =>
        new(db, NullLogger<AdminService>.Instance, _revocationStore);

    private static User NewUser(string email, string role = "User", bool active = true, string fullName = "Test User")
    {
        var user = new User(email, "secret-hash", fullName, role);
        if (!active) user.Deactivate();
        return user;
    }

    private async Task<(Guid AdminId, Guid UserId)> SeedAdminAndUserAsync()
    {
        await using var db = _fixture.CreateDbContext();
        var admin = NewUser("admin@test.com", "Admin", fullName: "Admin User");
        var user = NewUser("user@test.com");
        db.Users.AddRange(admin, user);
        await db.SaveChangesAsync();
        return (admin.Id, user.Id);
    }

    private async Task<Guid> SeedAdminAsync()
    {
        await using var db = _fixture.CreateDbContext();
        var admin = NewUser("admin@test.com", "Admin", fullName: "Admin User");
        db.Users.Add(admin);
        await db.SaveChangesAsync();
        return admin.Id;
    }

    [Fact]
    public async Task GetUsers_DefaultPagination_ReturnsPagedList()
    {
        Guid adminId;
        await using (var seedDb = _fixture.CreateDbContext())
        {
            var admin = NewUser("admin@test.com", "Admin");
            adminId = admin.Id;
            seedDb.Users.AddRange(
                admin,
                NewUser("a@test.com", fullName: "Alice"),
                NewUser("b@test.com", fullName: "Bob"),
                NewUser("c@test.com", fullName: "Carol"));
            await seedDb.SaveChangesAsync();
        }

        await using var db = _fixture.CreateDbContext();
        var result = await CreateService(db).GetUsersAsync(adminId, 1, 2, null, null, null);

        Assert.True(result.IsSuccess);
        var page = result.Value!;
        Assert.Equal(2, page.Data.Count);
        Assert.Equal(1, page.Pagination.Page);
        Assert.Equal(2, page.Pagination.PageSize);
        Assert.Equal(4, page.Pagination.TotalItems);
        Assert.Equal(2, page.Pagination.TotalPages);
    }

    [Fact]
    public async Task GetUsers_FilterByRole_ReturnsOnlyRecruiters()
    {
        Guid adminId;
        await using (var seedDb = _fixture.CreateDbContext())
        {
            var admin = NewUser("admin@test.com", "Admin");
            adminId = admin.Id;
            seedDb.Users.AddRange(
                admin,
                NewUser("recruiter@test.com", "Recruiter"),
                NewUser("user@test.com"));
            await seedDb.SaveChangesAsync();
        }

        await using var db = _fixture.CreateDbContext();
        var result = await CreateService(db).GetUsersAsync(adminId, 1, 20, "Recruiter", null, null);

        Assert.True(result.IsSuccess);
        var item = Assert.Single(result.Value!.Data);
        Assert.Equal("Recruiter", item.Role);
    }

    [Fact]
    public async Task GetUsers_FilterByIsActive_ReturnsInactiveOnly()
    {
        Guid adminId;
        await using (var seedDb = _fixture.CreateDbContext())
        {
            var admin = NewUser("admin@test.com", "Admin");
            adminId = admin.Id;
            seedDb.Users.AddRange(
                admin,
                NewUser("active@test.com"),
                NewUser("inactive@test.com", active: false));
            await seedDb.SaveChangesAsync();
        }

        await using var db = _fixture.CreateDbContext();
        var result = await CreateService(db).GetUsersAsync(adminId, 1, 20, null, false, null);

        Assert.True(result.IsSuccess);
        var item = Assert.Single(result.Value!.Data);
        Assert.Equal("inactive@test.com", item.Email);
        Assert.False(item.IsActive);
    }

    [Fact]
    public async Task GetUsers_SearchByEmailOrFullName_ReturnsMatches()
    {
        Guid adminId;
        await using (var seedDb = _fixture.CreateDbContext())
        {
            var admin = NewUser("admin@test.com", "Admin");
            adminId = admin.Id;
            seedDb.Users.AddRange(
                admin,
                NewUser("alice@test.com", fullName: "Alice Nguyen"),
                NewUser("bob@test.com", fullName: "Bob Tran"));
            await seedDb.SaveChangesAsync();
        }

        await using var db = _fixture.CreateDbContext();
        var service = CreateService(db);

        var byEmail = await service.GetUsersAsync(adminId, 1, 20, null, null, "alice");
        var byName = await service.GetUsersAsync(adminId, 1, 20, null, null, "Tran");

        Assert.Equal("alice@test.com", Assert.Single(byEmail.Value!.Data).Email);
        Assert.Equal("bob@test.com", Assert.Single(byName.Value!.Data).Email);
    }

    [Fact]
    public async Task GetUsers_ClampsPageAndSize()
    {
        var adminId = await SeedAdminAsync();
        await using var db = _fixture.CreateDbContext();
        var result = await CreateService(db).GetUsersAsync(adminId, 0, 500, null, null, null);

        Assert.True(result.IsSuccess);
        Assert.Equal(1, result.Value!.Pagination.Page);
        Assert.Equal(100, result.Value.Pagination.PageSize);
    }

    [Fact]
    public async Task GetUser_NotFound_ReturnsFailure()
    {
        var adminId = await SeedAdminAsync();
        await using var db = _fixture.CreateDbContext();
        var result = await CreateService(db).GetUserAsync(adminId, Guid.NewGuid());

        Assert.False(result.IsSuccess);
        Assert.Equal("User not found", result.Error);
    }

    [Fact]
    public async Task GetUser_ReturnsDetail()
    {
        Guid adminId;
        await using (var seedDb = _fixture.CreateDbContext())
        {
            var admin = NewUser("admin@test.com", "Admin");
            adminId = admin.Id;
            seedDb.Users.AddRange(admin, NewUser("detail@test.com", "Recruiter", fullName: "Detail User"));
            await seedDb.SaveChangesAsync();
        }

        Guid userId;
        await using (var idDb = _fixture.CreateDbContext())
            userId = (await idDb.Users.SingleAsync(u => u.Email == "detail@test.com")).Id;

        await using var db = _fixture.CreateDbContext();
        var result = await CreateService(db).GetUserAsync(adminId, userId);

        Assert.True(result.IsSuccess);
        Assert.Equal("detail@test.com", result.Value!.Email);
        Assert.Equal("Recruiter", result.Value.Role);
        Assert.Equal("Detail User", result.Value.FullName);
    }

    [Fact]
    public async Task GetUsers_ActorNotAdmin_ReturnsFailure()
    {
        Guid userId;
        await using (var seedDb = _fixture.CreateDbContext())
        {
            var user = NewUser("plain@test.com");
            seedDb.Users.Add(user);
            await seedDb.SaveChangesAsync();
            userId = user.Id;
        }

        await using var db = _fixture.CreateDbContext();
        var result = await CreateService(db).GetUsersAsync(userId, 1, 20, null, null, null);

        Assert.False(result.IsSuccess);
        Assert.Equal("Admin access required", result.Error);
    }

    [Fact]
    public async Task GetUsers_InactiveAdminActor_ReturnsFailure()
    {
        Guid adminId;
        await using (var seedDb = _fixture.CreateDbContext())
        {
            var admin = NewUser("inactive-admin@test.com", "Admin", active: false);
            seedDb.Users.Add(admin);
            await seedDb.SaveChangesAsync();
            adminId = admin.Id;
        }

        await using var db = _fixture.CreateDbContext();
        var result = await CreateService(db).GetUsersAsync(adminId, 1, 20, null, null, null);

        Assert.False(result.IsSuccess);
        Assert.Equal("Admin access required", result.Error);
    }

    [Fact]
    public async Task DeactivateUser_Success_DeactivatesRevokesTokensAndWritesAudit()
    {
        var (adminId, userId) = await SeedAdminAndUserAsync();

        await using (var seedDb = _fixture.CreateDbContext())
        {
            seedDb.RefreshTokens.AddRange(
                new RefreshToken(userId, new string('a', 64), DateTime.UtcNow.AddDays(7)),
                new RefreshToken(userId, new string('b', 64), DateTime.UtcNow.AddDays(7)));
            var alreadyRevoked = new RefreshToken(userId, new string('c', 64), DateTime.UtcNow.AddDays(7));
            alreadyRevoked.Revoke();
            seedDb.RefreshTokens.Add(alreadyRevoked);
            await seedDb.SaveChangesAsync();
        }

        await using (var db = _fixture.CreateDbContext())
        {
            var result = await CreateService(db).DeactivateUserAsync(adminId, userId, "  spam account  ");
            Assert.True(result.IsSuccess);
        }

        await using var verifyDb = _fixture.CreateDbContext();
        var user = await verifyDb.Users.SingleAsync(u => u.Id == userId);
        Assert.False(user.IsActive);

        var tokens = await verifyDb.RefreshTokens.Where(t => t.UserId == userId).ToListAsync();
        Assert.All(tokens, t => Assert.True(t.IsRevoked));

        var audit = await verifyDb.AuditLogs.SingleAsync();
        Assert.Equal(adminId, audit.ActorUserId);
        Assert.Equal("ADMIN_DEACTIVATE_USER", audit.Action);
        Assert.Equal("User", audit.TargetType);
        Assert.Equal(userId, audit.TargetId);
        Assert.Equal("spam account", audit.Reason);
        Assert.Contains("revokedRefreshTokenCount", audit.Metadata);

        var revocation = Assert.Single(_revocationStore.Revocations);
        Assert.Equal(userId, revocation.UserId);
    }

    [Fact]
    public async Task DeactivateUser_RevocationFailure_ReturnsFailureAndKeepsUserActive()
    {
        var (adminId, userId) = await SeedAdminAndUserAsync();
        _revocationStore.Failure = new InvalidOperationException("redis down");

        await using (var db = _fixture.CreateDbContext())
        {
            var result = await CreateService(db).DeactivateUserAsync(adminId, userId, null);
            Assert.False(result.IsSuccess);
            Assert.Equal("Unable to revoke user sessions", result.Error);
        }

        await using var verifyDb = _fixture.CreateDbContext();
        Assert.True((await verifyDb.Users.SingleAsync(u => u.Id == userId)).IsActive);
        Assert.Empty(await verifyDb.AuditLogs.ToListAsync());
    }

    [Fact]
    public async Task DeactivateUser_Self_ReturnsFailure()
    {
        var (adminId, _) = await SeedAdminAndUserAsync();

        await using var db = _fixture.CreateDbContext();
        var result = await CreateService(db).DeactivateUserAsync(adminId, adminId, null);

        Assert.False(result.IsSuccess);
        Assert.Equal("Cannot deactivate your own account", result.Error);
        Assert.Empty(await db.AuditLogs.ToListAsync());
    }

    [Fact]
    public async Task DeactivateUser_TargetAdmin_ReturnsFailure()
    {
        var adminId = Guid.NewGuid();
        var otherAdminId = Guid.NewGuid();

        await using (var seedDb = _fixture.CreateDbContext())
        {
            var admin = NewUser("admin@test.com", "Admin");
            var otherAdmin = NewUser("other-admin@test.com", "Admin");
            seedDb.Users.AddRange(admin, otherAdmin);
            await seedDb.SaveChangesAsync();
            adminId = admin.Id;
            otherAdminId = otherAdmin.Id;
        }

        await using var db = _fixture.CreateDbContext();
        var result = await CreateService(db).DeactivateUserAsync(adminId, otherAdminId, null);

        Assert.False(result.IsSuccess);
        Assert.Equal("Cannot deactivate Admin accounts", result.Error);
    }

    [Fact]
    public async Task DeactivateUser_ReasonTooLong_ReturnsFailure()
    {
        var (adminId, userId) = await SeedAdminAndUserAsync();

        await using var db = _fixture.CreateDbContext();
        var result = await CreateService(db).DeactivateUserAsync(adminId, userId, new string('x', 501));

        Assert.False(result.IsSuccess);
        Assert.Equal("Reason must not exceed 500 characters", result.Error);
    }

    [Fact]
    public async Task DeactivateUser_ReasonWithControlChars_ReturnsFailure()
    {
        var (adminId, userId) = await SeedAdminAndUserAsync();

        await using var db = _fixture.CreateDbContext();
        var result = await CreateService(db).DeactivateUserAsync(adminId, userId, "bad\tactor");

        Assert.False(result.IsSuccess);
        Assert.Equal("Reason must not contain control characters", result.Error);
    }

    [Fact]
    public async Task ActivateUser_InactiveUser_ActivatesAndWritesAudit()
    {
        var (adminId, userId) = await SeedAdminAndUserAsync();
        await using (var seedDb = _fixture.CreateDbContext())
        {
            var user = await seedDb.Users.SingleAsync(u => u.Id == userId);
            user.Deactivate();
            await seedDb.SaveChangesAsync();
        }

        await using (var db = _fixture.CreateDbContext())
        {
            var result = await CreateService(db).ActivateUserAsync(adminId, userId);
            Assert.True(result.IsSuccess);
        }

        await using var verifyDb = _fixture.CreateDbContext();
        Assert.True((await verifyDb.Users.SingleAsync(u => u.Id == userId)).IsActive);

        var audit = await verifyDb.AuditLogs.SingleAsync();
        Assert.Equal("ADMIN_ACTIVATE_USER", audit.Action);
        Assert.Equal(userId, audit.TargetId);
    }

    [Fact]
    public async Task ActivateUser_AlreadyActive_IsIdempotentAndWritesAudit()
    {
        var (adminId, userId) = await SeedAdminAndUserAsync();

        await using (var db = _fixture.CreateDbContext())
        {
            var result = await CreateService(db).ActivateUserAsync(adminId, userId);
            Assert.True(result.IsSuccess);
        }

        await using var verifyDb = _fixture.CreateDbContext();
        Assert.True((await verifyDb.Users.SingleAsync(u => u.Id == userId)).IsActive);
        Assert.Equal("ADMIN_ACTIVATE_USER", (await verifyDb.AuditLogs.SingleAsync()).Action);
    }

    private sealed class FakeTokenRevocationStore : ITokenRevocationStore
    {
        public List<(Guid UserId, DateTimeOffset RevokedAt)> Revocations { get; } = [];
        public Exception? Failure { get; set; }

        public Task RevokeUserTokensAsync(Guid userId, DateTimeOffset revokedAt, CancellationToken ct = default)
        {
            if (Failure is not null) throw Failure;

            Revocations.Add((userId, revokedAt));
            return Task.CompletedTask;
        }

        public Task<DateTimeOffset?> GetRevokedAfterAsync(Guid userId, CancellationToken ct = default) =>
            Task.FromResult<DateTimeOffset?>(
                Revocations
                    .Where(r => r.UserId == userId)
                    .Select(r => (DateTimeOffset?)r.RevokedAt)
                    .LastOrDefault());
    }
}
