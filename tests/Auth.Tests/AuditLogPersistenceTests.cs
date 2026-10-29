using Auth.Core.Entities;
using Auth.Tests.Fixtures;
using Microsoft.EntityFrameworkCore;

namespace Auth.Tests;

[Collection(PostgresCollection.Name)]
public class AuditLogPersistenceTests : IAsyncLifetime
{
    private readonly PostgresFixture _fixture;

    public AuditLogPersistenceTests(PostgresFixture fixture)
    {
        _fixture = fixture;
    }

    public Task InitializeAsync() => _fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task AuditLog_PersistsAllFields()
    {
        var actorId = Guid.NewGuid();
        var targetId = Guid.NewGuid();

        await using (var db = _fixture.CreateDbContext())
        {
            db.AuditLogs.Add(new AuditLog(
                actorId,
                "ADMIN_DEACTIVATE_USER",
                "User",
                targetId,
                "spam account",
                "{\"revokedRefreshTokenCount\":2}"));
            await db.SaveChangesAsync();
        }

        await using var readDb = _fixture.CreateDbContext();
        var log = await readDb.AuditLogs.SingleAsync();

        Assert.Equal(actorId, log.ActorUserId);
        Assert.Equal("ADMIN_DEACTIVATE_USER", log.Action);
        Assert.Equal("User", log.TargetType);
        Assert.Equal(targetId, log.TargetId);
        Assert.Equal("spam account", log.Reason);
        Assert.Equal("{\"revokedRefreshTokenCount\":2}", log.Metadata);
        Assert.NotEqual(Guid.Empty, log.Id);
    }

    [Fact]
    public async Task AuditLog_IsQueryableByTarget()
    {
        var targetId = Guid.NewGuid();

        await using (var db = _fixture.CreateDbContext())
        {
            db.AuditLogs.Add(new AuditLog(Guid.NewGuid(), "ADMIN_ACTIVATE_USER", "User", targetId));
            db.AuditLogs.Add(new AuditLog(Guid.NewGuid(), "ADMIN_ACTIVATE_USER", "User", Guid.NewGuid()));
            await db.SaveChangesAsync();
        }

        await using var readDb = _fixture.CreateDbContext();
        var count = await readDb.AuditLogs.CountAsync(x => x.TargetType == "User" && x.TargetId == targetId);

        Assert.Equal(1, count);
    }
}
