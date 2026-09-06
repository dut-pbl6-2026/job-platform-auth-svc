using Auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Auth.Tests.Fixtures;

/// <summary>
/// Shared PostgreSQL Testcontainer for integration tests.
/// One container per test run; each test truncates all user tables beforehand
/// (see <see cref="ResetAsync"/>) so tests stay isolated without paying
/// per-test database creation cost.
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    // NOTE: no explicit WithWaitStrategy — PostgreSqlBuilder's default
    // (pg_isready readiness probe) is strictly stronger than a TCP port
    // check: an open port does not mean Postgres accepts connections yet.
    // CI pull stalls are guarded by the 3-minute CTS in InitializeAsync.
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:16-alpine")
        .Build();

    public string ConnectionString => _container.GetConnectionString();

    public async Task InitializeAsync()
    {
        // Generous timeout: CI image pulls on ubuntu-latest can stall.
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        await _container.StartAsync(cts.Token);

        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseNpgsql(ConnectionString)
            .Options;
        await using var db = new AuthDbContext(options);
        await db.Database.MigrateAsync(cts.Token);
    }

    public Task DisposeAsync() => _container.DisposeAsync().AsTask();

    public AuthDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseNpgsql(ConnectionString)
            .Options;
        return new AuthDbContext(options);
    }

    /// <summary>
    /// Truncates every user table in schema public (except __EFMigrationsHistory)
    /// so each test starts from a clean relational state. Dynamic lookup keeps
    /// the fixture correct when new entities are added later.
    /// </summary>
    public async Task ResetAsync()
    {
        await using var conn = new NpgsqlConnection(ConnectionString);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            DO $$
            DECLARE r RECORD;
            BEGIN
              FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename != '__EFMigrationsHistory') LOOP
                EXECUTE 'TRUNCATE TABLE "' || r.tablename || '" RESTART IDENTITY CASCADE;';
              END LOOP;
            END $$;
            """, conn);
        await cmd.ExecuteNonQueryAsync();
    }
}
