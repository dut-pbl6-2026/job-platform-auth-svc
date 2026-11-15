using Auth.Api.Bootstrap;
using Auth.Infrastructure.Data;
using Auth.Tests.Fixtures;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Auth.Tests;

[Collection(PostgresCollection.Name)]
public class MigrateCommandTests(PostgresFixture fixture)
{
    private static async Task<(int Exit, string Stdout, string Stderr)> RunCommandAsync(string[] args, string? connectionString)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var exit = await MigrateCommand.RunAsync(args, connectionString, stdout, stderr);
        return (exit, stdout.ToString(), stderr.ToString());
    }

    private async Task<string> CreateEmptyDatabaseAsync()
    {
        var name = "migrate_" + Guid.NewGuid().ToString("N");
        await using (var conn = new NpgsqlConnection(fixture.ConnectionString))
        {
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", conn);
            await cmd.ExecuteNonQueryAsync();
        }
        return new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = name }.ConnectionString;
    }

    [Fact]
    public void IsInvoked_OnlyForFirstArgumentMigrate()
    {
        Assert.True(MigrateCommand.IsInvoked(["migrate"]));
        Assert.False(MigrateCommand.IsInvoked([]));
        Assert.False(MigrateCommand.IsInvoked(["bootstrap-admin"]));
    }

    [Fact]
    public async Task EmptyDatabase_IsMigrated_AndSecondRunIsNoOp()
    {
        var connection = await CreateEmptyDatabaseAsync();

        var first = await RunCommandAsync(["migrate"], connection);
        Assert.Equal(0, first.Exit);
        Assert.Empty(first.Stderr);

        await using (var db = new AuthDbContext(new DbContextOptionsBuilder<AuthDbContext>().UseNpgsql(connection).Options))
        {
            Assert.Empty(await db.Database.GetPendingMigrationsAsync());
            Assert.Equal(0, await db.Users.CountAsync());
        }

        var second = await RunCommandAsync(["migrate"], connection);
        Assert.Equal(0, second.Exit);
    }

    [Fact]
    public async Task MissingConnectionString_Fails()
    {
        var result = await RunCommandAsync(["migrate"], null);

        Assert.Equal(1, result.Exit);
        Assert.Contains("connection string missing", result.Stderr);
    }

    [Fact]
    public async Task ExtraArguments_AreRejected()
    {
        var result = await RunCommandAsync(["migrate", "now"], fixture.ConnectionString);

        Assert.Equal(2, result.Exit);
    }
}
