using Auth.Api.Bootstrap;
using Auth.Core.Entities;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Auth.Tests.Fixtures;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Auth.Tests;

[Collection(PostgresCollection.Name)]
public class AdminBootstrapCommandTests : IAsyncLifetime
{
    private const string Email = "root.admin@test.com";
    private const string Password = "Sup3r-Secret-Pass";

    private readonly PostgresFixture _fixture;

    public AdminBootstrapCommandTests(PostgresFixture fixture)
    {
        _fixture = fixture;
    }

    public Task InitializeAsync() => _fixture.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private static Func<string, string?> Env(string? email, string? password) => name => name switch
    {
        AdminBootstrapCommand.EmailVariable => email,
        AdminBootstrapCommand.PasswordVariable => password,
        _ => null,
    };

    private static async Task<(int Exit, string Stdout, string Stderr)> RunCommandAsync(
        string? connectionString, Func<string, string?> env)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var exit = await AdminBootstrapCommand.RunAsync(["bootstrap-admin"], connectionString, env, stdout, stderr);
        return (exit, stdout.ToString(), stderr.ToString());
    }

    /// <summary>Creates an empty database on the test server, so migrations have to run from scratch.</summary>
    private async Task<string> CreateEmptyDatabaseAsync()
    {
        var name = "bootstrap_" + Guid.NewGuid().ToString("N");
        await using (var conn = new NpgsqlConnection(_fixture.ConnectionString))
        {
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", conn);
            await cmd.ExecuteNonQueryAsync();
        }
        return new NpgsqlConnectionStringBuilder(_fixture.ConnectionString) { Database = name }.ConnectionString;
    }

    [Fact]
    public async Task FreshDatabase_CreatesVerifiedAdmin()
    {
        var connection = await CreateEmptyDatabaseAsync();

        var result = await RunCommandAsync(connection, Env(Email, Password));

        Assert.Equal(0, result.Exit);
        Assert.Empty(result.Stderr);
        await using var db = new AuthDbContext(new DbContextOptionsBuilder<AuthDbContext>().UseNpgsql(connection).Options);
        var user = await db.Users.SingleAsync();
        Assert.Equal(Email, user.Email);
        Assert.Equal("Admin", user.Role);
        Assert.True(user.IsEmailVerified);
        Assert.True(user.IsActive);
        Assert.True(new PasswordHasherService().Verify(Password, user.PasswordHash));
    }

    [Fact]
    public async Task SecondRun_IsNoOp_AndKeepsExistingAccount()
    {
        var first = await RunCommandAsync(_fixture.ConnectionString, Env(Email, Password));
        Assert.Equal(0, first.Exit);

        string originalHash;
        await using (var db = _fixture.CreateDbContext())
        {
            originalHash = (await db.Users.SingleAsync()).PasswordHash;
        }

        // Different password and a differently cased/padded email: still the same account, still untouched.
        var second = await RunCommandAsync(_fixture.ConnectionString, Env("  ROOT.admin@TEST.com ", "Other-Password-9"));

        Assert.Equal(0, second.Exit);
        Assert.Contains("already exists", second.Stdout);
        await using var verifyDb = _fixture.CreateDbContext();
        var user = await verifyDb.Users.SingleAsync();
        Assert.Equal(originalHash, user.PasswordHash);
        Assert.Equal("Admin", user.Role);
        Assert.True(new PasswordHasherService().Verify(Password, user.PasswordHash));
    }

    [Fact]
    public async Task ExistingAccount_IsNeitherPromotedNorVerified()
    {
        await using (var seed = _fixture.CreateDbContext())
        {
            seed.Users.Add(new User(Email, "seeded-hash", "Existing User", "User"));
            await seed.SaveChangesAsync();
        }

        var result = await RunCommandAsync(_fixture.ConnectionString, Env(Email, Password));

        Assert.Equal(0, result.Exit);
        await using var db = _fixture.CreateDbContext();
        var user = await db.Users.SingleAsync();
        Assert.Equal("User", user.Role);
        Assert.False(user.IsEmailVerified);
        Assert.Equal("seeded-hash", user.PasswordHash);
    }

    [Theory]
    [InlineData(null, Password)]
    [InlineData(Email, null)]
    [InlineData("", Password)]
    [InlineData(Email, "")]
    [InlineData(null, null)]
    [InlineData("not-an-email", Password)]
    [InlineData(Email, "weakpass")]
    [InlineData(Email, "nouppercase1")]
    [InlineData(Email, "NoDigitHere")]
    public async Task InvalidInput_FailsWithNonZeroExit_AndCreatesNothing(string? email, string? password)
    {
        var result = await RunCommandAsync(_fixture.ConnectionString, Env(email, password));

        Assert.NotEqual(0, result.Exit);
        Assert.Contains("bootstrap-admin failed", result.Stderr);
        await using var db = _fixture.CreateDbContext();
        Assert.False(await db.Users.AnyAsync());
    }

    [Fact]
    public async Task MissingConnectionString_FailsWithNonZeroExit()
    {
        var result = await RunCommandAsync(" ", Env(Email, Password));

        Assert.Equal(1, result.Exit);
        Assert.Contains("connection string missing", result.Stderr);
    }

    [Theory]
    [InlineData(Password)]
    [InlineData("weakpass")]
    public async Task Output_NeverContainsThePassword(string password)
    {
        var created = await RunCommandAsync(_fixture.ConnectionString, Env(Email, password));
        var skipped = await RunCommandAsync(_fixture.ConnectionString, Env(Email, password));
        var failed = await RunCommandAsync(_fixture.ConnectionString, Env("bad", password));

        foreach (var output in new[] { created, skipped, failed }.SelectMany(r => new[] { r.Stdout, r.Stderr }))
        {
            Assert.DoesNotContain(password, output);
        }
    }
}
