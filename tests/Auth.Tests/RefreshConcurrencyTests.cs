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
/// Refresh-token rotation under concurrency, against the real Postgres container. The race is made
/// deterministic by giving the losing request a context that loaded the token before the winner rotated it.
/// </summary>
[Collection(PostgresCollection.Name)]
public class RefreshConcurrencyTests : IAsyncLifetime
{
    private readonly PostgresFixture _fixture;

    public RefreshConcurrencyTests(PostgresFixture fixture) => _fixture = fixture;

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

    private static JwtTokenService Tokens() => new(Options.Create(Jwt), TestSigningKeys.Keys);

    private AuthDbContext CreateDb() => _fixture.CreateDbContext();

    private static AuthService Service(AuthDbContext db) =>
        new(db, new PasswordHasherService(), Tokens(), NullLogger<AuthService>.Instance,
            Config, new Mock<ITokenRevocationStore>().Object);

    [Fact]
    public async Task Refresh_LosingConcurrentRotation_FailsAsInvalidToken_AndLeavesWinnerIntact()
    {
        const string email = "rotate@race.test";
        var plain = Tokens().GenerateRefreshToken();
        var hash = Tokens().HashToken(plain);
        await using (var seed = CreateDb())
        {
            seed.Users.Add(new User(email, "stored-hash", "Rotate User"));
            await seed.SaveChangesAsync();
            await AccountHelpers.VerifyEmailAsync(seed, email);
            var user = await seed.Users.SingleAsync(u => u.Email == email);
            seed.RefreshTokens.Add(new RefreshToken(user.Id, hash, DateTime.UtcNow.AddDays(7)));
            await seed.SaveChangesAsync();
        }

        // The loser reads the token while it is still active, before the winner rotates it.
        await using var loser = CreateDb();
        var stale = await loser.RefreshTokens.SingleAsync(t => t.TokenHash == hash);
        Assert.False(stale.IsRevoked);

        await using (var winner = CreateDb())
            Assert.True((await Service(winner).RefreshAsync(plain)).IsSuccess);

        var lost = await Service(loser).RefreshAsync(plain);

        Assert.False(lost.IsSuccess);
        Assert.Equal("Invalid refresh token", lost.Error);
        // The losing request must not revoke the family (that is reuse detection, which it did not trigger).
        await using var check = CreateDb();
        var family = await check.RefreshTokens.Where(t => t.TokenFamily == stale.TokenFamily).ToListAsync();
        Assert.Equal(2, family.Count);
        Assert.Single(family, t => !t.IsRevoked);
    }
}
