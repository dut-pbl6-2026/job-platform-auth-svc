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
/// Resend-verification rules against the real Postgres container: token creation and expiry, the
/// single outbox row, and writing nothing for unknown or already verified emails.
/// </summary>
[Collection(PostgresCollection.Name)]
public class ResendVerificationTests : IAsyncLifetime
{
    private readonly PostgresFixture _fixture;

    public ResendVerificationTests(PostgresFixture fixture) => _fixture = fixture;

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

    private async Task SeedUserAsync(string email, bool verified)
    {
        await using var db = CreateDb();
        db.Users.Add(new User(email, "stored-hash", "Resend User"));
        await db.SaveChangesAsync();
        if (verified)
            await AccountHelpers.VerifyEmailAsync(db, email);
    }

    [Fact]
    public async Task Resend_UnverifiedAccount_CreatesOneUsableTokenAndOneOutboxRow()
    {
        const string email = "pending@resend.test";
        await SeedUserAsync(email, verified: false);
        var before = DateTime.UtcNow;

        await using (var db = CreateDb())
        {
            var res = await Service(db).ResendVerificationAsync(new ResendVerificationRequest(email));
            Assert.True(res.IsSuccess);
        }

        await using var check = CreateDb();
        var user = await check.Users.SingleAsync(u => u.Email == email);
        var token = await check.EmailVerificationTokens.SingleAsync(t => t.UserId == user.Id);
        var row = await check.EmailOutboxMessages.SingleAsync(m => m.Recipient == email);

        Assert.Equal(EmailKind.EmailVerification, row.Kind);
        Assert.Null(row.SentAt);
        // The link carries the plain token; only its hash is stored.
        var plain = RecordingEmailSender.TokenFrom(row.Link!);
        Assert.Equal(Tokens().HashToken(plain), token.TokenHash);
        Assert.True(token.IsUsableAt(DateTime.UtcNow));
        // Same 24h lifetime as registration, and the outbox row's link expiry matches the token.
        Assert.InRange(token.ExpiresAt, before.Add(EmailVerificationToken.Lifetime).AddMinutes(-1), DateTime.UtcNow.Add(EmailVerificationToken.Lifetime).AddMinutes(1));
        Assert.Equal(token.ExpiresAt, row.LinkExpiresAt);
    }

    [Fact]
    public async Task Resend_AfterExpiredLink_IssuesNewTokenAndExpiredOneStaysUnusable()
    {
        const string email = "expired@resend.test";
        await SeedUserAsync(email, verified: false);
        await using (var seed = CreateDb())
        {
            var user = await seed.Users.SingleAsync(u => u.Email == email);
            seed.EmailVerificationTokens.Add(new EmailVerificationToken(user.Id, "old-hash", DateTime.UtcNow.AddHours(-1)));
            await seed.SaveChangesAsync();
        }

        await using (var db = CreateDb())
            Assert.True((await Service(db).ResendVerificationAsync(new ResendVerificationRequest(email))).IsSuccess);

        await using var check = CreateDb();
        var tokens = await check.EmailVerificationTokens.OrderBy(t => t.ExpiresAt).ToListAsync();
        Assert.Equal(2, tokens.Count);
        Assert.False(tokens[0].IsUsableAt(DateTime.UtcNow));
        Assert.True(tokens[1].IsUsableAt(DateTime.UtcNow));
    }

    [Fact]
    public async Task Resend_VerifiedAccount_WritesNothing()
    {
        const string email = "verified@resend.test";
        await SeedUserAsync(email, verified: true);

        await using (var db = CreateDb())
            Assert.True((await Service(db).ResendVerificationAsync(new ResendVerificationRequest(email))).IsSuccess);

        await using var check = CreateDb();
        Assert.Equal(0, await check.EmailVerificationTokens.CountAsync());
        Assert.Equal(0, await check.EmailOutboxMessages.CountAsync());
    }

    [Fact]
    public async Task Resend_UnknownEmail_SucceedsAndWritesNothing()
    {
        await using (var db = CreateDb())
            Assert.True((await Service(db).ResendVerificationAsync(new ResendVerificationRequest("nobody@resend.test"))).IsSuccess);

        await using var check = CreateDb();
        Assert.Equal(0, await check.EmailVerificationTokens.CountAsync());
        Assert.Equal(0, await check.EmailOutboxMessages.CountAsync());
    }

    [Fact]
    public async Task Resend_NormalizesEmailCase()
    {
        await SeedUserAsync("case@resend.test", verified: false);

        await using (var db = CreateDb())
            await Service(db).ResendVerificationAsync(new ResendVerificationRequest("  CASE@Resend.Test "));

        await using var check = CreateDb();
        var row = await check.EmailOutboxMessages.SingleAsync();
        Assert.Equal("case@resend.test", row.Recipient);
    }
}
