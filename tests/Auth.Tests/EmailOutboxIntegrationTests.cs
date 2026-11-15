using System.Net;
using System.Net.Http.Json;
using Auth.Core.Contracts;
using Auth.Core.Email;
using Auth.Core.Entities;
using Auth.Infrastructure.Data;
using Auth.Tests.Fixtures;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Tests;

/// <summary>
/// Outbox behaviour against the real Postgres container: same-transaction writes, retries, give-up,
/// claim selection and two dispatchers. Registrations stay under the register limit (10 per IP per hour)
/// and forgot-password calls under 5, because this class shares one host.
/// </summary>
public sealed class EmailOutboxIntegrationTests : IClassFixture<RecordingAuthFactory>, IAsyncLifetime
{
    private const string Password = "SecureP@ss123";
    private readonly RecordingAuthFactory _factory;

    public EmailOutboxIntegrationTests(RecordingAuthFactory factory) => _factory = factory;

    public Task InitializeAsync() => _factory.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private static string UniqueEmail(string prefix) => $"{prefix}{Guid.NewGuid():N}@test.com";

    private async Task<HttpResponseMessage> RegisterAsync(string email) =>
        await _factory.CreateClient().PostAsJsonAsync("/api/auth/register", new RegisterRequest(email, Password, "Outbox User"));

    private AsyncServiceScope Scope() => _factory.Services.CreateAsyncScope();

    [Fact]
    public async Task Register_WritesOneVerificationRow_InTheSameSaveAsTheAccount()
    {
        var email = UniqueEmail("row");

        var res = await RegisterAsync(email);

        Assert.Equal(HttpStatusCode.Accepted, res.StatusCode);
        await using var scope = Scope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        Assert.Equal(1, await db.Users.CountAsync(u => u.Email == email));
        var row = await db.EmailOutboxMessages.SingleAsync(m => m.Recipient == email);
        Assert.Equal(EmailKind.EmailVerification, row.Kind);
        Assert.StartsWith("http://localhost:5173/verify-email?token=", row.Link);
        Assert.Null(row.SentAt);
        Assert.Equal(0, row.AttemptCount);
    }

    [Fact]
    public async Task Register_WhenOutboxInsertFails_CreatesNoAccount()
    {
        // A database trigger makes the outbox insert fail. The account and token must roll back with it,
        // proving they share one transaction with the outbox row.
        var email = UniqueEmail("atomic");
        await using (var scope = Scope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            await db.Database.ExecuteSqlRawAsync("""
                CREATE OR REPLACE FUNCTION fail_email_outbox() RETURNS trigger AS $$
                BEGIN RAISE EXCEPTION 'outbox unavailable for test'; END $$ LANGUAGE plpgsql;
                CREATE TRIGGER fail_email_outbox BEFORE INSERT ON "EmailOutboxMessages"
                FOR EACH ROW EXECUTE FUNCTION fail_email_outbox();
                """);
        }

        try
        {
            var res = await RegisterAsync(email);

            Assert.NotEqual(HttpStatusCode.Accepted, res.StatusCode);
            await using var check = Scope();
            var db = check.ServiceProvider.GetRequiredService<AuthDbContext>();
            Assert.Equal(0, await db.Users.CountAsync(u => u.Email == email));
            Assert.Equal(0, await db.EmailVerificationTokens.CountAsync());
        }
        finally
        {
            await using var scope = Scope();
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            await db.Database.ExecuteSqlRawAsync("""
                DROP TRIGGER IF EXISTS fail_email_outbox ON "EmailOutboxMessages";
                DROP FUNCTION IF EXISTS fail_email_outbox();
                """);
        }
    }

    [Fact]
    public async Task Register_Duplicate_WritesOneNoticeRow_AndChangesNothingOnTheAccount()
    {
        var email = UniqueEmail("dupe");
        await RegisterAsync(email);
        await using (var scope = Scope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var before = await db.Users.AsNoTracking().SingleAsync(u => u.Email == email);

            var res = await RegisterAsync(email);

            Assert.Equal(HttpStatusCode.Accepted, res.StatusCode);
            var after = await db.Users.AsNoTracking().SingleAsync(u => u.Email == email);
            Assert.Equal(before.PasswordHash, after.PasswordHash);
        }

        await using var check = Scope();
        var rows = await check.ServiceProvider.GetRequiredService<AuthDbContext>().EmailOutboxMessages
            .Where(m => m.Recipient == email).OrderBy(m => m.CreatedAt).ToListAsync();
        Assert.Equal([EmailKind.EmailVerification, EmailKind.DuplicateRegistrationNotice], rows.Select(r => r.Kind));
        Assert.Null(rows[1].Link);
    }

    [Fact]
    public async Task UnknownAndKnownEmail_ReturnTheSameForgotPasswordResponse_AndEachWritesOneRow()
    {
        var known = UniqueEmail("known");
        var unknown = UniqueEmail("unknown");
        await RegisterAsync(known);
        await _factory.DeliverPendingEmailsAsync();
        var client = _factory.CreateClient();

        var knownRes = await client.PostAsJsonAsync("/api/auth/forgot-password", new ForgotPasswordRequest(known));
        var unknownRes = await client.PostAsJsonAsync("/api/auth/forgot-password", new ForgotPasswordRequest(unknown));

        Assert.Equal(knownRes.StatusCode, unknownRes.StatusCode);
        Assert.Equal(await knownRes.Content.ReadAsStringAsync(), await unknownRes.Content.ReadAsStringAsync());
        await using var scope = Scope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var knownRow = await db.EmailOutboxMessages.SingleAsync(m => m.Recipient == known && m.Kind == EmailKind.PasswordReset);
        Assert.NotNull(knownRow.Link);
        var unknownRow = await db.EmailOutboxMessages.SingleAsync(m => m.Recipient == unknown);
        Assert.Equal(EmailKind.UnknownAccountResetNotice, unknownRow.Kind);
        Assert.Null(unknownRow.Link);
    }

    [Fact]
    public async Task ResponsesDoNotExposeOutboxRows()
    {
        var email = UniqueEmail("shape");

        var register = await RegisterAsync(email);
        var forgot = await _factory.CreateClient().PostAsJsonAsync("/api/auth/forgot-password", new ForgotPasswordRequest(email));

        foreach (var res in new[] { register, forgot })
        {
            var body = await res.Content.ReadAsStringAsync();
            Assert.DoesNotContain("verify-email?token=", body);
            Assert.DoesNotContain("reset-password?token=", body);
            Assert.DoesNotContain("EmailOutbox", body);
            Assert.DoesNotContain("recipient", body, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task FailedSend_KeepsTheRow_AndALaterRunSendsIt()
    {
        var email = UniqueEmail("retry");
        await RegisterAsync(email);
        _factory.Emails.FailNextSends(1);

        var first = await _factory.Dispatcher.DispatchOnceAsync(DateTime.UtcNow);

        Assert.Equal(1, first.Claimed);
        Assert.Equal(1, first.Failed);
        Assert.Empty(_factory.Emails.Sent);
        await using (var scope = Scope())
        {
            var row = await scope.ServiceProvider.GetRequiredService<AuthDbContext>().EmailOutboxMessages.SingleAsync(m => m.Recipient == email);
            Assert.Null(row.SentAt);
            Assert.Equal(1, row.AttemptCount);
            Assert.Contains("Simulated SMTP failure", row.LastError);
            Assert.NotNull(row.Link);
            Assert.True(row.NextAttemptAt > DateTime.UtcNow);
            Assert.Null(row.LockToken);
        }

        var later = await _factory.Dispatcher.DispatchOnceAsync(DateTime.UtcNow.AddHours(1));

        Assert.Equal(1, later.Sent);
        Assert.Equal(email, Assert.Single(_factory.Emails.Sent).Email);
        await using var check = Scope();
        var sent = await check.ServiceProvider.GetRequiredService<AuthDbContext>().EmailOutboxMessages.SingleAsync(m => m.Recipient == email);
        Assert.NotNull(sent.SentAt);
        Assert.Null(sent.Link);
        Assert.Null(sent.LastError);
    }

    [Fact]
    public async Task RowIsGivenUpOnTheMaximumAttempt_KeepsItsIdAndClearsTheLink()
    {
        var email = UniqueEmail("giveup");
        await RegisterAsync(email);
        Guid id;
        await using (var scope = Scope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            id = (await db.EmailOutboxMessages.SingleAsync(m => m.Recipient == email)).Id;
            await db.EmailOutboxMessages.Where(m => m.Id == id).ExecuteUpdateAsync(s => s
                .SetProperty(m => m.AttemptCount, EmailOutboxRetryPolicy.MaxAttempts - 1)
                .SetProperty(m => m.NextAttemptAt, DateTime.UtcNow.AddSeconds(-1)));
        }
        _factory.Emails.FailNextSends(1);

        var result = await _factory.Dispatcher.DispatchOnceAsync(DateTime.UtcNow);

        Assert.Equal(1, result.GaveUp);
        await using var check = Scope();
        var row = await check.ServiceProvider.GetRequiredService<AuthDbContext>().EmailOutboxMessages.SingleAsync(m => m.Id == id);
        Assert.NotNull(row.GaveUpAt);
        Assert.Equal(EmailOutboxRetryPolicy.MaxAttempts, row.AttemptCount);
        Assert.Null(row.SentAt);
        Assert.Null(row.Link);
        Assert.Contains("Simulated SMTP failure", row.LastError);
    }

    [Fact]
    public async Task ClaimSelection_TakesOnlyDueUnsentUngivenUnlockedRows()
    {
        var now = DateTime.UtcNow;
        Guid due, expiredLease, future, locked;
        await using (var scope = Scope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            EmailOutboxMessage Notice() => EmailOutboxMessage.Create(EmailKind.DuplicateRegistrationNotice, UniqueEmail("claim"), now.AddMinutes(-5));

            var dueRow = Notice();
            var futureRow = Notice();
            var sentRow = Notice();
            var gaveUpRow = Notice();
            var lockedRow = Notice();
            var expiredLeaseRow = Notice();
            db.EmailOutboxMessages.AddRange(dueRow, futureRow, sentRow, gaveUpRow, lockedRow, expiredLeaseRow);
            await db.SaveChangesAsync();
            due = dueRow.Id;
            future = futureRow.Id;
            locked = lockedRow.Id;
            expiredLease = expiredLeaseRow.Id;

            await db.EmailOutboxMessages.Where(m => m.Id == futureRow.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(m => m.NextAttemptAt, now.AddHours(1)));
            await db.EmailOutboxMessages.Where(m => m.Id == sentRow.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(m => m.SentAt, now));
            await db.EmailOutboxMessages.Where(m => m.Id == gaveUpRow.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(m => m.GaveUpAt, now));
            await db.EmailOutboxMessages.Where(m => m.Id == lockedRow.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(m => m.LockedUntil, now.AddMinutes(5)).SetProperty(m => m.LockToken, Guid.NewGuid()));
            await db.EmailOutboxMessages.Where(m => m.Id == expiredLeaseRow.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(m => m.LockedUntil, now.AddMinutes(-1)).SetProperty(m => m.LockToken, Guid.NewGuid()));
        }

        var result = await _factory.Dispatcher.DispatchOnceAsync(now);

        Assert.Equal(2, result.Claimed);
        Assert.Equal(2, result.Sent);
        await using var check = Scope();
        var db2 = check.ServiceProvider.GetRequiredService<AuthDbContext>();
        Assert.NotNull((await db2.EmailOutboxMessages.SingleAsync(m => m.Id == due)).SentAt);
        Assert.NotNull((await db2.EmailOutboxMessages.SingleAsync(m => m.Id == expiredLease)).SentAt);
        Assert.Null((await db2.EmailOutboxMessages.SingleAsync(m => m.Id == future)).SentAt);
        var lockedAfter = await db2.EmailOutboxMessages.SingleAsync(m => m.Id == locked);
        Assert.Null(lockedAfter.SentAt);
        Assert.NotNull(lockedAfter.LockToken);
    }

    [Fact]
    public async Task SecondDispatcher_DoesNotSend_ARowClaimedByTheFirst()
    {
        var email = UniqueEmail("twice");
        await RegisterAsync(email);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _factory.Emails.BeforeSend = async ct =>
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(ct);
        };

        var first = _factory.Dispatcher.DispatchOnceAsync(DateTime.UtcNow);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(30));

        // The first run is inside the SMTP send. Its row is leased, so a second run claims nothing.
        var second = await _factory.Dispatcher.DispatchOnceAsync(DateTime.UtcNow);
        Assert.Equal(0, second.Claimed);
        Assert.Equal(0, second.Sent);

        release.SetResult();
        var firstResult = await first;
        Assert.Equal(1, firstResult.Sent);
        Assert.Equal(email, Assert.Single(_factory.Emails.Sent).Email);
    }
}
