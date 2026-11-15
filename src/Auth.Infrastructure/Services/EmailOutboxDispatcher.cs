using System.Text.RegularExpressions;
using Auth.Core.Email;
using Auth.Core.Entities;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

/// <summary>Counts from one <see cref="EmailOutboxDispatcher.DispatchOnceAsync"/> run.</summary>
public readonly record struct EmailDispatchResult(int Claimed, int Sent, int Failed, int GaveUp);

/// <summary>
/// Sends pending outbox rows. Safe with several replicas:
/// <list type="number">
/// <item>Claim: in one short transaction, rows are selected with <c>FOR UPDATE SKIP LOCKED</c> and given a
/// lease (<c>LockedUntil</c>, <c>LockToken</c>), then the transaction commits. Another replica skips a
/// locked row, and a row with an unexpired lease is not selected.</item>
/// <item>Send: outside the transaction, so no database lock is held during SMTP.</item>
/// <item>Record: the result is written only where the row still carries this run's <c>LockToken</c>.</item>
/// </list>
/// Delivery is at-least-once. A crash after the SMTP server accepts a message but before the row is marked
/// sent makes the row due again when its lease expires, so the recipient can get a second copy.
/// </summary>
public sealed partial class EmailOutboxDispatcher(
    IServiceScopeFactory scopes,
    IEmailSender sender,
    ILogger<EmailOutboxDispatcher> logger)
{
    public const int BatchSize = 10;

    public async Task<EmailDispatchResult> DispatchOnceAsync(DateTime utcNow, CancellationToken ct = default)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var token = Guid.NewGuid();

        var claimed = await ClaimAsync(db, token, utcNow, ct);
        int sent = 0, failed = 0, gaveUp = 0;

        foreach (var message in claimed)
        {
            ct.ThrowIfCancellationRequested();
            var outcome = await DeliverAsync(db, message, token, utcNow, ct);
            switch (outcome)
            {
                case DeliveryOutcome.Sent: sent++; break;
                case DeliveryOutcome.Retry: failed++; break;
                case DeliveryOutcome.GaveUp: gaveUp++; break;
            }
        }

        return new EmailDispatchResult(claimed.Count, sent, failed, gaveUp);
    }

    private static async Task<List<EmailOutboxMessage>> ClaimAsync(AuthDbContext db, Guid token, DateTime utcNow, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var rows = await db.EmailOutboxMessages.FromSql($"""
            SELECT * FROM "EmailOutboxMessages"
            WHERE "SentAt" IS NULL
              AND "GaveUpAt" IS NULL
              AND "NextAttemptAt" <= {utcNow}
              AND ("LockedUntil" IS NULL OR "LockedUntil" <= {utcNow})
            ORDER BY "NextAttemptAt"
            LIMIT {BatchSize}
            FOR UPDATE SKIP LOCKED
            """).ToListAsync(ct);

        var lockedUntil = utcNow.Add(EmailOutboxRetryPolicy.ClaimLease);
        foreach (var row in rows)
            row.Lock(token, lockedUntil);

        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return rows;
    }

    private enum DeliveryOutcome { Sent, Retry, GaveUp }

    private async Task<DeliveryOutcome> DeliverAsync(AuthDbContext db, EmailOutboxMessage message, Guid token, DateTime utcNow, CancellationToken ct)
    {
        if (message.LinkExpiresAt is { } linkExpiresAt && linkExpiresAt <= utcNow)
        {
            await GiveUpAsync(db, message, token, utcNow, "LinkExpiredBeforeDelivery", ct);
            return DeliveryOutcome.GaveUp;
        }

        try
        {
            await sender.SendAsync(message, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var attempt = message.AttemptCount + 1;
            var decision = EmailOutboxRetryPolicy.AfterFailure(attempt, utcNow);
            var error = SafeError(ex);

            if (decision.GiveUp)
            {
                await GiveUpAsync(db, message, token, utcNow, error, ct, attempt);
                return DeliveryOutcome.GaveUp;
            }

            await db.EmailOutboxMessages
                .Where(m => m.Id == message.Id && m.LockToken == token)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(m => m.AttemptCount, attempt)
                    .SetProperty(m => m.LastError, error)
                    .SetProperty(m => m.NextAttemptAt, decision.NextAttemptAt)
                    .SetProperty(m => m.LockedUntil, (DateTime?)null)
                    .SetProperty(m => m.LockToken, (Guid?)null), ct);

            LogRetry(message.Id, message.Kind, attempt, decision.NextAttemptAt, error);
            return DeliveryOutcome.Retry;
        }

        var updated = await db.EmailOutboxMessages
            .Where(m => m.Id == message.Id && m.LockToken == token)
            .ExecuteUpdateAsync(s => s
                .SetProperty(m => m.SentAt, utcNow)
                .SetProperty(m => m.Link, (string?)null)
                .SetProperty(m => m.LinkExpiresAt, (DateTime?)null)
                .SetProperty(m => m.LastError, (string?)null)
                .SetProperty(m => m.LockedUntil, (DateTime?)null)
                .SetProperty(m => m.LockToken, (Guid?)null), ct);

        if (updated == 0)
            LogLeaseLost(message.Id);
        else
            LogSent(message.Id, message.Kind, message.AttemptCount + 1);
        return DeliveryOutcome.Sent;
    }

    private async Task GiveUpAsync(AuthDbContext db, EmailOutboxMessage message, Guid token, DateTime utcNow, string reason, CancellationToken ct, int? attempts = null)
    {
        var count = attempts ?? message.AttemptCount;
        await db.EmailOutboxMessages
            .Where(m => m.Id == message.Id && m.LockToken == token)
            .ExecuteUpdateAsync(s => s
                .SetProperty(m => m.AttemptCount, count)
                .SetProperty(m => m.LastError, reason)
                .SetProperty(m => m.GaveUpAt, utcNow)
                .SetProperty(m => m.Link, (string?)null)
                .SetProperty(m => m.LinkExpiresAt, (DateTime?)null)
                .SetProperty(m => m.LockedUntil, (DateTime?)null)
                .SetProperty(m => m.LockToken, (Guid?)null), ct);

        LogGaveUp(message.Id, message.Kind, count, reason);
    }

    /// <summary>Exception type and message, with email addresses masked, capped at the column size.</summary>
    internal static string SafeError(Exception ex)
    {
        var text = EmailAddressPattern().Replace($"{ex.GetType().Name}: {ex.Message}", "[email]");
        return text.Length <= 500 ? text : text[..500];
    }

    [GeneratedRegex(@"[^\s@<>""]+@[^\s@<>""]+")]
    private static partial Regex EmailAddressPattern();

    private void LogSent(Guid messageId, EmailKind kind, int attempt) =>
        logger.LogInformation("AUDIT EmailSent MessageId={MessageId} Kind={Kind} Attempt={Attempt}", messageId, kind, attempt);

    private void LogLeaseLost(Guid messageId) =>
        logger.LogWarning("AUDIT EmailSent MessageId={MessageId} was delivered but its claim had expired; another run may deliver it again", messageId);

    private void LogRetry(Guid messageId, EmailKind kind, int attempt, DateTime nextAttemptAt, string error) =>
        logger.LogWarning("AUDIT EmailRetry MessageId={MessageId} Kind={Kind} Attempt={Attempt} NextAttemptAt={NextAttemptAt} Error={Error}", messageId, kind, attempt, nextAttemptAt, error);

    private void LogGaveUp(Guid messageId, EmailKind kind, int attempts, string reason) =>
        logger.LogError("AUDIT EmailGaveUp MessageId={MessageId} Kind={Kind} Attempts={Attempts} Reason={Reason}. The email was not delivered.", messageId, kind, attempts, reason);
}
