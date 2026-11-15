using SharedKernel;

namespace Auth.Core.Entities;

/// <summary>Kinds of auth email. The name is stored in the outbox row and selects the template.</summary>
public enum EmailKind
{
    EmailVerification,
    PasswordReset,
    DuplicateRegistrationNotice,
    UnknownAccountResetNotice,
}

/// <summary>
/// An auth email waiting to be sent. It is written in the same transaction as the account change that
/// triggers it, and sent later by the outbox dispatcher. <see cref="Link"/> holds the one-time link only
/// while the row is pending: sending or giving up clears it, so the plain token does not stay at rest.
/// </summary>
public class EmailOutboxMessage : Entity
{
    public EmailKind Kind { get; private set; }
    public string Recipient { get; private set; } = "";
    public string? Link { get; private set; }

    /// <summary>When the one-time token in <see cref="Link"/> expires. Null for notices without a link.</summary>
    public DateTime? LinkExpiresAt { get; private set; }

    public DateTime NextAttemptAt { get; private set; }
    public int AttemptCount { get; private set; }
    public string? LastError { get; private set; }
    public DateTime? LockedUntil { get; private set; }
    public Guid? LockToken { get; private set; }
    public DateTime? SentAt { get; private set; }
    public DateTime? GaveUpAt { get; private set; }

    private EmailOutboxMessage() { }

    public static EmailOutboxMessage Create(EmailKind kind, string recipient, DateTime utcNow, string? link = null, DateTime? linkExpiresAt = null) => new()
    {
        Kind = kind,
        Recipient = recipient,
        Link = link,
        LinkExpiresAt = linkExpiresAt,
        NextAttemptAt = utcNow,
    };

    /// <summary>Marks the row as claimed by one dispatcher run until <paramref name="lockedUntil"/>.</summary>
    public void Lock(Guid token, DateTime lockedUntil)
    {
        LockToken = token;
        LockedUntil = lockedUntil;
    }
}
