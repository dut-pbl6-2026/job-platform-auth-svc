using SharedKernel;

namespace Auth.Core.Entities;

/// <summary>
/// One-time, expiring token sent to a newly registered address. Stored as a SHA-256 hash
/// only; the plain token exists only in the verification link.
/// </summary>
public class EmailVerificationToken : Entity
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(24);

    public Guid UserId { get; private set; }
    public string TokenHash { get; private set; } = "";
    public DateTime ExpiresAt { get; private set; }
    public bool IsUsed { get; private set; }

    private EmailVerificationToken() { }
    public EmailVerificationToken(Guid userId, string tokenHash, DateTime expiresAt)
    {
        UserId = userId;
        TokenHash = tokenHash;
        ExpiresAt = expiresAt;
    }

    /// <summary>A token can be redeemed only once and only before it expires.</summary>
    public bool IsUsableAt(DateTime utcNow) => !IsUsed && utcNow < ExpiresAt;
    public void MarkUsed() { IsUsed = true; Touch(); }
}
