using SharedKernel;

namespace Auth.Core.Entities;

public class PasswordResetToken : Entity
{
    public Guid UserId { get; private set; }
    public string TokenHash { get; private set; } = "";
    public DateTime ExpiresAt { get; private set; }
    public bool IsUsed { get; private set; }

    private PasswordResetToken() { }
    public PasswordResetToken(Guid userId, string tokenHash, DateTime expiresAt)
    {
        UserId = userId;
        TokenHash = tokenHash;
        ExpiresAt = expiresAt;
    }
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
    public void MarkUsed() { IsUsed = true; Touch(); }
}
