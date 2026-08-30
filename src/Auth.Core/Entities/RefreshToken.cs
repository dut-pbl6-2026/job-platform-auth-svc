using SharedKernel;

namespace Auth.Core.Entities;

public class RefreshToken : Entity
{
    public Guid UserId { get; private set; }
    public string TokenHash { get; private set; } = "";
    public Guid TokenFamily { get; private set; }
    public bool IsLongLived { get; private set; }
    public DateTime ExpiresAt { get; private set; }
    public bool IsRevoked { get; private set; }
    public DateTime? RevokedAt { get; private set; }

    private RefreshToken() { }
    public RefreshToken(Guid userId, string tokenHash, DateTime expiresAt, Guid? tokenFamily = null, bool isLongLived = false)
    {
        UserId = userId;
        TokenHash = tokenHash;
        TokenFamily = tokenFamily ?? Guid.NewGuid();
        IsLongLived = isLongLived;
        ExpiresAt = expiresAt;
    }
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
    public bool IsActive => !IsRevoked && !IsExpired;
    public void Revoke() { IsRevoked = true; RevokedAt = DateTime.UtcNow; Touch(); }
}
