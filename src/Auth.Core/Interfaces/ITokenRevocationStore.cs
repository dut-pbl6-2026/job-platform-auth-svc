namespace Auth.Core.Interfaces;

/// <summary>
/// Tracks the instant after which previously issued access tokens for a user
/// must be rejected (used when an account is deactivated).
/// </summary>
public interface ITokenRevocationStore
{
    Task RevokeUserTokensAsync(Guid userId, DateTimeOffset revokedAt, CancellationToken ct = default);

    Task<DateTimeOffset?> GetRevokedAfterAsync(Guid userId, CancellationToken ct = default);
}
