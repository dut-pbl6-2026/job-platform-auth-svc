namespace Auth.Core.Interfaces;

/// <summary>
/// Calls job-svc's internal invite-code endpoints (SRS AUTH-01-09). Sends auth-svc's own
/// per-caller token; the codes themselves are never logged.
/// </summary>
public interface IInviteCodeClient
{
    /// <summary>Read-only check. Returns null when the code is invalid, expired or used.</summary>
    /// <exception cref="InviteCodeServiceUnavailableException">Transport failure or unexpected status.</exception>
    Task<InviteCodeCheckResult?> CheckAsync(string code, CancellationToken ct = default);

    /// <summary>Atomic single-use redeem. Returns null when the code is invalid, expired or already used.</summary>
    /// <exception cref="InviteCodeServiceUnavailableException">Transport failure or unexpected status.</exception>
    Task<InviteCodeRedeemResult?> RedeemAsync(string code, CancellationToken ct = default);

    /// <summary>
    /// Clears the used marker after a failed registration. Best effort: returns false (never throws)
    /// when the release cannot be confirmed; the code then stays used.
    /// </summary>
    Task<bool> ReleaseAsync(Guid inviteCodeId, CancellationToken ct = default);
}

public sealed record InviteCodeCheckResult(Guid CompanyId, string CompanyName);

public sealed record InviteCodeRedeemResult(Guid InviteCodeId, Guid CompanyId);

public sealed class InviteCodeServiceUnavailableException(string message, Exception? inner = null)
    : Exception(message, inner);
