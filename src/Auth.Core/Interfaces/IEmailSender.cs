namespace Auth.Core.Interfaces;

/// <summary>
/// Outbound auth email. Implementations must not throw on delivery failure: callers
/// must look the same to the client whether or not an address has an account.
/// </summary>
public interface IEmailSender
{
    Task SendPasswordResetAsync(string email, string resetLink, CancellationToken ct = default);

    /// <summary>Sent to a pending account's address with the one-time verification link.</summary>
    Task SendEmailVerificationAsync(string email, string verificationLink, CancellationToken ct = default);

    /// <summary>Sent to the owner of an existing account when someone registers with their address.</summary>
    Task SendDuplicateRegistrationNoticeAsync(string email, CancellationToken ct = default);

    /// <summary>Sent when a password reset is requested for an address with no account (keeps outbound work equal).</summary>
    Task SendUnknownAccountPasswordResetNoticeAsync(string email, CancellationToken ct = default);
}
