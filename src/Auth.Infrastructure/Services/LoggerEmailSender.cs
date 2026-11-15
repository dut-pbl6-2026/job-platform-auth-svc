using Auth.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

/// <summary>
/// Development-only transport (EMAIL_SENDER=log). Selection in <see cref="EmailSenderSelection"/> keeps
/// it out of every other environment, so the link is written to the log only on a developer's machine.
/// Nothing is delivered.
/// </summary>
public class LoggerEmailSender : IEmailSender
{
    private readonly ILogger<LoggerEmailSender> _logger;

    public LoggerEmailSender(ILogger<LoggerEmailSender> logger)
    {
        _logger = logger;
    }

    public Task SendPasswordResetAsync(string email, string resetLink, CancellationToken ct = default)
    {
        _logger.LogInformation("DEV ONLY AUDIT PasswordReset Email={Email} Link={Link} Sent=false (EMAIL_SENDER=log)", LogRedaction.MaskEmail(email), resetLink);
        return Task.CompletedTask;
    }

    public Task SendEmailVerificationAsync(string email, string verificationLink, CancellationToken ct = default)
    {
        _logger.LogInformation("DEV ONLY AUDIT EmailVerification Email={Email} Link={Link} Sent=false (EMAIL_SENDER=log)", LogRedaction.MaskEmail(email), verificationLink);
        return Task.CompletedTask;
    }

    public Task SendDuplicateRegistrationNoticeAsync(string email, CancellationToken ct = default)
    {
        _logger.LogInformation("DEV ONLY AUDIT DuplicateRegistrationNotice Email={Email} Sent=false (EMAIL_SENDER=log)", LogRedaction.MaskEmail(email));
        return Task.CompletedTask;
    }

    public Task SendUnknownAccountPasswordResetNoticeAsync(string email, CancellationToken ct = default)
    {
        _logger.LogInformation("DEV ONLY AUDIT UnknownAccountResetNotice Email={Email} Sent=false (EMAIL_SENDER=log)", LogRedaction.MaskEmail(email));
        return Task.CompletedTask;
    }
}
