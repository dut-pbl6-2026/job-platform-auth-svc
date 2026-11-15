using Auth.Core.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

public class LoggerEmailSender : IEmailSender
{
    private readonly ILogger<LoggerEmailSender> _logger;
    private readonly IConfiguration _config;

    public LoggerEmailSender(ILogger<LoggerEmailSender> logger, IConfiguration config)
    {
        _logger = logger;
        _config = config;
    }

    public Task SendPasswordResetAsync(string email, string resetLink, CancellationToken ct = default)
    {
        // Sanitize: never log full resetLink at Information (SEC-08); hash preview at Debug only
        var hash = resetLink.Length > 16 ? resetLink[..16] + "..." : resetLink;
        _logger.LogInformation("AUDIT PasswordReset Email={Email} Sent=false Reason=NoSmtp (fallback)", email);
        _logger.LogDebug("AUDIT PasswordReset Email={Email} LinkHash={Hash} (logger fallback — no SMTP configured)", email, hash);
        return Task.CompletedTask;
    }

    public Task SendEmailVerificationAsync(string email, string verificationLink, CancellationToken ct = default)
    {
        // Verification links are bearer secrets: never logged, not even as a preview.
        _logger.LogInformation("AUDIT EmailVerification Email={Email} Sent=false Reason=NoSmtp (fallback)", email);
        return Task.CompletedTask;
    }

    public Task SendDuplicateRegistrationNoticeAsync(string email, CancellationToken ct = default)
    {
        _logger.LogInformation("AUDIT DuplicateRegistrationNotice Email={Email} Sent=false Reason=NoSmtp (fallback)", email);
        return Task.CompletedTask;
    }

    public Task SendUnknownAccountPasswordResetNoticeAsync(string email, CancellationToken ct = default)
    {
        _logger.LogInformation("AUDIT UnknownAccountResetNotice Email={Email} Sent=false Reason=NoSmtp (fallback)", email);
        return Task.CompletedTask;
    }
}
