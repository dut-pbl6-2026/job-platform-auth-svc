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
        var smtpHost = _config["EMAIL_SMTP_HOST"];
        if (string.IsNullOrWhiteSpace(smtpHost))
        {
            _logger.LogInformation("AUDIT PasswordReset Email={Email} Link={Link} (logger fallback — no SMTP configured)", email, resetLink);
            return Task.CompletedTask;
        }

        // SMTP host configured — log and defer to external provider (Resend/SMTP relay).
        // Keeping logger abstraction to avoid hard SMTP coupling in MUST; production can swap via DI.
        _logger.LogInformation("AUDIT PasswordReset Email={Email} Link={Link} SmtpHost={Host}", email, resetLink, smtpHost);
        return Task.CompletedTask;
    }
}
