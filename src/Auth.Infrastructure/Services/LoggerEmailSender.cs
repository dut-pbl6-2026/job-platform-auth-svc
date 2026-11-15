using Auth.Core.Entities;
using Auth.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

/// <summary>
/// Development-only transport (EMAIL_SENDER=log). Selection in <see cref="EmailSenderSelection"/> keeps
/// it out of every other environment, so the link is written to the log only on a developer's machine.
/// Nothing is delivered.
/// </summary>
public class LoggerEmailSender(ILogger<LoggerEmailSender> logger) : IEmailSender
{
    public Task SendAsync(EmailOutboxMessage message, CancellationToken ct = default)
    {
        logger.LogInformation(
            "DEV ONLY AUDIT {Kind} Email={Email} Link={Link} Sent=false (EMAIL_SENDER=log)",
            message.Kind,
            LogRedaction.MaskEmail(message.Recipient),
            message.Link ?? "(none)");
        return Task.CompletedTask;
    }
}
