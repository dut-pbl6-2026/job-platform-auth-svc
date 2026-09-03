using Auth.Core.Interfaces;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MimeKit;

namespace Auth.Infrastructure.Services;

public class SmtpEmailSender : IEmailSender
{
    private readonly ILogger<SmtpEmailSender> _logger;
    private readonly IConfiguration _config;

    public SmtpEmailSender(ILogger<SmtpEmailSender> logger, IConfiguration config)
    {
        _logger = logger;
        _config = config;
    }

    public async Task SendPasswordResetAsync(string email, string resetLink, CancellationToken ct = default)
    {
        var host = _config["SMTP_HOST"] ?? _config["EMAIL_SMTP_HOST"] ?? "";
        var portStr = _config["SMTP_PORT"] ?? "587";
        var user = _config["SMTP_USER"] ?? _config["EMAIL_SMTP_USER"];
        var pass = _config["SMTP_PASS"] ?? _config["EMAIL_SMTP_PASS"];
        var from = _config["SMTP_FROM"] ?? _config["EMAIL_FROM"] ?? "no-reply@job-platform.local";
        var useSsl = bool.TryParse(_config["SMTP_SSL"] ?? _config["EMAIL_SMTP_SSL"], out var ssl) ? ssl : true;

        if (string.IsNullOrWhiteSpace(host))
        {
            _logger.LogDebug("AUDIT PasswordReset Email={Email} Hash={Hash} (SMTP not configured, skipped)", email, HashPreview(resetLink));
            return;
        }

        if (!int.TryParse(portStr, out var port)) port = 587;

        try
        {
            var message = new MimeMessage();
            message.From.Add(MailboxAddress.Parse(from));
            message.To.Add(MailboxAddress.Parse(email));
            message.Subject = "Reset your password — job-platform";
            message.Body = new BodyBuilder
            {
                HtmlBody = $"<p>Click <a href=\"{System.Net.WebUtility.HtmlEncode(resetLink)}\">here</a> to reset your password (15 minutes, one-time).</p><p>If you did not request this, ignore this email.</p>",
                TextBody = $"Reset your password (15m, one-time): {resetLink}\nIf you did not request this, ignore."
            }.ToMessageBody();

            using var client = new SmtpClient();
            // MailHog local: no SSL, no auth; prod: STARTTLS/SSL
            var secure = useSsl ? SecureSocketOptions.StartTlsWhenAvailable : SecureSocketOptions.None;
            // Allow MailHog self-signed / no TLS
            if (host is "localhost" or "127.0.0.1" or "mailhog")
                secure = SecureSocketOptions.None;

            await client.ConnectAsync(host, port, secure, ct);
            if (!string.IsNullOrWhiteSpace(user) && !string.IsNullOrWhiteSpace(pass))
                await client.AuthenticateAsync(user, pass, ct);

            await client.SendAsync(message, ct);
            await client.DisconnectAsync(true, ct);
            _logger.LogInformation("AUDIT PasswordReset Email={Email} Sent=true Host={Host}", email, host);
        }
        catch (Exception ex)
        {
            // Fallback to log at Debug (do not leak token at Information); still anti-enumeration for caller
            _logger.LogWarning(ex, "AUDIT PasswordReset Email={Email} Sent=false Host={Host} Hash={Hash}", email, host, HashPreview(resetLink));
            _logger.LogDebug("AUDIT PasswordReset Email={Email} LinkHash={Hash} (send failed, debug only)", email, HashPreview(resetLink));
        }
    }

    private static string HashPreview(string link) => link.Length > 16 ? link[..16] + "..." : link;
}
