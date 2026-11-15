using System.Net;
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

    public Task SendPasswordResetAsync(string email, string resetLink, CancellationToken ct = default)
    {
        var html = $"<p>Click <a href=\"{WebUtility.HtmlEncode(resetLink)}\">here</a> to reset your password (15 minutes, one-time).</p><p>If you did not request this, ignore this email.</p>";
        var text = $"Reset your password (15m, one-time): {resetLink}\nIf you did not request this, ignore.";
        return SendAsync("PasswordReset", email, "Reset your password — job-platform", html, text, HashPreview(resetLink), ct);
    }

    public Task SendEmailVerificationAsync(string email, string verificationLink, CancellationToken ct = default)
    {
        var html = $"<p>Click <a href=\"{WebUtility.HtmlEncode(verificationLink)}\">here</a> to verify your email and activate your account (valid 24 hours, one-time).</p><p>If you did not register, ignore this email.</p>";
        var text = $"Verify your email (24h, one-time): {verificationLink}\nIf you did not register, ignore.";
        return SendAsync("EmailVerification", email, "Verify your email — job-platform", html, text, null, ct);
    }

    public Task SendDuplicateRegistrationNoticeAsync(string email, CancellationToken ct = default)
    {
        var html = "<p>Someone tried to register a new account with your email address. No changes were made to your account.</p><p>If this was you, log in to your existing account. If not, you can ignore this email.</p>";
        var text = "Someone tried to register a new account with your email address. No changes were made to your account. If this was not you, ignore this email.";
        return SendAsync("DuplicateRegistrationNotice", email, "Registration attempt with your email — job-platform", html, text, null, ct);
    }

    public Task SendUnknownAccountPasswordResetNoticeAsync(string email, CancellationToken ct = default)
    {
        var html = "<p>A password reset was requested for your email address, but no account exists for it.</p><p>If you meant to sign up, register on the platform. If not, you can ignore this email.</p>";
        var text = "A password reset was requested for your email address, but no account exists for it. If you did not request this, ignore this email.";
        return SendAsync("UnknownAccountResetNotice", email, "Password reset request — job-platform", html, text, null, ct);
    }

    /// <summary>
    /// Single delivery path for every auth email. Delivery failures are logged and swallowed
    /// so that the caller's response and timing do not depend on whether mail was sent.
    /// </summary>
    private async Task SendAsync(string kind, string email, string subject, string html, string text, string? linkPreview, CancellationToken ct)
    {
        var host = _config["SMTP_HOST"] ?? _config["EMAIL_SMTP_HOST"] ?? "";
        var portStr = _config["SMTP_PORT"] ?? "587";
        var user = _config["SMTP_USER"] ?? _config["EMAIL_SMTP_USER"];
        var pass = _config["SMTP_PASS"] ?? _config["EMAIL_SMTP_PASS"];
        var from = _config["SMTP_FROM"] ?? _config["EMAIL_FROM"] ?? "no-reply@job-platform.local";
        var useSsl = bool.TryParse(_config["SMTP_SSL"] ?? _config["EMAIL_SMTP_SSL"], out var ssl) ? ssl : true;

        if (string.IsNullOrWhiteSpace(host))
        {
            _logger.LogDebug("AUDIT {Kind} Email={Email} Sent=false Reason=NoSmtp", kind, email);
            return;
        }

        if (!int.TryParse(portStr, out var port)) port = 587;

        try
        {
            var message = new MimeMessage();
            message.From.Add(MailboxAddress.Parse(from));
            message.To.Add(MailboxAddress.Parse(email));
            message.Subject = subject;
            message.Body = new BodyBuilder { HtmlBody = html, TextBody = text }.ToMessageBody();

            using var client = new SmtpClient();
            // MailHog local: no SSL, no auth; prod: STARTTLS/SSL
            var secure = useSsl ? SecureSocketOptions.StartTls : SecureSocketOptions.None;
            // Allow MailHog self-signed / no TLS
            if (host is "localhost" or "127.0.0.1" or "mailhog")
                secure = SecureSocketOptions.None;

            await client.ConnectAsync(host, port, secure, ct);
            if (!string.IsNullOrWhiteSpace(user) && !string.IsNullOrWhiteSpace(pass))
                await client.AuthenticateAsync(user, pass, ct);

            await client.SendAsync(message, ct);
            await client.DisconnectAsync(true, ct);
            _logger.LogInformation("AUDIT {Kind} Email={Email} Sent=true Host={Host}", kind, email, host);
        }
        catch (Exception ex)
        {
            // Never log the link (it is a bearer secret); the preview is Debug-only.
            _logger.LogWarning(ex, "AUDIT {Kind} Email={Email} Sent=false Host={Host}", kind, email, host);
            if (linkPreview is not null)
                _logger.LogDebug("AUDIT {Kind} Email={Email} LinkHash={Hash} (send failed, debug only)", kind, email, linkPreview);
        }
    }

    private static string HashPreview(string link) => link.Length > 16 ? link[..16] + "..." : link;
}
