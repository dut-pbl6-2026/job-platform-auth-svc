using System.Net;
using Auth.Core.Interfaces;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MimeKit;

namespace Auth.Infrastructure.Services;

/// <summary>
/// SMTP transport. Startup (<see cref="EmailSenderSelection"/>) guarantees the SMTP settings are present
/// before this class is created.
/// </summary>
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
        return SendAsync("PasswordReset", email, "Reset your password — job-platform", html, text, ct);
    }

    public Task SendEmailVerificationAsync(string email, string verificationLink, CancellationToken ct = default)
    {
        var html = $"<p>Click <a href=\"{WebUtility.HtmlEncode(verificationLink)}\">here</a> to verify your email and activate your account (valid 24 hours, one-time).</p><p>If you did not register, ignore this email.</p>";
        var text = $"Verify your email (24h, one-time): {verificationLink}\nIf you did not register, ignore.";
        return SendAsync("EmailVerification", email, "Verify your email — job-platform", html, text, ct);
    }

    public Task SendDuplicateRegistrationNoticeAsync(string email, CancellationToken ct = default)
    {
        var html = "<p>Someone tried to register a new account with your email address. No changes were made to your account.</p><p>If this was you, log in to your existing account. If not, you can ignore this email.</p>";
        var text = "Someone tried to register a new account with your email address. No changes were made to your account. If this was not you, ignore this email.";
        return SendAsync("DuplicateRegistrationNotice", email, "Registration attempt with your email — job-platform", html, text, ct);
    }

    public Task SendUnknownAccountPasswordResetNoticeAsync(string email, CancellationToken ct = default)
    {
        var html = "<p>A password reset was requested for your email address, but no account exists for it.</p><p>If you meant to sign up, register on the platform. If not, you can ignore this email.</p>";
        var text = "A password reset was requested for your email address, but no account exists for it. If you did not request this, ignore this email.";
        return SendAsync("UnknownAccountResetNotice", email, "Password reset request — job-platform", html, text, ct);
    }

    /// <summary>
    /// Single delivery path for every auth email. Delivery failures are logged and swallowed
    /// so that the caller's response and timing do not depend on whether mail was sent.
    /// Log lines never carry the message body or a link.
    /// </summary>
    private async Task SendAsync(string kind, string email, string subject, string html, string text, CancellationToken ct)
    {
        var host = _config["SMTP_HOST"] ?? throw new InvalidOperationException("SMTP_HOST missing after startup validation");
        var portStr = _config["SMTP_PORT"] ?? "587";
        var user = _config["SMTP_USER"];
        var pass = _config["SMTP_PASS"];
        var from = _config["SMTP_FROM"] ?? throw new InvalidOperationException("SMTP_FROM missing after startup validation");
        var useSsl = bool.TryParse(_config["SMTP_SSL"], out var ssl) ? ssl : true;
        var maskedEmail = LogRedaction.MaskEmail(email);

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
            _logger.LogInformation("AUDIT {Kind} Email={Email} Sent=true Host={Host}", kind, maskedEmail, host);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "AUDIT {Kind} Email={Email} Sent=false Host={Host}", kind, maskedEmail, host);
        }
    }
}
