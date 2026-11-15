using Auth.Core.Entities;
using Auth.Core.Interfaces;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Configuration;
using MimeKit;

namespace Auth.Infrastructure.Services;

/// <summary>
/// SMTP transport for the outbox. Startup (<see cref="EmailSenderSelection"/>) guarantees the SMTP settings
/// are present before this class is created. Failures propagate: the dispatcher decides about retries.
/// </summary>
public class SmtpEmailSender(IConfiguration config) : IEmailSender
{
    /// <summary>
    /// Bounds each SMTP operation. A claim lease (<see cref="Auth.Core.Email.EmailOutboxRetryPolicy.ClaimLease"/>)
    /// must cover a whole send, so one slow server cannot hold a claim past its lease.
    /// </summary>
    public static readonly TimeSpan OperationTimeout = TimeSpan.FromSeconds(30);

    public async Task SendAsync(EmailOutboxMessage message, CancellationToken ct = default)
    {
        var host = config["SMTP_HOST"] ?? throw new InvalidOperationException("SMTP_HOST missing after startup validation");
        var portStr = config["SMTP_PORT"] ?? "587";
        var user = config["SMTP_USER"];
        var pass = config["SMTP_PASS"];
        var from = config["SMTP_FROM"] ?? throw new InvalidOperationException("SMTP_FROM missing after startup validation");
        var useSsl = bool.TryParse(config["SMTP_SSL"], out var ssl) ? ssl : true;
        if (!int.TryParse(portStr, out var port)) port = 587;

        var (subject, html, text) = AuthEmailContent.For(message);
        var mime = new MimeMessage();
        mime.From.Add(MailboxAddress.Parse(from));
        mime.To.Add(MailboxAddress.Parse(message.Recipient));
        mime.Subject = subject;
        mime.Body = new BodyBuilder { HtmlBody = html, TextBody = text }.ToMessageBody();

        using var client = new SmtpClient { Timeout = (int)OperationTimeout.TotalMilliseconds };
        // MailHog local: no SSL, no auth; prod: STARTTLS/SSL
        var secure = useSsl ? SecureSocketOptions.StartTls : SecureSocketOptions.None;
        if (host is "localhost" or "127.0.0.1" or "mailhog")
            secure = SecureSocketOptions.None;

        await client.ConnectAsync(host, port, secure, ct);
        if (!string.IsNullOrWhiteSpace(user) && !string.IsNullOrWhiteSpace(pass))
            await client.AuthenticateAsync(user, pass, ct);
        await client.SendAsync(mime, ct);
        await client.DisconnectAsync(true, ct);
    }
}
