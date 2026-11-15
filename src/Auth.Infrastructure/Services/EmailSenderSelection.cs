using Microsoft.Extensions.Configuration;

namespace Auth.Infrastructure.Services;

public enum EmailSenderKind
{
    Smtp,
    Log,
}

/// <summary>
/// Chooses the outbound mail transport once at startup. It never falls back silently: outside
/// Development, a missing SMTP setting stops the host, so users cannot be left without mail while
/// the API reports success. The logger transport is reachable only through an explicit
/// <c>EMAIL_SENDER=log</c> in Development.
/// </summary>
public static class EmailSenderSelection
{
    public const string SenderVariable = "EMAIL_SENDER";
    public const string SmtpHostVariable = "SMTP_HOST";
    public const string SmtpUserVariable = "SMTP_USER";
    public const string SmtpPassVariable = "SMTP_PASS";
    public const string SmtpFromVariable = "SMTP_FROM";

    public static EmailSenderKind Resolve(bool isDevelopment, IConfiguration config)
    {
        var mode = config[SenderVariable]?.Trim();
        if (string.IsNullOrEmpty(mode))
            mode = null;

        if (mode is not null &&
            !mode.Equals("smtp", StringComparison.OrdinalIgnoreCase) &&
            !mode.Equals("log", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"{SenderVariable} must be 'smtp' or 'log' when set");
        }

        var isLog = mode?.Equals("log", StringComparison.OrdinalIgnoreCase) == true;
        if (isLog)
        {
            if (!isDevelopment)
                throw new InvalidOperationException(
                    $"{SenderVariable}=log is allowed only in Development; outside Development auth mail must be sent over SMTP");
            return EmailSenderKind.Log;
        }

        var isExplicitSmtp = mode is not null;
        var hasHost = !string.IsNullOrWhiteSpace(config[SmtpHostVariable]);
        if (isDevelopment && !isExplicitSmtp && !hasHost)
        {
            throw new InvalidOperationException(
                $"{SmtpHostVariable} is not set. Set {SmtpHostVariable} (for example MailHog on localhost:1025), " +
                $"or set {SenderVariable}=log to write auth emails to the log instead of sending them");
        }

        // Development (MailHog) needs no user or password; every other environment needs all four.
        string[] required = isDevelopment
            ? [SmtpHostVariable, SmtpFromVariable]
            : [SmtpHostVariable, SmtpUserVariable, SmtpPassVariable, SmtpFromVariable];

        var missing = required.Where(key => string.IsNullOrWhiteSpace(config[key])).ToArray();
        if (missing.Length > 0)
        {
            var hint = isDevelopment ? $" Or set {SenderVariable}=log to write auth emails to the log instead." : string.Empty;
            throw new InvalidOperationException(
                $"Auth email requires SMTP settings. Missing: {string.Join(", ", missing)}.{hint}");
        }

        return EmailSenderKind.Smtp;
    }
}
