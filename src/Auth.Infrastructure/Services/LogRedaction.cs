namespace Auth.Infrastructure.Services;

/// <summary>
/// Keeps personal data out of log lines. Use only where a log line has no user id to correlate with.
/// </summary>
public static class LogRedaction
{
    // "jane.doe@example.com" -> "j***@example.com". Keeps the domain for triage, drops the local part.
    public static string MaskEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return "<empty>";

        var at = email.IndexOf('@');
        if (at <= 0)
            return "***";

        return email[0] + "***" + email[at..];
    }
}
