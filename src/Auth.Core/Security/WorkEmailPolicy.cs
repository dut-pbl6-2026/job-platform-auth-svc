namespace Auth.Core.Security;

/// <summary>
/// Free public email providers that cannot be used for company sign-up (AUTH-01-11). The built-in list
/// is always applied; FREE_EMAIL_DOMAINS can add more, never remove one.
/// </summary>
public sealed class WorkEmailPolicy
{
    public static readonly IReadOnlyList<string> DefaultFreeEmailDomains =
    [
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "icloud.com", "aol.com", "proton.me",
    ];

    private readonly HashSet<string> _blocked;

    public WorkEmailPolicy(IEnumerable<string>? additionalDomains = null)
    {
        _blocked = new HashSet<string>(DefaultFreeEmailDomains, StringComparer.OrdinalIgnoreCase);
        if (additionalDomains is null)
            return;
        foreach (var domain in additionalDomains)
        {
            var trimmed = domain.Trim();
            if (trimmed.Length > 0)
                _blocked.Add(trimmed);
        }
    }

    /// <summary>The part after the last '@' of an address that has already been trimmed and lowercased.</summary>
    public static string DomainOf(string normalizedEmail) => normalizedEmail[(normalizedEmail.LastIndexOf('@') + 1)..];

    public bool IsBlockedDomain(string domain) => _blocked.Contains(domain);

    public bool IsWorkEmail(string normalizedEmail) => !IsBlockedDomain(DomainOf(normalizedEmail));
}
