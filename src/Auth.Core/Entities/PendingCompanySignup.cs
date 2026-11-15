using SharedKernel;

namespace Auth.Core.Entities;

/// <summary>
/// A company sign-up waiting for its verification link (AUTH-01-10, AUTH-01-11). Nothing else exists
/// until the link is verified: no user, Company or join request. The password is stored as a hash and
/// the token only as a SHA-256 hash. The row is deleted on verification, on a later sign-up for the
/// same address, on a notice case, or on expiry.
/// </summary>
public class PendingCompanySignup : Entity
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(24);

    public string CompanyName { get; private set; } = "";
    public string? TaxCode { get; private set; }
    public string Email { get; private set; } = "";
    public string PasswordHash { get; private set; } = "";
    public string FullName { get; private set; } = "";
    public string TokenHash { get; private set; } = "";
    public DateTime ExpiresAt { get; private set; }

    private PendingCompanySignup() { }

    public PendingCompanySignup(string companyName, string? taxCode, string email, string passwordHash, string fullName, string tokenHash, DateTime expiresAt)
    {
        CompanyName = companyName;
        TaxCode = taxCode;
        Email = email;
        PasswordHash = passwordHash;
        FullName = fullName;
        TokenHash = tokenHash;
        ExpiresAt = expiresAt;
    }

    public bool IsUsableAt(DateTime utcNow) => utcNow < ExpiresAt;
}
