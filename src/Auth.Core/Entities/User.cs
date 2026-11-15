using SharedKernel;

namespace Auth.Core.Entities;

public class User : Entity
{
    public string Email { get; private set; } = "";
    public string PasswordHash { get; private set; } = "";
    public string FullName { get; private set; } = "";
    public string Role { get; private set; } = "User";
    public Guid? CompanyId { get; private set; }
    public bool IsActive { get; private set; } = true;
    public DateTime? LastLoginAt { get; private set; }

    /// <summary>Set once the owner redeems the verification link. Null means the account is pending.</summary>
    public DateTime? EmailVerifiedAt { get; private set; }
    public bool IsEmailVerified => EmailVerifiedAt is not null;

    private User() { }
    public User(string email, string passwordHash, string fullName, string role = "User", Guid? companyId = null)
    {
        Email = email.ToLowerInvariant();
        PasswordHash = passwordHash;
        FullName = fullName;
        Role = role;
        CompanyId = companyId;
    }
    public void UpdatePassword(string hash) { PasswordHash = hash; Touch(); }
    public void RecordLogin() { LastLoginAt = DateTime.UtcNow; Touch(); }
    public void VerifyEmail() { EmailVerifiedAt ??= DateTime.UtcNow; Touch(); }
    public void Deactivate() { IsActive = false; Touch(); }
    public void Activate() { IsActive = true; Touch(); }

    /// <summary>Makes the account a Recruiter of the Company (AUTH-01-06, AUTH-01-12). Callers check the rule first.</summary>
    public void LinkCompany(Guid companyId) { Role = "Recruiter"; CompanyId = companyId; Touch(); }
}
