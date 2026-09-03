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
}
