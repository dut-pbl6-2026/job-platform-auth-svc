using SharedKernel;

namespace Auth.Core.Entities;

public class User : Entity
{
    public string Email { get; private set; } = "";
    public string PasswordHash { get; private set; } = "";
    public string FullName { get; private set; } = "";
    public string Role { get; private set; } = "User";
    public bool IsActive { get; private set; } = true;
    public DateTime? LastLoginAt { get; private set; }

    private User() {}
    public User(string email, string passwordHash, string fullName, string role="User")
    {
        Email=email.ToLowerInvariant();
        PasswordHash=passwordHash;
        FullName=fullName;
        Role=role;
    }
    public void UpdatePassword(string hash){ PasswordHash=hash; Touch(); }
    public void RecordLogin(){ LastLoginAt=DateTime.UtcNow; Touch(); }
}
