namespace Auth.Core.Security;

/// <summary>Single password policy shared by registration, reset and the admin bootstrap command.</summary>
public static class PasswordPolicy
{
    public const string Description = "at least 8 characters with 1 uppercase and 1 digit";

    public static bool IsStrong(string pwd)
    {
        if (pwd.Length < 8) return false;
        if (!pwd.Any(char.IsUpper)) return false;
        if (!pwd.Any(char.IsDigit)) return false;
        return true;
    }
}
