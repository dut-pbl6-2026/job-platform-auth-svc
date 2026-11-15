using System.ComponentModel.DataAnnotations;
using Auth.Core.Entities;
using Auth.Core.Security;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Auth.Api.Bootstrap;

/// <summary>
/// One-time <c>bootstrap-admin</c> command. Creates the first Admin account from the
/// ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD environment variables, already email-verified.
/// Idempotent: when an account with that email exists it is left untouched and the command succeeds.
/// Migrations run first, so it also works on an empty database.
/// </summary>
public static class AdminBootstrapCommand
{
    public const string Name = "bootstrap-admin";
    public const string EmailVariable = "ADMIN_BOOTSTRAP_EMAIL";
    public const string PasswordVariable = "ADMIN_BOOTSTRAP_PASSWORD";

    private const string AdminRole = "Admin";
    private const string AdminFullName = "Administrator";
    private const int MaxEmailLength = 256;

    /// <summary>True when the process was started with the command name as its first argument.</summary>
    public static bool IsInvoked(string[] args) => args.Length > 0 && args[0] == Name;

    /// <summary>
    /// Runs the command and returns the process exit code: 0 on success or when the account already
    /// exists, 1 on configuration or database failure, 2 on unexpected extra arguments.
    /// The password is never written to <paramref name="stdout"/> or <paramref name="stderr"/>.
    /// </summary>
    public static async Task<int> RunAsync(
        string[] args,
        string? connectionString,
        Func<string, string?> getEnv,
        TextWriter stdout,
        TextWriter stderr,
        CancellationToken ct = default)
    {
        if (args.Length != 1)
        {
            stderr.WriteLine($"Usage: {Name}   (takes no further arguments)");
            return 2;
        }

        if (!TryReadInput(getEnv, out var email, out var password, out var error))
        {
            stderr.WriteLine($"{Name} failed: {error}");
            return 1;
        }

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            stderr.WriteLine($"{Name} failed: AuthDb connection string missing (set DATABASE_URL_AUTH or ConnectionStrings__AuthDb)");
            return 1;
        }

        try
        {
            var options = new DbContextOptionsBuilder<AuthDbContext>().UseNpgsql(connectionString).Options;
            await using var db = new AuthDbContext(options);
            await db.Database.MigrateAsync(ct);

            if (await db.Users.AnyAsync(u => u.Email == email, ct))
            {
                stdout.WriteLine($"{Name}: an account for {email} already exists; nothing changed.");
                return 0;
            }

            var user = new User(email, new PasswordHasherService().Hash(password), AdminFullName, AdminRole);
            user.VerifyEmail();
            db.Users.Add(user);

            try
            {
                await db.SaveChangesAsync(ct);
            }
            catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
            {
                // Another instance created the account between the check and the insert.
                stdout.WriteLine($"{Name}: an account for {email} already exists; nothing changed.");
                return 0;
            }

            stdout.WriteLine($"{Name}: created verified {AdminRole} account for {email}.");
            return 0;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            stderr.WriteLine($"{Name} failed: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    private static bool TryReadInput(Func<string, string?> getEnv, out string email, out string password, out string error)
    {
        email = (getEnv(EmailVariable) ?? string.Empty).Trim().ToLowerInvariant();
        password = getEnv(PasswordVariable) ?? string.Empty;

        if (email.Length == 0)
        {
            error = $"{EmailVariable} is not set";
            return false;
        }
        if (email.Length > MaxEmailLength || !new EmailAddressAttribute().IsValid(email))
        {
            error = $"{EmailVariable} is not a valid email address";
            return false;
        }
        if (password.Length == 0)
        {
            error = $"{PasswordVariable} is not set";
            return false;
        }
        if (!PasswordPolicy.IsStrong(password))
        {
            error = $"{PasswordVariable} does not meet the password policy: {PasswordPolicy.Description}";
            return false;
        }

        error = string.Empty;
        return true;
    }
}
