using Auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Auth.Tests.Fixtures;

/// <summary>Shared test helpers for account state. Registration leaves accounts pending, so suites use this to activate them.</summary>
public static class AccountHelpers
{
    /// <summary>Marks the account as verified directly in the database, bypassing the emailed link.</summary>
    public static async Task VerifyEmailAsync(AuthDbContext db, string email, CancellationToken ct = default)
    {
        var user = await db.Users.SingleAsync(u => u.Email == email.ToLowerInvariant(), ct);
        user.VerifyEmail();
        await db.SaveChangesAsync(ct);
    }
}
