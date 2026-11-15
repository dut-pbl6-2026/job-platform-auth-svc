using Microsoft.EntityFrameworkCore;

namespace Auth.Infrastructure.Data;

/// <summary>Classifies database failures the services handle as races rather than errors.</summary>
public static class PersistenceErrors
{
    /// <summary>True when the save failed on a unique constraint (Postgres 23505).</summary>
    public static bool IsUniqueViolation(DbUpdateException ex)
    {
        if (ex.InnerException is Npgsql.PostgresException pgEx && pgEx.SqlState == "23505")
            return true;

        var message = ex.InnerException?.Message ?? ex.Message;
        return message.Contains("unique", StringComparison.OrdinalIgnoreCase)
            || message.Contains("duplicate", StringComparison.OrdinalIgnoreCase);
    }
}
