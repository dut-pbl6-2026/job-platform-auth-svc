using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Auth.Infrastructure.Data;

/// <summary>
/// Design-time only (dotnet ef migrations add / has-pending-model-changes). Lets the EF tools build
/// the model without starting the API host, so they need no connection string at all.
/// Nothing connects to this placeholder; runtime always uses the configured connection string.
/// </summary>
public sealed class AuthDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public AuthDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseNpgsql("Host=design-time-only;Database=design_time_only")
            .Options;
        return new AuthDbContext(options);
    }
}
