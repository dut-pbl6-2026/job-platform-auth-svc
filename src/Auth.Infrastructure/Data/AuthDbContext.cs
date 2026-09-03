using Auth.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace Auth.Infrastructure.Data;

public class AuthDbContext : DbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }
    public DbSet<User> Users => Set<User>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>(e =>
        {
            e.HasKey(x => x.Id);
            // Email is always persisted normalized (Trim + ToLowerInvariant) via User ctor / AuthService;
            // unique index therefore enforces case-insensitive uniqueness without extra NormalizedEmail column.
            e.HasIndex(x => x.Email).IsUnique();
            e.HasIndex(x => x.CompanyId);
            e.Property(x => x.Email).HasMaxLength(256).IsRequired();
            e.Property(x => x.PasswordHash).IsRequired();
            e.Property(x => x.FullName).HasMaxLength(128);
            e.Property(x => x.Role).HasMaxLength(32).HasDefaultValue("User");
            e.Property(x => x.CompanyId).HasColumnName("company_id");
        });
        b.Entity<RefreshToken>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.TokenHash);
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => x.ExpiresAt);
            e.HasIndex(x => x.TokenFamily);
            e.HasIndex(x => new { x.UserId, x.TokenFamily });
            e.Property(x => x.TokenHash).IsRequired().HasMaxLength(128);
            e.Property(x => x.TokenFamily).IsRequired();
            e.Property(x => x.IsLongLived).HasDefaultValue(false);
        });
        b.Entity<PasswordResetToken>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.TokenHash);
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => x.ExpiresAt);
            e.Property(x => x.TokenHash).IsRequired().HasMaxLength(128);
        });
    }
}
