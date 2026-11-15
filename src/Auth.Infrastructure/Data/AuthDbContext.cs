using Auth.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace Auth.Infrastructure.Data;

public class AuthDbContext : DbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }
    public DbSet<User> Users => Set<User>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();
    public DbSet<EmailVerificationToken> EmailVerificationTokens => Set<EmailVerificationToken>();
    public DbSet<PendingCompanySignup> PendingCompanySignups => Set<PendingCompanySignup>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<EmailOutboxMessage> EmailOutboxMessages => Set<EmailOutboxMessage>();

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
            e.Property(x => x.ConcurrencyStamp).IsConcurrencyToken();
        });
        b.Entity<PasswordResetToken>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.TokenHash);
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => x.ExpiresAt);
            e.Property(x => x.TokenHash).IsRequired().HasMaxLength(128);
        });
        b.Entity<EmailVerificationToken>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.TokenHash);
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => x.ExpiresAt);
            e.Property(x => x.TokenHash).IsRequired().HasMaxLength(128);
        });
        b.Entity<PendingCompanySignup>(e =>
        {
            e.HasKey(x => x.Id);
            // One pending sign-up per address (a newer attempt replaces the older one) and one row per link token.
            e.HasIndex(x => x.Email).IsUnique();
            e.HasIndex(x => x.TokenHash).IsUnique();
            e.HasIndex(x => x.ExpiresAt);
            e.Property(x => x.CompanyName).HasMaxLength(200).IsRequired();
            e.Property(x => x.TaxCode).HasMaxLength(32);
            e.Property(x => x.Email).HasMaxLength(256).IsRequired();
            e.Property(x => x.PasswordHash).IsRequired();
            e.Property(x => x.FullName).HasMaxLength(128).IsRequired();
            e.Property(x => x.TokenHash).HasMaxLength(128).IsRequired();
        });
        b.Entity<EmailOutboxMessage>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Kind).HasConversion<string>().HasMaxLength(64).IsRequired();
            e.Property(x => x.Recipient).HasMaxLength(256).IsRequired();
            e.Property(x => x.Link).HasMaxLength(2048);
            e.Property(x => x.LastError).HasMaxLength(500);
            // Partial index: the dispatcher only scans rows that are still pending.
            e.HasIndex(x => x.NextAttemptAt)
                .HasDatabaseName("IX_EmailOutboxMessages_Pending")
                .HasFilter("\"SentAt\" IS NULL AND \"GaveUpAt\" IS NULL");
        });
        b.Entity<AuditLog>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.ActorUserId);
            e.HasIndex(x => new { x.TargetType, x.TargetId });
            e.HasIndex(x => x.CreatedAt);
            e.Property(x => x.Action).IsRequired().HasMaxLength(64);
            e.Property(x => x.TargetType).IsRequired().HasMaxLength(64);
            e.Property(x => x.Reason).HasMaxLength(500);
        });
    }
}
