using Auth.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace Auth.Infrastructure.Data;

public class AuthDbContext : DbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) {}
    public DbSet<User> Users => Set<User>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>(e=>{
            e.HasKey(x=>x.Id);
            e.HasIndex(x=>x.Email).IsUnique();
            e.Property(x=>x.Email).HasMaxLength(256).IsRequired();
            e.Property(x=>x.PasswordHash).IsRequired();
            e.Property(x=>x.FullName).HasMaxLength(128);
            e.Property(x=>x.Role).HasMaxLength(32).HasDefaultValue("User");
        });
        b.Entity<RefreshToken>(e=>{
            e.HasKey(x=>x.Id);
            e.HasIndex(x=>x.TokenHash);
            e.HasIndex(x=>x.UserId);
            e.Property(x=>x.TokenHash).IsRequired().HasMaxLength(128);
        });
        b.Entity<PasswordResetToken>(e=>{
            e.HasKey(x=>x.Id);
            e.HasIndex(x=>x.TokenHash);
            e.HasIndex(x=>x.UserId);
        });
    }
}
