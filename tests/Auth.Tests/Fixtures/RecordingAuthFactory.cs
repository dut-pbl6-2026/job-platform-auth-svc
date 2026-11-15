using System.Collections.Concurrent;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.PostgreSql;

namespace Auth.Tests.Fixtures;

/// <summary>
/// Full API host against a real Postgres container, with outbound email captured in memory so
/// tests can read the one-time links the service would have mailed. One instance per test class,
/// so the per-IP rate-limit buckets are not shared between classes.
/// </summary>
public sealed class RecordingAuthFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    public const string JwtSecret = "unit-test-signing-key-0123456789abcdef";
    public const string InternalToken = "test-internal-token-0123456789abcdef";

    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:16-alpine").Build();

    public RecordingEmailSender Emails { get; } = new();

    public string ConnectionString => _container.GetConnectionString();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Jwt:Secret", JwtSecret);
        // Read when the host is built, which happens after InitializeAsync has started the container.
        builder.UseSetting("ConnectionStrings:AuthDb", ConnectionString);
        builder.UseSetting("WEB_URL", "http://localhost:5173");
        builder.UseSetting("INTERNAL_SERVICE_TOKEN", InternalToken);
        // Outside Development the host requires SMTP settings. They are placeholders: the recording sender below replaces the SMTP sender.
        builder.UseSetting("SMTP_HOST", "smtp.test.invalid");
        builder.UseSetting("SMTP_USER", "test-user");
        builder.UseSetting("SMTP_PASS", "test-pass");
        builder.UseSetting("SMTP_FROM", "no-reply@test.invalid");
        builder.ConfigureTestServices(services => services.AddSingleton<IEmailSender>(Emails));
    }

    public async Task InitializeAsync()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        await _container.StartAsync(cts.Token);
        using var scope = Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<AuthDbContext>().Database.MigrateAsync(cts.Token);
    }

    public async Task ResetAsync()
    {
        Emails.Clear();
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        await db.Database.ExecuteSqlRawAsync("""
            DO $$
            DECLARE r RECORD;
            BEGIN
              FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename != '__EFMigrationsHistory') LOOP
                EXECUTE 'TRUNCATE TABLE "' || r.tablename || '" RESTART IDENTITY CASCADE;';
              END LOOP;
            END $$;
            """);
    }

    public new async Task DisposeAsync()
    {
        await _container.DisposeAsync();
        await base.DisposeAsync();
    }
}

public sealed record SentEmail(string Kind, string Email, string? Link);

public sealed class RecordingEmailSender : IEmailSender
{
    private readonly ConcurrentQueue<SentEmail> _sent = new();

    public IReadOnlyList<SentEmail> Sent => _sent.ToArray();

    public SentEmail Single(string kind) => _sent.Where(e => e.Kind == kind).Single();

    public void Clear() => _sent.Clear();

    public Task SendPasswordResetAsync(string email, string resetLink, CancellationToken ct = default)
    {
        _sent.Enqueue(new SentEmail("PasswordReset", email, resetLink));
        return Task.CompletedTask;
    }

    public Task SendEmailVerificationAsync(string email, string verificationLink, CancellationToken ct = default)
    {
        _sent.Enqueue(new SentEmail("EmailVerification", email, verificationLink));
        return Task.CompletedTask;
    }

    public Task SendDuplicateRegistrationNoticeAsync(string email, CancellationToken ct = default)
    {
        _sent.Enqueue(new SentEmail("DuplicateRegistrationNotice", email, null));
        return Task.CompletedTask;
    }

    public Task SendUnknownAccountPasswordResetNoticeAsync(string email, CancellationToken ct = default)
    {
        _sent.Enqueue(new SentEmail("UnknownAccountResetNotice", email, null));
        return Task.CompletedTask;
    }

    /// <summary>Extracts the plain token from a link such as <c>.../verify-email?token=...</c>.</summary>
    public static string TokenFrom(string link) => Uri.UnescapeDataString(link[(link.IndexOf("token=", StringComparison.Ordinal) + "token=".Length)..]);
}
