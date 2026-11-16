using System.Collections.Concurrent;
using System.Net;
using Auth.Api.Networking;
using Auth.Api.Security;
using Auth.Core.Entities;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Testcontainers.PostgreSql;

namespace Auth.Tests.Fixtures;

/// <summary>
/// Full API host against a real Postgres container, with outbound email captured in memory so
/// tests can read the one-time links the service would have mailed. One instance per test class,
/// so the per-IP rate-limit buckets are not shared between classes.
/// The outbox worker is removed from this host: tests deliver pending rows with
/// <see cref="DeliverPendingEmailsAsync"/>, so each run is deterministic.
/// </summary>
public sealed class RecordingAuthFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    /// <summary>Token notif-svc presents on <c>/api/internal/users/{id}/email</c> (AUTH_INTERNAL_TOKEN_FOR_NOTIF).</summary>
    public const string NotifInternalToken = "test-notif-internal-token-0123456789abcdef";
    /// <summary>Token auth-svc presents to job-svc and app-svc; must not open auth's own internal endpoints.</summary>
    public const string OutboundJobToken = "test-job-internal-token-0123456789abcdef";
    /// <summary>Pre-split shared token. Must no longer be accepted anywhere under <c>/api/internal/*</c>.</summary>
    public const string LegacySharedToken = "test-legacy-shared-token-0123456789abcdef";
    /// <summary>Token job-svc presents to auth-svc's <c>/api/internal/users/{id}/link-company</c> (AUTH_INTERNAL_TOKEN_FOR_JOB).</summary>
    public const string JobCallerInternalToken = "test-job-caller-internal-token-0123456789abcdef";

    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:16-alpine").Build();

    /// <summary>
    /// Optional counter store. Setting one instance on several factories makes those hosts share one
    /// set of per-IP counts. Null keeps the default per-process store.
    /// </summary>
    public IRateLimitCounterStore? RateLimitStore { get; init; }

    /// <summary>Value for TRUSTED_PROXIES. Null leaves it unset, so the connection IP is used.</summary>
    public string? TrustedProxies { get; init; }

    /// <summary>Legacy value for ForwardedHeaders:KnownNetworks. Null leaves it unset (non-Production).</summary>
    public string? ForwardedKnownNetworks { get; init; }

    /// <summary>
    /// Peer address the test server reports for every request. TestServer has no real socket, so a
    /// forwarded-header test sets the peer explicitly to decide whether that peer is trusted.
    /// </summary>
    public IPAddress? PeerAddress { get; init; }

    public RecordingEmailSender Emails { get; } = new();

    /// <summary>job-svc company endpoints. Replaces the HTTP client, so no test reaches a real job-svc.</summary>
    public FakeCompanyDirectory CompanyDirectory { get; } = new();

    public string ConnectionString => _container.GetConnectionString();

    public EmailOutboxDispatcher Dispatcher => Services.GetRequiredService<EmailOutboxDispatcher>();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting(JwtSigningKeys.SigningKeyPemSetting, TestSigningKeys.PrivateKeyPemBase64);
        // Read when the host is built, which happens after InitializeAsync has started the container.
        builder.UseSetting("ConnectionStrings:AuthDb", ConnectionString);
        builder.UseSetting("WEB_URL", "http://localhost:5173");
        builder.UseSetting("AUTH_INTERNAL_TOKEN_FOR_NOTIF", NotifInternalToken);
        builder.UseSetting("JOB_INTERNAL_TOKEN_FOR_AUTH", OutboundJobToken);
        builder.UseSetting(InternalServiceAuth.JobCallerTokenKey, JobCallerInternalToken);
        builder.UseSetting("APP_INTERNAL_TOKEN_FOR_AUTH", "test-app-internal-token-0123456789abcdef");
        builder.UseSetting("INTERNAL_SERVICE_TOKEN", LegacySharedToken);
        // Outside Development the host requires SMTP settings. They are placeholders: the recording sender below replaces the SMTP sender.
        builder.UseSetting("SMTP_HOST", "smtp.test.invalid");
        builder.UseSetting("SMTP_USER", "test-user");
        builder.UseSetting("SMTP_PASS", "test-pass");
        builder.UseSetting("SMTP_FROM", "no-reply@test.invalid");
        if (TrustedProxies is not null)
            builder.UseSetting(ForwardedProxyTrust.TrustedProxiesKey, TrustedProxies);
        if (ForwardedKnownNetworks is not null)
            builder.UseSetting("ForwardedHeaders:KnownNetworks", ForwardedKnownNetworks);
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<IEmailSender>(Emails);
            services.AddSingleton<ICompanyDirectoryClient>(CompanyDirectory);
            EmailOutboxWorkerRemoval.Remove(services);
        });
        if (RateLimitStore is not null)
            builder.ConfigureTestServices(services => services.AddSingleton(RateLimitStore));
        if (PeerAddress is not null)
            builder.ConfigureServices(services => services.AddSingleton<IStartupFilter>(new PeerAddressFilter(PeerAddress)));
    }

    /// <summary>Sends every due outbox row now, the same as the worker would on its next poll.</summary>
    public async Task DeliverPendingEmailsAsync()
    {
        while ((await Dispatcher.DispatchOnceAsync(DateTime.UtcNow)).Claimed > 0)
        {
        }
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
        CompanyDirectory.Reset();
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

    private sealed class PeerAddressFilter(IPAddress peer) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, nextMiddleware) =>
            {
                context.Connection.RemoteIpAddress = peer;
                await nextMiddleware();
            });
            next(app);
        };
    }
}

/// <summary>Removes the outbox worker from a test host (tests deliver rows explicitly).</summary>
public static class EmailOutboxWorkerRemoval
{
    public static void Remove(IServiceCollection services)
    {
        var workers = services
            .Where(d => d.ServiceType == typeof(IHostedService) && d.ImplementationType == typeof(EmailOutboxWorker))
            .ToList();
        foreach (var worker in workers)
            services.Remove(worker);
    }
}

public sealed record SentEmail(string Kind, string Email, string? Link);

/// <summary>
/// Stands in for SMTP in tests. Records each delivered message; can fail the next sends and can hold a
/// send open, so concurrency tests control exactly when a delivery finishes.
/// </summary>
public sealed class RecordingEmailSender : IEmailSender
{
    private readonly ConcurrentQueue<SentEmail> _sent = new();
    private readonly object _gate = new();
    private int _failuresRemaining;

    public IReadOnlyList<SentEmail> Sent => _sent.ToArray();

    /// <summary>Runs before each send; a test can block here to hold a delivery open.</summary>
    public Func<CancellationToken, Task>? BeforeSend { get; set; }

    public SentEmail Single(string kind) => _sent.Where(e => e.Kind == kind).Single();

    public void Clear()
    {
        _sent.Clear();
        lock (_gate) _failuresRemaining = 0;
        BeforeSend = null;
    }

    public void FailNextSends(int count)
    {
        lock (_gate) _failuresRemaining = count;
    }

    public async Task SendAsync(EmailOutboxMessage message, CancellationToken ct = default)
    {
        if (BeforeSend is { } hook)
            await hook(ct);

        bool fail;
        lock (_gate)
        {
            fail = _failuresRemaining > 0;
            if (fail) _failuresRemaining--;
        }
        if (fail)
            throw new InvalidOperationException("Simulated SMTP failure for test");

        _sent.Enqueue(new SentEmail(message.Kind.ToString(), message.Recipient, message.Link));
    }

    /// <summary>Extracts the plain token from a link such as <c>.../verify-email?token=...</c>.</summary>
    public static string TokenFrom(string link) => Uri.UnescapeDataString(link[(link.IndexOf("token=", StringComparison.Ordinal) + "token=".Length)..]);
}
