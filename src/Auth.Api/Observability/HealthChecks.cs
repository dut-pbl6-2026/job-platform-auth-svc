using System.Text.Json;
using Auth.Infrastructure.Data;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Auth.Api.Observability;

public static class HealthCheckTags
{
    public const string Ready = "ready";
}

/// <summary>Postgres reachability through the service's own DbContext.</summary>
public sealed class DatabaseHealthCheck(AuthDbContext db) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            return await db.Database.CanConnectAsync(cts.Token)
                ? HealthCheckResult.Healthy()
                : HealthCheckResult.Unhealthy("cannot connect");
        }
        catch (Exception)
        {
            // Never surface exception text: it may include connection-string details.
            return HealthCheckResult.Unhealthy("unreachable");
        }
    }
}

/// <summary>Redis reachability (via the registered IDistributedCache) — only registered when REDIS_URL is set.</summary>
public sealed class RedisHealthCheck(IDistributedCache cache) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            await cache.GetAsync("health:probe", cts.Token);
            return HealthCheckResult.Healthy();
        }
        catch (Exception)
        {
            return HealthCheckResult.Unhealthy("unreachable");
        }
    }
}

public static class HealthCheckResponseWriter
{
    public static Task WriteAsync(HttpContext context, HealthReport report)
    {
        context.Response.ContentType = "application/json";
        var payload = new
        {
            status = report.Status.ToString(),
            service = ObservabilityExtensions.ServiceName,
            totalDurationMs = (long)report.TotalDuration.TotalMilliseconds,
            checks = report.Entries.Select(e => new
            {
                name = e.Key,
                status = e.Value.Status.ToString(),
                durationMs = (long)e.Value.Duration.TotalMilliseconds,
                description = e.Value.Description
            })
        };
        return context.Response.WriteAsync(JsonSerializer.Serialize(payload, JsonSerializerOptions.Web));
    }
}
