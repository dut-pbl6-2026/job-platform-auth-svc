using StackExchange.Redis;

namespace Auth.Api.RateLimiting;

/// <summary>
/// Connection options for the rate-limit counters. Rate limiting is fail-open, so a Redis outage must
/// not hold a login or registration for the client's default 5 s timeout. The short timeout applies to
/// this connection only; the revocation cache keeps the shared options.
/// </summary>
public static class RateLimitRedisOptions
{
    public static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(500);

    public static ConfigurationOptions Create(ConfigurationOptions shared)
    {
        var options = shared.Clone();
        var milliseconds = (int)Timeout.TotalMilliseconds;
        options.ConnectTimeout = milliseconds;
        options.AsyncTimeout = milliseconds;
        options.SyncTimeout = milliseconds;
        return options;
    }
}
