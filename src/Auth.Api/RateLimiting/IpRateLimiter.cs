using Auth.Core.Interfaces;

namespace Auth.Api.RateLimiting;

/// <summary>
/// Applies an <see cref="IpRateLimitPolicy"/> to one client IP through the shared counter store.
/// A store failure allows the request and logs a warning, the same fail-open policy as token
/// revocation: a Redis outage must not take down login.
/// </summary>
public sealed class IpRateLimiter(IRateLimitCounterStore store, ILogger<IpRateLimiter> logger)
{
    public const string KeyPrefix = "job-platform:auth:ratelimit:";

    public async Task<IpRateLimitDecision> CheckAsync(IpRateLimitPolicy policy, string clientIp, CancellationToken ct = default)
    {
        try
        {
            var count = await store.IncrementAsync(KeyFor(policy, clientIp), policy.Window, ct);
            if (count.Count <= policy.PermitLimit)
                return IpRateLimitDecision.Allow;

            return new IpRateLimitDecision(false, count.TimeToLive);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Rate-limit store unavailable for policy {Policy}; allowing request (fail-open)", policy.Name);
            return IpRateLimitDecision.Allow;
        }
    }

    public static string KeyFor(IpRateLimitPolicy policy, string clientIp) => $"{KeyPrefix}{policy.Name}:{clientIp}";
}
