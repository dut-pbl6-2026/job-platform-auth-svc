namespace Auth.Api.RateLimiting;

/// <summary>Outcome of one rate-limit check.</summary>
public readonly record struct IpRateLimitDecision(bool Allowed, TimeSpan RetryAfter)
{
    public static readonly IpRateLimitDecision Allow = new(true, TimeSpan.Zero);
}
