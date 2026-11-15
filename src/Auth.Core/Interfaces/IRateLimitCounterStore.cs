namespace Auth.Core.Interfaces;

/// <summary>
/// Shared fixed-window request counter. Every replica must see the same counts, so implementations
/// keep state outside the process (Redis in production).
/// </summary>
public interface IRateLimitCounterStore
{
    /// <summary>
    /// Atomically counts one request for <paramref name="key"/>. The window starts with the first
    /// request and ends <paramref name="window"/> later; the count resets when it ends.
    /// </summary>
    Task<RateLimitCount> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default);
}

/// <param name="Count">Requests counted in the current window, including this one.</param>
/// <param name="TimeToLive">Time left in the current window.</param>
public readonly record struct RateLimitCount(long Count, TimeSpan TimeToLive);
