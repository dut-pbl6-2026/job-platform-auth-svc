using System.Collections.Concurrent;
using Auth.Core.Interfaces;

namespace Auth.Tests.Fixtures;

/// <summary>
/// In-memory fixed-window counter whose counts a test can clear. The shared host keeps one store, so a test
/// that sends several sign-ups would otherwise exhaust the per-IP bucket for the tests after it.
/// </summary>
public sealed class ResettableRateLimitCounterStore : IRateLimitCounterStore
{
    private readonly ConcurrentDictionary<string, (long Count, DateTimeOffset EndsAt)> _windows = new();

    public void Clear() => _windows.Clear();

    public Task<RateLimitCount> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        var next = _windows.AddOrUpdate(
            key,
            _ => (1, now + window),
            (_, current) => current.EndsAt > now ? (current.Count + 1, current.EndsAt) : (1, now + window));
        return Task.FromResult(new RateLimitCount(next.Count, next.EndsAt - now));
    }
}
