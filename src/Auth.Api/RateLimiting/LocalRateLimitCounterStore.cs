using System.Collections.Concurrent;
using Auth.Core.Interfaces;

namespace Auth.Api.RateLimiting;

/// <summary>
/// In-process counter for Development and tests only. Used when REDIS_URL is not set, which
/// production startup rejects. Its counts are not shared between instances.
/// </summary>
public sealed class LocalRateLimitCounterStore(TimeProvider time) : IRateLimitCounterStore
{
    private sealed record Window(long Count, DateTimeOffset EndsAt);

    private readonly ConcurrentDictionary<string, Window> _windows = new();
    private readonly object _gate = new();

    public Task<RateLimitCount> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var now = time.GetUtcNow();
            if (_windows.TryGetValue(key, out var current) && current.EndsAt > now)
            {
                var next = current with { Count = current.Count + 1 };
                _windows[key] = next;
                return Task.FromResult(new RateLimitCount(next.Count, next.EndsAt - now));
            }

            // Drop windows that already ended so the dictionary does not grow without bound.
            foreach (var entry in _windows)
            {
                if (entry.Value.EndsAt <= now)
                    _windows.TryRemove(entry.Key, out _);
            }

            var started = new Window(1, now + window);
            _windows[key] = started;
            return Task.FromResult(new RateLimitCount(1, window));
        }
    }
}
