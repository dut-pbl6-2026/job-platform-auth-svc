using Auth.Core.Interfaces;
using StackExchange.Redis;

namespace Auth.Api.RateLimiting;

/// <summary>
/// Fixed-window counter in Redis. INCR and the expiry run in one Lua script, so a crash between
/// the two cannot leave a key without a TTL. The TTL is set only when the key has none, which
/// keeps the window fixed: later hits do not extend it.
/// </summary>
public sealed class RedisRateLimitCounterStore(IConnectionMultiplexer redis) : IRateLimitCounterStore
{
    private const string IncrementScript = """
        local count = redis.call('INCR', KEYS[1])
        local ttl = redis.call('PTTL', KEYS[1])
        if ttl < 0 then
          redis.call('PEXPIRE', KEYS[1], ARGV[1])
          ttl = tonumber(ARGV[1])
        end
        return {count, ttl}
        """;

    public async Task<RateLimitCount> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default)
    {
        var database = redis.GetDatabase();
        var result = (long[])(await database.ScriptEvaluateAsync(
            IncrementScript,
            [key],
            [(long)window.TotalMilliseconds]))!;

        return new RateLimitCount(result[0], TimeSpan.FromMilliseconds(result[1]));
    }
}
