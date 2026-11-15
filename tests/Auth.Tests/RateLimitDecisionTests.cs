using Auth.Api.RateLimiting;
using Auth.Core.Interfaces;
using Microsoft.Extensions.Logging.Abstractions;

namespace Auth.Tests;

/// <summary>Unit tests for the per-IP limit decision, using in-process stores only.</summary>
public sealed class RateLimitDecisionTests
{
    private static readonly IpRateLimitPolicy Policy = new("test", 3, TimeSpan.FromMinutes(15));

    private static IpRateLimiter LimiterOver(IRateLimitCounterStore store) =>
        new(store, NullLogger<IpRateLimiter>.Instance);

    [Fact]
    public async Task Request_WithinLimit_IsAllowed()
    {
        var limiter = LimiterOver(new LocalRateLimitCounterStore(new ManualClock(DateTimeOffset.UtcNow)));

        for (var i = 0; i < Policy.PermitLimit; i++)
        {
            var decision = await limiter.CheckAsync(Policy, "203.0.113.7");
            Assert.True(decision.Allowed);
        }
    }

    [Fact]
    public async Task Request_OverLimit_IsBlocked_WithRetryAfterFromWindow()
    {
        var store = new FixedCountStore(new RateLimitCount(Policy.PermitLimit + 1, TimeSpan.FromMinutes(4)));
        var limiter = LimiterOver(store);

        var decision = await limiter.CheckAsync(Policy, "203.0.113.7");

        Assert.False(decision.Allowed);
        Assert.Equal(TimeSpan.FromMinutes(4), decision.RetryAfter);
    }

    [Fact]
    public async Task StoreFailure_FailsOpen_AndAllowsRequest()
    {
        var limiter = LimiterOver(new FailingStore());

        var decision = await limiter.CheckAsync(Policy, "203.0.113.7");

        Assert.True(decision.Allowed);
    }

    [Fact]
    public async Task Cancellation_IsNotSwallowedAsFailOpen()
    {
        var limiter = LimiterOver(new CancellingStore());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => limiter.CheckAsync(Policy, "203.0.113.7"));
    }

    [Fact]
    public async Task Window_ResetsAfterItEnds_AndCountsRestart()
    {
        var clock = new ManualClock(DateTimeOffset.UtcNow);
        var limiter = LimiterOver(new LocalRateLimitCounterStore(clock));

        for (var i = 0; i < Policy.PermitLimit; i++)
            Assert.True((await limiter.CheckAsync(Policy, "203.0.113.7")).Allowed);

        var blocked = await limiter.CheckAsync(Policy, "203.0.113.7");
        Assert.False(blocked.Allowed);
        Assert.Equal(Policy.Window, blocked.RetryAfter);

        clock.Now = clock.Now + Policy.Window;

        var afterReset = await limiter.CheckAsync(Policy, "203.0.113.7");
        Assert.True(afterReset.Allowed);
    }

    [Fact]
    public async Task Window_DoesNotExtend_OnLaterHits()
    {
        var clock = new ManualClock(DateTimeOffset.UtcNow);
        var limiter = LimiterOver(new LocalRateLimitCounterStore(clock));

        await limiter.CheckAsync(Policy, "203.0.113.7");
        clock.Now += TimeSpan.FromMinutes(10);
        for (var i = 0; i < Policy.PermitLimit; i++)
            await limiter.CheckAsync(Policy, "203.0.113.7");

        // Five minutes after the first hit the window has ended, even though later hits came in.
        clock.Now += TimeSpan.FromMinutes(5);
        Assert.True((await limiter.CheckAsync(Policy, "203.0.113.7")).Allowed);
    }

    [Fact]
    public async Task Counts_AreKeyedPerPolicyAndIp()
    {
        var limiter = LimiterOver(new LocalRateLimitCounterStore(new ManualClock(DateTimeOffset.UtcNow)));
        var other = new IpRateLimitPolicy("other", 3, TimeSpan.FromMinutes(15));

        for (var i = 0; i < Policy.PermitLimit + 1; i++)
            await limiter.CheckAsync(Policy, "203.0.113.7");

        Assert.True((await limiter.CheckAsync(Policy, "203.0.113.8")).Allowed);
        Assert.True((await limiter.CheckAsync(other, "203.0.113.7")).Allowed);
        Assert.Equal("job-platform:auth:ratelimit:test:203.0.113.7", IpRateLimiter.KeyFor(Policy, "203.0.113.7"));
    }

    private sealed class ManualClock(DateTimeOffset start) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = start;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class FixedCountStore(RateLimitCount result) : IRateLimitCounterStore
    {
        public Task<RateLimitCount> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default) =>
            Task.FromResult(result);
    }

    private sealed class FailingStore : IRateLimitCounterStore
    {
        public Task<RateLimitCount> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default) =>
            throw new InvalidOperationException("store down");
    }

    private sealed class CancellingStore : IRateLimitCounterStore
    {
        public Task<RateLimitCount> IncrementAsync(string key, TimeSpan window, CancellationToken ct = default) =>
            Task.FromCanceled<RateLimitCount>(new CancellationToken(canceled: true));
    }
}
