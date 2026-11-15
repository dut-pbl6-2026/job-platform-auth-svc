using Auth.Api.RateLimiting;
using StackExchange.Redis;

namespace Auth.Tests;

public class RateLimitRedisOptionsTests
{
    [Fact]
    public void RateLimitConnection_UsesHalfSecondTimeouts()
    {
        var options = RateLimitRedisOptions.Create(ConfigurationOptions.Parse("localhost:6379"));

        Assert.Equal(500, options.ConnectTimeout);
        Assert.Equal(500, options.AsyncTimeout);
        Assert.Equal(500, options.SyncTimeout);
    }

    [Fact]
    public void SharedOptions_AreNotChanged()
    {
        var shared = ConfigurationOptions.Parse("localhost:6379,password=unused");
        var before = (shared.ConnectTimeout, shared.AsyncTimeout, shared.SyncTimeout);

        var rateLimit = RateLimitRedisOptions.Create(shared);

        Assert.Equal(before, (shared.ConnectTimeout, shared.AsyncTimeout, shared.SyncTimeout));
        Assert.NotEqual(before.AsyncTimeout, rateLimit.AsyncTimeout);
        Assert.Equal(shared.Password, rateLimit.Password);
        Assert.Equal(shared.EndPoints.Single(), rateLimit.EndPoints.Single());
    }
}
