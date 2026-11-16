using System.Net;
using Auth.Api.Networking;

namespace Auth.Tests;

public class ClientIpResolverTests
{
    private static ClientIpResolver Resolver(params string[] trusted) =>
        new(ForwardedProxyTrust.Parse(trusted));

    private static readonly IPAddress Gateway = IPAddress.Parse("203.0.113.10");
    private static readonly IPAddress User = IPAddress.Parse("198.51.100.7");

    [Fact]
    public void NoTrustedProxies_FallsBackToConnectionIp()
    {
        var resolved = Resolver().Resolve(Gateway, "1.2.3.4");

        Assert.Equal(Gateway, resolved);
    }

    [Fact]
    public void UntrustedPeer_IgnoresForwardedFor()
    {
        var resolved = Resolver("10.0.0.0/8").Resolve(Gateway, "1.2.3.4");

        Assert.Equal(Gateway, resolved);
    }

    [Fact]
    public void TrustedPeer_SingleForwardedHop_ReturnsClient()
    {
        var resolved = Resolver("203.0.113.0/24").Resolve(Gateway, User.ToString());

        Assert.Equal(User, resolved);
    }

    [Fact]
    public void SameClientBehindProxy_ResolvesToSameBucketKey()
    {
        var resolver = Resolver("203.0.113.0/24");

        var first = resolver.Resolve(Gateway, User.ToString());
        var second = resolver.Resolve(Gateway, User.ToString());

        Assert.Equal(first, second);
    }

    [Fact]
    public void DifferentForwardedClients_ResolveToDifferentBuckets()
    {
        var resolver = Resolver("203.0.113.0/24");

        var first = resolver.Resolve(Gateway, User.ToString());
        var second = resolver.Resolve(Gateway, IPAddress.Parse("198.51.100.8").ToString());

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void MultipleUntrustedHops_UsesRightMostNotLeftMost()
    {
        var resolver = Resolver("203.0.113.0/24");

        var resolved = resolver.Resolve(Gateway, "1.2.3.4, 198.51.100.7");

        Assert.Equal(User, resolved);
    }

    [Fact]
    public void TrustedIntermediateHops_AreSkipped()
    {
        var resolver = Resolver("203.0.113.0/24", "10.0.0.0/8");

        var resolved = resolver.Resolve(Gateway, "198.51.100.7, 10.0.0.9");

        Assert.Equal(User, resolved);
    }

    [Fact]
    public void UnparseableHops_AreIgnored()
    {
        var resolver = Resolver("203.0.113.0/24");

        var resolved = resolver.Resolve(Gateway, "unknown, 198.51.100.7");

        Assert.Equal(User, resolved);
    }

    [Fact]
    public void IPv4MappedPeer_IsMatchedAgainstIPv4TrustedRange()
    {
        var resolver = Resolver("203.0.113.0/24");

        var resolved = resolver.Resolve(Gateway.MapToIPv6(), User.ToString());

        Assert.Equal(User, resolved);
    }

    [Fact]
    public void NullPeer_ReturnsNull()
    {
        Assert.Null(Resolver("203.0.113.0/24").Resolve(null, User.ToString()));
    }
}
