using Auth.Api.Networking;
using Auth.Core.Entities;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using System.Net;

namespace Auth.Tests;

public class ForwardedProxyTrustTests
{
    private static IConfiguration Config(params (string Key, string? Value)[] settings) =>
        new ConfigurationBuilder().AddInMemoryCollection(settings.Select(s => new KeyValuePair<string, string?>(s.Key, s.Value))).Build();

    [Fact]
    public void Development_WithNoNetworks_TrustsNoForwardedHeaders()
    {
        Assert.Empty(ForwardedProxyTrust.ReadNetworks(Config(), isProduction: false));
    }

    [Fact]
    public void Production_WithNoNetworks_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ForwardedProxyTrust.ReadNetworks(Config(), isProduction: true));
        Assert.Contains("ForwardedHeaders:KnownNetworks", ex.Message);
    }

    [Fact]
    public void CommaSeparatedValue_ParsesCidrRangesAndBareAddresses()
    {
        var networks = ForwardedProxyTrust.ReadNetworks(
            Config((ForwardedProxyTrust.KnownNetworksKey, "10.0.0.0/8, 192.168.1.5")), isProduction: true);

        Assert.Equal(2, networks.Count);
        Assert.True(networks[0].Contains(IPAddress.Parse("10.20.30.40")));
        Assert.True(networks[1].Contains(IPAddress.Parse("192.168.1.5")));
        Assert.False(networks[1].Contains(IPAddress.Parse("192.168.1.6")));
    }

    [Fact]
    public void IndexedEntries_AreReadToo()
    {
        var networks = ForwardedProxyTrust.ReadNetworks(
            Config(("ForwardedHeaders:KnownNetworks:0", "10.0.0.0/8"), ("ForwardedHeaders:KnownNetworks:1", "172.16.0.0/12")),
            isProduction: true);

        Assert.Equal(2, networks.Count);
    }

    [Fact]
    public void TrustedProxiesSetting_IsThePrimarySource()
    {
        var networks = ForwardedProxyTrust.ReadNetworks(
            Config((ForwardedProxyTrust.TrustedProxiesKey, "172.21.0.0/16")), isProduction: true);

        Assert.Single(networks);
        Assert.True(networks[0].Contains(IPAddress.Parse("172.21.0.17")));
    }

    [Fact]
    public void TrustedProxiesSetting_WinsOverLegacyKnownNetworks()
    {
        var networks = ForwardedProxyTrust.ReadNetworks(
            Config(
                (ForwardedProxyTrust.TrustedProxiesKey, "172.21.0.0/16"),
                (ForwardedProxyTrust.KnownNetworksKey, "10.0.0.0/8")),
            isProduction: true);

        Assert.Single(networks);
        Assert.True(networks[0].Contains(IPAddress.Parse("172.21.0.17")));
    }

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("::/0")]
    [InlineData("10.0.0.0/8,0.0.0.0/0")]
    public void CatchAllRange_Throws(string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            ForwardedProxyTrust.ReadNetworks(Config((ForwardedProxyTrust.KnownNetworksKey, value)), isProduction: false));
        Assert.Contains("trusts every peer", ex.Message);
    }

    [Theory]
    [InlineData("10.0.0.0/33")]
    [InlineData("not-an-address")]
    [InlineData("10.0.0.300")]
    public void InvalidEntry_Throws(string value)
    {
        Assert.Throws<InvalidOperationException>(() =>
            ForwardedProxyTrust.ReadNetworks(Config((ForwardedProxyTrust.KnownNetworksKey, value)), isProduction: false));
    }

    [Fact]
    public void Apply_ReplacesFrameworkDefaultsWithConfiguredNetworks()
    {
        var options = new ForwardedHeadersOptions();
        Assert.NotEmpty(options.KnownProxies);

        ForwardedProxyTrust.Apply(options, ForwardedProxyTrust.Parse(["10.0.0.0/8"]));

        Assert.Empty(options.KnownProxies);
        Assert.Single(options.KnownIPNetworks);
    }
}
