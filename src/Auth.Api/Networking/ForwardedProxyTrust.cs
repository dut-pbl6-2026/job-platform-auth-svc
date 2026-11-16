using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.HttpOverrides;
using IPNetwork = System.Net.IPNetwork;

namespace Auth.Api.Networking;

/// <summary>
/// Decides which peers may set X-Forwarded-For and X-Forwarded-Proto. Auth is reachable only through
/// the gateway, so only the gateway's network in <c>ForwardedHeaders:KnownNetworks</c> is trusted; any
/// other peer's forwarded headers are ignored. Same rule as the gateway's <c>ForwardedProxyTrust</c>.
/// </summary>
public static class ForwardedProxyTrust
{
    /// <summary>
    /// Comma-separated proxy addresses/CIDRs trusted to append X-Forwarded-For. Primary setting; the
    /// older ForwardedHeaders:KnownNetworks key is still read as a fallback.
    /// </summary>
    public const string TrustedProxiesKey = "TRUSTED_PROXIES";
    public const string KnownNetworksKey = "ForwardedHeaders:KnownNetworks";

    /// <summary>
    /// Reads the configured proxy networks. Accepts a comma-separated value
    /// (TRUSTED_PROXIES=10.0.0.0/8,192.168.1.5) or indexed entries (TRUSTED_PROXIES__0=...), and falls
    /// back to ForwardedHeaders:KnownNetworks. Returns an empty list when unset (non-Production only).
    /// </summary>
    public static IReadOnlyList<IPNetwork> ReadNetworks(IConfiguration configuration, bool isProduction)
    {
        var entries = Collect(configuration, TrustedProxiesKey);
        if (entries.Count == 0)
            entries = Collect(configuration, KnownNetworksKey);

        if (entries.Count == 0)
        {
            if (isProduction)
                throw new InvalidOperationException(
                    "TRUSTED_PROXIES (or ForwardedHeaders:KnownNetworks) must list the gateway's network in " +
                    "Production (set TRUSTED_PROXIES to the compose network, e.g. 172.21.0.0/16). " +
                    "Without it every client shares the gateway's rate-limit bucket.");
            return [];
        }

        return Parse(entries);
    }

    private static List<string> Collect(IConfiguration configuration, string key)
    {
        var entries = new List<string>();
        var raw = configuration[key];
        if (!string.IsNullOrWhiteSpace(raw))
            entries.AddRange(raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        entries.AddRange(configuration.GetSection(key).GetChildren()
            .Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v!.Trim()));
        return entries;
    }

    /// <summary>Parses CIDR ranges or single addresses. Rejects invalid entries and catch-all ranges.</summary>
    public static IReadOnlyList<IPNetwork> Parse(IEnumerable<string> entries)
    {
        var networks = new List<IPNetwork>();
        foreach (var entry in entries)
        {
            IPNetwork network;
            if (entry.Contains('/'))
            {
                if (!IPNetwork.TryParse(entry, out network))
                    throw new InvalidOperationException($"ForwardedHeaders:KnownNetworks entry '{entry}' is not a valid CIDR range.");
            }
            else
            {
                if (!IPAddress.TryParse(entry, out var address))
                    throw new InvalidOperationException($"ForwardedHeaders:KnownNetworks entry '{entry}' is not a valid IP address.");
                var prefix = address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
                network = new IPNetwork(address, prefix);
            }

            if (network.PrefixLength == 0)
                throw new InvalidOperationException(
                    $"ForwardedHeaders:KnownNetworks entry '{entry}' trusts every peer. Use the gateway's address or subnet.");

            networks.Add(network);
        }

        return networks;
    }

    /// <summary>Replaces the framework defaults with the configured networks.</summary>
    public static void Apply(ForwardedHeadersOptions options, IReadOnlyList<IPNetwork> networks)
    {
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        foreach (var network in networks)
            options.KnownIPNetworks.Add(network);
    }
}
