using System.Net;

namespace Auth.Api.Networking;

/// <summary>
/// Resolves the rate-limit client IP from a proxy chain. Forwarded entries are honoured only when the
/// immediate peer is a configured trusted proxy; otherwise the connection IP is used unchanged, so a
/// client cannot pick its own bucket by sending X-Forwarded-For.
/// </summary>
public sealed class ClientIpResolver
{
    private readonly IReadOnlyList<IPNetwork> _trustedProxies;

    public ClientIpResolver(IReadOnlyList<IPNetwork> trustedProxies) => _trustedProxies = trustedProxies;

    /// <summary>
    /// Returns the right-most hop that is not itself a trusted proxy, walking X-Forwarded-For from the
    /// nearest proxy backwards. The left-most entry is attacker-controlled and is never used directly.
    /// Falls back to <paramref name="peer"/> when no proxy is trusted, the header is missing, or it has
    /// no parseable hop.
    /// </summary>
    public IPAddress? Resolve(IPAddress? peer, string? forwardedFor)
    {
        if (peer is null)
            return null;

        peer = Normalize(peer);
        if (_trustedProxies.Count == 0 || !IsTrusted(peer) || string.IsNullOrWhiteSpace(forwardedFor))
            return peer;

        var hops = ParseHops(forwardedFor);
        for (var i = hops.Count - 1; i >= 0; i--)
        {
            if (!IsTrusted(hops[i]))
                return hops[i];
        }

        // Every hop is a trusted proxy (or none parsed): keep the connection IP rather than trusting
        // unverified data.
        return hops.Count == 0 ? peer : hops[0];
    }

    private bool IsTrusted(IPAddress address) => _trustedProxies.Any(network => network.Contains(address));

    private static List<IPAddress> ParseHops(string forwardedFor)
    {
        var hops = new List<IPAddress>();
        foreach (var entry in forwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            // Some proxies append "ip:port"; unparseable entries are ignored, not trusted.
            if (IPAddress.TryParse(entry, out var address))
                hops.Add(Normalize(address));
        }
        return hops;
    }

    private static IPAddress Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
