using System.Net;
using System.Net.Http.Json;
using Auth.Core.Contracts;
using Auth.Tests.Fixtures;

namespace Auth.Tests;

/// <summary>
/// Rate-limit buckets are keyed by the real client behind a trusted proxy. Login allows 10 attempts
/// per IP per 15 minutes, so the 11th attempt answers 429 when the attempts share a bucket and stays
/// 401 when each forwarded client has its own.
/// </summary>
public sealed class TrustedProxyRateLimitTests : IClassFixture<TrustedProxyRateLimitTests.Hosts>
{
    public sealed class Hosts : IAsyncLifetime
    {
        private static readonly IPAddress Peer = IPAddress.Parse("203.0.113.10");

        public ResettableRateLimitCounterStore TrustedStore { get; } = new();
        public ResettableRateLimitCounterStore ConfiguredUntrustedStore { get; } = new();
        public ResettableRateLimitCounterStore UnsetStore { get; } = new();

        /// <summary>Peer is a trusted gateway; forwarded clients are honoured.</summary>
        public RecordingAuthFactory Trusted { get; }
        /// <summary>Proxy list is configured, but the peer is not in it: forwarded headers are ignored.</summary>
        public RecordingAuthFactory ConfiguredUntrusted { get; }
        /// <summary>No proxy list at all: the connection IP is the bucket key.</summary>
        public RecordingAuthFactory Unset { get; }

        public Hosts()
        {
            Trusted = new RecordingAuthFactory
            {
                TrustedProxies = "203.0.113.0/24",
                PeerAddress = Peer,
                RateLimitStore = TrustedStore,
            };
            ConfiguredUntrusted = new RecordingAuthFactory
            {
                TrustedProxies = "10.0.0.0/8",
                PeerAddress = Peer,
                RateLimitStore = ConfiguredUntrustedStore,
            };
            Unset = new RecordingAuthFactory
            {
                PeerAddress = Peer,
                RateLimitStore = UnsetStore,
            };
        }

        public async Task InitializeAsync()
        {
            await Task.WhenAll(
                Trusted.InitializeAsync(),
                ConfiguredUntrusted.InitializeAsync(),
                Unset.InitializeAsync());
        }

        public async Task DisposeAsync()
        {
            await Task.WhenAll(
                Trusted.DisposeAsync(),
                ConfiguredUntrusted.DisposeAsync(),
                Unset.DisposeAsync());
        }

        public void ResetCounters()
        {
            TrustedStore.Clear();
            ConfiguredUntrustedStore.Clear();
            UnsetStore.Clear();
        }
    }

    private readonly Hosts _hosts;

    public TrustedProxyRateLimitTests(Hosts hosts) => _hosts = hosts;

    [Fact]
    public async Task SameClientBehindTrustedProxy_SharesOneBucket()
    {
        _hosts.ResetCounters();

        var statuses = await LoginAsync(_hosts.Trusted, "198.51.100.7", attempts: 11);

        Assert.All(statuses.Take(10), status => Assert.Equal(HttpStatusCode.Unauthorized, status));
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[10]);
    }

    [Fact]
    public async Task DifferentForwardedClients_GetIndependentBuckets()
    {
        _hosts.ResetCounters();

        var first = await LoginAsync(_hosts.Trusted, "198.51.100.7", attempts: 10);
        var second = await LoginAsync(_hosts.Trusted, "198.51.100.8", attempts: 10);

        Assert.All(first, status => Assert.Equal(HttpStatusCode.Unauthorized, status));
        Assert.All(second, status => Assert.Equal(HttpStatusCode.Unauthorized, status));
    }

    [Fact]
    public async Task ClientSuppliedForwardedFor_FromUntrustedPeer_DoesNotEscapePeerBucket()
    {
        _hosts.ResetCounters();

        var statuses = await LoginAsync(
            _hosts.ConfiguredUntrusted,
            forwardedFor: i => $"198.51.100.{i}",
            attempts: 11);

        Assert.All(statuses.Take(10), status => Assert.Equal(HttpStatusCode.Unauthorized, status));
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[10]);
    }

    [Fact]
    public async Task UnsetProxyList_FallsBackToConnectionIp()
    {
        _hosts.ResetCounters();

        var statuses = await LoginAsync(
            _hosts.Unset,
            forwardedFor: i => $"198.51.100.{i}",
            attempts: 11);

        Assert.All(statuses.Take(10), status => Assert.Equal(HttpStatusCode.Unauthorized, status));
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[10]);
    }

    private static Task<List<HttpStatusCode>> LoginAsync(
        RecordingAuthFactory factory, string forwardedFor, int attempts) =>
        LoginAsync(factory, _ => forwardedFor, attempts);

    private static async Task<List<HttpStatusCode>> LoginAsync(
        RecordingAuthFactory factory, Func<int, string> forwardedFor, int attempts)
    {
        var client = factory.CreateClient();
        var statuses = new List<HttpStatusCode>();
        for (var i = 1; i <= attempts; i++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login")
            {
                Content = JsonContent.Create(new LoginRequest($"nobody{i}@test.com", "Wrong-pass1")),
            };
            request.Headers.Add("X-Forwarded-For", forwardedFor(i));
            statuses.Add((await client.SendAsync(request)).StatusCode);
        }
        return statuses;
    }
}
