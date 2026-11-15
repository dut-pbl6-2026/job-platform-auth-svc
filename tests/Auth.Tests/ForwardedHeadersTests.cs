using System.Net;
using System.Net.Http.Json;
using Auth.Core.Contracts;
using Auth.Tests.Fixtures;

namespace Auth.Tests;

/// <summary>
/// Forwarded client IPs are honoured only from the configured gateway network. Login allows 10 attempts
/// per IP per 15 minutes, so the 11th attempt answers 429 exactly when all attempts share one bucket.
/// The trusted-peer control proves the middleware is active and the 429 comes from ignored headers.
/// </summary>
public sealed class ForwardedHeadersTests : IAsyncLifetime
{
    private static readonly IPAddress Peer = IPAddress.Parse("203.0.113.10");
    private readonly RecordingAuthFactory _untrusted = new()
    {
        ForwardedKnownNetworks = "10.0.0.0/8",
        PeerAddress = Peer,
    };
    private readonly RecordingAuthFactory _trusted = new()
    {
        ForwardedKnownNetworks = "203.0.113.0/24",
        PeerAddress = Peer,
    };

    public async Task InitializeAsync()
    {
        await _untrusted.InitializeAsync();
        await _trusted.InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await _untrusted.DisposeAsync();
        await _trusted.DisposeAsync();
    }

    private static async Task<List<HttpStatusCode>> LoginWithDistinctForwardedAddressesAsync(RecordingAuthFactory factory)
    {
        var client = factory.CreateClient();
        var statuses = new List<HttpStatusCode>();
        for (var i = 1; i <= 11; i++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login")
            {
                Content = JsonContent.Create(new LoginRequest($"nobody{i}@test.com", "Wrong-pass1")),
            };
            request.Headers.Add("X-Forwarded-For", $"198.51.100.{i}");
            statuses.Add((await client.SendAsync(request)).StatusCode);
        }
        return statuses;
    }

    [Fact]
    public async Task ForwardedFor_FromUntrustedPeer_IsIgnored()
    {
        var statuses = await LoginWithDistinctForwardedAddressesAsync(_untrusted);

        Assert.All(statuses.Take(10), s => Assert.Equal(HttpStatusCode.Unauthorized, s));
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[10]);
    }

    [Fact]
    public async Task ForwardedFor_FromTrustedGateway_IsHonoured()
    {
        var statuses = await LoginWithDistinctForwardedAddressesAsync(_trusted);

        Assert.All(statuses, s => Assert.Equal(HttpStatusCode.Unauthorized, s));
    }
}
