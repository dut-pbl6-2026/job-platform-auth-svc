using System.Net;
using System.Net.Http.Json;
using Auth.Api.RateLimiting;
using Auth.Core.Contracts;
using Auth.Tests.Fixtures;

namespace Auth.Tests;

/// <summary>
/// Two API hosts that share one counter store (standing in for Redis) must count against the same
/// per-IP limit. TestServer sends no RemoteIpAddress, so every request keys as "unknown", which is
/// the same key for both hosts.
/// </summary>
public sealed class SharedRateLimitTests : IAsyncLifetime
{
    private readonly Auth.Api.RateLimiting.LocalRateLimitCounterStore _sharedStore = new(TimeProvider.System);
    private RecordingAuthFactory _hostA = null!;
    private RecordingAuthFactory _hostB = null!;

    public async Task InitializeAsync()
    {
        _hostA = new RecordingAuthFactory { RateLimitStore = _sharedStore };
        _hostB = new RecordingAuthFactory { RateLimitStore = _sharedStore };
        await _hostA.InitializeAsync();
        await _hostB.InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await _hostA.DisposeAsync();
        await _hostB.DisposeAsync();
    }

    [Fact]
    public async Task EleventhLogin_FromSameIp_Returns429_WithGenericBody()
    {
        var client = _hostA.CreateClient();
        for (var i = 0; i < 10; i++)
        {
            var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest($"nobody{i}@test.com", "WrongP@ss123"));
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        var limited = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest("nobody@test.com", "WrongP@ss123"));

        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.NotNull(limited.Headers.RetryAfter);
        var retryAfter = limited.Headers.RetryAfter!.Delta!.Value.TotalSeconds;
        Assert.InRange(retryAfter, 1, IpRateLimitPolicy.Login.Window.TotalSeconds);

        var body = await limited.Content.ReadAsStringAsync();
        Assert.Contains("Too many requests. Please try again later.", body);
        Assert.DoesNotContain("nobody", body);
    }

    [Fact]
    public async Task TwoHosts_SharingStore_CountTogether()
    {
        var clientA = _hostA.CreateClient();
        var clientB = _hostB.CreateClient();

        for (var i = 0; i < 6; i++)
            await clientA.PostAsJsonAsync("/api/auth/login", new LoginRequest($"a{i}@test.com", "WrongP@ss123"));
        for (var i = 0; i < 4; i++)
            await clientB.PostAsJsonAsync("/api/auth/login", new LoginRequest($"b{i}@test.com", "WrongP@ss123"));

        // Ten attempts have now been counted across both hosts, so the next one is blocked on either host.
        var blockedOnB = await clientB.PostAsJsonAsync("/api/auth/login", new LoginRequest("c@test.com", "WrongP@ss123"));
        Assert.Equal(HttpStatusCode.TooManyRequests, blockedOnB.StatusCode);
    }

    [Fact]
    public async Task ForgotPassword_Limit5PerHour_SharedAcrossHosts()
    {
        var clientA = _hostA.CreateClient();
        var clientB = _hostB.CreateClient();

        for (var i = 0; i < 3; i++)
            await clientA.PostAsJsonAsync("/api/auth/forgot-password", new ForgotPasswordRequest($"f{i}@test.com"));
        for (var i = 0; i < 2; i++)
            await clientB.PostAsJsonAsync("/api/auth/forgot-password", new ForgotPasswordRequest($"g{i}@test.com"));

        var limited = await clientA.PostAsJsonAsync("/api/auth/forgot-password", new ForgotPasswordRequest("h@test.com"));
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
    }
}
