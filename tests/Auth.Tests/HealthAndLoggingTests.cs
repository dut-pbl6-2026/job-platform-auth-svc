using System.Net;
using System.Text.Json;
using Auth.Api.Observability;
using Auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Moq;

namespace Auth.Tests;

public class HealthAndLoggingTests : IClassFixture<CustomAuthFactory>
{
    private readonly CustomAuthFactory _factory;

    public HealthAndLoggingTests(CustomAuthFactory factory) => _factory = factory;

    [Fact]
    public async Task Health_KeepsStaticLivenessContract()
    {
        var res = await _factory.CreateClient().GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        using var json = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
        Assert.Equal("ok", json.RootElement.GetProperty("status").GetString());
        Assert.Equal("auth", json.RootElement.GetProperty("service").GetString());
    }

    [Fact]
    public async Task Ready_ReportsPostgresHealthy()
    {
        var res = await _factory.CreateClient().GetAsync("/health/ready");

        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        using var json = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
        Assert.Equal("Healthy", json.RootElement.GetProperty("status").GetString());
        var checks = json.RootElement.GetProperty("checks").EnumerateArray().ToList();
        Assert.Contains(checks, c => c.GetProperty("name").GetString() == "postgres"
                                     && c.GetProperty("status").GetString() == "Healthy");
    }

    [Fact]
    public async Task DatabaseCheck_Unreachable_IsUnhealthyWithoutLeakingDetails()
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseNpgsql("Host=127.0.0.1;Port=1;Database=x;Username=u;Password=secret-pw;Timeout=2")
            .Options;
        await using var db = new AuthDbContext(options);

        var result = await new DatabaseHealthCheck(db).CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.DoesNotContain("secret-pw", result.Description ?? "");
    }

    [Fact]
    public async Task RedisCheck_Failure_IsUnhealthy()
    {
        var cache = new Mock<IDistributedCache>();
        cache.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("boom"));

        var result = await new RedisHealthCheck(cache.Object).CheckHealthAsync(new HealthCheckContext());

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
    }

    [Fact]
    public async Task CorrelationId_IsGeneratedWhenAbsent()
    {
        var res = await _factory.CreateClient().GetAsync("/health");

        var id = Assert.Single(res.Headers.GetValues("X-Correlation-Id"));
        Assert.False(string.IsNullOrWhiteSpace(id));
    }

    [Fact]
    public async Task CorrelationId_IsEchoedWhenProvided()
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Add("X-Correlation-Id", "abc-123");

        var res = await _factory.CreateClient().SendAsync(req);

        Assert.Equal("abc-123", Assert.Single(res.Headers.GetValues("X-Correlation-Id")));
    }

    [Fact]
    public async Task CorrelationId_UnsafeValueIsReplaced()
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.TryAddWithoutValidation("X-Correlation-Id", new string('x', 200));

        var res = await _factory.CreateClient().SendAsync(req);

        var id = Assert.Single(res.Headers.GetValues("X-Correlation-Id"));
        Assert.NotEqual(new string('x', 200), id);
    }
}
