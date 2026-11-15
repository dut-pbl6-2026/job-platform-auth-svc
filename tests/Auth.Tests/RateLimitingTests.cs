using System.Net;
using System.Net.Http.Json;
using Auth.Core.Contracts;

namespace Auth.Tests;

// Own factory instance: rate-limit partitions are per factory, so these budgets
// do not interact with the other test classes.
public sealed class RateLimitingTests : IClassFixture<CustomAuthFactory>
{
    private readonly CustomAuthFactory _factory;

    public RateLimitingTests(CustomAuthFactory factory) => _factory = factory;

    [Theory]
    [InlineData("/api/auth/login", 10)]
    [InlineData("/api/auth/register", 10)]
    [InlineData("/api/auth/refresh", 30)]
    [InlineData("/api/auth/reset-password", 10)]
    public async Task Endpoint_Returns429_AfterPermitLimit(string route, int permitLimit)
    {
        var client = _factory.CreateClient();

        for (var i = 0; i < permitLimit; i++)
        {
            var response = await client.PostAsJsonAsync(route, new { });
            Assert.NotEqual(HttpStatusCode.TooManyRequests, response.StatusCode);
        }

        var limited = await client.PostAsJsonAsync(route, new { });
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
    }

    [Fact]
    public async Task ForgotPassword_RotatingForwardedFor_DoesNotBypassLimit()
    {
        var client = _factory.CreateClient();
        HttpStatusCode? last = null;

        for (var i = 0; i < 6; i++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "api/auth/forgot-password")
            {
                Content = JsonContent.Create(new ForgotPasswordRequest($"xff{i}@test.com"))
            };
            request.Headers.Add("X-Forwarded-For", $"203.0.113.{i + 1}");
            last = (await client.SendAsync(request)).StatusCode;
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, last);
    }
}
