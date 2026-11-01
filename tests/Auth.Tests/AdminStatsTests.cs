using System.Net;
using System.Net.Http.Json;
using Auth.Core.Contracts;
using Auth.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;

namespace Auth.Tests;

public sealed class AdminStatsTests
{
    [Fact]
    public async Task GetStats_WhenJobSvcDown_ReturnsUnavailableNull()
    {
        using var http = new HttpClient(new StubHandler(
            (_, _) => throw new HttpRequestException("job service is down")))
        {
            BaseAddress = new Uri("http://job-service/")
        };
        var client = new JobServiceClient(http, NullLogger<JobServiceClient>.Instance);

        var stats = await client.GetStatsOrNullAsync();

        Assert.Null(stats);
    }

    [Fact]
    public async Task GetStats_WhenServiceReturnsStats_DeserializesResponse()
    {
        var expected = new JobStats(10, 2, 6, 1, 1, 3);
        using var http = new HttpClient(new StubHandler(
            (_, _) => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(expected)
            }))
        {
            BaseAddress = new Uri("http://job-service/")
        };
        var client = new JobServiceClient(http, NullLogger<JobServiceClient>.Instance);

        var stats = await client.GetStatsOrNullAsync();

        Assert.Equal(expected, stats);
    }

    [Fact]
    public async Task GetStats_WhenAppSvcReturnsError_ReturnsUnavailableNull()
    {
        using var http = new HttpClient(new StubHandler(
            (_, _) => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)))
        {
            BaseAddress = new Uri("http://app-service/")
        };
        var client = new AppServiceClient(http, NullLogger<AppServiceClient>.Instance);

        var stats = await client.GetStatsOrNullAsync();

        Assert.Null(stats);
    }

    private sealed class StubHandler(
        Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(respond(request, cancellationToken));
    }
}
