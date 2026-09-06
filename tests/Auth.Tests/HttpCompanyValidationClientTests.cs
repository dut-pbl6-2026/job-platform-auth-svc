using System.Net;
using Auth.Infrastructure.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Auth.Tests;

public class HttpCompanyValidationClientTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;

        public int CallCount { get; private set; }

        public HttpRequestMessage? LastRequest { get; private set; }

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            CallCount++;
            LastRequest = request;
            return Task.FromResult(_respond(request));
        }
    }

    private static HttpCompanyValidationClient CreateClient(StubHandler handler, string? baseAddress = "http://localhost:5002/")
    {
        var http = new HttpClient(handler);
        if (baseAddress is not null)
            http.BaseAddress = new Uri(baseAddress);
        var config = new ConfigurationBuilder().Build();
        return new HttpCompanyValidationClient(http, NullLogger<HttpCompanyValidationClient>.Instance, config);
    }

    [Fact]
    public async Task Exists_200_ReturnsTrue()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var client = CreateClient(handler);
        Assert.True(await client.ExistsAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task Exists_404_ReturnsFalse()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        var client = CreateClient(handler);
        Assert.False(await client.ExistsAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task Exists_500_ReturnsFalse_FailClosed()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var client = CreateClient(handler);
        Assert.False(await client.ExistsAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task Exists_HandlerThrows_ReturnsFalse()
    {
        var handler = new StubHandler(_ => throw new HttpRequestException("connection refused"));
        var client = CreateClient(handler);
        Assert.False(await client.ExistsAsync(Guid.NewGuid()));
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task RelativePath_PreservesBaseAddressSubpath()
    {
        // Regression test for RFC 3986 resolution: a leading '/' in the
        // relative path would discard the "/job-svc" subpath of BaseAddress.
        var id = Guid.NewGuid();
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var client = CreateClient(handler, "http://gateway/job-svc/");
        Assert.True(await client.ExistsAsync(id));
        Assert.Equal($"http://gateway/job-svc/api/companies/{id}", handler.LastRequest?.RequestUri?.ToString());
    }

    [Fact]
    public void MissingBaseAddress_Throws()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        Assert.Throws<ArgumentNullException>(() => CreateClient(handler, baseAddress: null));
    }
}
