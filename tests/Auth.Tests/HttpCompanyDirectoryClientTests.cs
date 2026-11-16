using System.Net;
using System.Text;
using System.Text.Json;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;

namespace Auth.Tests;

/// <summary>Status and transport mapping of the job-svc company-directory client (AUTH-01-10, AUTH-01-12).</summary>
public class HttpCompanyDirectoryClientTests
{
    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<string> Paths { get; } = new();
        public List<string> Bodies { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Paths.Add(request.RequestUri!.AbsolutePath);
            Bodies.Add(request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct));
            return respond(request);
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static HttpCompanyDirectoryClient Client(StubHandler handler)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri("http://localhost:5002/") };
        return new HttpCompanyDirectoryClient(http, NullLogger<HttpCompanyDirectoryClient>.Instance);
    }

    [Fact]
    public async Task DomainMatch_NoCompany_ReturnsNull_OnTheDomainMatchPath()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """{"companyId":null}"""));

        Assert.Null(await Client(handler).FindVerifiedCompanyIdAsync("acme.example"));
        Assert.Equal("/api/internal/companies/domain-match", handler.Paths.Single());
        Assert.Equal("acme.example", JsonDocument.Parse(handler.Bodies.Single()).RootElement.GetProperty("domain").GetString());
    }

    [Fact]
    public async Task DomainMatch_ReturnsTheVerifiedCompany()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """{"companyId":"11111111-1111-1111-1111-111111111111"}"""));

        Assert.Equal(Guid.Parse("11111111-1111-1111-1111-111111111111"), await Client(handler).FindVerifiedCompanyIdAsync("acme.example"));
    }

    [Fact]
    public async Task Availability_SendsNameAndTaxCode_AndReadsTheAnswer()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """{"available":false}"""));

        Assert.False(await Client(handler).IsAvailableAsync("Acme Labs", "0101234567"));
        Assert.Equal("/api/internal/companies/availability", handler.Paths.Single());
        var body = JsonDocument.Parse(handler.Bodies.Single()).RootElement;
        Assert.Equal("Acme Labs", body.GetProperty("companyName").GetString());
        Assert.Equal("0101234567", body.GetProperty("taxCode").GetString());
    }

    [Fact]
    public async Task CreateCompany_201_ReturnsTheNewId_AndSendsTheAdminAndDomain()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.Created, """{"companyId":"22222222-2222-2222-2222-222222222222"}"""));
        var admin = Guid.NewGuid();

        var id = await Client(handler).CreateCompanyAsync("Acme Labs", null, admin, "acme.example");

        Assert.Equal(Guid.Parse("22222222-2222-2222-2222-222222222222"), id);
        Assert.Equal("/api/internal/companies", handler.Paths.Single());
        var body = JsonDocument.Parse(handler.Bodies.Single()).RootElement;
        Assert.Equal(admin, body.GetProperty("createdBy").GetGuid());
        Assert.Equal("acme.example", body.GetProperty("emailDomain").GetString());
        Assert.Equal("Acme Labs", body.GetProperty("name").GetString());
    }

    [Fact]
    public async Task CreateCompany_409_IsAlreadyExists()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.Conflict, "{}"));

        await Assert.ThrowsAsync<CompanyAlreadyExistsException>(() =>
            Client(handler).CreateCompanyAsync("Acme Labs", null, Guid.NewGuid(), "acme.example"));
    }

    [Fact]
    public async Task CreateCompany_201WithoutCompanyId_IsUnavailable_NotAnEmptyLink()
    {
        // job-svc once answered `{ "id": ... }`: binding that into CreatedCompanyBody left Guid.Empty and
        // linked the founder to no company. A 2xx without a usable id must fail the verification instead.
        var handler = new StubHandler(_ => Json(HttpStatusCode.Created, """{"id":"22222222-2222-2222-2222-222222222222"}"""));
        var handlerEmpty = new StubHandler(_ => Json(HttpStatusCode.Created, """{"companyId":"00000000-0000-0000-0000-000000000000"}"""));

        await Assert.ThrowsAsync<CompanyDirectoryUnavailableException>(() =>
            Client(handler).CreateCompanyAsync("Acme Labs", null, Guid.NewGuid(), "acme.example"));
        await Assert.ThrowsAsync<CompanyDirectoryUnavailableException>(() =>
            Client(handlerEmpty).CreateCompanyAsync("Acme Labs", null, Guid.NewGuid(), "acme.example"));
    }

    [Fact]
    public async Task CreateCompany_500_IsUnavailable_NotAlreadyExists()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));

        await Assert.ThrowsAsync<CompanyDirectoryUnavailableException>(() =>
            Client(handler).CreateCompanyAsync("Acme Labs", null, Guid.NewGuid(), "acme.example"));
    }

    [Fact]
    public async Task Lookup_404_IsUnavailable_NeverReadAsNoMatch()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));

        await Assert.ThrowsAsync<CompanyDirectoryUnavailableException>(() => Client(handler).FindVerifiedCompanyIdAsync("acme.example"));
    }

    [Fact]
    public async Task Lookup_TransportFailure_IsUnavailable()
    {
        var handler = new StubHandler(_ => throw new HttpRequestException("connection refused"));

        await Assert.ThrowsAsync<CompanyDirectoryUnavailableException>(() => Client(handler).IsAvailableAsync("Acme", null));
    }

    [Fact]
    public async Task Lookup_UnreadableBody_IsUnavailable()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, "not json"));

        await Assert.ThrowsAsync<CompanyDirectoryUnavailableException>(() => Client(handler).IsAvailableAsync("Acme", null));
    }

    [Fact]
    public async Task JoinRequest_201_Succeeds_OnTheJoinRequestPath()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.Created, """{"joinRequestId":"33333333-3333-3333-3333-333333333333","expiresAt":"2026-11-22T00:00:00Z"}"""));

        await Client(handler).CreateJoinRequestAsync(Guid.NewGuid(), Guid.NewGuid());

        Assert.Equal("/api/internal/company-join-requests", handler.Paths.Single());
    }

    [Fact]
    public async Task JoinRequest_500_IsUnavailable()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));

        await Assert.ThrowsAsync<CompanyDirectoryUnavailableException>(() => Client(handler).CreateJoinRequestAsync(Guid.NewGuid(), Guid.NewGuid()));
    }
}
