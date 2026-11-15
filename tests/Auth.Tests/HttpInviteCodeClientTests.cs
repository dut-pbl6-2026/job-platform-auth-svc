using System.Net;
using System.Text;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;

namespace Auth.Tests;

/// <summary>Status mapping of the job-svc invite-code client (SRS AUTH-01-09).</summary>
public class HttpInviteCodeClientTests
{
    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<string> Paths { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Paths.Add(request.RequestUri!.AbsolutePath);
            return Task.FromResult(respond(request));
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static HttpInviteCodeClient Client(StubHandler handler)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri("http://localhost:5002/") };
        return new HttpInviteCodeClient(http, NullLogger<HttpInviteCodeClient>.Instance);
    }

    [Fact]
    public async Task Check_200_ReturnsCompany_OnInternalPath()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """{"companyId":"11111111-1111-1111-1111-111111111111","companyName":"Acme"}"""));
        var result = await Client(handler).CheckAsync("ABCDEFGHJKLM");

        Assert.NotNull(result);
        Assert.Equal("Acme", result!.CompanyName);
        Assert.Equal("/api/internal/invite-codes/check", handler.Paths.Single());
    }

    [Fact]
    public async Task Check_422_IsInvalidNotAnError()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.UnprocessableEntity, """{"errorCode":"INVITE_CODE_INVALID"}"""));
        Assert.Null(await Client(handler).CheckAsync("ABCDEFGHJKLM"));
    }

    [Fact]
    public async Task Check_500_ThrowsUnavailable()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        await Assert.ThrowsAsync<InviteCodeServiceUnavailableException>(() => Client(handler).CheckAsync("ABCDEFGHJKLM"));
    }

    [Fact]
    public async Task Check_TransportFailure_ThrowsUnavailable()
    {
        var handler = new StubHandler(_ => throw new HttpRequestException("connection refused"));
        await Assert.ThrowsAsync<InviteCodeServiceUnavailableException>(() => Client(handler).CheckAsync("ABCDEFGHJKLM"));
    }

    [Fact]
    public async Task Redeem_200_ReturnsIdAndCompany()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, """{"inviteCodeId":"22222222-2222-2222-2222-222222222222","companyId":"11111111-1111-1111-1111-111111111111"}"""));
        var result = await Client(handler).RedeemAsync("ABCDEFGHJKLM");

        Assert.Equal(Guid.Parse("22222222-2222-2222-2222-222222222222"), result!.InviteCodeId);
        Assert.Equal("/api/internal/invite-codes/redeem", handler.Paths.Single());
    }

    [Fact]
    public async Task Redeem_422_IsInvalid()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.UnprocessableEntity, "{}"));
        Assert.Null(await Client(handler).RedeemAsync("ABCDEFGHJKLM"));
    }

    [Fact]
    public async Task Redeem_UnreadableBody_ThrowsUnavailable()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK, "not json"));
        await Assert.ThrowsAsync<InviteCodeServiceUnavailableException>(() => Client(handler).RedeemAsync("ABCDEFGHJKLM"));
    }

    [Fact]
    public async Task Release_Success_ReturnsTrue_OnReleasePath()
    {
        var id = Guid.NewGuid();
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.NoContent));
        Assert.True(await Client(handler).ReleaseAsync(id));
        Assert.Equal($"/api/internal/invite-codes/{id}/release", handler.Paths.Single());
    }

    [Fact]
    public async Task Release_Failure_ReturnsFalse_AndNeverThrows()
    {
        var failing = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var throwing = new StubHandler(_ => throw new HttpRequestException("down"));
        Assert.False(await Client(failing).ReleaseAsync(Guid.NewGuid()));
        Assert.False(await Client(throwing).ReleaseAsync(Guid.NewGuid()));
    }
}
