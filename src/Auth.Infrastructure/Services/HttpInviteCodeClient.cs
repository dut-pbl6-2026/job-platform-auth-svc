using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Auth.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

/// <summary>
/// job-svc invite-code client. Uses a dedicated HttpClient with auth-svc's per-caller token
/// (JOB_INTERNAL_TOKEN_FOR_AUTH). No retry handler: redeem is not idempotent, and a retry after
/// a lost response would report a valid code as used.
/// </summary>
public sealed class HttpInviteCodeClient(HttpClient http, ILogger<HttpInviteCodeClient> logger) : IInviteCodeClient
{
    private const string CheckPath = "api/internal/invite-codes/check";
    private const string RedeemPath = "api/internal/invite-codes/redeem";

    public async Task<InviteCodeCheckResult?> CheckAsync(string code, CancellationToken ct = default)
    {
        var response = await PostCodeAsync(CheckPath, code, ct);
        if (response.StatusCode == HttpStatusCode.UnprocessableEntity)
            return null;
        var body = await ReadOrThrowAsync<CheckBody>(response, "check", ct);
        return new InviteCodeCheckResult(body.CompanyId, body.CompanyName);
    }

    public async Task<InviteCodeRedeemResult?> RedeemAsync(string code, CancellationToken ct = default)
    {
        var response = await PostCodeAsync(RedeemPath, code, ct);
        if (response.StatusCode == HttpStatusCode.UnprocessableEntity)
            return null;
        var body = await ReadOrThrowAsync<RedeemBody>(response, "redeem", ct);
        return new InviteCodeRedeemResult(body.InviteCodeId, body.CompanyId);
    }

    public async Task<bool> ReleaseAsync(Guid inviteCodeId, CancellationToken ct = default)
    {
        try
        {
            using var response = await http.PostAsync($"api/internal/invite-codes/{inviteCodeId}/release", null, ct);
            if (response.IsSuccessStatusCode)
                return true;
            logger.LogError("Invite code release returned HTTP {StatusCode} InviteCodeId {InviteCodeId}", response.StatusCode, inviteCodeId);
            return false;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            logger.LogError(ex, "Invite code release failed InviteCodeId {InviteCodeId}", inviteCodeId);
            return false;
        }
    }

    private async Task<HttpResponseMessage> PostCodeAsync(string path, string code, CancellationToken ct)
    {
        try
        {
            // No leading '/' per AGENTS.md outbound rules (RFC 3986 subpath).
            return await http.PostAsJsonAsync(path, new { code }, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            logger.LogWarning(ex, "Invite code {Path} request failed", path);
            throw new InviteCodeServiceUnavailableException("job-svc invite-code call failed", ex);
        }
    }

    private async Task<T> ReadOrThrowAsync<T>(HttpResponseMessage response, string operation, CancellationToken ct) where T : class
    {
        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Invite code {Operation} returned HTTP {StatusCode}", operation, response.StatusCode);
                throw new InviteCodeServiceUnavailableException($"job-svc invite-code {operation} returned {(int)response.StatusCode}");
            }
            try
            {
                var body = await response.Content.ReadFromJsonAsync<T>(ct);
                return body ?? throw new InviteCodeServiceUnavailableException($"job-svc invite-code {operation} returned an empty body");
            }
            catch (Exception ex) when (ex is JsonException or HttpRequestException)
            {
                throw new InviteCodeServiceUnavailableException($"job-svc invite-code {operation} returned an unreadable body", ex);
            }
        }
    }

    private sealed record CheckBody(Guid CompanyId, string CompanyName);

    private sealed record RedeemBody(Guid InviteCodeId, Guid CompanyId);
}
