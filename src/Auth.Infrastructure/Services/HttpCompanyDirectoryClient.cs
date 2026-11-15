using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Auth.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

/// <summary>
/// job-svc company-directory client for company sign-up and verification (AUTH-01-10, AUTH-01-12). Uses a
/// dedicated HttpClient with auth-svc's per-caller token and no retry handler: the create calls are not
/// idempotent. Request bodies carry company names and tax codes, so they are never logged.
/// </summary>
public sealed class HttpCompanyDirectoryClient(HttpClient http, ILogger<HttpCompanyDirectoryClient> logger) : ICompanyDirectoryClient
{
    public async Task<Guid?> FindVerifiedCompanyIdAsync(string emailDomain, CancellationToken ct = default)
    {
        using var response = await SendAsync("api/internal/companies/domain-match", new { domain = emailDomain }, "domain-match", ct);
        var body = await ReadAsync<DomainMatchBody>(response, "domain-match", ct);
        return body.CompanyId;
    }

    public async Task<bool> IsAvailableAsync(string companyName, string? taxCode, CancellationToken ct = default)
    {
        using var response = await SendAsync("api/internal/companies/availability", new { companyName, taxCode }, "availability", ct);
        var body = await ReadAsync<AvailabilityBody>(response, "availability", ct);
        return body.Available;
    }

    public async Task<Guid> CreateCompanyAsync(string companyName, string? taxCode, Guid createdBy, string emailDomain, CancellationToken ct = default)
    {
        using var response = await SendAsync(
            "api/internal/companies",
            new { name = companyName, taxCode, createdBy, emailDomain },
            "create-company",
            ct);
        if (response.StatusCode == HttpStatusCode.Conflict)
            throw new CompanyAlreadyExistsException();
        var body = await ReadAsync<CreatedCompanyBody>(response, "create-company", ct);
        return body.CompanyId;
    }

    public async Task CreateJoinRequestAsync(Guid userId, Guid companyId, CancellationToken ct = default)
    {
        using var response = await SendAsync(
            "api/internal/company-join-requests",
            new { userId, companyId },
            "join-request",
            ct);
        if (!response.IsSuccessStatusCode)
            throw Unavailable("join-request", response.StatusCode);
    }

    private async Task<HttpResponseMessage> SendAsync(string path, object body, string operation, CancellationToken ct)
    {
        try
        {
            // No leading '/' per AGENTS.md outbound rules (RFC 3986 subpath).
            return await http.PostAsJsonAsync(path, body, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException || (ex is TaskCanceledException && !ct.IsCancellationRequested))
        {
            logger.LogWarning(ex, "Company directory {Operation} request failed", operation);
            throw new CompanyDirectoryUnavailableException($"job-svc company {operation} call failed", ex);
        }
    }

    private async Task<T> ReadAsync<T>(HttpResponseMessage response, string operation, CancellationToken ct) where T : class
    {
        if (!response.IsSuccessStatusCode)
            throw Unavailable(operation, response.StatusCode);
        try
        {
            return await response.Content.ReadFromJsonAsync<T>(ct)
                ?? throw new CompanyDirectoryUnavailableException($"job-svc company {operation} returned an empty body");
        }
        catch (Exception ex) when (ex is JsonException or HttpRequestException or NotSupportedException)
        {
            throw new CompanyDirectoryUnavailableException($"job-svc company {operation} returned an unreadable body", ex);
        }
    }

    private CompanyDirectoryUnavailableException Unavailable(string operation, HttpStatusCode status)
    {
        logger.LogWarning("Company directory {Operation} returned HTTP {StatusCode}", operation, (int)status);
        return new CompanyDirectoryUnavailableException($"job-svc company {operation} returned {(int)status}");
    }

    private sealed record DomainMatchBody(Guid? CompanyId);

    private sealed record AvailabilityBody(bool Available);

    private sealed record CreatedCompanyBody(Guid CompanyId);
}
