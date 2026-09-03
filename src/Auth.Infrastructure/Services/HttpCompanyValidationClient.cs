using Auth.Core.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

public class HttpCompanyValidationClient : ICompanyValidationClient
{
    private readonly HttpClient _http;
    private readonly ILogger<HttpCompanyValidationClient> _logger;

    public HttpCompanyValidationClient(HttpClient http, ILogger<HttpCompanyValidationClient> logger, IConfiguration config)
    {
        _http = http;
        _logger = logger;
    }

    public async Task<bool> ExistsAsync(Guid companyId, CancellationToken ct = default)
    {
        try
        {
            var resp = await _http.GetAsync($"/api/companies/{companyId}", ct);
            if (resp.IsSuccessStatusCode) return true;
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound) return false;
            _logger.LogWarning("Company validation HTTP {Status} CompanyId {CompanyId}", resp.StatusCode, companyId);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Company validation failed CompanyId {CompanyId}", companyId);
            return false;
        }
    }
}
