using System.Net.Http.Json;
using System.Text.Json;
using Auth.Core.Contracts;
using Auth.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

public sealed class JobServiceClient(
    HttpClient http,
    ILogger<JobServiceClient> logger) : IJobServiceClient
{
    public async Task<JobStats?> GetStatsOrNullAsync(CancellationToken ct = default)
    {
        try
        {
            using var response = await http.GetAsync("api/internal/stats", ct);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Job stats request returned HTTP {StatusCode}", response.StatusCode);
                return null;
            }

            return await response.Content.ReadFromJsonAsync<JobStats>(cancellationToken: ct);
        }
        catch (HttpRequestException ex)
        {
            logger.LogWarning(ex, "Job stats request failed");
            return null;
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            logger.LogWarning(ex, "Job stats request timed out");
            return null;
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "Job stats response was invalid");
            return null;
        }
    }
}
