using Auth.Core.Contracts;

namespace Auth.Core.Interfaces;

public interface IJobServiceClient
{
    Task<JobStats?> GetStatsOrNullAsync(CancellationToken ct = default);
}
