using Auth.Core.Contracts;

namespace Auth.Core.Interfaces;

public interface IAppServiceClient
{
    Task<ApplicationStats?> GetStatsOrNullAsync(CancellationToken ct = default);
}
