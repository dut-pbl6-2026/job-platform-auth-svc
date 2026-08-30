using Auth.Core.Contracts;
using SharedKernel;

namespace Auth.Core.Interfaces;

public interface IAuthService
{
    Task<Result<Guid>> RegisterAsync(RegisterRequest request, CancellationToken ct = default);
    Task<Result<AuthResponse>> LoginAsync(LoginRequest request, CancellationToken ct = default);
}
