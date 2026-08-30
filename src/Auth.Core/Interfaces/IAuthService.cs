using Auth.Core.Contracts;
using SharedKernel;

namespace Auth.Core.Interfaces;

public interface IAuthService
{
    Task<Result<Guid>> RegisterAsync(RegisterRequest request, CancellationToken ct = default);
    Task<Result<AuthResponse>> LoginAsync(LoginRequest request, CancellationToken ct = default);
    Task<Result<AuthResponse>> RefreshAsync(string refreshToken, CancellationToken ct = default);
    Task<Result> LogoutAsync(Guid userId, string? refreshToken, CancellationToken ct = default);
    Task<Result<UserMeDto>> GetMeAsync(Guid userId, CancellationToken ct = default);
    Task<Result> ForgotPasswordAsync(ForgotPasswordRequest request, CancellationToken ct = default);
    Task<Result> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken ct = default);
}
