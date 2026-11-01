using Auth.Core.Contracts;
using SharedKernel;

namespace Auth.Core.Interfaces;

public interface IAdminService
{
    Task<Result<PagedResponse<AdminUserListItemDto>>> GetUsersAsync(
        Guid actorUserId,
        int page,
        int size,
        string? role,
        bool? isActive,
        string? search,
        CancellationToken ct = default);

    Task<Result<AdminUserDetailDto>> GetUserAsync(
        Guid actorUserId,
        Guid id,
        CancellationToken ct = default);

    Task<Result> DeactivateUserAsync(
        Guid actorUserId,
        Guid targetUserId,
        string? reason,
        CancellationToken ct = default);

    Task<Result> ActivateUserAsync(
        Guid actorUserId,
        Guid targetUserId,
        CancellationToken ct = default);
}
