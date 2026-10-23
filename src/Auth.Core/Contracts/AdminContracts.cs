using System.ComponentModel.DataAnnotations;

namespace Auth.Core.Contracts;

public record AdminUserListItemDto(
    Guid Id,
    string Email,
    string FullName,
    string Role,
    bool IsActive,
    Guid? CompanyId,
    DateTime CreatedAt,
    DateTime? LastLoginAt);

public record AdminUserDetailDto(
    Guid Id,
    string Email,
    string FullName,
    string Role,
    bool IsActive,
    Guid? CompanyId,
    DateTime CreatedAt,
    DateTime UpdatedAt,
    DateTime? LastLoginAt);

public record PaginationMeta(int Page, int PageSize, int TotalItems, int TotalPages);

public record PagedResponse<T>(IReadOnlyList<T> Data, PaginationMeta Pagination);

public record DeactivateUserRequest(
    [property: MaxLength(500)] string? Reason = null);
