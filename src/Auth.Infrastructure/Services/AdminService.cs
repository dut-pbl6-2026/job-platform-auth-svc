using System.Text.Json;
using Auth.Core.Contracts;
using Auth.Core.Entities;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SharedKernel;

namespace Auth.Infrastructure.Services;

public class AdminService : IAdminService
{
    private const string AdminRole = "Admin";
    private const string AdminAccessDenied = "Admin access required";
    private const int MaxReasonLength = 500;

    private readonly AuthDbContext _db;
    private readonly ILogger<AdminService> _logger;
    private readonly ITokenRevocationStore _revocationStore;

    public AdminService(
        AuthDbContext db,
        ILogger<AdminService> logger,
        ITokenRevocationStore revocationStore)
    {
        _db = db;
        _logger = logger;
        _revocationStore = revocationStore;
    }

    public async Task<Result<PagedResponse<AdminUserListItemDto>>> GetUsersAsync(
        Guid actorUserId,
        int page,
        int size,
        string? role,
        bool? isActive,
        string? search,
        CancellationToken ct = default)
    {
        if (!await IsActiveAdminAsync(actorUserId, ct))
            return Result<PagedResponse<AdminUserListItemDto>>.Failure(AdminAccessDenied);

        page = Math.Max(1, page);
        size = Math.Clamp(size, 1, 100);

        var query = _db.Users.AsNoTracking().AsQueryable();

        if (!string.IsNullOrWhiteSpace(role))
        {
            var roleFilter = role.Trim();
            query = query.Where(u => u.Role == roleFilter);
        }

        if (isActive.HasValue)
            query = query.Where(u => u.IsActive == isActive.Value);

        if (!string.IsNullOrWhiteSpace(search))
        {
            var pattern = $"%{EscapeLike(search.Trim())}%";
            query = query.Where(u =>
                EF.Functions.ILike(u.Email, pattern, "\\") ||
                EF.Functions.ILike(u.FullName, pattern, "\\"));
        }

        var totalItems = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(u => u.CreatedAt)
            .Skip((page - 1) * size)
            .Take(size)
            .Select(u => new AdminUserListItemDto(
                u.Id,
                u.Email,
                u.FullName,
                u.Role,
                u.IsActive,
                u.CompanyId,
                u.CreatedAt,
                u.LastLoginAt))
            .ToListAsync(ct);

        var totalPages = (int)Math.Ceiling(totalItems / (double)size);
        var response = new PagedResponse<AdminUserListItemDto>(
            items,
            new PaginationMeta(page, size, totalItems, totalPages));

        return Result<PagedResponse<AdminUserListItemDto>>.Success(response);
    }

    public async Task<Result<AdminUserDetailDto>> GetUserAsync(
        Guid actorUserId,
        Guid id,
        CancellationToken ct = default)
    {
        if (!await IsActiveAdminAsync(actorUserId, ct))
            return Result<AdminUserDetailDto>.Failure(AdminAccessDenied);

        var user = await _db.Users
            .AsNoTracking()
            .Where(u => u.Id == id)
            .Select(u => new AdminUserDetailDto(
                u.Id,
                u.Email,
                u.FullName,
                u.Role,
                u.IsActive,
                u.CompanyId,
                u.CreatedAt,
                u.UpdatedAt,
                u.LastLoginAt))
            .FirstOrDefaultAsync(ct);

        return user is null
            ? Result<AdminUserDetailDto>.Failure("User not found")
            : Result<AdminUserDetailDto>.Success(user);
    }

    public async Task<Result> DeactivateUserAsync(
        Guid actorUserId,
        Guid targetUserId,
        string? reason,
        CancellationToken ct = default)
    {
        if (!await IsActiveAdminAsync(actorUserId, ct))
            return Result.Failure(AdminAccessDenied);

        var normalizedReason = NormalizeReason(reason);
        if (!normalizedReason.IsSuccess)
            return Result.Failure(normalizedReason.Error!);

        var target = await _db.Users.FirstOrDefaultAsync(u => u.Id == targetUserId, ct);
        if (target is null)
            return Result.Failure("User not found");

        if (target.Id == actorUserId)
            return Result.Failure("Cannot deactivate your own account");

        if (target.Role == AdminRole)
            return Result.Failure("Cannot deactivate Admin accounts");

        try
        {
            await _revocationStore.RevokeUserTokensAsync(target.Id, DateTimeOffset.UtcNow, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revoke access tokens for user {TargetId}", target.Id);
            return Result.Failure("Unable to revoke user sessions");
        }

        target.Deactivate();

        var tokens = await _db.RefreshTokens
            .Where(t => t.UserId == target.Id && !t.IsRevoked)
            .ToListAsync(ct);
        foreach (var token in tokens)
            token.Revoke();

        var metadata = JsonSerializer.Serialize(new { revokedRefreshTokenCount = tokens.Count });
        _db.AuditLogs.Add(new AuditLog(
            actorUserId,
            "ADMIN_DEACTIVATE_USER",
            "User",
            target.Id,
            normalizedReason.Value,
            metadata));

        await _db.SaveChangesAsync(ct);
        _logger.LogInformation(
            "Admin {AdminId} {Action} user {TargetId}",
            actorUserId,
            "ADMIN_DEACTIVATE_USER",
            target.Id);

        return Result.Success();
    }

    public async Task<Result> ActivateUserAsync(
        Guid actorUserId,
        Guid targetUserId,
        CancellationToken ct = default)
    {
        if (!await IsActiveAdminAsync(actorUserId, ct))
            return Result.Failure(AdminAccessDenied);

        var target = await _db.Users.FirstOrDefaultAsync(u => u.Id == targetUserId, ct);
        if (target is null)
            return Result.Failure("User not found");

        var wasActive = target.IsActive;
        target.Activate();

        var metadata = JsonSerializer.Serialize(new { wasActive });
        _db.AuditLogs.Add(new AuditLog(
            actorUserId,
            "ADMIN_ACTIVATE_USER",
            "User",
            target.Id,
            metadata: metadata));

        await _db.SaveChangesAsync(ct);
        _logger.LogInformation(
            "Admin {AdminId} {Action} user {TargetId}",
            actorUserId,
            "ADMIN_ACTIVATE_USER",
            target.Id);

        return Result.Success();
    }

    private Task<bool> IsActiveAdminAsync(Guid userId, CancellationToken ct) =>
        _db.Users
            .AsNoTracking()
            .AnyAsync(u => u.Id == userId && u.IsActive && u.Role == AdminRole, ct);

    private static Result<string?> NormalizeReason(string? reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
            return Result<string?>.Success(null);

        var trimmed = reason.Trim();
        if (trimmed.Length > MaxReasonLength)
            return Result<string?>.Failure($"Reason must not exceed {MaxReasonLength} characters");
        if (trimmed.Any(char.IsControl))
            return Result<string?>.Failure("Reason must not contain control characters");

        return Result<string?>.Success(trimmed);
    }

    private static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
}
