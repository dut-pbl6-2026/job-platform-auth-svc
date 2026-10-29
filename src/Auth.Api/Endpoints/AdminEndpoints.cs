using Auth.Core.Contracts;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Auth.Api.Endpoints;

public static class AdminEndpoints
{
    public static IEndpointRouteBuilder MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/admin").WithTags("Admin");

        group.MapGet("/users", async (
            HttpContext ctx,
            IAdminService svc,
            int? page,
            int? size,
            string? role,
            bool? isActive,
            string? search,
            CancellationToken ct) =>
        {
            var denied = EnsureAdmin(ctx, out var adminId);
            if (denied is not null) return denied;

            var result = await svc.GetUsersAsync(adminId, page ?? 1, size ?? 20, role, isActive, search, ct);
            if (!result.IsSuccess)
                return MapFailure(result.Error);

            return Results.Ok(result.Value);
        })
        .WithName("AdminGetUsers")
        .WithSummary("List users with pagination and filters")
        .Produces<PagedResponse<AdminUserListItemDto>>(200)
        .ProducesProblem(401)
        .ProducesProblem(403);

        group.MapGet("/users/{id:guid}", async (
            HttpContext ctx,
            Guid id,
            IAdminService svc,
            CancellationToken ct) =>
        {
            var denied = EnsureAdmin(ctx, out var adminId);
            if (denied is not null) return denied;

            var result = await svc.GetUserAsync(adminId, id, ct);
            if (!result.IsSuccess)
                return MapFailure(result.Error);

            return Results.Ok(result.Value);
        })
        .WithName("AdminGetUser")
        .WithSummary("Get user detail")
        .Produces<AdminUserDetailDto>(200)
        .ProducesProblem(401)
        .ProducesProblem(403)
        .ProducesProblem(404);

        group.MapPatch("/users/{id:guid}/deactivate", async (
            HttpContext ctx,
            Guid id,
            DeactivateUserRequest req,
            IAdminService svc,
            CancellationToken ct) =>
        {
            var denied = EnsureAdmin(ctx, out var adminId);
            if (denied is not null) return denied;

            var result = await svc.DeactivateUserAsync(adminId, id, req.Reason, ct);
            return result.IsSuccess ? Results.NoContent() : MapFailure(result.Error);
        })
        .WithName("AdminDeactivateUser")
        .WithSummary("Deactivate a User/Recruiter account and revoke its sessions")
        .Accepts<DeactivateUserRequest>("application/json")
        .Produces(204)
        .ProducesProblem(400)
        .ProducesProblem(401)
        .ProducesProblem(403)
        .ProducesProblem(404)
        .ProducesProblem(422);

        group.MapPatch("/users/{id:guid}/activate", async (
            HttpContext ctx,
            Guid id,
            IAdminService svc,
            CancellationToken ct) =>
        {
            var denied = EnsureAdmin(ctx, out var adminId);
            if (denied is not null) return denied;

            var result = await svc.ActivateUserAsync(adminId, id, ct);
            return result.IsSuccess ? Results.NoContent() : MapFailure(result.Error);
        })
        .WithName("AdminActivateUser")
        .WithSummary("Activate a user account (idempotent)")
        .Produces(204)
        .ProducesProblem(401)
        .ProducesProblem(403)
        .ProducesProblem(404);

        group.MapGet("/stats", async (
            HttpContext ctx,
            AuthDbContext db,
            IJobServiceClient jobClient,
            IAppServiceClient appClient,
            CancellationToken ct) =>
        {
            var denied = EnsureAdmin(ctx, out _);
            if (denied is not null) return denied;

            var jobTask = jobClient.GetStatsOrNullAsync(ct);
            var appTask = appClient.GetStatsOrNullAsync(ct);
            await Task.WhenAll(jobTask, appTask);

            var now = DateTime.UtcNow;
            var monthStart = new DateTime(now.Year, now.Month, 1, 0, 0, 0, DateTimeKind.Utc);
            var users = db.Users.AsNoTracking();
            var byRole = await users
                .GroupBy(user => user.Role)
                .ToDictionaryAsync(grouping => grouping.Key, grouping => grouping.Count(), ct);

            var userStats = new StatsSection(
                Status: "ok",
                Total: await users.CountAsync(ct),
                Active: await users.CountAsync(user => user.IsActive, ct),
                Inactive: await users.CountAsync(user => !user.IsActive, ct),
                ByRole: byRole,
                NewThisMonth: await users.CountAsync(user => user.CreatedAt >= monthStart, ct));

            return Results.Ok(new AdminStatsResponse(
                Users: userStats,
                Jobs: ToJobStatsSection(jobTask.Result),
                Applications: ToApplicationStatsSection(appTask.Result)));
        })
        .WithName("AdminGetStats")
        .WithSummary("Get aggregate admin dashboard statistics")
        .Produces<AdminStatsResponse>(200)
        .ProducesProblem(401)
        .ProducesProblem(403);

        return app;
    }

    private static StatsSection ToJobStatsSection(JobStats? stats) =>
        stats is null
            ? new StatsSection("unavailable", null)
            : new StatsSection(
                Status: "ok",
                Total: stats.Total,
                Pending: stats.Pending,
                Active: stats.Active,
                Closed: stats.Closed,
                Rejected: stats.Rejected,
                NewThisMonth: stats.NewThisMonth);

    private static StatsSection ToApplicationStatsSection(ApplicationStats? stats) =>
        stats is null
            ? new StatsSection("unavailable", null)
            : new StatsSection(
                Status: "ok",
                Total: stats.Total,
                Pending: stats.Pending,
                Accepted: stats.Accepted,
                Rejected: stats.Rejected,
                NewThisMonth: stats.NewThisMonth);

    private static IResult? EnsureAdmin(HttpContext ctx, out Guid adminId)
    {
        adminId = Guid.Empty;

        if (!string.Equals(
                ctx.Request.Headers["X-User-Role"].ToString(),
                "Admin",
                StringComparison.OrdinalIgnoreCase))
        {
            return Results.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                title: "Forbidden",
                detail: "Admin role required");
        }

        if (!Guid.TryParse(ctx.Request.Headers["X-User-Id"].ToString(), out adminId))
            return Results.Unauthorized();

        return null;
    }

    private static IResult MapFailure(string? error)
    {
        var statusCode = error switch
        {
            "User not found" => StatusCodes.Status404NotFound,
            "Cannot deactivate your own account" => StatusCodes.Status403Forbidden,
            "Cannot deactivate Admin accounts" => StatusCodes.Status403Forbidden,
            "Admin access required" => StatusCodes.Status403Forbidden,
            "Unable to revoke user sessions" => StatusCodes.Status503ServiceUnavailable,
            _ when error is not null && error.StartsWith("Reason", StringComparison.Ordinal)
                => StatusCodes.Status422UnprocessableEntity,
            _ => StatusCodes.Status400BadRequest
        };

        return Results.Problem(statusCode: statusCode, detail: error);
    }
}
