using Auth.Api.Security;
using Auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Auth.Api.Endpoints;

/// <summary>
/// Service-to-service lookups. Not routed through the gateway (gateway only forwards
/// <c>/api/auth/*</c> and <c>/api/admin/*</c>); callers must present the internal service token.
/// </summary>
public static class InternalUserEndpoints
{
    public static IEndpointRouteBuilder MapInternalUserEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/internal/users/{id:guid}/email", async (
            Guid id,
            HttpContext ctx,
            AuthDbContext db,
            IConfiguration config,
            ILoggerFactory loggerFactory,
            CancellationToken ct) =>
        {
            // Token is checked before the lookup, so unauthenticated callers learn nothing about ids.
            var denied = InternalServiceAuth.Authorize(
                ctx, config, InternalServiceAuth.NotifCallerTokenKey, loggerFactory.CreateLogger("InternalUserEndpoints"));
            if (denied is not null)
                return denied;

            var user = await db.Users.AsNoTracking()
                .Where(u => u.Id == id)
                .Select(u => new InternalUserEmailResponse(u.Id, u.Email))
                .FirstOrDefaultAsync(ct);

            return user is null ? Results.NotFound() : Results.Ok(user);
        })
        .WithTags("Internal")
        .WithName("InternalGetUserEmail")
        .ExcludeFromDescription();

        return app;
    }
}

/// <summary>Response of the internal user-email lookup.</summary>
public sealed record InternalUserEmailResponse(Guid UserId, string Email);
