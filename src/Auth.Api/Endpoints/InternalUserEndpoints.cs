using Auth.Api.Security;
using Auth.Core.Contracts;
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

        // Called by job-svc only, when an admin or support approves a join request (AUTH-01-12, AUTH-01-14).
        // Idempotent for the same Company; a different Company is refused.
        app.MapPost("/api/internal/users/{id:guid}/link-company", async (
            Guid id,
            LinkCompanyRequest body,
            HttpContext ctx,
            AuthDbContext db,
            IConfiguration config,
            ILoggerFactory loggerFactory,
            CancellationToken ct) =>
        {
            var logger = loggerFactory.CreateLogger("InternalUserEndpoints");
            var denied = InternalServiceAuth.Authorize(ctx, config, InternalServiceAuth.JobCallerTokenKey, logger);
            if (denied is not null)
                return denied;

            if (body.CompanyId == Guid.Empty)
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["CompanyId"] = ["CompanyId is required"] });

            // One conditional update: it applies only while the account has no Company, so two approvals cannot both win.
            var linked = await db.Users
                .Where(u => u.Id == id && u.CompanyId == null)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(u => u.CompanyId, body.CompanyId)
                    .SetProperty(u => u.Role, "Recruiter")
                    .SetProperty(u => u.UpdatedAt, DateTime.UtcNow), ct);
            if (linked == 1)
            {
                logger.LogInformation("AUDIT AuthEvent=CompanyLinked UserId={UserId} CompanyId={CompanyId}", id, body.CompanyId);
                return Results.NoContent();
            }

            var user = await db.Users.AsNoTracking()
                .Where(u => u.Id == id)
                .Select(u => new { u.CompanyId })
                .FirstOrDefaultAsync(ct);
            if (user is null)
                return Results.NotFound();
            if (user.CompanyId == body.CompanyId)
                return Results.NoContent();

            logger.LogWarning("AUDIT AuthEvent=CompanyLinkRefused UserId={UserId} CompanyId={CompanyId}", id, body.CompanyId);
            return Results.Problem(
                statusCode: 409,
                title: "Account already has a company",
                detail: CompanySignUpErrors.AccountAlreadyHasCompanyMessage,
                extensions: new Dictionary<string, object?> { ["errorCode"] = CompanySignUpErrors.AccountAlreadyHasCompanyCode });
        })
        .WithTags("Internal")
        .WithName("InternalLinkCompany")
        .ExcludeFromDescription();

        return app;
    }
}

/// <summary>Response of the internal user-email lookup.</summary>
public sealed record InternalUserEmailResponse(Guid UserId, string Email);

/// <summary>Body of the job-svc call that links an approved join request's user to its Company.</summary>
public sealed record LinkCompanyRequest(Guid CompanyId);
