using System.Security.Claims;
using Auth.Api.Filters;
using Auth.Core.Contracts;
using Auth.Api.RateLimiting;
using Auth.Core.Interfaces;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Auth.Api.Endpoints;

/// <summary>
/// Auth endpoints — request validation via generic <see cref="ValidationFilter{T}"/>
/// endpoint filter (DataAnnotations on DTOs + <c>NonWhitespace</c> for blank strings).
/// </summary>
public static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/auth").WithTags("Auth");

        group.MapPost("/register", async (
            RegisterRequest req,
            IAuthService svc,
            CancellationToken ct) =>
        {
            if (req.CompanyId.HasValue && req.CompanyId.Value == Guid.Empty)
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["CompanyId"] = ["Invalid companyId"] });

            var result = await svc.RegisterAsync(req, ct);
            if (!result.IsSuccess)
            {
                if (result.Error is not null && result.Error.Contains("Password"))
                    return Results.ValidationProblem(new Dictionary<string, string[]> { ["Password"] = [result.Error] });
                if (result.Error == "Invalid role")
                    return Results.ValidationProblem(new Dictionary<string, string[]> { ["Role"] = [result.Error] });
                if (result.Error == "Invalid companyId")
                    return Results.Problem(statusCode: 422, detail: result.Error);
                if (result.Error == "companyId required for Recruiter")
                    return Results.ValidationProblem(new Dictionary<string, string[]> { ["CompanyId"] = [result.Error] });
                return Results.BadRequest(new Microsoft.AspNetCore.Mvc.ProblemDetails { Status = 400, Detail = result.Error });
            }

            // Same 202 whether or not the email is already registered (no account enumeration).
            return Results.Accepted(value: new RegisterResponse("Check your email to verify your account."));
        })
        .WithName("Register")
        .WithSummary("Register new user; the account stays pending until the emailed link is verified")
        .AddEndpointFilter<ValidationFilter<RegisterRequest>>()
        .WithMetadata(IpRateLimitPolicy.Register)
        .Produces<RegisterResponse>(202)
        .ProducesValidationProblem();

        group.MapPost("/verify-email", async (
            VerifyEmailRequest req,
            IAuthService svc,
            CancellationToken ct) =>
        {
            var result = await svc.VerifyEmailAsync(req.Token, ct);
            if (!result.IsSuccess)
                return Results.Problem(statusCode: 400, detail: result.Error);

            return Results.Ok(new { message = "Email verified. You can now log in." });
        })
        .WithName("VerifyEmail")
        .WithSummary("Activate a pending account with the emailed one-time link token (24h)")
        .AddEndpointFilter<ValidationFilter<VerifyEmailRequest>>()
        .WithMetadata(IpRateLimitPolicy.Verify)
        .Produces(200)
        .ProducesProblem(400)
        .ProducesValidationProblem();

        group.MapPost("/resend-verification", async (
            ResendVerificationRequest req,
            IAuthService svc,
            CancellationToken ct) =>
        {
            await svc.ResendVerificationAsync(req, ct);
            // Same 202 for unknown, verified and unverified emails: verification state is never revealed.
            return Results.Accepted(value: new ResendVerificationResponse("If this email is awaiting verification, a new link was sent."));
        })
        .WithName("ResendVerification")
        .WithSummary("Queue a new verification link for an unverified account (anti-enumeration, 24h TTL, 5/IP/h)")
        .AddEndpointFilter<ValidationFilter<ResendVerificationRequest>>()
        .WithMetadata(IpRateLimitPolicy.ResendVerification)
        .Produces<ResendVerificationResponse>(202)
        .ProducesValidationProblem();

        group.MapPost("/login", async (
            LoginRequest req,
            IAuthService svc,
            CancellationToken ct) =>
        {
            var result = await svc.LoginAsync(req, ct);
            if (!result.IsSuccess)
            {
                if (result.Error == "Invalid credentials")
                    return Results.Unauthorized();
                if (result.Error == "Account inactive")
                    return Results.Problem(statusCode: 403, detail: "Account inactive");
                return Results.BadRequest(new Microsoft.AspNetCore.Mvc.ProblemDetails { Status = 400, Detail = result.Error });
            }

            return Results.Ok(result.Value!);
        })
        .WithName("Login")
        .WithSummary("Login and issue JWT")
        .AddEndpointFilter<ValidationFilter<LoginRequest>>()
        .WithMetadata(IpRateLimitPolicy.Login)
        .Produces<AuthResponse>(200)
        .Produces(401)
        .ProducesProblem(403);

        group.MapPost("/refresh", async (
            RefreshRequest req,
            IAuthService svc,
            CancellationToken ct) =>
        {
            var result = await svc.RefreshAsync(req.RefreshToken, ct);
            if (!result.IsSuccess)
            {
                if (result.Error == "Refresh token revoked" || result.Error == "Invalid refresh token")
                    return Results.Unauthorized();
                if (result.Error == "Refresh token expired")
                    return Results.Problem(statusCode: 401, detail: "Refresh token expired");
                if (result.Error == "User not found")
                    return Results.Problem(statusCode: 404, detail: "User not found");
                return Results.BadRequest(new Microsoft.AspNetCore.Mvc.ProblemDetails { Status = 400, Detail = result.Error });
            }

            return Results.Ok(result.Value!);
        })
        .WithName("Refresh")
        .WithSummary("Rotate refresh token (family-scoped reuse detection)")
        .AddEndpointFilter<ValidationFilter<RefreshRequest>>()
        .WithMetadata(IpRateLimitPolicy.Refresh)
        .Produces<AuthResponse>(200)
        .Produces(401);

        group.MapPost("/logout", async (
            ClaimsPrincipal user,
            LogoutRequest? req,
            IAuthService svc,
            CancellationToken ct) =>
        {
            var sub = user.FindFirstValue(ClaimTypes.NameIdentifier) ?? user.FindFirstValue("sub");
            if (sub == null || !Guid.TryParse(sub, out var userId))
                return Results.Unauthorized();

            var result = await svc.LogoutAsync(userId, req?.RefreshToken, ct);
            if (!result.IsSuccess)
                return Results.BadRequest(new Microsoft.AspNetCore.Mvc.ProblemDetails { Status = 400, Detail = result.Error });

            return Results.NoContent();
        })
        .RequireAuthorization()
        .WithName("Logout")
        .WithSummary("Revoke refresh token(s)")
        .AddEndpointFilter<ValidationFilter<LogoutRequest>>()
        .Produces(204)
        .Produces(401);

        group.MapGet("/me", async (
            ClaimsPrincipal user,
            IAuthService svc,
            CancellationToken ct) =>
        {
            var sub = user.FindFirstValue(ClaimTypes.NameIdentifier) ?? user.FindFirstValue("sub");
            if (sub == null || !Guid.TryParse(sub, out var userId))
                return Results.Unauthorized();

            var result = await svc.GetMeAsync(userId, ct);
            if (!result.IsSuccess)
                return Results.Problem(statusCode: 404, detail: result.Error);

            return Results.Ok(result.Value!);
        })
        .RequireAuthorization()
        .WithName("Me")
        .WithSummary("Get current user")
        .Produces<UserMeDto>(200)
        .Produces(401)
        .ProducesProblem(404);

        group.MapPost("/forgot-password", async (
            ForgotPasswordRequest req,
            IAuthService svc,
            CancellationToken ct) =>
        {
            await svc.ForgotPasswordAsync(req, ct);
            // Always 200 anti-enumeration per SRS AUTH-01-07
            return Results.Ok(new { message = "If email exists, reset link sent" });
        })
        .WithName("ForgotPassword")
        .WithSummary("Request password reset (anti-enumeration, 15m TTL, 5/IP/h)")
        .AddEndpointFilter<ValidationFilter<ForgotPasswordRequest>>()
        .WithMetadata(IpRateLimitPolicy.Forgot)
        .Produces(200)
        .ProducesValidationProblem();

        group.MapPost("/reset-password", async (
            ResetPasswordRequest req,
            IAuthService svc,
            CancellationToken ct) =>
        {
            var result = await svc.ResetPasswordAsync(req, ct);
            if (!result.IsSuccess)
            {
                if (result.Error == "Invalid or expired token")
                    return Results.Problem(statusCode: 401, detail: result.Error);
                if (result.Error is not null && result.Error.Contains("Password"))
                    return Results.ValidationProblem(new Dictionary<string, string[]> { ["NewPassword"] = [result.Error] });
                return Results.BadRequest(new Microsoft.AspNetCore.Mvc.ProblemDetails { Status = 400, Detail = result.Error });
            }

            return Results.Ok(new { message = "Password reset successful. Please login." });
        })
        .WithName("ResetPassword")
        .WithSummary("Reset password (single-use 15m, revokes all refresh tokens)")
        .AddEndpointFilter<ValidationFilter<ResetPasswordRequest>>()
        .WithMetadata(IpRateLimitPolicy.Reset)
        .Produces(200)
        .Produces(401)
        .ProducesValidationProblem();

        return app;
    }
}
