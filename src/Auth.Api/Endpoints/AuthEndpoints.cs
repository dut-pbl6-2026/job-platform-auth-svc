using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Auth.Core.Contracts;
using Auth.Core.Interfaces;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Auth.Api.Endpoints;

/// <summary>
/// Auth endpoints — validation is performed explicitly via <see cref="Validator.TryValidateObject"/>
/// to ensure portable, dependency-free execution on Minimal API.
/// This avoids reliance on <c>WithParameterValidation()</c> which fluctuates across .NET 10 preview ref packs
/// and requires extra <c>Microsoft.AspNetCore.OpenApi</c> surface; the centralized <see cref="Validate{T}"/>
/// helper also handles trim/whitespace edge cases (e.g., "   " bypassing [Required]) without custom attributes.
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
            if (!string.IsNullOrWhiteSpace(req.CompanyName))
                return Results.Problem(statusCode: 400, detail: "companyName is deprecated. Please create company first and use companyId.");

            var validation = Validate(req);
            if (validation is not null) return validation;

            if (req.CompanyId.HasValue && req.CompanyId.Value == Guid.Empty)
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["CompanyId"] = ["Invalid companyId"] });

            var result = await svc.RegisterAsync(req, ct);
            if (!result.IsSuccess)
            {
                if (result.Error == "Email exists")
                    return Results.Conflict(new Microsoft.AspNetCore.Mvc.ProblemDetails
                    {
                        Status = 409,
                        Title = "Email exists",
                        Detail = "Email already registered"
                    });
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

            var userId = result.Value!;
            // 201 Created with relative Location per RFC 9110 §10.2.2 — gateway compatible
            return TypedResults.Created($"/api/users/{userId}", new RegisterResponse(userId, "registered"));
        })
        .WithName("Register")
        .WithSummary("Register new user")
        .RequireRateLimiting("global")
        .Produces<RegisterResponse>(201)
        .ProducesValidationProblem()
        .ProducesProblem(409);

        group.MapPost("/login", async (
            LoginRequest req,
            IAuthService svc,
            CancellationToken ct) =>
        {
            var validation = Validate(req);
            if (validation is not null) return validation;

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
        .RequireRateLimiting("global")
        .Produces<AuthResponse>(200)
        .Produces(401)
        .ProducesProblem(403);

        group.MapPost("/refresh", async (
            RefreshRequest req,
            IAuthService svc,
            CancellationToken ct) =>
        {
            var validation = Validate(req);
            if (validation is not null) return validation;

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
        .RequireRateLimiting("global")
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
            var validation = Validate(req);
            if (validation is not null) return validation;

            await svc.ForgotPasswordAsync(req, ct);
            // Always 200 anti-enumeration per SRS AUTH-01-07
            return Results.Ok(new { message = "If email exists, reset link sent" });
        })
        .WithName("ForgotPassword")
        .WithSummary("Request password reset (anti-enumeration, 15m TTL, 5/IP/h)")
        .RequireRateLimiting("forgot")
        .Produces(200)
        .ProducesValidationProblem();

        group.MapPost("/reset-password", async (
            ResetPasswordRequest req,
            IAuthService svc,
            CancellationToken ct) =>
        {
            var validation = Validate(req);
            if (validation is not null) return validation;

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
        .Produces(200)
        .Produces(401)
        .ProducesValidationProblem();

        return app;
    }

    /// <summary>
    /// Centralized DataAnnotations validation via <see cref="Validator.TryValidateObject"/> + whitespace guard.
    /// Returns standardized <see cref="Results.ValidationProblem"/> with field-level errors; null if valid.
    /// Keeps Minimal API endpoints portable across .NET 10 preview SDKs without WithParameterValidation.
    /// </summary>
    private static IResult? Validate<T>(T req)
    {
        var results = new List<ValidationResult>();
        var ctx = new ValidationContext(req!);
        Validator.TryValidateObject(req!, ctx, results, true);

        // DataAnnotations [Required] allows whitespace; enforce non-whitespace for key fields
        if (req is RegisterRequest rr)
        {
            if (string.IsNullOrWhiteSpace(rr.FullName))
                results.Add(new ValidationResult("FullName is required", ["FullName"]));
            if (string.IsNullOrWhiteSpace(rr.Email))
                results.Add(new ValidationResult("Email is required", ["Email"]));
            if (string.IsNullOrWhiteSpace(rr.Password))
                results.Add(new ValidationResult("Password is required", ["Password"]));
        }
        else if (req is LoginRequest lr)
        {
            if (string.IsNullOrWhiteSpace(lr.Email))
                results.Add(new ValidationResult("Email is required", ["Email"]));
            if (string.IsNullOrWhiteSpace(lr.Password))
                results.Add(new ValidationResult("Password is required", ["Password"]));
        }
        else if (req is RefreshRequest rr2)
        {
            if (string.IsNullOrWhiteSpace(rr2.RefreshToken))
                results.Add(new ValidationResult("RefreshToken is required", ["RefreshToken"]));
        }
        else if (req is ForgotPasswordRequest fr)
        {
            if (string.IsNullOrWhiteSpace(fr.Email))
                results.Add(new ValidationResult("Email is required", ["Email"]));
        }
        else if (req is ResetPasswordRequest rp)
        {
            if (string.IsNullOrWhiteSpace(rp.Token))
                results.Add(new ValidationResult("Token is required", ["Token"]));
            if (string.IsNullOrWhiteSpace(rp.NewPassword))
                results.Add(new ValidationResult("NewPassword is required", ["NewPassword"]));
        }

        if (results.Count == 0) return null;

        var errors = results
            .GroupBy(r => r.MemberNames.FirstOrDefault() ?? "request")
            .ToDictionary(g => g.Key, g => g.Select(v => v.ErrorMessage ?? "Invalid").ToArray());
        return Results.ValidationProblem(errors);
    }
}
