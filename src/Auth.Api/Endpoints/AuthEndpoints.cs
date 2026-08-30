using System.ComponentModel.DataAnnotations;
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
            var validation = Validate(req);
            if (validation is not null) return validation;

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
                return Results.BadRequest(new Microsoft.AspNetCore.Mvc.ProblemDetails { Status = 400, Detail = result.Error });
            }

            var userId = result.Value!;
            // 201 Created with relative Location per RFC 9110 §10.2.2 — gateway compatible
            return TypedResults.Created($"/api/users/{userId}", new RegisterResponse(userId, "registered"));
        })
        .WithName("Register")
        .WithSummary("Register new user")
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
        .Produces<AuthResponse>(200)
        .Produces(401)
        .ProducesProblem(403);

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

        if (results.Count == 0) return null;

        var errors = results
            .GroupBy(r => r.MemberNames.FirstOrDefault() ?? "request")
            .ToDictionary(g => g.Key, g => g.Select(v => v.ErrorMessage ?? "Invalid").ToArray());
        return Results.ValidationProblem(errors);
    }
}
