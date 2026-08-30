using Auth.Core.Contracts;
using Auth.Core.Interfaces;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Auth.Api.Endpoints;

public static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/auth").WithTags("Auth");

        group.MapPost("/register", async (
            RegisterRequest req,
            IAuthService svc,
            ILoggerFactory lf,
            CancellationToken ct) =>
        {
            // Basic DataAnnotations validation is auto via WithParameterValidation if enabled,
            // manual fallback for minimal API
            if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password) || string.IsNullOrWhiteSpace(req.FullName))
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["request"] = ["Email, Password, FullName are required"] });

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
            if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["request"] = ["Email and Password are required"] });

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
}
