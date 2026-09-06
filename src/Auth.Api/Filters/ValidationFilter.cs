using System.ComponentModel.DataAnnotations;

namespace Auth.Api.Filters;

/// <summary>
/// Generic DataAnnotations validation as an endpoint filter: finds the first
/// argument of type <typeparamref name="T"/>, validates it (including
/// <c>NonWhitespace</c>), and short-circuits with <c>400 ValidationProblem</c>
/// grouped by field on failure. Null arguments are skipped (optional bodies).
/// </summary>
public sealed class ValidationFilter<T> : IEndpointFilter where T : class
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var arg = context.Arguments.OfType<T>().FirstOrDefault();
        if (arg is not null)
        {
            var results = new List<ValidationResult>();
            Validator.TryValidateObject(arg, new ValidationContext(arg), results, true);
            if (results.Count > 0)
            {
                var errors = results
                    .GroupBy(r => r.MemberNames.FirstOrDefault() ?? "request")
                    .ToDictionary(g => g.Key, g => g.Select(v => v.ErrorMessage ?? "Invalid").ToArray());
                return Results.ValidationProblem(errors);
            }
        }
        return await next(context);
    }
}
