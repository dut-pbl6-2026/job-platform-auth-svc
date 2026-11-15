using System.Globalization;
using Microsoft.AspNetCore.Http;

namespace Auth.Api.RateLimiting;

/// <summary>
/// Rejects requests over the per-IP limit declared on the matched endpoint. Runs where the old
/// <c>UseRateLimiter</c> ran, so a rejected request is not counted as a valid attempt by later
/// middleware and never reaches model binding.
/// </summary>
public sealed class IpRateLimitMiddleware(RequestDelegate next, IpRateLimiter limiter)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var policy = context.GetEndpoint()?.Metadata.GetMetadata<IpRateLimitPolicy>();
        if (policy is null)
        {
            await next(context);
            return;
        }

        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var decision = await limiter.CheckAsync(policy, ip, context.RequestAborted);
        if (decision.Allowed)
        {
            await next(context);
            return;
        }

        var retryAfterSeconds = Math.Max(1, (long)Math.Ceiling(decision.RetryAfter.TotalSeconds));
        context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        context.Response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);
        await context.Response.WriteAsJsonAsync(new
        {
            status = 429,
            title = "Too Many Requests",
            detail = "Too many requests. Please try again later."
        }, context.RequestAborted);
    }
}
