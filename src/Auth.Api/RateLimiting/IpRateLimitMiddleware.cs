using System.Globalization;
using Auth.Api.Networking;
using Microsoft.AspNetCore.Http;

namespace Auth.Api.RateLimiting;

/// <summary>
/// Rejects requests over the per-IP limit declared on the matched endpoint. Runs where the old
/// <c>UseRateLimiter</c> ran, so a rejected request is not counted as a valid attempt by later
/// middleware and never reaches model binding. The bucket key comes from <see cref="ClientIpResolver"/>:
/// the real client behind a trusted proxy, otherwise the connection IP.
/// </summary>
public sealed class IpRateLimitMiddleware(RequestDelegate next, IpRateLimiter limiter, ClientIpResolver clientIp)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var policy = context.GetEndpoint()?.Metadata.GetMetadata<IpRateLimitPolicy>();
        if (policy is null)
        {
            await next(context);
            return;
        }

        // Runs before UseForwardedHeaders: the peer here is the actual connection, and the resolver
        // walks X-Forwarded-For only when that peer is a trusted proxy.
        var ip = clientIp.Resolve(
                     context.Connection.RemoteIpAddress,
                     context.Request.Headers["X-Forwarded-For"].ToString())
                 ?.ToString() ?? "unknown";
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
