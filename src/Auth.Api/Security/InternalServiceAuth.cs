using System.Security.Cryptography;
using System.Text;

namespace Auth.Api.Security;

/// <summary>
/// Bearer-token check for service-to-service endpoints under <c>/api/internal/*</c>. Mirrors the
/// job-svc / app-svc helper (separate repos, so no shared code yet). Callers present
/// <c>Authorization: Bearer &lt;INTERNAL_SERVICE_TOKEN&gt;</c>. Fails closed: an unconfigured token
/// never makes an endpoint public.
/// </summary>
public static class InternalServiceAuth
{
    /// <summary>Configuration/env key holding the shared internal service token.</summary>
    public const string TokenConfigKey = "INTERNAL_SERVICE_TOKEN";

    private const string BearerPrefix = "Bearer ";

    /// <summary>Returns <c>null</c> when the request carries the configured token, otherwise a 401 result.</summary>
    public static IResult? Authorize(HttpContext ctx, IConfiguration config, ILogger logger)
    {
        var expected = config[TokenConfigKey];
        if (string.IsNullOrWhiteSpace(expected))
        {
            logger.LogError(
                "{TokenKey} is not configured. Returning 401 to avoid exposing the endpoint.",
                TokenConfigKey);
            return Unauthorized();
        }

        return IsAuthorized(ctx.Request.Headers.Authorization.ToString(), expected)
            ? null
            : Unauthorized();
    }

    private static IResult Unauthorized() =>
        Results.Json(new { message = "Unauthorized" }, statusCode: 401);

    internal static bool IsAuthorized(string header, string expected)
    {
        if (!header.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase))
            return false;

        var token = header[BearerPrefix.Length..].Trim();
        if (token.Length == 0)
            return false;

        // Hash both sides first so the compared arrays always have the same length
        // (FixedTimeEquals returns early on a length mismatch, which would leak the token length).
        return CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(Encoding.UTF8.GetBytes(token)),
            SHA256.HashData(Encoding.UTF8.GetBytes(expected)));
    }
}
