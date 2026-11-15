namespace Auth.Api.RateLimiting;

/// <summary>
/// Per-IP fixed-window limit for one endpoint group. Used as endpoint metadata: the middleware
/// reads it after routing and before model binding, so rejected requests are never parsed.
/// </summary>
public sealed record IpRateLimitPolicy(string Name, int PermitLimit, TimeSpan Window)
{
    public static readonly IpRateLimitPolicy Login = new("login", 10, TimeSpan.FromMinutes(15));
    public static readonly IpRateLimitPolicy Register = new("register", 10, TimeSpan.FromHours(1));
    public static readonly IpRateLimitPolicy Refresh = new("refresh", 30, TimeSpan.FromMinutes(15));
    public static readonly IpRateLimitPolicy Reset = new("reset", 10, TimeSpan.FromHours(1));
    public static readonly IpRateLimitPolicy Forgot = new("forgot", 5, TimeSpan.FromHours(1));
    public static readonly IpRateLimitPolicy Verify = new("verify", 10, TimeSpan.FromMinutes(15));
    public static readonly IpRateLimitPolicy ResendVerification = new("resend-verification", 5, TimeSpan.FromHours(1));
    // AUTH-01-10 / AUTH-01-11: every request counts, whatever its outcome.
    public static readonly IpRateLimitPolicy CompanySignUp = new("register-company", 5, TimeSpan.FromHours(1));
}
