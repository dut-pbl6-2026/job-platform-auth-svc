using Auth.Core.Contracts;

namespace Auth.Core.Interfaces;

public enum CompanySignUpStatus
{
    /// <summary>Accepted. The response is the same for every outcome, so this is the only success value.</summary>
    Accepted,
    /// <summary>The email domain is a free public provider (AUTH-01-11). Nothing was looked up or stored.</summary>
    WorkEmailRequired,
    /// <summary>The password does not meet the strength rules (AUTH-01-01).</summary>
    WeakPassword,
    /// <summary>A lookup to job-svc failed. Nothing was stored (AUTH-01-10).</summary>
    Unavailable,
}

public enum CompanyVerifyOutcome
{
    /// <summary>No company sign-up has this token. The caller may try the personal verification path.</summary>
    NotCompanyToken,
    /// <summary>The sign-up was completed, turned into a join request, or ended in the notice case.</summary>
    Processed,
    /// <summary>The token is expired or was already used.</summary>
    Invalid,
    /// <summary>A lookup or job-svc call failed. The link still works until it expires.</summary>
    Unavailable,
}

public interface ICompanySignUpService
{
    Task<CompanySignUpStatus> RegisterAsync(RegisterCompanyRequest request, CancellationToken ct = default);

    Task<CompanyVerifyOutcome> VerifyAsync(string token, CancellationToken ct = default);
}
