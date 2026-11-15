namespace Auth.Core.Interfaces;

/// <summary>
/// job-svc internal company endpoints used by company sign-up and verification (AUTH-01-10, AUTH-01-12).
/// Every call is read-only except create. Create calls are not idempotent, so they are never retried.
/// </summary>
public interface ICompanyDirectoryClient
{
    /// <summary>Id of the verified Company that holds the domain, or null when none does.</summary>
    /// <exception cref="CompanyDirectoryUnavailableException">Transport failure or any non-success status.</exception>
    Task<Guid?> FindVerifiedCompanyIdAsync(string emailDomain, CancellationToken ct = default);

    /// <summary>True when the company name is free and, if a tax code is given, the tax code is free.</summary>
    /// <exception cref="CompanyDirectoryUnavailableException">Transport failure or any non-success status.</exception>
    Task<bool> IsAvailableAsync(string companyName, string? taxCode, CancellationToken ct = default);

    /// <summary>Creates the verified Company with the given admin and domain.</summary>
    /// <exception cref="CompanyAlreadyExistsException">job-svc answered 409: the name, tax code or domain is taken.</exception>
    /// <exception cref="CompanyDirectoryUnavailableException">Transport failure or any other non-success status.</exception>
    Task<Guid> CreateCompanyAsync(string companyName, string? taxCode, Guid createdBy, string emailDomain, CancellationToken ct = default);

    /// <summary>Creates a Pending join request from the user to the Company.</summary>
    /// <exception cref="CompanyDirectoryUnavailableException">Transport failure or any non-success status.</exception>
    Task CreateJoinRequestAsync(Guid userId, Guid companyId, CancellationToken ct = default);
}

/// <summary>job-svc could not be reached or answered with an error. Callers fail closed.</summary>
public sealed class CompanyDirectoryUnavailableException(string message, Exception? inner = null)
    : Exception(message, inner);

/// <summary>job-svc refused to create a Company because one of its unique values is already taken.</summary>
public sealed class CompanyAlreadyExistsException(string message = "Company already exists") : Exception(message);
