using System.ComponentModel.DataAnnotations;

namespace Auth.Core.Contracts;

// See RegisterRequest.cs for why validation attributes use explicit `property:` targeting.

/// <summary>Company self-serve sign-up request (AUTH-01-10).</summary>
public record RegisterCompanyRequest(
    [property: Required, NonWhitespace(ErrorMessage = "CompanyName is required"), MaxLength(200)] string CompanyName,
    [property: MaxLength(32)] string? TaxCode,
    [property: Required, NonWhitespace(ErrorMessage = "Email is required"), EmailAddress, MaxLength(256)] string Email,
    [property: Required, NonWhitespace(ErrorMessage = "Password is required"), MinLength(8), MaxLength(128)] string Password,
    [property: Required, NonWhitespace(ErrorMessage = "FullName is required"), MaxLength(128)] string FullName);

/// <summary>Error codes and messages for company sign-up and verification.</summary>
public static class CompanySignUpErrors
{
    public const string WorkEmailRequiredCode = "WORK_EMAIL_REQUIRED";
    public const string WorkEmailRequiredMessage = "A work email address is required to register a company.";

    public const string VerificationTokenInvalidCode = "VERIFICATION_TOKEN_INVALID";
    public const string VerificationTokenInvalidMessage = "The verification link is invalid, expired or already used.";

    public const string AccountAlreadyHasCompanyCode = "ACCOUNT_ALREADY_HAS_COMPANY";
    public const string AccountAlreadyHasCompanyMessage = "This account already belongs to a company.";

    public const string ServiceUnavailableMessage = "The service is temporarily unavailable. Try again later.";
}

/// <summary>
/// Fixed response texts. The same text is returned for every outcome of a sign-up or verification, so a
/// caller cannot tell which case applied (AUTH-01-10, backlog A13).
/// </summary>
public static class CompanySignUpMessages
{
    public const string SignUpAccepted = "Check your email to continue the company sign-up.";
    public const string VerificationProcessed = "Your sign-up has been processed.";
}
