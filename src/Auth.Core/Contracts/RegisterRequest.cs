using System.ComponentModel.DataAnnotations;

namespace Auth.Core.Contracts;

// NOTE: validation attributes use explicit `property:` targeting. Attributes on
// record positional parameters are NOT reliably copied to the synthesized
// property, and Validator.TryValidateObject only reads property attributes —
// without `property:` the whole DataAnnotations layer is silently skipped.

public record RegisterRequest(
    [property: Required, NonWhitespace(ErrorMessage = "Email is required"), EmailAddress, MaxLength(256)] string Email,
    [property: Required, NonWhitespace(ErrorMessage = "Password is required"), MinLength(8), MaxLength(128)] string Password,
    [property: Required, NonWhitespace(ErrorMessage = "FullName is required"), MaxLength(128)] string FullName,
    [property: MaxLength(32)] string? Role = "User",
    Guid? CompanyId = null,
    string? CompanyName = null
);

public record RegisterResponse(Guid UserId, string Message);

public record LoginRequest(
    [property: Required, NonWhitespace(ErrorMessage = "Email is required"), EmailAddress] string Email,
    [property: Required, NonWhitespace(ErrorMessage = "Password is required")] string Password,
    bool RememberMe = false
);

public record UserDto(Guid Id, string Email, string FullName, string Role, Guid? CompanyId);

public record AuthResponse(string AccessToken, string RefreshToken, UserDto User);

public record RefreshRequest([property: Required, NonWhitespace(ErrorMessage = "RefreshToken is required")] string RefreshToken);

public record LogoutRequest(string? RefreshToken = null);

public record UserMeDto(Guid Id, string Email, string FullName, string Role, Guid? CompanyId, bool IsActive);

public record ForgotPasswordRequest([property: Required, NonWhitespace(ErrorMessage = "Email is required"), EmailAddress, MaxLength(256)] string Email);

public record ResetPasswordRequest(
    [property: Required, NonWhitespace(ErrorMessage = "Token is required")] string Token,
    [property: Required, NonWhitespace(ErrorMessage = "NewPassword is required"), MinLength(8), MaxLength(128)] string NewPassword);
