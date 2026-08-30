using System.ComponentModel.DataAnnotations;

namespace Auth.Core.Contracts;

public record RegisterRequest(
    [Required, EmailAddress, MaxLength(256)] string Email,
    [Required, MinLength(8), MaxLength(128)] string Password,
    [Required, MaxLength(128)] string FullName,
    [MaxLength(32)] string? Role = "User",
    Guid? CompanyId = null
);

public record RegisterResponse(Guid UserId, string Message);

public record LoginRequest(
    [Required, EmailAddress] string Email,
    [Required] string Password,
    bool RememberMe = false
);

public record UserDto(Guid Id, string Email, string FullName, string Role);

public record AuthResponse(string AccessToken, string RefreshToken, UserDto User);

public record RefreshRequest(string RefreshToken);

public record LogoutRequest(string? RefreshToken = null);

public record UserMeDto(Guid Id, string Email, string FullName, string Role, bool IsActive);
