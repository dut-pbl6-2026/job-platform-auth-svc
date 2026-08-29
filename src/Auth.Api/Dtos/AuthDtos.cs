namespace Auth.Api.Dtos;

public record RegisterRequest(string Email, string Password, string FullName, string Role = "User");
public record LoginRequest(string Email, string Password);
public record RefreshRequest(string RefreshToken);
public record LogoutRequest(string RefreshToken);
public record ForgotPasswordRequest(string Email);
public record ResetPasswordRequest(string Token, string NewPassword);
public record AuthResponse(string AccessToken, string RefreshToken, Guid UserId, string Email, string FullName, string Role);
public record UserResponse(Guid Id, string Email, string FullName, string Role, bool IsActive);
