using Auth.Core.Contracts;
using Auth.Core.Entities;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SharedKernel;

namespace Auth.Infrastructure.Services;

public class AuthService : IAuthService
{
    private readonly AuthDbContext _db;
    private readonly PasswordHasherService _hasher;
    private readonly JwtTokenService _jwt;
    private readonly ILogger<AuthService> _logger;

    public AuthService(AuthDbContext db, PasswordHasherService hasher, JwtTokenService jwt, ILogger<AuthService> logger)
    {
        _db = db;
        _hasher = hasher;
        _jwt = jwt;
        _logger = logger;
    }

    public async Task<Result<Guid>> RegisterAsync(RegisterRequest request, CancellationToken ct = default)
    {
        var email = request.Email.Trim().ToLowerInvariant();
        var role = string.IsNullOrWhiteSpace(request.Role) ? "User" : request.Role.Trim();
        var allowedRoles = new[] { "User", "Recruiter", "Admin" };
        if (!allowedRoles.Contains(role))
            return Result<Guid>.Failure("Invalid role");

        if (!IsPasswordStrong(request.Password))
            return Result<Guid>.Failure("Password must be at least 8 characters with 1 uppercase and 1 digit");

        var exists = await _db.Users.AnyAsync(u => u.Email == email, ct);
        if (exists)
        {
            _logger.LogWarning("Register failed duplicate email {Email}", email);
            return Result<Guid>.Failure("Email exists");
        }

        var hash = _hasher.Hash(request.Password);
        var user = new User(email, hash, request.FullName.Trim(), role);
        // TODO PBL6-44: if Recruiter validate CompanyId FK via companies table/profile service
        _db.Users.Add(user);
        await _db.SaveChangesAsync(ct);
        _logger.LogInformation("User registered {UserId} {Email}", user.Id, email);
        return Result<Guid>.Success(user.Id);
    }

    public async Task<Result<AuthResponse>> LoginAsync(LoginRequest request, CancellationToken ct = default)
    {
        var email = request.Email.Trim().ToLowerInvariant();
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);
        if (user == null || !_hasher.Verify(request.Password, user.PasswordHash))
        {
            _logger.LogWarning("Login failed invalid credentials {Email}", email);
            return Result<AuthResponse>.Failure("Invalid credentials");
        }

        if (!user.IsActive)
        {
            _logger.LogWarning("Login failed inactive account {UserId}", user.Id);
            return Result<AuthResponse>.Failure("Account inactive");
        }

        var accessToken = _jwt.GenerateAccessToken(user.Id, user.Email, user.Role);
        var refreshToken = _jwt.GenerateRefreshToken();
        var tokenHash = _jwt.HashToken(refreshToken);
        var expiresAt = DateTime.UtcNow.AddDays(request.RememberMe ? 30 : 7);

        var rt = new RefreshToken(user.Id, tokenHash, expiresAt);
        _db.RefreshTokens.Add(rt);
        user.RecordLogin();
        await _db.SaveChangesAsync(ct);

        _logger.LogInformation("User login success {UserId}", user.Id);
        var dto = new UserDto(user.Id, user.Email, user.FullName, user.Role);
        return Result<AuthResponse>.Success(new AuthResponse(accessToken, refreshToken, dto));
    }

    private static bool IsPasswordStrong(string pwd)
    {
        if (pwd.Length < 8) return false;
        if (!pwd.Any(char.IsUpper)) return false;
        if (!pwd.Any(char.IsDigit)) return false;
        return true;
    }
}
