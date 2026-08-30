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
        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (IsUniqueViolation(ex))
        {
            _logger.LogWarning(ex, "Register failed duplicate email {Email}", email);
            return Result<Guid>.Failure("Email exists");
        }

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

    public async Task<Result<AuthResponse>> RefreshAsync(string refreshToken, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
            return Result<AuthResponse>.Failure("Refresh token required");

        var hash = _jwt.HashToken(refreshToken);
        var stored = await _db.RefreshTokens.FirstOrDefaultAsync(x => x.TokenHash == hash, ct);
        if (stored == null)
        {
            _logger.LogWarning("Refresh failed not found");
            return Result<AuthResponse>.Failure("Invalid refresh token");
        }

        if (stored.IsRevoked)
        {
            // Reuse detection — scoped family revocation (SEC-09 anti-DoS)
            _logger.LogWarning("Refresh reuse detected Family {Family} User {UserId}", stored.TokenFamily, stored.UserId);
            var familyTokens = await _db.RefreshTokens
                .Where(x => x.UserId == stored.UserId && x.TokenFamily == stored.TokenFamily && !x.IsRevoked)
                .ToListAsync(ct);
            foreach (var t in familyTokens) t.Revoke();
            await _db.SaveChangesAsync(ct);
            return Result<AuthResponse>.Failure("Refresh token revoked");
        }

        if (stored.IsExpired)
        {
            _logger.LogWarning("Refresh failed expired {UserId}", stored.UserId);
            return Result<AuthResponse>.Failure("Refresh token expired");
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == stored.UserId, ct);
        if (user == null || !user.IsActive)
            return Result<AuthResponse>.Failure("User not found");

        // Normal rotation: revoke old, issue new child same family
        stored.Revoke();
        var newRefresh = _jwt.GenerateRefreshToken();
        var newHash = _jwt.HashToken(newRefresh);
        var expiresAt = DateTime.UtcNow.AddDays(7);
        // Keep original 30d if original was long-lived (heuristic: >14d remaining)
        var remaining = stored.ExpiresAt - DateTime.UtcNow;
        if (remaining.TotalDays > 14) expiresAt = DateTime.UtcNow.AddDays(30);

        var newRt = new RefreshToken(user.Id, newHash, expiresAt, stored.TokenFamily);
        _db.RefreshTokens.Add(newRt);
        await _db.SaveChangesAsync(ct);

        var newAccess = _jwt.GenerateAccessToken(user.Id, user.Email, user.Role);
        _logger.LogInformation("Refresh rotated Family {Family} User {UserId}", stored.TokenFamily, user.Id);
        var dto = new UserDto(user.Id, user.Email, user.FullName, user.Role);
        return Result<AuthResponse>.Success(new AuthResponse(newAccess, newRefresh, dto));
    }

    public async Task<Result> LogoutAsync(Guid userId, string? refreshToken, CancellationToken ct = default)
    {
        if (!string.IsNullOrWhiteSpace(refreshToken))
        {
            var hash = _jwt.HashToken(refreshToken);
            var stored = await _db.RefreshTokens.FirstOrDefaultAsync(x => x.TokenHash == hash && x.UserId == userId, ct);
            if (stored != null && !stored.IsRevoked)
            {
                stored.Revoke();
                await _db.SaveChangesAsync(ct);
                _logger.LogInformation("Logout single token User {UserId}", userId);
            }
        }
        else
        {
            // Revoke all active tokens for user (all devices) — explicit logout all
            var actives = await _db.RefreshTokens.Where(x => x.UserId == userId && !x.IsRevoked && x.ExpiresAt > DateTime.UtcNow).ToListAsync(ct);
            foreach (var t in actives) t.Revoke();
            if (actives.Count > 0) await _db.SaveChangesAsync(ct);
            _logger.LogInformation("Logout all tokens User {UserId} Count {Count}", userId, actives.Count);
        }
        return Result.Success();
    }

    public async Task<Result<UserMeDto>> GetMeAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user == null) return Result<UserMeDto>.Failure("User not found");
        return Result<UserMeDto>.Success(new UserMeDto(user.Id, user.Email, user.FullName, user.Role, user.IsActive));
    }

    private static bool IsPasswordStrong(string pwd)
    {
        if (pwd.Length < 8) return false;
        if (!pwd.Any(char.IsUpper)) return false;
        if (!pwd.Any(char.IsDigit)) return false;
        return true;
    }

    private static bool IsUniqueViolation(DbUpdateException ex)
    {
        if (ex.InnerException is Npgsql.PostgresException pgEx && pgEx.SqlState == "23505")
            return true;

        var message = ex.InnerException?.Message ?? ex.Message;
        return message.Contains("unique", StringComparison.OrdinalIgnoreCase)
            || message.Contains("duplicate", StringComparison.OrdinalIgnoreCase);
    }
}
