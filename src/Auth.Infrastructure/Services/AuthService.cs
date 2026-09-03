using Auth.Core.Contracts;
using Auth.Core.Entities;
using Auth.Core.Interfaces;
using Auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SharedKernel;

namespace Auth.Infrastructure.Services;

public class AuthService : IAuthService
{
    private readonly AuthDbContext _db;
    private readonly PasswordHasherService _hasher;
    private readonly JwtTokenService _jwt;
    private readonly ILogger<AuthService> _logger;
    private readonly IEmailSender _emailSender;
    private readonly ICompanyValidationClient? _companyClient;
    private readonly IConfiguration _config;

    public AuthService(AuthDbContext db, PasswordHasherService hasher, JwtTokenService jwt, ILogger<AuthService> logger, IEmailSender emailSender, IConfiguration config, ICompanyValidationClient? companyClient = null)
    {
        _db = db;
        _hasher = hasher;
        _jwt = jwt;
        _logger = logger;
        _emailSender = emailSender;
        _config = config;
        _companyClient = companyClient;
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

        // SRS AUTH-01-06: Recruiter requires companyId (FK → Company)
        if (role == "Recruiter" && !request.CompanyId.HasValue)
            return Result<Guid>.Failure("companyId required for Recruiter");
        if (request.CompanyId.HasValue && _companyClient != null)
        {
            var exists = await _companyClient.ExistsAsync(request.CompanyId.Value, ct);
            if (!exists)
                return Result<Guid>.Failure("Invalid companyId");
        }

        var existsEmail = await _db.Users.AnyAsync(u => u.Email == email, ct);
        if (existsEmail)
        {
            _logger.LogWarning("AUDIT AuthEvent=RegisterFailed Email={Email} Reason=Duplicate", email);
            return Result<Guid>.Failure("Email exists");
        }

        var hash = _hasher.Hash(request.Password);
        var companyId = role == "Recruiter" ? request.CompanyId : null;
        var user = new User(email, hash, request.FullName.Trim(), role, companyId);
        _db.Users.Add(user);
        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (IsUniqueViolation(ex))
        {
            _logger.LogWarning(ex, "AUDIT AuthEvent=RegisterFailed Email={Email} Reason=Duplicate", email);
            return Result<Guid>.Failure("Email exists");
        }

        _logger.LogInformation("AUDIT AuthEvent=RegisterSuccess UserId={UserId} Email={Email} Role={Role} CompanyId={CompanyId}", user.Id, email, role, companyId);
        return Result<Guid>.Success(user.Id);
    }

    public async Task<Result<AuthResponse>> LoginAsync(LoginRequest request, CancellationToken ct = default)
    {
        var email = request.Email.Trim().ToLowerInvariant();
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);
        if (user == null || !_hasher.Verify(request.Password, user.PasswordHash))
        {
            _logger.LogWarning("AUDIT AuthEvent=LoginFailed Email={Email} Reason=InvalidCredentials", email);
            return Result<AuthResponse>.Failure("Invalid credentials");
        }

        if (!user.IsActive)
        {
            _logger.LogWarning("AUDIT AuthEvent=LoginFailed UserId={UserId} Reason=Inactive", user.Id);
            return Result<AuthResponse>.Failure("Account inactive");
        }

        var accessToken = _jwt.GenerateAccessToken(user.Id, user.Email, user.Role, user.CompanyId);
        var refreshToken = _jwt.GenerateRefreshToken();
        var tokenHash = _jwt.HashToken(refreshToken);
        var expiresAt = DateTime.UtcNow.AddDays(request.RememberMe ? 30 : 7);

        var rt = new RefreshToken(user.Id, tokenHash, expiresAt, null, request.RememberMe);
        _db.RefreshTokens.Add(rt);
        user.RecordLogin();
        await _db.SaveChangesAsync(ct);

        _logger.LogInformation("AUDIT AuthEvent=LoginSuccess UserId={UserId} RememberMe={RememberMe} CompanyId={CompanyId}", user.Id, request.RememberMe, user.CompanyId);
        var dto = new UserDto(user.Id, user.Email, user.FullName, user.Role, user.CompanyId);
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
            _logger.LogWarning("AUDIT AuthEvent=RefreshFailed Reason=NotFound");
            return Result<AuthResponse>.Failure("Invalid refresh token");
        }

        if (stored.IsRevoked)
        {
            _logger.LogWarning("AUDIT AuthEvent=RefreshReuseDetected Family={Family} UserId={UserId}", stored.TokenFamily, stored.UserId);
            var familyTokens = await _db.RefreshTokens
                .Where(x => x.UserId == stored.UserId && x.TokenFamily == stored.TokenFamily && !x.IsRevoked)
                .ToListAsync(ct);
            foreach (var t in familyTokens) t.Revoke();
            await _db.SaveChangesAsync(ct);
            return Result<AuthResponse>.Failure("Refresh token revoked");
        }

        if (stored.IsExpired)
        {
            _logger.LogWarning("AUDIT AuthEvent=RefreshFailed UserId={UserId} Reason=Expired", stored.UserId);
            return Result<AuthResponse>.Failure("Refresh token expired");
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == stored.UserId, ct);
        if (user == null || !user.IsActive)
            return Result<AuthResponse>.Failure("User not found");

        stored.Revoke();
        var newRefresh = _jwt.GenerateRefreshToken();
        var newHash = _jwt.HashToken(newRefresh);
        var expiresAt = DateTime.UtcNow.AddDays(stored.IsLongLived ? 30 : 7);

        var newRt = new RefreshToken(user.Id, newHash, expiresAt, stored.TokenFamily, stored.IsLongLived);
        _db.RefreshTokens.Add(newRt);
        await _db.SaveChangesAsync(ct);

        var newAccess = _jwt.GenerateAccessToken(user.Id, user.Email, user.Role, user.CompanyId);
        _logger.LogInformation("AUDIT AuthEvent=RefreshSuccess Family={Family} UserId={UserId}", stored.TokenFamily, user.Id);
        var dto = new UserDto(user.Id, user.Email, user.FullName, user.Role, user.CompanyId);
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
                _logger.LogInformation("AUDIT AuthEvent=Logout UserId={UserId} Mode=Single", userId);
            }
        }
        else
        {
            var actives = await _db.RefreshTokens.Where(x => x.UserId == userId && !x.IsRevoked && x.ExpiresAt > DateTime.UtcNow).ToListAsync(ct);
            foreach (var t in actives) t.Revoke();
            if (actives.Count > 0) await _db.SaveChangesAsync(ct);
            _logger.LogInformation("AUDIT AuthEvent=Logout UserId={UserId} Mode=All Count={Count}", userId, actives.Count);
        }
        return Result.Success();
    }

    public async Task<Result<UserMeDto>> GetMeAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user == null) return Result<UserMeDto>.Failure("User not found");
        return Result<UserMeDto>.Success(new UserMeDto(user.Id, user.Email, user.FullName, user.Role, user.CompanyId, user.IsActive));
    }

    public async Task<Result> ForgotPasswordAsync(ForgotPasswordRequest request, CancellationToken ct = default)
    {
        var email = request.Email.Trim().ToLowerInvariant();
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);
        if (user == null)
        {
            _logger.LogInformation("AUDIT AuthEvent=ForgotPassword Email={Email} Found=false", email);
            return Result.Success();
        }

        var plainToken = _jwt.GenerateRefreshToken();
        var hash = _jwt.HashToken(plainToken);
        var expiresAt = DateTime.UtcNow.AddMinutes(15);
        var prt = new PasswordResetToken(user.Id, hash, expiresAt);
        _db.PasswordResetTokens.Add(prt);
        await _db.SaveChangesAsync(ct);

        var webUrl = _config["WEB_URL"] ?? _config["WebUrl"] ?? "http://localhost:5173";
        var link = $"{webUrl.TrimEnd('/')}/reset-password?token={Uri.EscapeDataString(plainToken)}";
        await _emailSender.SendPasswordResetAsync(email, link, ct);
        _logger.LogInformation("AUDIT AuthEvent=ForgotPassword Email={Email} Found=true TokenHash={Hash}", email, hash[..8]);
        return Result.Success();
    }

    public async Task<Result> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken ct = default)
    {
        if (!IsPasswordStrong(request.NewPassword))
            return Result.Failure("Password must be at least 8 characters with 1 uppercase and 1 digit");

        var hash = _jwt.HashToken(request.Token);
        var stored = await _db.PasswordResetTokens.FirstOrDefaultAsync(x => x.TokenHash == hash, ct);
        if (stored == null || stored.IsUsed || stored.IsExpired)
        {
            _logger.LogWarning("AUDIT AuthEvent=ResetPasswordFailed Reason=InvalidOrExpired");
            return Result.Failure("Invalid or expired token");
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == stored.UserId, ct);
        if (user == null) return Result.Failure("User not found");

        user.UpdatePassword(_hasher.Hash(request.NewPassword));
        stored.MarkUsed();

        var actives = await _db.RefreshTokens.Where(x => x.UserId == user.Id && !x.IsRevoked).ToListAsync(ct);
        foreach (var t in actives) t.Revoke();

        await _db.SaveChangesAsync(ct);
        _logger.LogInformation("AUDIT AuthEvent=ResetPasswordSuccess UserId={UserId} RevokedCount={Count}", user.Id, actives.Count);
        return Result.Success();
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
