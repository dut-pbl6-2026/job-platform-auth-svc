using Auth.Core.Contracts;
using Auth.Core.Entities;
using Auth.Core.Interfaces;
using Auth.Core.Security;
using Auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SharedKernel;

namespace Auth.Infrastructure.Services;

public class AuthService : IAuthService
{
    private readonly AuthDbContext _db;
    private readonly IPasswordHasher _hasher;
    private readonly JwtTokenService _jwt;
    private readonly ILogger<AuthService> _logger;
    private readonly ICompanyValidationClient? _companyClient;
    private readonly ITokenRevocationStore _revocationStore;
    private readonly IConfiguration _config;

    public AuthService(AuthDbContext db, IPasswordHasher hasher, JwtTokenService jwt, ILogger<AuthService> logger, IConfiguration config, ITokenRevocationStore revocationStore, ICompanyValidationClient? companyClient = null)
    {
        _db = db;
        _hasher = hasher;
        _jwt = jwt;
        _logger = logger;
        _config = config;
        _revocationStore = revocationStore;
        _companyClient = companyClient;
    }

    /// <summary>
    /// Succeeds for any well-formed request, whether or not the email is already registered, so
    /// the response cannot be used to enumerate accounts. A new address gets a pending account and
    /// a verification link; an existing address gets a notice to its owner and no account change.
    /// Both paths do the same work: password hash, lookup, one save. The email is an outbox row
    /// written in that same save, so it is sent later by the worker and the response never waits for SMTP.
    /// </summary>
    public async Task<Result> RegisterAsync(RegisterRequest request, CancellationToken ct = default)
    {
        var email = request.Email.Trim().ToLowerInvariant();
        var role = string.IsNullOrWhiteSpace(request.Role) ? "User" : request.Role.Trim();
        // Admin accounts are provisioned out-of-band (DB bootstrap), never via public registration.
        var allowedRoles = new[] { "User", "Recruiter" };
        if (!allowedRoles.Contains(role))
            return Result.Failure("Invalid role");

        if (!PasswordPolicy.IsStrong(request.Password))
            return Result.Failure("Password must be " + PasswordPolicy.Description);

        // SRS AUTH-01-06: Recruiter requires companyId (FK → Company)
        if (role == "Recruiter" && !request.CompanyId.HasValue)
            return Result.Failure("companyId required for Recruiter");
        if (request.CompanyId.HasValue && _companyClient != null)
        {
            var exists = await _companyClient.ExistsAsync(request.CompanyId.Value, ct);
            if (!exists)
                return Result.Failure("Invalid companyId");
        }

        // Hash before the lookup on BOTH paths, so a duplicate costs the same as a new registration.
        var hash = _hasher.Hash(request.Password);

        var existingUser = await _db.Users.AnyAsync(u => u.Email == email, ct);
        if (existingUser)
        {
            _logger.LogWarning("AUDIT AuthEvent=RegisterDuplicate Email={Email}", LogRedaction.MaskEmail(email));
            _db.EmailOutboxMessages.Add(EmailOutboxMessage.Create(EmailKind.DuplicateRegistrationNotice, email, DateTime.UtcNow));
            await _db.SaveChangesAsync(ct);
            return Result.Success();
        }

        var companyId = role == "Recruiter" ? request.CompanyId : null;
        var user = new User(email, hash, request.FullName.Trim(), role, companyId);
        var plainToken = _jwt.GenerateRefreshToken();
        var tokenHash = _jwt.HashToken(plainToken);
        var now = DateTime.UtcNow;
        var verificationExpiresAt = now.Add(EmailVerificationToken.Lifetime);
        var link = $"{WebUrl()}/verify-email?token={Uri.EscapeDataString(plainToken)}";
        _db.Users.Add(user);
        _db.EmailVerificationTokens.Add(new EmailVerificationToken(user.Id, tokenHash, verificationExpiresAt));
        _db.EmailOutboxMessages.Add(EmailOutboxMessage.Create(EmailKind.EmailVerification, email, now, link, verificationExpiresAt));
        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (IsUniqueViolation(ex))
        {
            // Lost a race with a concurrent registration for the same address: same response as the duplicate path.
            // The failed save rolled back the user, token and link row together, so none of them is written.
            _logger.LogWarning(ex, "AUDIT AuthEvent=RegisterDuplicate Email={Email} Reason=Race", LogRedaction.MaskEmail(email));
            _db.ChangeTracker.Clear();
            _db.EmailOutboxMessages.Add(EmailOutboxMessage.Create(EmailKind.DuplicateRegistrationNotice, email, DateTime.UtcNow));
            await _db.SaveChangesAsync(ct);
            return Result.Success();
        }

        _logger.LogInformation("AUDIT AuthEvent=RegisterPending UserId={UserId} Role={Role} CompanyId={CompanyId}", user.Id, role, companyId);
        return Result.Success();
    }

    public async Task<Result> VerifyEmailAsync(string token, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(token))
            return Result.Failure("Invalid or expired token");

        var hash = _jwt.HashToken(token);
        var stored = await _db.EmailVerificationTokens.FirstOrDefaultAsync(x => x.TokenHash == hash, ct);
        if (stored == null || !stored.IsUsableAt(DateTime.UtcNow))
        {
            _logger.LogWarning("AUDIT AuthEvent=VerifyEmailFailed Reason=InvalidOrExpired");
            return Result.Failure("Invalid or expired token");
        }

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == stored.UserId, ct);
        if (user == null)
            return Result.Failure("Invalid or expired token");

        user.VerifyEmail();
        stored.MarkUsed();
        await _db.SaveChangesAsync(ct);
        _logger.LogInformation("AUDIT AuthEvent=VerifyEmailSuccess UserId={UserId}", user.Id);
        return Result.Success();
    }

    public async Task<Result<AuthResponse>> LoginAsync(LoginRequest request, CancellationToken ct = default)
    {
        var email = request.Email.Trim().ToLowerInvariant();
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);
        // Always run one hash verification, against a dummy hash for unknown emails, so
        // response time does not reveal whether the account exists.
        var passwordMatches = _hasher.Verify(request.Password, user?.PasswordHash ?? _hasher.DummyHash);
        if (user == null || !passwordMatches)
        {
            _logger.LogWarning("AUDIT AuthEvent=LoginFailed Email={Email} Reason=InvalidCredentials", LogRedaction.MaskEmail(email));
            return Result<AuthResponse>.Failure("Invalid credentials");
        }

        // Pending accounts get the same response as bad credentials (no account-state oracle).
        if (!user.IsEmailVerified)
        {
            _logger.LogWarning("AUDIT AuthEvent=LoginFailed UserId={UserId} Reason=EmailNotVerified", user.Id);
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
            // Access tokens are stateless JWTs: revoke them too, or they stay valid until they expire.
            await _revocationStore.RevokeUserTokensAsync(userId, DateTimeOffset.UtcNow, ct);
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
            // No account: send a notice instead of a reset link, so the same email send happens either way.
            _logger.LogInformation("AUDIT AuthEvent=ForgotPassword Email={Email} Found=false", LogRedaction.MaskEmail(email));
            _db.EmailOutboxMessages.Add(EmailOutboxMessage.Create(EmailKind.UnknownAccountResetNotice, email, DateTime.UtcNow));
            await _db.SaveChangesAsync(ct);
            return Result.Success();
        }

        var plainToken = _jwt.GenerateRefreshToken();
        var hash = _jwt.HashToken(plainToken);
        var expiresAt = DateTime.UtcNow.AddMinutes(15);
        var prt = new PasswordResetToken(user.Id, hash, expiresAt);
        var link = $"{WebUrl()}/reset-password?token={Uri.EscapeDataString(plainToken)}";
        _db.PasswordResetTokens.Add(prt);
        _db.EmailOutboxMessages.Add(EmailOutboxMessage.Create(EmailKind.PasswordReset, email, DateTime.UtcNow, link, expiresAt));
        await _db.SaveChangesAsync(ct);

        _logger.LogInformation("AUDIT AuthEvent=ForgotPassword UserId={UserId} Found=true", user.Id);
        return Result.Success();
    }

    public async Task<Result> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken ct = default)
    {
        if (!PasswordPolicy.IsStrong(request.NewPassword))
            return Result.Failure("Password must be " + PasswordPolicy.Description);

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
        // Access tokens issued before the reset must stop working now, not at their expiry.
        await _revocationStore.RevokeUserTokensAsync(user.Id, DateTimeOffset.UtcNow, ct);
        _logger.LogInformation("AUDIT AuthEvent=ResetPasswordSuccess UserId={UserId} RevokedCount={Count}", user.Id, actives.Count);
        return Result.Success();
    }

    private string WebUrl() => (_config["WEB_URL"] ?? _config["WebUrl"] ?? "http://localhost:5173").TrimEnd('/');

    private static bool IsUniqueViolation(DbUpdateException ex)
    {
        if (ex.InnerException is Npgsql.PostgresException pgEx && pgEx.SqlState == "23505")
            return true;

        var message = ex.InnerException?.Message ?? ex.Message;
        return message.Contains("unique", StringComparison.OrdinalIgnoreCase)
            || message.Contains("duplicate", StringComparison.OrdinalIgnoreCase);
    }
}
