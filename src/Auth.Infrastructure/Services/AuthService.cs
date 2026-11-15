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
    private readonly IInviteCodeClient? _inviteCodes;
    private readonly ITokenRevocationStore _revocationStore;
    private readonly IConfiguration _config;

    public AuthService(AuthDbContext db, IPasswordHasher hasher, JwtTokenService jwt, ILogger<AuthService> logger, IConfiguration config, ITokenRevocationStore revocationStore, IInviteCodeClient? inviteCodes = null)
    {
        _db = db;
        _hasher = hasher;
        _jwt = jwt;
        _logger = logger;
        _config = config;
        _revocationStore = revocationStore;
        _inviteCodes = inviteCodes;
    }

    /// <summary>
    /// Returns null when the code is usable. Fails closed: an unreachable job-svc refuses the registration.
    /// </summary>
    private async Task<Result?> CheckInviteCodeAsync(string code, string email, CancellationToken ct)
    {
        if (_inviteCodes is null)
            return Result.Failure(InviteCodeErrors.Unavailable);
        try
        {
            if (await _inviteCodes.CheckAsync(code, email, ct) is not null)
                return null;
        }
        catch (InviteCodeServiceUnavailableException ex)
        {
            _logger.LogWarning(ex, "AUDIT AuthEvent=RegisterInviteUnavailable Email={Email}", LogRedaction.MaskEmail(email));
            return Result.Failure(InviteCodeErrors.Unavailable);
        }
        _logger.LogWarning("AUDIT AuthEvent=RegisterInviteRejected Email={Email}", LogRedaction.MaskEmail(email));
        return Result.Failure(InviteCodeErrors.Invalid);
    }

    private async Task ReleaseInviteCodeAsync(Guid inviteCodeId, CancellationToken ct)
    {
        if (_inviteCodes is null)
            return;
        try
        {
            if (!await _inviteCodes.ReleaseAsync(inviteCodeId, ct))
                _logger.LogError("AUDIT AuthEvent=InviteCodeReleaseFailed InviteCodeId={InviteCodeId}", inviteCodeId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AUDIT AuthEvent=InviteCodeReleaseFailed InviteCodeId={InviteCodeId}", inviteCodeId);
        }
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

        // SRS AUTH-01-06 / AUTH-01-09: Recruiter registration needs a valid invite code; the Company comes from
        // the code and client-sent companyId/companyName are ignored. The check runs before the duplicate lookup:
        // its outcome depends only on the code, so it reveals nothing about existing emails.
        string? inviteCode = null;
        if (role == "Recruiter")
        {
            inviteCode = request.InviteCode?.Trim();
            if (string.IsNullOrWhiteSpace(inviteCode))
                return Result.Failure(InviteCodeErrors.Missing);
            var checkFailure = await CheckInviteCodeAsync(inviteCode, email, ct);
            if (checkFailure is not null)
                return checkFailure;
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

        // Redeem after the duplicate check, so a duplicate registration never consumes a code.
        // Redeem is atomic in job-svc; a code used since the check fails here with the same error.
        InviteCodeRedeemResult? redemption = null;
        if (role == "Recruiter")
        {
            try
            {
                redemption = _inviteCodes is null
                    ? null
                    : await _inviteCodes.RedeemAsync(inviteCode!, email, ct);
            }
            catch (InviteCodeServiceUnavailableException ex)
            {
                _logger.LogWarning(ex, "AUDIT AuthEvent=RegisterInviteUnavailable Email={Email}", LogRedaction.MaskEmail(email));
                return Result.Failure(InviteCodeErrors.Unavailable);
            }
            if (redemption is null)
                return Result.Failure(InviteCodeErrors.Invalid);
        }

        var companyId = redemption?.CompanyId;
        var user = new User(email, hash, request.FullName.Trim(), role, companyId);
        var now = DateTime.UtcNow;
        _db.Users.Add(user);
        if (role == "Recruiter")
        {
            // AUTH-01-15: the invite code is bound to this address and accepted with it, so the account is
            // active at once and no verification mail is sent.
            user.VerifyEmail();
        }
        else
        {
            var plainToken = _jwt.GenerateRefreshToken();
            var tokenHash = _jwt.HashToken(plainToken);
            var verificationExpiresAt = now.Add(EmailVerificationToken.Lifetime);
            var link = $"{WebUrl()}/verify-email?token={Uri.EscapeDataString(plainToken)}";
            _db.EmailVerificationTokens.Add(new EmailVerificationToken(user.Id, tokenHash, verificationExpiresAt));
            _db.EmailOutboxMessages.Add(EmailOutboxMessage.Create(EmailKind.EmailVerification, email, now, link, verificationExpiresAt));
        }
        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (PersistenceErrors.IsUniqueViolation(ex))
        {
            // Lost a race with a concurrent registration for the same address: same response as the duplicate path.
            // The failed save rolled back the user, token and link row together, so none of them is written.
            _logger.LogWarning(ex, "AUDIT AuthEvent=RegisterDuplicate Email={Email} Reason=Race", LogRedaction.MaskEmail(email));
            _db.ChangeTracker.Clear();
            if (redemption is not null)
                await ReleaseInviteCodeAsync(redemption.InviteCodeId, ct);
            _db.EmailOutboxMessages.Add(EmailOutboxMessage.Create(EmailKind.DuplicateRegistrationNotice, email, DateTime.UtcNow));
            await _db.SaveChangesAsync(ct);
            return Result.Success();
        }
        catch (Exception)
        {
            // Creation failed after the code was redeemed: give the code back so the creator's code is not burned.
            if (redemption is not null)
                await ReleaseInviteCodeAsync(redemption.InviteCodeId, ct);
            throw;
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

    /// <summary>
    /// Queues a fresh verification link for an account that is still unverified (for example after the
    /// previous link expired). Succeeds for every well-formed email, so the caller cannot tell whether the
    /// account exists or is already verified. The token is generated and hashed on every path, so the
    /// known and unknown paths do the same hashing and lookup work. Only the unverified path writes.
    /// </summary>
    public async Task<Result> ResendVerificationAsync(ResendVerificationRequest request, CancellationToken ct = default)
    {
        var email = request.Email.Trim().ToLowerInvariant();
        var plainToken = _jwt.GenerateRefreshToken();
        var tokenHash = _jwt.HashToken(plainToken);

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email, ct);
        if (user == null || user.IsEmailVerified)
        {
            _logger.LogInformation("AUDIT AuthEvent=ResendVerification Email={Email} Queued=false", LogRedaction.MaskEmail(email));
            return Result.Success();
        }

        var now = DateTime.UtcNow;
        var expiresAt = now.Add(EmailVerificationToken.Lifetime);
        var link = $"{WebUrl()}/verify-email?token={Uri.EscapeDataString(plainToken)}";
        _db.EmailVerificationTokens.Add(new EmailVerificationToken(user.Id, tokenHash, expiresAt));
        _db.EmailOutboxMessages.Add(EmailOutboxMessage.Create(EmailKind.EmailVerification, email, now, link, expiresAt));
        await _db.SaveChangesAsync(ct);

        _logger.LogInformation("AUDIT AuthEvent=ResendVerification UserId={UserId} Queued=true", user.Id);
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
            try
            {
                await _db.SaveChangesAsync(ct);
            }
            catch (DbUpdateConcurrencyException ex)
            {
                // A concurrent request changed the family first; the family is revoked either way.
                _logger.LogWarning(ex, "AUDIT AuthEvent=RefreshFailed Reason=ConcurrentRevoke Family={Family} UserId={UserId}", stored.TokenFamily, stored.UserId);
                return Result<AuthResponse>.Failure("Invalid refresh token");
            }
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
        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // Another request rotated this token first. The save rolled back, so only one successor exists.
            _logger.LogWarning(ex, "AUDIT AuthEvent=RefreshFailed Reason=ConcurrentRotation Family={Family} UserId={UserId}", stored.TokenFamily, user.Id);
            return Result<AuthResponse>.Failure("Invalid refresh token");
        }

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
                try
                {
                    await _db.SaveChangesAsync(ct);
                    _logger.LogInformation("AUDIT AuthEvent=Logout UserId={UserId} Mode=Single", userId);
                }
                catch (DbUpdateConcurrencyException)
                {
                    // A concurrent logout or refresh revoked this row first. Only Revoke() changes the row, so it is
                    // revoked now: the same idempotent success as a token that was already revoked.
                    _logger.LogInformation("AUDIT AuthEvent=Logout UserId={UserId} Mode=Single Reason=ConcurrentRevoke", userId);
                }
            }
        }
        else
        {
            var revoked = await RevokeActiveRefreshTokensAsync(userId, ct);
            if (revoked is null)
                return Result.Failure("Unable to revoke sessions");

            // Access tokens are stateless JWTs: revoke them too, or they stay valid until they expire.
            await _revocationStore.RevokeUserTokensAsync(userId, DateTimeOffset.UtcNow, ct);
            _logger.LogInformation("AUDIT AuthEvent=Logout UserId={UserId} Mode=All Count={Count}", userId, revoked);
        }
        return Result.Success();
    }

    /// <summary>
    /// Revokes every still-valid refresh token of the user in one save. A conflict means a concurrent refresh
    /// or logout changed one of those rows; the whole save rolled back, so the rows are reloaded and the
    /// revocation runs once more. Returns null when the second attempt also conflicts (nothing was revoked).
    /// </summary>
    private async Task<int?> RevokeActiveRefreshTokensAsync(Guid userId, CancellationToken ct)
    {
        for (var attempt = 1; attempt <= 2; attempt++)
        {
            var actives = await _db.RefreshTokens
                .Where(x => x.UserId == userId && !x.IsRevoked && x.ExpiresAt > DateTime.UtcNow)
                .ToListAsync(ct);
            foreach (var t in actives) t.Revoke();
            if (actives.Count == 0)
                return 0;

            try
            {
                await _db.SaveChangesAsync(ct);
                return actives.Count;
            }
            catch (DbUpdateConcurrencyException ex)
            {
                _logger.LogWarning(ex, "AUDIT AuthEvent=Logout UserId={UserId} Mode=All Reason=ConcurrentChange Attempt={Attempt}", userId, attempt);
                _db.ChangeTracker.Clear();
            }
        }
        return null;
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

        // The password change, the token use and the session revocations are one SaveChanges, so they commit or roll
        // back together. A concurrent refresh can make that save conflict; the reset then never happened, so it runs
        // once more against fresh rows.
        var result = await TryResetPasswordAsync(request, ct);
        result ??= await TryResetPasswordAsync(request, ct);
        return result ?? Result.Failure("Password reset failed, please try again");
    }

    /// <summary>Returns null when the save conflicted with a concurrent refresh or logout and rolled back entirely.</summary>
    private async Task<Result?> TryResetPasswordAsync(ResetPasswordRequest request, CancellationToken ct)
    {
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

        try
        {
            await _db.SaveChangesAsync(ct);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "AUDIT AuthEvent=ResetPasswordRetry UserId={UserId} Reason=ConcurrentChange", user.Id);
            _db.ChangeTracker.Clear();
            return null;
        }

        // Access tokens issued before the reset must stop working now, not at their expiry.
        await _revocationStore.RevokeUserTokensAsync(user.Id, DateTimeOffset.UtcNow, ct);
        _logger.LogInformation("AUDIT AuthEvent=ResetPasswordSuccess UserId={UserId} RevokedCount={Count}", user.Id, actives.Count);
        return Result.Success();
    }

    private string WebUrl() => (_config["WEB_URL"] ?? _config["WebUrl"] ?? "http://localhost:5173").TrimEnd('/');
}
