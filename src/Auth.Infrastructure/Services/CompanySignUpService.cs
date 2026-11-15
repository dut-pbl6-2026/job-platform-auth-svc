using Auth.Core.Contracts;
using Auth.Core.Entities;
using Auth.Core.Interfaces;
using Auth.Core.Security;
using Auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

/// <summary>
/// Company self-serve sign-up and its email verification (AUTH-01-10, AUTH-01-11, AUTH-01-12).
/// <para>
/// Sign-up: both job-svc lookups run on every request before an outcome is chosen. A new address whose company
/// name and tax code are free, or whose domain a verified Company holds, gets a pending sign-up and a verification
/// link. Any other case gets the fixed notice and no link. The caller sees the same response either way.
/// </para>
/// <para>
/// Verification: the lookups run again. The sign-up row is claimed by a conditional delete before any write, so
/// only one request can use a link. The user is created inactive. If job-svc fails, the user is removed and the
/// row restored, so the same link works until it expires.
/// </para>
/// </summary>
public sealed class CompanySignUpService(
    AuthDbContext db,
    IPasswordHasher hasher,
    JwtTokenService jwt,
    ICompanyDirectoryClient directory,
    WorkEmailPolicy workEmail,
    IConfiguration config,
    ILogger<CompanySignUpService> logger) : ICompanySignUpService
{
    public async Task<CompanySignUpStatus> RegisterAsync(RegisterCompanyRequest request, CancellationToken ct = default)
    {
        var email = request.Email.Trim().ToLowerInvariant();
        // AUTH-01-11: checked before any lookup, because it depends only on the address. Nothing is stored.
        if (!workEmail.IsWorkEmail(email))
        {
            logger.LogWarning("AUDIT AuthEvent=CompanySignUpRejected Reason=FreeEmailProvider Email={Email}", LogRedaction.MaskEmail(email));
            return CompanySignUpStatus.WorkEmailRequired;
        }
        if (!PasswordPolicy.IsStrong(request.Password))
            return CompanySignUpStatus.WeakPassword;

        var companyName = request.CompanyName.Trim();
        var taxCode = NormalizeTaxCode(request.TaxCode);
        var domain = WorkEmailPolicy.DomainOf(email);

        var lookup = await LookupAsync(domain, companyName, taxCode, ct);
        if (lookup is null)
            return CompanySignUpStatus.Unavailable;

        // Hashed on every path, so a notice costs the same as a new sign-up (as in AuthService.RegisterAsync).
        var passwordHash = hasher.Hash(request.Password);
        var accountExists = await db.Users.AnyAsync(u => u.Email == email, ct);
        var proceed = !accountExists && (lookup.MatchedCompanyId is not null || lookup.Available);

        // A newer attempt replaces the pending sign-up for this address, and a notice case drops it too.
        await db.PendingCompanySignups.Where(p => p.Email == email).ExecuteDeleteAsync(ct);

        if (!proceed)
        {
            logger.LogInformation("AUDIT AuthEvent=CompanySignUpNotice Email={Email} AccountExists={AccountExists}", LogRedaction.MaskEmail(email), accountExists);
            QueueNotice(email);
            await db.SaveChangesAsync(ct);
            return CompanySignUpStatus.Accepted;
        }

        var plainToken = jwt.GenerateRefreshToken();
        var now = DateTime.UtcNow;
        var expiresAt = now.Add(PendingCompanySignup.Lifetime);
        db.PendingCompanySignups.Add(new PendingCompanySignup(
            companyName, taxCode, email, passwordHash, request.FullName.Trim(), jwt.HashToken(plainToken), expiresAt));
        db.EmailOutboxMessages.Add(EmailOutboxMessage.Create(
            EmailKind.CompanySignUpVerification, email, now, VerifyLink(plainToken), expiresAt));
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (PersistenceErrors.IsUniqueViolation(ex))
        {
            // A concurrent attempt for the same address took the slot. Its link is the valid one, so this
            // request gets the same response and no second link.
            db.ChangeTracker.Clear();
            logger.LogWarning(ex, "AUDIT AuthEvent=CompanySignUpRace Email={Email}", LogRedaction.MaskEmail(email));
        }

        logger.LogInformation("AUDIT AuthEvent=CompanySignUpPending Email={Email} DomainMatched={DomainMatched}", LogRedaction.MaskEmail(email), lookup.MatchedCompanyId is not null);
        return CompanySignUpStatus.Accepted;
    }

    public async Task<CompanyVerifyOutcome> VerifyAsync(string token, CancellationToken ct = default)
    {
        var hash = jwt.HashToken(token);
        var pending = await db.PendingCompanySignups.AsNoTracking().FirstOrDefaultAsync(p => p.TokenHash == hash, ct);
        if (pending is null)
            return CompanyVerifyOutcome.NotCompanyToken;

        if (!pending.IsUsableAt(DateTime.UtcNow))
        {
            await db.PendingCompanySignups.Where(p => p.Id == pending.Id).ExecuteDeleteAsync(ct);
            logger.LogWarning("AUDIT AuthEvent=CompanyVerifyFailed Reason=Expired");
            return CompanyVerifyOutcome.Invalid;
        }

        var domain = WorkEmailPolicy.DomainOf(pending.Email);
        // The lookups are authoritative at verification (AUTH-01-12). A failure here leaves the row alone.
        var lookup = await LookupAsync(domain, pending.CompanyName, pending.TaxCode, ct);
        if (lookup is null)
            return CompanyVerifyOutcome.Unavailable;

        // Claim the row before any write. Only one request can delete it, so a concurrent second use stops here.
        var claimed = await db.PendingCompanySignups.Where(p => p.Id == pending.Id && p.TokenHash == hash).ExecuteDeleteAsync(ct);
        if (claimed == 0)
        {
            logger.LogWarning("AUDIT AuthEvent=CompanyVerifyFailed Reason=AlreadyUsed");
            return CompanyVerifyOutcome.Invalid;
        }

        var matchedCompanyId = lookup.MatchedCompanyId;
        var accountExists = await db.Users.AnyAsync(u => u.Email == pending.Email, ct);
        if (accountExists || (matchedCompanyId is null && !lookup.Available))
        {
            // Taken since sign-up: the row is already gone, so the notice is the only effect.
            logger.LogInformation("AUDIT AuthEvent=CompanyVerifyNotice Email={Email} AccountExists={AccountExists}", LogRedaction.MaskEmail(pending.Email), accountExists);
            QueueNotice(pending.Email);
            await db.SaveChangesAsync(ct);
            return CompanyVerifyOutcome.Processed;
        }

        // Inactive until the Company or the join request exists (AUTH-01-10). A domain match makes a plain User;
        // a new Company makes the founding Recruiter.
        var user = new User(pending.Email, pending.PasswordHash, pending.FullName, matchedCompanyId is null ? "Recruiter" : "User");
        user.Deactivate();
        db.Users.Add(user);
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (PersistenceErrors.IsUniqueViolation(ex))
        {
            // Another registration took the address after the check. Same as a notice case.
            db.ChangeTracker.Clear();
            logger.LogWarning(ex, "AUDIT AuthEvent=CompanyVerifyNotice Reason=EmailTaken Email={Email}", LogRedaction.MaskEmail(pending.Email));
            QueueNotice(pending.Email);
            await db.SaveChangesAsync(ct);
            return CompanyVerifyOutcome.Processed;
        }

        Guid? companyId = null;
        try
        {
            if (matchedCompanyId is { } existingCompanyId)
                await directory.CreateJoinRequestAsync(user.Id, existingCompanyId, ct);
            else
                companyId = await directory.CreateCompanyAsync(pending.CompanyName, pending.TaxCode, user.Id, domain, ct);
        }
        catch (CompanyAlreadyExistsException ex)
        {
            // Taken between the lookup and the create. The request is settled as a notice.
            logger.LogWarning(ex, "AUDIT AuthEvent=CompanyVerifyNotice Reason=TakenSinceLookup UserId={UserId}", user.Id);
            await RemoveInactiveUserAsync(user.Id, ct);
            QueueNotice(pending.Email);
            await db.SaveChangesAsync(ct);
            return CompanyVerifyOutcome.Processed;
        }
        catch (CompanyDirectoryUnavailableException ex)
        {
            // Nothing was created: remove the user and restore the row, so the same link works until it expires.
            logger.LogWarning(ex, "AUDIT AuthEvent=CompanyVerifyUnavailable UserId={UserId}", user.Id);
            await RemoveInactiveUserAsync(user.Id, ct);
            await RestorePendingAsync(pending, ct);
            return CompanyVerifyOutcome.Unavailable;
        }

        user.Activate();
        user.VerifyEmail();
        if (companyId is { } createdCompanyId)
            user.LinkCompany(createdCompanyId);
        await db.SaveChangesAsync(ct);

        logger.LogInformation("AUDIT AuthEvent=CompanyVerifySuccess UserId={UserId} CompanyCreated={CompanyCreated}", user.Id, companyId is not null);
        return CompanyVerifyOutcome.Processed;
    }

    /// <summary>Both lookups, run together. Null when either failed: the caller stores nothing and fails closed.</summary>
    private async Task<Lookup?> LookupAsync(string domain, string companyName, string? taxCode, CancellationToken ct)
    {
        try
        {
            var domainTask = directory.FindVerifiedCompanyIdAsync(domain, ct);
            var availabilityTask = directory.IsAvailableAsync(companyName, taxCode, ct);
            await Task.WhenAll(domainTask, availabilityTask);
            return new Lookup(domainTask.Result, availabilityTask.Result);
        }
        catch (CompanyDirectoryUnavailableException ex)
        {
            logger.LogWarning(ex, "AUDIT AuthEvent=CompanyLookupUnavailable");
            return null;
        }
    }

    /// <summary>Deletes the user only while it is still inactive, so an active account is never removed here.</summary>
    private async Task RemoveInactiveUserAsync(Guid userId, CancellationToken ct)
    {
        db.ChangeTracker.Clear();
        await db.Users.Where(u => u.Id == userId && !u.IsActive).ExecuteDeleteAsync(ct);
    }

    /// <summary>Puts back the claimed row with the same id and token, so the same link works again.</summary>
    private async Task RestorePendingAsync(PendingCompanySignup pending, CancellationToken ct)
    {
        db.ChangeTracker.Clear();
        db.PendingCompanySignups.Add(pending);
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (PersistenceErrors.IsUniqueViolation(ex))
        {
            // A newer sign-up for the address now holds the slot, so this link is superseded.
            db.ChangeTracker.Clear();
            logger.LogWarning(ex, "AUDIT AuthEvent=CompanyVerifyRestoreSuperseded");
        }
    }

    private void QueueNotice(string email) =>
        db.EmailOutboxMessages.Add(EmailOutboxMessage.Create(EmailKind.CompanySignUpNotice, email, DateTime.UtcNow));

    private string VerifyLink(string plainToken) => $"{WebUrl()}/verify-email?token={Uri.EscapeDataString(plainToken)}";

    private static string? NormalizeTaxCode(string? taxCode)
    {
        var trimmed = taxCode?.Trim();
        return string.IsNullOrEmpty(trimmed) ? null : trimmed;
    }

    private string WebUrl() => (config["WEB_URL"] ?? config["WebUrl"] ?? "http://localhost:5173").TrimEnd('/');

    private sealed record Lookup(Guid? MatchedCompanyId, bool Available);
}
