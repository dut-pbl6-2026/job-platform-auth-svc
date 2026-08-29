using System.Security.Claims;
using System.Text.RegularExpressions;
using Auth.Api.Dtos;
using Auth.Core.Entities;
using Auth.Infrastructure.Data;
using Auth.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace Auth.Api.Endpoints;

public static class AuthEndpoints
{
    private static readonly Regex PasswordRegex = new(@"^(?=.*[A-Z])(?=.*\d).{8,}$", RegexOptions.Compiled);

    public static void MapAuthEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/auth").WithTags("Auth");

        group.MapPost("/register", async (RegisterRequest req, AuthDbContext db, PasswordHasherService hasher, JwtTokenService jwt) =>
        {
            if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password) || string.IsNullOrWhiteSpace(req.FullName))
                return Results.BadRequest(new { message = "Email, password and fullName are required" });

            if (!IsValidEmail(req.Email))
                return Results.BadRequest(new { message = "Invalid email format" });

            if (!PasswordRegex.IsMatch(req.Password))
                return Results.BadRequest(new { message = "Password must be 8+ chars, 1 uppercase, 1 number" });

            var email = req.Email.ToLowerInvariant();
            if (await db.Users.AnyAsync(u => u.Email == email))
                return Results.Conflict(new { message = "Email already registered" });

            var role = string.IsNullOrWhiteSpace(req.Role) ? "User" : req.Role;
            var allowedRoles = new[] { "User", "Employer", "Admin" };
            if (!allowedRoles.Contains(role))
                role = "User";

            var hash = hasher.Hash(req.Password);
            var user = new User(email, hash, req.FullName.Trim(), role);
            db.Users.Add(user);

            var refreshRaw = jwt.GenerateRefreshToken();
            var refreshHash = jwt.HashToken(refreshRaw);
            var refresh = new RefreshToken(user.Id, refreshHash, DateTime.UtcNow.AddDays(30));
            db.RefreshTokens.Add(refresh);

            await db.SaveChangesAsync();

            var access = jwt.GenerateAccessToken(user.Id, user.Email, user.Role);
            return Results.Created($"/api/auth/me", new AuthResponse(access, refreshRaw, user.Id, user.Email, user.FullName, user.Role));
        });

        group.MapPost("/login", async (LoginRequest req, AuthDbContext db, PasswordHasherService hasher, JwtTokenService jwt) =>
        {
            if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
                return Results.BadRequest(new { message = "Email and password required" });

            var email = req.Email.ToLowerInvariant();
            var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user is null || !hasher.Verify(req.Password, user.PasswordHash))
                return Results.Unauthorized();

            if (!user.IsActive)
                return Results.Forbid();

            // revoke old? keep multiple devices; create new refresh
            var refreshRaw = jwt.GenerateRefreshToken();
            var refreshHash = jwt.HashToken(refreshRaw);
            var refresh = new RefreshToken(user.Id, refreshHash, DateTime.UtcNow.AddDays(30));
            db.RefreshTokens.Add(refresh);
            user.RecordLogin();
            await db.SaveChangesAsync();

            var access = jwt.GenerateAccessToken(user.Id, user.Email, user.Role);
            return Results.Ok(new AuthResponse(access, refreshRaw, user.Id, user.Email, user.FullName, user.Role));
        });

        group.MapPost("/refresh", async (RefreshRequest req, AuthDbContext db, JwtTokenService jwt) =>
        {
            if (string.IsNullOrWhiteSpace(req.RefreshToken))
                return Results.BadRequest(new { message = "Refresh token required" });

            var hash = jwt.HashToken(req.RefreshToken);
            var stored = await db.RefreshTokens.FirstOrDefaultAsync(r => r.TokenHash == hash);

            if (stored is null || stored.IsRevoked || stored.IsExpired)
                return Results.Unauthorized();

            // rotation: revoke old, issue new
            stored.Revoke();
            var newRaw = jwt.GenerateRefreshToken();
            var newHash = jwt.HashToken(newRaw);
            var newToken = new RefreshToken(stored.UserId, newHash, DateTime.UtcNow.AddDays(30));
            db.RefreshTokens.Add(newToken);

            var user = await db.Users.FindAsync(stored.UserId);
            if (user is null) return Results.Unauthorized();

            await db.SaveChangesAsync();
            var access = jwt.GenerateAccessToken(user.Id, user.Email, user.Role);
            return Results.Ok(new { accessToken = access, refreshToken = newRaw });
        });

        group.MapPost("/logout", async (LogoutRequest req, AuthDbContext db, JwtTokenService jwt) =>
        {
            if (string.IsNullOrWhiteSpace(req.RefreshToken))
                return Results.BadRequest(new { message = "Refresh token required" });

            var hash = jwt.HashToken(req.RefreshToken);
            var stored = await db.RefreshTokens.FirstOrDefaultAsync(r => r.TokenHash == hash);
            if (stored is not null && !stored.IsRevoked)
            {
                stored.Revoke();
                await db.SaveChangesAsync();
            }
            return Results.Ok(new { message = "Logged out" });
        });

        // Alternative logout-all: revoke family when reuse detected is already partially via refresh rotation.
        // Add logout-all for completeness
        group.MapPost("/logout-all", async (ClaimsPrincipal userPrincipal, AuthDbContext db) =>
        {
            var uid = GetUserId(userPrincipal);
            if (uid is null) return Results.Unauthorized();
            var tokens = await db.RefreshTokens.Where(r => r.UserId == uid && !r.IsRevoked).ToListAsync();
            foreach (var t in tokens) t.Revoke();
            await db.SaveChangesAsync();
            return Results.Ok(new { message = "All sessions revoked" });
        }).RequireAuthorization();

        group.MapGet("/me", async (ClaimsPrincipal principal, AuthDbContext db) =>
        {
            var uid = GetUserId(principal);
            if (uid is null) return Results.Unauthorized();
            var user = await db.Users.FindAsync(uid.Value);
            if (user is null) return Results.NotFound();
            return Results.Ok(new UserResponse(user.Id, user.Email, user.FullName, user.Role, user.IsActive));
        }).RequireAuthorization();

        group.MapPost("/forgot-password", async (ForgotPasswordRequest req, AuthDbContext db, JwtTokenService jwt) =>
        {
            // anti-enumeration: always return ok
            if (string.IsNullOrWhiteSpace(req.Email))
                return Results.Ok(new { message = "If email exists, reset link sent" });

            var email = req.Email.ToLowerInvariant();
            var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user is not null)
            {
                var raw = jwt.GenerateRefreshToken(); // reuse secure random
                var hash = jwt.HashToken(raw);
                var prt = new PasswordResetToken(user.Id, hash, DateTime.UtcNow.AddMinutes(15));
                db.PasswordResetTokens.Add(prt);
                await db.SaveChangesAsync();
                // In production: send email with raw token. For dev, log it.
                Console.WriteLine($"[forgot-password] user={email} token={raw} hash={hash}");
            }
            return Results.Ok(new { message = "If email exists, reset link sent" });
        });

        group.MapPost("/reset-password", async (ResetPasswordRequest req, AuthDbContext db, PasswordHasherService hasher, JwtTokenService jwt) =>
        {
            if (string.IsNullOrWhiteSpace(req.Token) || string.IsNullOrWhiteSpace(req.NewPassword))
                return Results.BadRequest(new { message = "Token and new password required" });

            if (!PasswordRegex.IsMatch(req.NewPassword))
                return Results.BadRequest(new { message = "Password must be 8+ chars, 1 uppercase, 1 number" });

            var hash = jwt.HashToken(req.Token);
            var prt = await db.PasswordResetTokens.FirstOrDefaultAsync(p => p.TokenHash == hash);
            if (prt is null || prt.IsUsed || prt.IsExpired)
                return Results.BadRequest(new { message = "Invalid or expired token" });

            var user = await db.Users.FindAsync(prt.UserId);
            if (user is null) return Results.BadRequest(new { message = "Invalid token" });

            var pwdHash = hasher.Hash(req.NewPassword);
            user.UpdatePassword(pwdHash);
            prt.MarkUsed();

            // revoke all refresh tokens per spec
            var tokens = await db.RefreshTokens.Where(r => r.UserId == user.Id && !r.IsRevoked).ToListAsync();
            foreach (var t in tokens) t.Revoke();

            await db.SaveChangesAsync();
            return Results.Ok(new { message = "Password reset successful" });
        });
    }

    private static Guid? GetUserId(ClaimsPrincipal principal)
    {
        var sub = principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? principal.FindFirstValue("sub");
        if (Guid.TryParse(sub, out var g)) return g;
        return null;
    }

    private static bool IsValidEmail(string email)
    {
        try { var a = new System.Net.Mail.MailAddress(email); return a.Address == email; }
        catch { return false; }
    }
}
