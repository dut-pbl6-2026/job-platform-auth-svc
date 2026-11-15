using System.Net;
using Auth.Core.Entities;

namespace Auth.Infrastructure.Services;

/// <summary>Subject and body for each outbox kind. Shared by the SMTP and development transports.</summary>
public static class AuthEmailContent
{
    public static (string Subject, string Html, string Text) For(EmailOutboxMessage message)
    {
        switch (message.Kind)
        {
            case EmailKind.PasswordReset:
                {
                    var link = RequireLink(message);
                    return (
                        "Reset your password — job-platform",
                        $"<p>Click <a href=\"{WebUtility.HtmlEncode(link)}\">here</a> to reset your password (15 minutes, one-time).</p><p>If you did not request this, ignore this email.</p>",
                        $"Reset your password (15m, one-time): {link}\nIf you did not request this, ignore.");
                }
            case EmailKind.EmailVerification:
                {
                    var link = RequireLink(message);
                    return (
                        "Verify your email — job-platform",
                        $"<p>Click <a href=\"{WebUtility.HtmlEncode(link)}\">here</a> to verify your email and activate your account (valid 24 hours, one-time).</p><p>If you did not register, ignore this email.</p>",
                        $"Verify your email (24h, one-time): {link}\nIf you did not register, ignore.");
                }
            case EmailKind.CompanySignUpVerification:
                {
                    var link = RequireLink(message);
                    return (
                        "Verify your work email — job-platform",
                        $"<p>Click <a href=\"{WebUtility.HtmlEncode(link)}\">here</a> to verify your work email and continue your company sign-up (valid 24 hours, one-time).</p><p>If you did not start a company sign-up, ignore this email.</p>",
                        $"Verify your work email to continue your company sign-up (24h, one-time): {link}\nIf you did not start a company sign-up, ignore.");
                }
            case EmailKind.CompanySignUpNotice:
                // Fixed text for every notice case. It names no company, no value and no link (AUTH-01-10, backlog A13).
                return (
                    "Company sign-up could not be completed — job-platform",
                    "<p>Your company could not be registered with the details you submitted, so no account was created.</p><p>If you need help, contact platform support.</p>",
                    "Your company could not be registered with the details you submitted, so no account was created. If you need help, contact platform support.");
            case EmailKind.DuplicateRegistrationNotice:
                return (
                    "Registration attempt with your email — job-platform",
                    "<p>Someone tried to register a new account with your email address. No changes were made to your account.</p><p>If this was you, log in to your existing account. If not, you can ignore this email.</p>",
                    "Someone tried to register a new account with your email address. No changes were made to your account. If this was not you, ignore this email.");
            case EmailKind.UnknownAccountResetNotice:
                return (
                    "Password reset request — job-platform",
                    "<p>A password reset was requested for your email address, but no account exists for it.</p><p>If you meant to sign up, register on the platform. If not, you can ignore this email.</p>",
                    "A password reset was requested for your email address, but no account exists for it. If you did not request this, ignore this email.");
            default:
                throw new ArgumentOutOfRangeException(nameof(message), message.Kind, "Unknown email kind");
        }
    }

    private static string RequireLink(EmailOutboxMessage message) =>
        message.Link ?? throw new InvalidOperationException($"Email kind {message.Kind} requires a link");
}
