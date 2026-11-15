namespace Auth.Core.Contracts;

/// <summary>Registration error strings returned by AuthService and mapped to HTTP in AuthEndpoints.</summary>
public static class InviteCodeErrors
{
    /// <summary>Role is Recruiter and no code was sent. Maps to 400 validation on InviteCode.</summary>
    public const string Missing = "Invite code is required for Recruiter";

    /// <summary>Unknown, malformed, expired or used. One message for all of them. Maps to 422 INVITE_CODE_INVALID.</summary>
    public const string Invalid = "Invite code is invalid or has expired";

    /// <summary>job-svc unreachable or failing. Maps to 503.</summary>
    public const string Unavailable = "Invite code service is unavailable";

    public const string ErrorCode = "INVITE_CODE_INVALID";
}
