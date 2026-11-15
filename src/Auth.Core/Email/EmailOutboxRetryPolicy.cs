namespace Auth.Core.Email;

/// <param name="GiveUp">True when no further attempt will be made.</param>
/// <param name="NextAttemptAt">When the next attempt may start. Meaningful only when <see cref="GiveUp"/> is false.</param>
public readonly record struct RetryDecision(bool GiveUp, DateTime NextAttemptAt);

/// <summary>
/// Backoff and give-up rules for the auth email outbox. Pure functions of the attempt number and the
/// current time, so the schedule can be tested without a clock or a database.
/// </summary>
/// <remarks>
/// Schedule after each failed attempt: 1, 2, 4, 8, 16 and 30 minutes, then give up on the eighth
/// failure. The total retry window is about 91 minutes. A row whose one-time link expires inside that
/// window is given up on before it is sent (see <c>EmailOutboxDispatcher</c>).
/// </remarks>
public static class EmailOutboxRetryPolicy
{
    /// <summary>Failed attempts after which a row is given up and kept with an Error log.</summary>
    public const int MaxAttempts = 8;

    public static readonly TimeSpan BaseDelay = TimeSpan.FromMinutes(1);
    public static readonly TimeSpan MaxDelay = TimeSpan.FromMinutes(30);

    /// <summary>
    /// How long a claimed row stays locked. It must exceed one SMTP send, so a live worker never loses its
    /// claim mid-send. A crashed worker's rows become claimable again after this long.
    /// </summary>
    public static readonly TimeSpan ClaimLease = TimeSpan.FromMinutes(10);

    /// <summary>Delay after the given failed attempt (1-based): doubles each time, capped at <see cref="MaxDelay"/>.</summary>
    public static TimeSpan DelayAfterFailure(int failedAttempt)
    {
        if (failedAttempt < 1)
            throw new ArgumentOutOfRangeException(nameof(failedAttempt), "Attempt numbers start at 1.");

        var seconds = BaseDelay.TotalSeconds * Math.Pow(2, failedAttempt - 1);
        return TimeSpan.FromSeconds(Math.Min(seconds, MaxDelay.TotalSeconds));
    }

    public static RetryDecision AfterFailure(int failedAttempt, DateTime utcNow)
    {
        if (failedAttempt >= MaxAttempts)
            return new RetryDecision(GiveUp: true, NextAttemptAt: utcNow);

        return new RetryDecision(GiveUp: false, NextAttemptAt: utcNow + DelayAfterFailure(failedAttempt));
    }
}
