using Auth.Core.Email;

namespace Auth.Tests;

public class EmailOutboxRetryPolicyTests
{
    private static readonly DateTime Now = new(2030, 1, 1, 12, 0, 0, DateTimeKind.Utc);

    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 2)]
    [InlineData(3, 4)]
    [InlineData(4, 8)]
    [InlineData(5, 16)]
    [InlineData(6, 30)]
    [InlineData(7, 30)]
    public void DelayDoublesEachAttemptAndCapsAtMaxDelay(int failedAttempt, int expectedMinutes)
    {
        Assert.Equal(TimeSpan.FromMinutes(expectedMinutes), EmailOutboxRetryPolicy.DelayAfterFailure(failedAttempt));
    }

    [Fact]
    public void FailureBeforeTheLastAttemptSchedulesTheNextAttempt()
    {
        var decision = EmailOutboxRetryPolicy.AfterFailure(1, Now);

        Assert.False(decision.GiveUp);
        Assert.Equal(Now.AddMinutes(1), decision.NextAttemptAt);
    }

    [Fact]
    public void FailureOnTheMaximumAttemptGivesUp()
    {
        Assert.Equal(8, EmailOutboxRetryPolicy.MaxAttempts);

        Assert.False(EmailOutboxRetryPolicy.AfterFailure(EmailOutboxRetryPolicy.MaxAttempts - 1, Now).GiveUp);
        Assert.True(EmailOutboxRetryPolicy.AfterFailure(EmailOutboxRetryPolicy.MaxAttempts, Now).GiveUp);
    }

    [Fact]
    public void ClaimLeaseOutlastsASingleSmtpOperationTimeout()
    {
        // A live worker must keep its claim for a whole send: every SMTP operation is bounded by this timeout.
        Assert.True(EmailOutboxRetryPolicy.ClaimLease > Auth.Infrastructure.Services.SmtpEmailSender.OperationTimeout * 4);
    }

    [Fact]
    public void AttemptNumbersStartAtOne()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => EmailOutboxRetryPolicy.DelayAfterFailure(0));
    }
}
