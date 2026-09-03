namespace Auth.Core.Interfaces;

public interface IEmailSender
{
    Task SendPasswordResetAsync(string email, string resetLink, CancellationToken ct = default);
}
