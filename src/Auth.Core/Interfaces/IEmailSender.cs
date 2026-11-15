using Auth.Core.Entities;

namespace Auth.Core.Interfaces;

/// <summary>
/// Delivers one outbox message. Implementations throw when delivery fails: the outbox dispatcher
/// records the failure, keeps the row and retries it later. Nothing here is called from a request.
/// </summary>
public interface IEmailSender
{
    Task SendAsync(EmailOutboxMessage message, CancellationToken ct = default);
}
