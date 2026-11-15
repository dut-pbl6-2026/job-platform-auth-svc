using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

/// <summary>
/// Polls the outbox. Every failure inside a run is logged and the loop continues: an exception that
/// escaped <c>ExecuteAsync</c> would stop the host.
/// </summary>
public sealed class EmailOutboxWorker(EmailOutboxDispatcher dispatcher, ILogger<EmailOutboxWorker> logger) : BackgroundService
{
    public static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(PollInterval);
        try
        {
            do
            {
                await DispatchSafelyAsync(stoppingToken);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Host shutdown.
        }
    }

    private async Task DispatchSafelyAsync(CancellationToken ct)
    {
        try
        {
            await dispatcher.DispatchOnceAsync(DateTime.UtcNow, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Auth email outbox run failed; rows stay pending and the next run retries them");
        }
    }
}
