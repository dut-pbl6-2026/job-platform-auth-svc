using Auth.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Auth.Infrastructure.Services;

public class ExpiredTokenPurgeService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<ExpiredTokenPurgeService> _logger;
    private readonly TimeSpan _interval = TimeSpan.FromHours(24);

    public ExpiredTokenPurgeService(IServiceScopeFactory scopeFactory, ILogger<ExpiredTokenPurgeService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(_interval);
        // Initial delay to avoid competing with startup migrate
        try { await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken); } catch { return; }
        do
        {
            try { await PurgeOnce(stoppingToken); }
            catch (Exception ex) { _logger.LogError(ex, "Purge expired tokens failed"); }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    public async Task PurgeOnce(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
        var now = DateTime.UtcNow;
        var expiredRefresh = await db.RefreshTokens.Where(x => x.ExpiresAt < now).ExecuteDeleteAsync(ct);
        var expiredReset = await db.PasswordResetTokens.Where(x => x.ExpiresAt < now || x.IsUsed).ExecuteDeleteAsync(ct);
        if (expiredRefresh > 0 || expiredReset > 0)
            _logger.LogInformation("AUDIT Purge ExpiredRefresh={Refresh} ResetTokens={Reset}", expiredRefresh, expiredReset);
    }
}
