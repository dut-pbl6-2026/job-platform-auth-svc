using System.Globalization;
using Auth.Core.Interfaces;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using SharedKernel;

namespace Auth.Infrastructure.Services;

public sealed class TokenRevocationStore : ITokenRevocationStore
{
    // Shared with the gateway — must stay in sync across services.
    private const string KeyPrefix = "job-platform:auth:revoked-after:";

    private readonly IDistributedCache _cache;
    private readonly JwtOptions _jwt;

    public TokenRevocationStore(IDistributedCache cache, IOptions<JwtOptions> jwt)
    {
        _cache = cache;
        _jwt = jwt.Value;
    }

    public Task RevokeUserTokensAsync(Guid userId, DateTimeOffset revokedAt, CancellationToken ct = default) =>
        _cache.SetStringAsync(
            KeyFor(userId),
            revokedAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(_jwt.ExpiresMinutes + 5)
            },
            ct);

    public async Task<DateTimeOffset?> GetRevokedAfterAsync(Guid userId, CancellationToken ct = default)
    {
        var raw = await _cache.GetStringAsync(KeyFor(userId), ct);
        return long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
    }

    public static string KeyFor(Guid userId) => $"{KeyPrefix}{userId:D}";
}
