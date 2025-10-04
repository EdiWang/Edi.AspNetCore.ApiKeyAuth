using Microsoft.Extensions.Caching.Memory;
using System.Collections.Concurrent;

namespace Edi.AspNetCore.ApiKeyAuth.Services;

public class MemoryRateLimitService : IRateLimitService
{
    private readonly IMemoryCache _cache;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _semaphores = new();

    public MemoryRateLimitService(IMemoryCache cache)
    {
        _cache = cache;
    }

    public async Task<bool> IsRateLimitExceededAsync(string identifier, CancellationToken cancellationToken = default)
    {
        var semaphore = _semaphores.GetOrAdd(identifier, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(cancellationToken);

        try
        {
            var now = DateTime.UtcNow;
            var minuteKey = $"rate_limit_minute_{identifier}_{now:yyyyMMddHHmm}";
            var hourKey = $"rate_limit_hour_{identifier}_{now:yyyyMMddHH}";
            var dayKey = $"rate_limit_day_{identifier}_{now:yyyyMMdd}";

            var minuteCount = _cache.GetOrCreate(minuteKey, entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1);
                return 0;
            });

            var hourCount = _cache.GetOrCreate(hourKey, entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1);
                return 0;
            });

            var dayCount = _cache.GetOrCreate(dayKey, entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(1);
                return 0;
            });

            // For simplicity, using default limits. In production, these should come from configuration
            return minuteCount >= 60 || hourCount >= 1000 || dayCount >= 10000;
        }
        finally
        {
            semaphore.Release();
        }
    }

    public async Task IncrementUsageAsync(string identifier, CancellationToken cancellationToken = default)
    {
        var semaphore = _semaphores.GetOrAdd(identifier, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(cancellationToken);

        try
        {
            var now = DateTime.UtcNow;
            var minuteKey = $"rate_limit_minute_{identifier}_{now:yyyyMMddHHmm}";
            var hourKey = $"rate_limit_hour_{identifier}_{now:yyyyMMddHH}";
            var dayKey = $"rate_limit_day_{identifier}_{now:yyyyMMdd}";

            IncrementCacheValue(minuteKey, TimeSpan.FromMinutes(1));
            IncrementCacheValue(hourKey, TimeSpan.FromHours(1));
            IncrementCacheValue(dayKey, TimeSpan.FromDays(1));
        }
        finally
        {
            semaphore.Release();
        }
    }

    private void IncrementCacheValue(string key, TimeSpan expiration)
    {
        var currentValue = _cache.Get<int>(key);
        _cache.Set(key, currentValue + 1, expiration);
    }
}