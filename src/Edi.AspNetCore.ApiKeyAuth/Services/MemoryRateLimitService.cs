using System.Collections.Concurrent;
using System.Threading.RateLimiting;
using Edi.AspNetCore.ApiKeyAuth.Models;

namespace Edi.AspNetCore.ApiKeyAuth.Services;

public class MemoryRateLimitService : IRateLimitService, IDisposable
{
    private static readonly RateLimitConfig DefaultConfig = new();
    private readonly ConcurrentDictionary<string, RateLimiterEntry> _limiters = new();
    private bool _disposed;

    public Task<bool> IsRateLimitExceededAsync(string identifier, CancellationToken cancellationToken = default)
        => IsRateLimitExceededAsync(identifier, null, cancellationToken);

    public async Task<bool> IsRateLimitExceededAsync(string identifier, RateLimitConfig config, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var effectiveConfig = config ?? DefaultConfig;
        var entry = _limiters.GetOrAdd(identifier, _ => CreateEntry(effectiveConfig));

        var minuteResult = await entry.MinuteLimiter.AcquireAsync(1, cancellationToken);
        if (!minuteResult.IsAcquired)
            return true;

        var hourResult = await entry.HourLimiter.AcquireAsync(1, cancellationToken);
        if (!hourResult.IsAcquired)
            return true;

        var dayResult = await entry.DayLimiter.AcquireAsync(1, cancellationToken);
        return !dayResult.IsAcquired;
    }

    public Task IncrementUsageAsync(string identifier, CancellationToken cancellationToken = default)
    {
        // The usage is already incremented in IsRateLimitExceededAsync when permits are acquired
        return Task.CompletedTask;
    }

    private static RateLimiterEntry CreateEntry(RateLimitConfig config)
    {
        return new RateLimiterEntry(
            new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions
            {
                PermitLimit = config.RequestsPerMinute,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }),
            new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions
            {
                PermitLimit = config.RequestsPerHour,
                Window = TimeSpan.FromHours(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            }),
            new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions
            {
                PermitLimit = config.RequestsPerDay,
                Window = TimeSpan.FromDays(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            })
        );
    }

    public void Dispose()
    {
        _disposed = true;
        foreach (var entry in _limiters.Values)
        {
            entry.Dispose();
        }
        _limiters.Clear();
    }

    private sealed class RateLimiterEntry(
        FixedWindowRateLimiter minuteLimiter,
        FixedWindowRateLimiter hourLimiter,
        FixedWindowRateLimiter dayLimiter) : IDisposable
    {
        public FixedWindowRateLimiter MinuteLimiter => minuteLimiter;
        public FixedWindowRateLimiter HourLimiter => hourLimiter;
        public FixedWindowRateLimiter DayLimiter => dayLimiter;

        public void Dispose()
        {
            minuteLimiter.Dispose();
            hourLimiter.Dispose();
            dayLimiter.Dispose();
        }
    }
}