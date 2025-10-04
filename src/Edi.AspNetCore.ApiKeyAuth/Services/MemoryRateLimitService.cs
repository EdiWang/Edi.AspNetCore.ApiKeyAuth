using System.Threading.RateLimiting;

namespace Edi.AspNetCore.ApiKeyAuth.Services;

public class MemoryRateLimitService : IRateLimitService, IDisposable
{
    private readonly PartitionedRateLimiter<string> _minuteLimiter;
    private readonly PartitionedRateLimiter<string> _hourLimiter;
    private readonly PartitionedRateLimiter<string> _dayLimiter;

    public MemoryRateLimitService()
    {
        _minuteLimiter = PartitionedRateLimiter.Create<string, string>(
            resource => RateLimitPartition.GetFixedWindowLimiter(
                resource,
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 60,
                    Window = TimeSpan.FromMinutes(1),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0
                }));

        _hourLimiter = PartitionedRateLimiter.Create<string, string>(
            resource => RateLimitPartition.GetFixedWindowLimiter(
                resource,
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 1000,
                    Window = TimeSpan.FromHours(1),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0
                }));

        _dayLimiter = PartitionedRateLimiter.Create<string, string>(
            resource => RateLimitPartition.GetFixedWindowLimiter(
                resource,
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 10000,
                    Window = TimeSpan.FromDays(1),
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = 0
                }));
    }

    public async Task<bool> IsRateLimitExceededAsync(string identifier, CancellationToken cancellationToken = default)
    {
        // Check all rate limits
        var minuteResult = await _minuteLimiter.AcquireAsync(identifier, 1, cancellationToken);
        if (!minuteResult.IsAcquired)
        {
            minuteResult.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter);
            return true;
        }

        var hourResult = await _hourLimiter.AcquireAsync(identifier, 1, cancellationToken);
        if (!hourResult.IsAcquired)
        {
            return true;
        }

        var dayResult = await _dayLimiter.AcquireAsync(identifier, 1, cancellationToken);
        if (!dayResult.IsAcquired)
        {
            return true;
        }

        return false;
    }

    public async Task IncrementUsageAsync(string identifier, CancellationToken cancellationToken = default)
    {
        // The usage is already incremented in IsRateLimitExceededAsync when permits are acquired
        // This method can be simplified or used for additional tracking if needed
        await Task.CompletedTask;
    }

    public void Dispose()
    {
        _minuteLimiter?.Dispose();
        _hourLimiter?.Dispose();
        _dayLimiter?.Dispose();
    }
}