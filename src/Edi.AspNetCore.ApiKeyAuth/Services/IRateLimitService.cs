using Edi.AspNetCore.ApiKeyAuth.Models;

namespace Edi.AspNetCore.ApiKeyAuth.Services;

public interface IRateLimitService
{
    Task<bool> IsRateLimitExceededAsync(string identifier, CancellationToken cancellationToken = default);
    Task<bool> IsRateLimitExceededAsync(string identifier, RateLimitConfig config, CancellationToken cancellationToken = default);
    Task IncrementUsageAsync(string identifier, CancellationToken cancellationToken = default);
}