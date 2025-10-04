using Edi.AspNetCore.ApiKeyAuth.Models;

namespace Edi.AspNetCore.ApiKeyAuth.Services;

public interface IApiKeyValidationService
{
    Task<ApiKeyValidationResult> ValidateApiKeyAsync(string apiKey, string ipAddress = null, CancellationToken cancellationToken = default);
    Task<bool> IsRateLimitExceededAsync(string identifier, CancellationToken cancellationToken = default);
    Task UpdateLastUsedAsync(string identifier, CancellationToken cancellationToken = default);
}

public class ApiKeyValidationResult
{
    public bool IsValid { get; set; }
    public string Identifier { get; set; }
    public string[] Roles { get; set; } = [];
    public string[] Scopes { get; set; } = [];
    public string FailureReason { get; set; }
    public ApiKeyConfig ApiKeyConfig { get; set; }
}