using Edi.AspNetCore.ApiKeyAuth.Models;
using Edi.AspNetCore.ApiKeyAuth.Security;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Edi.AspNetCore.ApiKeyAuth.Services;

public class ApiKeyValidationService : IApiKeyValidationService
{
    private readonly ILogger<ApiKeyValidationService> _logger;
    private readonly IMemoryCache _cache;
    private readonly IApiKeyHasher _hasher;
    private readonly IRateLimitService _rateLimitService;
    private readonly IOptionsMonitor<ApiKeyAuthenticationSchemeOptions> _schemeOptions;
    private readonly List<ApiKeyConfig> _apiKeys;

    public ApiKeyValidationService(
        IConfiguration configuration,
        ILogger<ApiKeyValidationService> logger,
        IMemoryCache cache,
        IApiKeyHasher hasher,
        IRateLimitService rateLimitService,
        IOptionsMonitor<ApiKeyAuthenticationSchemeOptions> schemeOptions)
    {
        _logger = logger;
        _cache = cache;
        _hasher = hasher;
        _rateLimitService = rateLimitService;
        _schemeOptions = schemeOptions;
        _apiKeys = configuration.GetSection("ApiKeys").Get<List<ApiKeyConfig>>() ?? [];
    }

    public async Task<ApiKeyValidationResult> ValidateApiKeyAsync(string apiKey, string ipAddress = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return new ApiKeyValidationResult { IsValid = false, FailureReason = "API key is required" };
        }

        var options = _schemeOptions.Get(ApiKeyAuthenticationSchemeOptions.DefaultScheme);
        string cacheKey = null;

        if (options.EnableCaching)
        {
            cacheKey = $"apikey_validation_{ComputeDeterministicHash(apiKey)}";
            if (_cache.TryGetValue(cacheKey, out ApiKeyConfig cachedConfig) && cachedConfig != null)
            {
                return await ValidateApiKeyConfigAsync(cachedConfig, ipAddress, cancellationToken);
            }
        }

        foreach (var config in _apiKeys)
        {
            bool isMatch = false;

            // Support both plain text (legacy) and hashed keys
            if (!string.IsNullOrEmpty(config.HashedKey))
            {
                isMatch = _hasher.VerifyApiKey(apiKey, config.HashedKey);
            }
            else if (!string.IsNullOrEmpty(config.Key))
            {
                // Use constant-time comparison to prevent timing attacks
                var configKeyBytes = Encoding.UTF8.GetBytes(config.Key);
                var apiKeyBytes = Encoding.UTF8.GetBytes(apiKey);
                isMatch = configKeyBytes.Length == apiKeyBytes.Length
                          && CryptographicOperations.FixedTimeEquals(configKeyBytes, apiKeyBytes);
            }

            if (isMatch)
            {
                if (options.EnableCaching)
                {
                    _cache.Set(cacheKey, config, options.CacheDuration);
                }
                return await ValidateApiKeyConfigAsync(config, ipAddress, cancellationToken);
            }
        }

        _logger.LogWarning("Invalid API key attempt from IP: {IpAddress}", ipAddress);
        return new ApiKeyValidationResult { IsValid = false, FailureReason = "Invalid API key" };
    }

    private async Task<ApiKeyValidationResult> ValidateApiKeyConfigAsync(ApiKeyConfig config, string ipAddress, CancellationToken cancellationToken)
    {
        // Check if API key is active
        if (!config.IsActive)
        {
            return new ApiKeyValidationResult { IsValid = false, FailureReason = "API key is disabled" };
        }

        // Check expiration
        if (config.ExpiresAt.HasValue && config.ExpiresAt.Value < DateTime.UtcNow)
        {
            return new ApiKeyValidationResult { IsValid = false, FailureReason = "API key has expired" };
        }

        // Check IP whitelist
        if (config.IpWhitelist?.Enabled == true && !string.IsNullOrEmpty(ipAddress))
        {
            if (!IsIpWhitelisted(ipAddress, config.IpWhitelist))
            {
                _logger.LogWarning("API key {Identifier} attempted access from non-whitelisted IP: {IpAddress}", config.Identifier, ipAddress);
                return new ApiKeyValidationResult { IsValid = false, FailureReason = "IP address not whitelisted" };
            }
        }

        // Check rate limits using per-key configuration
        if (await _rateLimitService.IsRateLimitExceededAsync(config.Identifier, config.RateLimit, cancellationToken))
        {
            return new ApiKeyValidationResult { IsValid = false, FailureReason = "Rate limit exceeded" };
        }

        return new ApiKeyValidationResult
        {
            IsValid = true,
            Identifier = config.Identifier,
            Roles = config.Roles,
            Scopes = config.Scopes,
            ApiKeyConfig = config
        };
    }

    public async Task<bool> IsRateLimitExceededAsync(string identifier, CancellationToken cancellationToken = default)
    {
        return await _rateLimitService.IsRateLimitExceededAsync(identifier, cancellationToken);
    }

    private static bool IsIpWhitelisted(string ipAddress, IpWhitelistConfig whitelist)
    {
        if (IPAddress.TryParse(ipAddress, out var ip))
        {
            // Check exact IP matches
            if (whitelist.AllowedIpAddresses.Contains(ipAddress))
                return true;

            // Check CIDR ranges
            foreach (var cidr in whitelist.AllowedCidrRanges)
            {
                if (IsIpInCidrRange(ip, cidr))
                    return true;
            }
        }
        return false;
    }

    private static bool IsIpInCidrRange(IPAddress ipAddress, string cidrRange)
    {
        var parts = cidrRange.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var networkAddress) || !int.TryParse(parts[1], out var prefixLength))
            return false;

        var ipBytes = ipAddress.GetAddressBytes();
        var networkBytes = networkAddress.GetAddressBytes();

        if (ipBytes.Length != networkBytes.Length)
            return false;

        var bytesToCheck = prefixLength / 8;
        var bitsToCheck = prefixLength % 8;

        for (int i = 0; i < bytesToCheck; i++)
        {
            if (ipBytes[i] != networkBytes[i])
                return false;
        }

        if (bitsToCheck > 0 && bytesToCheck < ipBytes.Length)
        {
            var mask = (byte)(0xFF << (8 - bitsToCheck));
            return (ipBytes[bytesToCheck] & mask) == (networkBytes[bytesToCheck] & mask);
        }

        return true;
    }

    /// <summary>
    /// Compute a deterministic hash for use as a cache key.
    /// Unlike PBKDF2 (which uses random salt), SHA256 always produces the same output for the same input.
    /// </summary>
    private static string ComputeDeterministicHash(string input)
    {
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hashBytes);
    }
}