using Edi.AspNetCore.ApiKeyAuth.Models;
using Edi.AspNetCore.ApiKeyAuth.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Edi.AspNetCore.ApiKeyAuth.Services;

public class ApiKeyValidationService : IApiKeyValidationService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<ApiKeyValidationService> _logger;
    private readonly IMemoryCache _cache;
    private readonly IApiKeyHasher _hasher;
    private readonly IRateLimitService _rateLimitService;

    public ApiKeyValidationService(
        IConfiguration configuration,
        ILogger<ApiKeyValidationService> logger,
        IMemoryCache cache,
        IApiKeyHasher hasher,
        IRateLimitService rateLimitService)
    {
        _configuration = configuration;
        _logger = logger;
        _cache = cache;
        _hasher = hasher;
        _rateLimitService = rateLimitService;
    }

    public async Task<ApiKeyValidationResult> ValidateApiKeyAsync(string apiKey, string ipAddress = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return new ApiKeyValidationResult { IsValid = false, FailureReason = "API key is required" };
        }

        // Use caching to improve performance
        var cacheKey = $"apikey_validation_{_hasher.HashApiKey(apiKey)}";
        if (_cache.TryGetValue(cacheKey, out ApiKeyConfig cachedConfig) && cachedConfig != null)
        {
            return await ValidateApiKeyConfigAsync(cachedConfig, apiKey, ipAddress, cancellationToken);
        }

        var apiKeys = _configuration.GetSection("ApiKeys").Get<List<ApiKeyConfig>>() ?? [];
        
        foreach (var config in apiKeys)
        {
            bool isMatch = false;
            
            // Support both plain text (legacy) and hashed keys
            if (!string.IsNullOrEmpty(config.HashedKey))
            {
                isMatch = _hasher.VerifyApiKey(apiKey, config.HashedKey);
            }
            else if (!string.IsNullOrEmpty(config.Key))
            {
                isMatch = config.Key == apiKey;
            }

            if (isMatch)
            {
                _cache.Set(cacheKey, config, TimeSpan.FromMinutes(5));
                return await ValidateApiKeyConfigAsync(config, apiKey, ipAddress, cancellationToken);
            }
        }

        _logger.LogWarning("Invalid API key attempt from IP: {IpAddress}", ipAddress);
        return new ApiKeyValidationResult { IsValid = false, FailureReason = "Invalid API key" };
    }

    private async Task<ApiKeyValidationResult> ValidateApiKeyConfigAsync(ApiKeyConfig config, string apiKey, string ipAddress, CancellationToken cancellationToken)
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

        // Check rate limits
        if (await IsRateLimitExceededAsync(config.Identifier, cancellationToken))
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

    public async Task UpdateLastUsedAsync(string identifier, CancellationToken cancellationToken = default)
    {
        // In a real implementation, this would update a database
        // For now, we'll use memory cache
        var cacheKey = $"last_used_{identifier}";
        _cache.Set(cacheKey, DateTime.UtcNow, TimeSpan.FromHours(24));
        await Task.CompletedTask;
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
}