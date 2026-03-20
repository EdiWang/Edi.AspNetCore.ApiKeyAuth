using Edi.AspNetCore.ApiKeyAuth.Models;
using Edi.AspNetCore.ApiKeyAuth.Security;
using Edi.AspNetCore.ApiKeyAuth.Services;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace Edi.AspNetCore.ApiKeyAuth.Tests.Services;

public class ApiKeyValidationServiceTests
{
    private readonly Mock<IApiKeyHasher> _hasher;
    private readonly Mock<IRateLimitService> _rateLimitService;
    private readonly Mock<ILogger<ApiKeyValidationService>> _logger;
    private readonly Mock<IOptionsMonitor<ApiKeyAuthenticationSchemeOptions>> _schemeOptions;
    private readonly ApiKeyAuthenticationSchemeOptions _options;

    public ApiKeyValidationServiceTests()
    {
        _hasher = new Mock<IApiKeyHasher>();
        _rateLimitService = new Mock<IRateLimitService>();
        _logger = new Mock<ILogger<ApiKeyValidationService>>();
        _schemeOptions = new Mock<IOptionsMonitor<ApiKeyAuthenticationSchemeOptions>>();

        _options = new ApiKeyAuthenticationSchemeOptions();
        _schemeOptions.Setup(x => x.Get(ApiKeyAuthenticationSchemeOptions.DefaultScheme)).Returns(_options);
    }

    private ApiKeyValidationService CreateService(params ApiKeyConfig[] apiKeys)
    {
        var configData = new Dictionary<string, string?>();
        for (int i = 0; i < apiKeys.Length; i++)
        {
            var prefix = $"ApiKeys:{i}";
            var cfg = apiKeys[i];
            configData[$"{prefix}:Identifier"] = cfg.Identifier;
            configData[$"{prefix}:Key"] = cfg.Key;
            configData[$"{prefix}:IsActive"] = cfg.IsActive.ToString();

            if (!string.IsNullOrEmpty(cfg.HashedKey))
                configData[$"{prefix}:HashedKey"] = cfg.HashedKey;

            if (cfg.ExpiresAt.HasValue)
                configData[$"{prefix}:ExpiresAt"] = cfg.ExpiresAt.Value.ToString("s");

            for (int j = 0; j < cfg.Roles.Length; j++)
                configData[$"{prefix}:Roles:{j}"] = cfg.Roles[j];

            for (int j = 0; j < cfg.Scopes.Length; j++)
                configData[$"{prefix}:Scopes:{j}"] = cfg.Scopes[j];

            if (cfg.IpWhitelist != null)
            {
                configData[$"{prefix}:IpWhitelist:Enabled"] = cfg.IpWhitelist.Enabled.ToString();
                for (int j = 0; j < cfg.IpWhitelist.AllowedIpAddresses.Length; j++)
                    configData[$"{prefix}:IpWhitelist:AllowedIpAddresses:{j}"] = cfg.IpWhitelist.AllowedIpAddresses[j];
                for (int j = 0; j < cfg.IpWhitelist.AllowedCidrRanges.Length; j++)
                    configData[$"{prefix}:IpWhitelist:AllowedCidrRanges:{j}"] = cfg.IpWhitelist.AllowedCidrRanges[j];
            }
        }

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        var cache = new MemoryCache(Options.Create(new MemoryCacheOptions()));

        return new ApiKeyValidationService(
            configuration,
            _logger.Object,
            cache,
            _hasher.Object,
            _rateLimitService.Object,
            _schemeOptions.Object);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ValidateApiKeyAsync_NullOrEmptyApiKey_ReturnsInvalid(string? apiKey)
    {
        var service = CreateService();

        var result = await service.ValidateApiKeyAsync(apiKey!);

        Assert.False(result.IsValid);
        Assert.Equal("API key is required", result.FailureReason);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_ValidPlainTextKey_ReturnsSuccess()
    {
        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "test-user",
            Key = "my-secret-key",
            IsActive = true,
            Roles = ["Admin"],
            Scopes = ["read", "write"]
        });

        var result = await service.ValidateApiKeyAsync("my-secret-key", "127.0.0.1");

        Assert.True(result.IsValid);
        Assert.Equal("test-user", result.Identifier);
        Assert.Contains("Admin", result.Roles);
        Assert.Contains("read", result.Scopes);
        Assert.Contains("write", result.Scopes);
        Assert.NotNull(result.ApiKeyConfig);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_ValidHashedKey_ReturnsSuccess()
    {
        _hasher.Setup(h => h.VerifyApiKey("my-secret-key", "hashed-value"))
            .Returns(true);

        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "hashed-user",
            Key = "",
            HashedKey = "hashed-value",
            IsActive = true,
            Roles = ["User"],
            Scopes = ["read"]
        });

        var result = await service.ValidateApiKeyAsync("my-secret-key", "127.0.0.1");

        Assert.True(result.IsValid);
        Assert.Equal("hashed-user", result.Identifier);
        _hasher.Verify(h => h.VerifyApiKey("my-secret-key", "hashed-value"), Times.Once);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_NoMatchingKey_ReturnsInvalid()
    {
        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "test-user",
            Key = "correct-key",
            IsActive = true
        });

        var result = await service.ValidateApiKeyAsync("wrong-key", "127.0.0.1");

        Assert.False(result.IsValid);
        Assert.Equal("Invalid API key", result.FailureReason);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_InactiveKey_ReturnsInvalid()
    {
        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "inactive-user",
            Key = "my-key",
            IsActive = false
        });

        var result = await service.ValidateApiKeyAsync("my-key", "127.0.0.1");

        Assert.False(result.IsValid);
        Assert.Equal("API key is disabled", result.FailureReason);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_ExpiredKey_ReturnsInvalid()
    {
        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "expired-user",
            Key = "my-key",
            IsActive = true,
            ExpiresAt = new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc)
        });

        var result = await service.ValidateApiKeyAsync("my-key", "127.0.0.1");

        Assert.False(result.IsValid);
        Assert.Equal("API key has expired", result.FailureReason);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_NotExpiredKey_ReturnsSuccess()
    {
        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "valid-user",
            Key = "my-key",
            IsActive = true,
            ExpiresAt = new DateTime(2099, 1, 1, 0, 0, 0, DateTimeKind.Utc)
        });

        var result = await service.ValidateApiKeyAsync("my-key", "127.0.0.1");

        Assert.True(result.IsValid);
        Assert.Equal("valid-user", result.Identifier);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_IpWhitelistEnabled_AllowedIp_ReturnsSuccess()
    {
        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "ip-user",
            Key = "my-key",
            IsActive = true,
            IpWhitelist = new IpWhitelistConfig
            {
                Enabled = true,
                AllowedIpAddresses = ["192.168.1.100"],
                AllowedCidrRanges = []
            }
        });

        var result = await service.ValidateApiKeyAsync("my-key", "192.168.1.100");

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_IpWhitelistEnabled_BlockedIp_ReturnsInvalid()
    {
        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "ip-user",
            Key = "my-key",
            IsActive = true,
            IpWhitelist = new IpWhitelistConfig
            {
                Enabled = true,
                AllowedIpAddresses = ["192.168.1.100"],
                AllowedCidrRanges = []
            }
        });

        var result = await service.ValidateApiKeyAsync("my-key", "10.0.0.1");

        Assert.False(result.IsValid);
        Assert.Equal("IP address not whitelisted", result.FailureReason);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_IpWhitelistEnabled_CidrRangeMatch_ReturnsSuccess()
    {
        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "cidr-user",
            Key = "my-key",
            IsActive = true,
            IpWhitelist = new IpWhitelistConfig
            {
                Enabled = true,
                AllowedIpAddresses = [],
                AllowedCidrRanges = ["192.168.1.0/24"]
            }
        });

        var result = await service.ValidateApiKeyAsync("my-key", "192.168.1.50");

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_IpWhitelistEnabled_CidrRangeNoMatch_ReturnsInvalid()
    {
        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "cidr-user",
            Key = "my-key",
            IsActive = true,
            IpWhitelist = new IpWhitelistConfig
            {
                Enabled = true,
                AllowedIpAddresses = [],
                AllowedCidrRanges = ["192.168.1.0/24"]
            }
        });

        var result = await service.ValidateApiKeyAsync("my-key", "10.0.0.1");

        Assert.False(result.IsValid);
        Assert.Equal("IP address not whitelisted", result.FailureReason);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_RateLimitExceeded_ReturnsInvalid()
    {
        _rateLimitService.Setup(r => r.IsRateLimitExceededAsync(
                "rate-user", It.IsAny<RateLimitConfig>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "rate-user",
            Key = "my-key",
            IsActive = true
        });

        var result = await service.ValidateApiKeyAsync("my-key", "127.0.0.1");

        Assert.False(result.IsValid);
        Assert.Equal("Rate limit exceeded", result.FailureReason);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_CachingEnabled_SecondCallUsesCache()
    {
        _options.EnableCaching = true;

        _hasher.Setup(h => h.VerifyApiKey("my-key", "hashed-value"))
            .Returns(true);

        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "cached-user",
            Key = "",
            HashedKey = "hashed-value",
            IsActive = true
        });

        // First call - should go through key matching
        await service.ValidateApiKeyAsync("my-key", "127.0.0.1");

        // Second call - should hit cache, not call hasher again
        var result = await service.ValidateApiKeyAsync("my-key", "127.0.0.1");

        Assert.True(result.IsValid);
        _hasher.Verify(h => h.VerifyApiKey("my-key", "hashed-value"), Times.Once);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_CachingDisabled_AlwaysMatchesKeys()
    {
        _options.EnableCaching = false;

        _hasher.Setup(h => h.VerifyApiKey("my-key", "hashed-value"))
            .Returns(true);

        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "no-cache-user",
            Key = "",
            HashedKey = "hashed-value",
            IsActive = true
        });

        await service.ValidateApiKeyAsync("my-key", "127.0.0.1");
        await service.ValidateApiKeyAsync("my-key", "127.0.0.1");

        _hasher.Verify(h => h.VerifyApiKey("my-key", "hashed-value"), Times.Exactly(2));
    }

    [Fact]
    public async Task ValidateApiKeyAsync_HashedKeyTakesPrecedenceOverPlainTextKey()
    {
        _hasher.Setup(h => h.VerifyApiKey("input-key", "hashed-value"))
            .Returns(true);

        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "test-user",
            Key = "plain-key",
            HashedKey = "hashed-value",
            IsActive = true
        });

        var result = await service.ValidateApiKeyAsync("input-key", "127.0.0.1");

        Assert.True(result.IsValid);
        _hasher.Verify(h => h.VerifyApiKey("input-key", "hashed-value"), Times.Once);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_IpWhitelistDisabled_AllowsAnyIp()
    {
        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "test-user",
            Key = "my-key",
            IsActive = true,
            IpWhitelist = new IpWhitelistConfig
            {
                Enabled = false,
                AllowedIpAddresses = ["192.168.1.100"]
            }
        });

        var result = await service.ValidateApiKeyAsync("my-key", "10.0.0.1");

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_IpWhitelistEnabled_NullIpAddress_AllowsAccess()
    {
        // When ipAddress is null or empty, IP whitelist check should not block
        var service = CreateService(new ApiKeyConfig
        {
            Identifier = "test-user",
            Key = "my-key",
            IsActive = true,
            IpWhitelist = new IpWhitelistConfig
            {
                Enabled = true,
                AllowedIpAddresses = ["192.168.1.100"]
            }
        });

        var result = await service.ValidateApiKeyAsync("my-key", null);

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task IsRateLimitExceededAsync_DelegatesToRateLimitService()
    {
        _rateLimitService.Setup(r => r.IsRateLimitExceededAsync("test-id", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var service = CreateService();

        var result = await service.IsRateLimitExceededAsync("test-id");

        Assert.True(result);
        _rateLimitService.Verify(r => r.IsRateLimitExceededAsync("test-id", It.IsAny<CancellationToken>()), Times.Once);
    }
}
