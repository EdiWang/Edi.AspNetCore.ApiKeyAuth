using Edi.AspNetCore.ApiKeyAuth.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace Edi.AspNetCore.ApiKeyAuth.Tests;

public class ApiKeyAuthenticationHandlerTests
{
    private readonly Mock<IOptionsMonitor<ApiKeyAuthenticationSchemeOptions>> _optionsMonitor;
    private readonly Mock<ILoggerFactory> _loggerFactory;
    private readonly Mock<ILogger<ApiKeyAuthenticationHandler>> _logger;
    private readonly Mock<IApiKeyValidationService> _validationService;
    private readonly UrlEncoder _urlEncoder;
    private readonly ApiKeyAuthenticationSchemeOptions _options;
    private readonly AuthenticationScheme _scheme;

    public ApiKeyAuthenticationHandlerTests()
    {
        _optionsMonitor = new Mock<IOptionsMonitor<ApiKeyAuthenticationSchemeOptions>>();
        _loggerFactory = new Mock<ILoggerFactory>();
        _logger = new Mock<ILogger<ApiKeyAuthenticationHandler>>();
        _validationService = new Mock<IApiKeyValidationService>();
        _urlEncoder = UrlEncoder.Default;
        
        _options = new ApiKeyAuthenticationSchemeOptions();
        _scheme = new AuthenticationScheme("ApiKey", "ApiKey", typeof(ApiKeyAuthenticationHandler));

        _optionsMonitor.Setup(x => x.Get(It.IsAny<string>())).Returns(_options);
        _loggerFactory.Setup(x => x.CreateLogger(It.IsAny<string>())).Returns(_logger.Object);
    }

    private ApiKeyAuthenticationHandler CreateHandler()
    {
        return new ApiKeyAuthenticationHandler(_optionsMonitor.Object, _loggerFactory.Object, _urlEncoder, _validationService.Object);
    }

    private DefaultHttpContext CreateHttpContext()
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("localhost");
        context.Request.Path = "/api/test";
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1");
        
        // Initialize response body with a MemoryStream for testing
        context.Response.Body = new MemoryStream();
        
        return context;
    }

    [Fact]
    public async Task HandleAuthenticateAsync_NoApiKey_ReturnsFailure()
    {
        // Arrange
        var handler = CreateHandler();
        var context = CreateHttpContext();
        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal("API Key not found", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ApiKeyInAuthorizationHeader_ReturnsSuccess()
    {
        // Arrange
        var apiKey = "test-api-key-123";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers.Authorization = $"Bearer {apiKey}";
        
        var validationResult = new ApiKeyValidationResult
        {
            IsValid = true,
            Identifier = "test-user",
            Roles = new[] { "Admin", "User" },
            Scopes = new[] { "read", "write" }
        };

        _validationService.Setup(x => x.ValidateApiKeyAsync(apiKey, "127.0.0.1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.True(result.Succeeded);
        Assert.NotNull(result.Principal);
        Assert.Equal("test-user", result.Principal.Identity!.Name);
        
        var claims = result.Principal.Claims.ToList();
        Assert.Contains(claims, c => c.Type == ClaimTypes.Name && c.Value == "test-user");
        Assert.Contains(claims, c => c.Type == "ApiKey" && c.Value == apiKey);
        Assert.Contains(claims, c => c.Type == ClaimTypes.Role && c.Value == "Admin");
        Assert.Contains(claims, c => c.Type == ClaimTypes.Role && c.Value == "User");
        Assert.Contains(claims, c => c.Type == "scope" && c.Value == "read");
        Assert.Contains(claims, c => c.Type == "scope" && c.Value == "write");
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ApiKeyInXApiKeyHeader_ReturnsSuccess()
    {
        // Arrange
        var apiKey = "test-api-key-456";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers["X-API-Key"] = apiKey;
        
        var validationResult = new ApiKeyValidationResult
        {
            IsValid = true,
            Identifier = "test-user-2",
            Roles = new[] { "User" },
            Scopes = new[] { "read" }
        };

        _validationService.Setup(x => x.ValidateApiKeyAsync(apiKey, "127.0.0.1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.True(result.Succeeded);
        Assert.Equal("test-user-2", result.Principal!.Identity!.Name);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ApiKeyInApiKeyHeader_ReturnsSuccess()
    {
        // Arrange
        var apiKey = "test-api-key-789";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers["ApiKey"] = apiKey;
        
        var validationResult = new ApiKeyValidationResult
        {
            IsValid = true,
            Identifier = "test-user-3",
            Roles = Array.Empty<string>(),
            Scopes = Array.Empty<string>()
        };

        _validationService.Setup(x => x.ValidateApiKeyAsync(apiKey, "127.0.0.1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.True(result.Succeeded);
        Assert.Equal("test-user-3", result.Principal!.Identity!.Name);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ApiKeyInQueryString_WhenAllowed_ReturnsSuccess()
    {
        // Arrange
        var apiKey = "test-api-key-query";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.QueryString = new QueryString($"?apikey={apiKey}");
        
        _options.AllowQueryStringAuth = true;
        
        var validationResult = new ApiKeyValidationResult
        {
            IsValid = true,
            Identifier = "query-user",
            Roles = new[] { "User" },
            Scopes = new[] { "read" }
        };

        _validationService.Setup(x => x.ValidateApiKeyAsync(apiKey, "127.0.0.1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.True(result.Succeeded);
        Assert.Equal("query-user", result.Principal!.Identity!.Name);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ApiKeyInQueryString_WhenNotAllowed_ReturnsFailure()
    {
        // Arrange
        var apiKey = "test-api-key-query";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.QueryString = new QueryString($"?apikey={apiKey}");
        
        _options.AllowQueryStringAuth = false; // Default is false

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal("API Key not found", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidApiKey_ReturnsFailure()
    {
        // Arrange
        var apiKey = "invalid-api-key";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers["X-API-Key"] = apiKey;
        
        var validationResult = new ApiKeyValidationResult
        {
            IsValid = false,
            FailureReason = "Invalid API key"
        };

        _validationService.Setup(x => x.ValidateApiKeyAsync(apiKey, "127.0.0.1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal("Invalid API key", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ValidationServiceThrows_ReturnsFailure()
    {
        // Arrange
        var apiKey = "test-api-key";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers["X-API-Key"] = apiKey;

        _validationService.Setup(x => x.ValidateApiKeyAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Database connection failed"));

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal("Authentication error occurred", result.Failure?.Message);
    }

    [Theory]
    [InlineData("192.168.1.100")]
    [InlineData("10.0.0.50")]
    [InlineData("172.16.0.200")]
    public async Task HandleAuthenticateAsync_DifferentClientIps_PassesCorrectIpToValidationService(string clientIp)
    {
        // Arrange
        var apiKey = "test-api-key";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers["X-API-Key"] = apiKey;
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse(clientIp);
        
        var validationResult = new ApiKeyValidationResult
        {
            IsValid = true,
            Identifier = "test-user",
            Roles = Array.Empty<string>(),
            Scopes = Array.Empty<string>()
        };

        _validationService.Setup(x => x.ValidateApiKeyAsync(apiKey, clientIp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.True(result.Succeeded);
        _validationService.Verify(x => x.ValidateApiKeyAsync(apiKey, clientIp, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_XForwardedForHeader_UsesForwardedIp()
    {
        // Arrange
        var apiKey = "test-api-key";
        var forwardedIp = "203.0.113.42";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers["X-API-Key"] = apiKey;
        context.Request.Headers["X-Forwarded-For"] = $"{forwardedIp}, 192.168.1.1";
        
        var validationResult = new ApiKeyValidationResult
        {
            IsValid = true,
            Identifier = "test-user",
            Roles = Array.Empty<string>(),
            Scopes = Array.Empty<string>()
        };

        _validationService.Setup(x => x.ValidateApiKeyAsync(apiKey, forwardedIp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.True(result.Succeeded);
        _validationService.Verify(x => x.ValidateApiKeyAsync(apiKey, forwardedIp, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_XRealIpHeader_UsesRealIp()
    {
        // Arrange
        var apiKey = "test-api-key";
        var realIp = "198.51.100.25";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers["X-API-Key"] = apiKey;
        context.Request.Headers["X-Real-IP"] = realIp;
        
        var validationResult = new ApiKeyValidationResult
        {
            IsValid = true,
            Identifier = "test-user",
            Roles = Array.Empty<string>(),
            Scopes = Array.Empty<string>()
        };

        _validationService.Setup(x => x.ValidateApiKeyAsync(apiKey, realIp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.True(result.Succeeded);
        _validationService.Verify(x => x.ValidateApiKeyAsync(apiKey, realIp, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_AuthorizationHeaderWithoutBearer_IgnoresHeader()
    {
        // Arrange
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers.Authorization = "Basic dGVzdDp0ZXN0"; // Not Bearer
        
        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal("API Key not found", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_BearerTokenWithWhitespace_TrimsCorrectly()
    {
        // Arrange
        var apiKey = "test-api-key-with-spaces";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers.Authorization = $"Bearer   {apiKey}   "; // Extra spaces
        
        var validationResult = new ApiKeyValidationResult
        {
            IsValid = true,
            Identifier = "test-user",
            Roles = Array.Empty<string>(),
            Scopes = Array.Empty<string>()
        };

        _validationService.Setup(x => x.ValidateApiKeyAsync(apiKey, "127.0.0.1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.True(result.Succeeded);
        _validationService.Verify(x => x.ValidateApiKeyAsync(apiKey, "127.0.0.1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task HandleChallengeAsync_SetsCorrectStatusAndHeaders()
    {
        // Arrange
        var handler = CreateHandler();
        var context = CreateHttpContext();
        await handler.InitializeAsync(_scheme, context);

        // Act
        await handler.ChallengeAsync(new AuthenticationProperties());

        // Assert
        Assert.Equal(401, context.Response.StatusCode);
        Assert.Contains(context.Response.Headers, h => h.Key == "WWW-Authenticate" && h.Value == "ApiKey");
        
        // Check response body
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(context.Response.Body);
        var responseBody = await reader.ReadToEndAsync();
        Assert.Equal("API Key authentication required", responseBody);
    }

    [Fact]
    public async Task HandleForbiddenAsync_SetsCorrectStatusAndBody()
    {
        // Arrange
        var handler = CreateHandler();
        var context = CreateHttpContext();
        await handler.InitializeAsync(_scheme, context);

        // Act
        await handler.ForbidAsync(new AuthenticationProperties());

        // Assert
        Assert.Equal(403, context.Response.StatusCode);
        
        // Check response body
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body);
        var responseBody = await reader.ReadToEndAsync();
        Assert.Equal("Access forbidden", responseBody);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_UpdatesRateLimitInBackground()
    {
        // Arrange
        var apiKey = "test-api-key";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers["X-API-Key"] = apiKey;
        
        var validationResult = new ApiKeyValidationResult
        {
            IsValid = true,
            Identifier = "test-user",
            Roles = Array.Empty<string>(),
            Scopes = Array.Empty<string>()
        };

        _validationService.Setup(x => x.ValidateApiKeyAsync(apiKey, "127.0.0.1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.True(result.Succeeded);
        
        // Wait a bit for the background task
        await Task.Delay(100);
        
        _validationService.Verify(x => x.IsRateLimitExceededAsync("test-user", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_RateLimitUpdateFailure_DoesNotAffectAuthentication()
    {
        // Arrange
        var apiKey = "test-api-key";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers["X-API-Key"] = apiKey;
        
        var validationResult = new ApiKeyValidationResult
        {
            IsValid = true,
            Identifier = "test-user",
            Roles = Array.Empty<string>(),
            Scopes = Array.Empty<string>()
        };

        _validationService.Setup(x => x.ValidateApiKeyAsync(apiKey, "127.0.0.1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);
        
        _validationService.Setup(x => x.IsRateLimitExceededAsync("test-user", It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Rate limit service unavailable"));

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.True(result.Succeeded); // Authentication should still succeed
        Assert.Equal("test-user", result.Principal!.Identity!.Name);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public async Task HandleAuthenticateAsync_EmptyOrWhitespaceApiKey_ReturnsFailure(string apiKey)
    {
        // Arrange
        var handler = CreateHandler();
        var context = CreateHttpContext();
        context.Request.Headers["X-API-Key"] = apiKey;
        
        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.False(result.Succeeded);
        Assert.Equal("API Key not found", result.Failure?.Message);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_MultipleApiKeySources_PrefersAuthorizationHeader()
    {
        // Arrange
        var bearerApiKey = "bearer-api-key";
        var headerApiKey = "header-api-key";
        var handler = CreateHandler();
        var context = CreateHttpContext();
        
        // Set multiple sources
        context.Request.Headers.Authorization = $"Bearer {bearerApiKey}";
        context.Request.Headers["X-API-Key"] = headerApiKey;
        
        var validationResult = new ApiKeyValidationResult
        {
            IsValid = true,
            Identifier = "test-user",
            Roles = Array.Empty<string>(),
            Scopes = Array.Empty<string>()
        };

        _validationService.Setup(x => x.ValidateApiKeyAsync(bearerApiKey, "127.0.0.1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(validationResult);

        await handler.InitializeAsync(_scheme, context);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.True(result.Succeeded);
        _validationService.Verify(x => x.ValidateApiKeyAsync(bearerApiKey, "127.0.0.1", It.IsAny<CancellationToken>()), Times.Once);
        _validationService.Verify(x => x.ValidateApiKeyAsync(headerApiKey, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}