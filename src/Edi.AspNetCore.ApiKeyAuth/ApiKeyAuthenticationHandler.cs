using Edi.AspNetCore.ApiKeyAuth.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Edi.AspNetCore.ApiKeyAuth;

public class ApiKeyAuthenticationHandler(
    IOptionsMonitor<ApiKeyAuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IApiKeyValidationService validationService) :
    AuthenticationHandler<ApiKeyAuthenticationSchemeOptions>(options, logger, encoder)
{
    private const string ApiKeyHeaderName = "X-API-Key";
    private const string ApiKeyQueryName = "apikey";
    private const string BearerPrefix = "Bearer ";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            var apiKey = GetApiKeyFromRequest();

            if (string.IsNullOrEmpty(apiKey))
            {
                Logger.LogDebug("API Key not found in request");
                return AuthenticateResult.Fail("API Key not found");
            }

            var clientIp = GetClientIpAddress();
            var validationResult = await validationService.ValidateApiKeyAsync(apiKey, clientIp, Context.RequestAborted);

            if (!validationResult.IsValid)
            {
                Logger.LogWarning("API Key validation failed: {Reason} for IP: {ClientIp}",
                    validationResult.FailureReason, clientIp);
                return AuthenticateResult.Fail(validationResult.FailureReason ?? "Invalid API Key");
            }

            // Update last used timestamp
            _ = Task.Run(async () =>
            {
                try
                {
                    await validationService.IsRateLimitExceededAsync(validationResult.Identifier!, CancellationToken.None);
                }
                catch (Exception ex)
                {
                    Logger.LogError(ex, "Failed to update API key usage for {Identifier}", validationResult.Identifier);
                }
            }, CancellationToken.None);

            var claims = CreateClaims(validationResult, apiKey);
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            Logger.LogInformation("API Key authenticated for user: {UserIdentifier} from IP: {ClientIp}",
                validationResult.Identifier, clientIp);

            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error during API key authentication");
            return AuthenticateResult.Fail("Authentication error occurred");
        }
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 401;
        Response.Headers.Append("WWW-Authenticate", "ApiKey");

        await Response.WriteAsync("API Key authentication required");
    }

    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 403;
        await Response.WriteAsync("Access forbidden");
    }

    private string GetApiKeyFromRequest()
    {
        // Check Authorization header with Bearer scheme
        if (Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            var authValue = authHeader.FirstOrDefault();
            if (!string.IsNullOrEmpty(authValue) && authValue.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return authValue[BearerPrefix.Length..].Trim();
            }
        }

        // Check custom headers
        if (Request.Headers.TryGetValue(ApiKeyHeaderName, out var headerApiKey))
        {
            return headerApiKey.FirstOrDefault();
        }

        if (Request.Headers.TryGetValue("ApiKey", out var altHeaderApiKey))
        {
            return altHeaderApiKey.FirstOrDefault();
        }

        // Check query string (least secure, should be configurable)
        if (Options.AllowQueryStringAuth && Request.Query.TryGetValue(ApiKeyQueryName, out var queryApiKey))
        {
            return queryApiKey.FirstOrDefault();
        }

        return null;
    }

    private string GetClientIpAddress()
    {
        // Check for forwarded headers first (for load balancers/proxies)
        if (Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor))
        {
            var firstIp = forwardedFor.FirstOrDefault()?.Split(',').FirstOrDefault()?.Trim();
            if (!string.IsNullOrEmpty(firstIp))
                return firstIp;
        }

        if (Request.Headers.TryGetValue("X-Real-IP", out var realIp))
        {
            return realIp.FirstOrDefault();
        }

        return Request.HttpContext.Connection.RemoteIpAddress?.ToString();
    }

    private static List<Claim> CreateClaims(ApiKeyValidationResult validationResult, string apiKey)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, validationResult.Identifier!),
            new("ApiKey", apiKey),
            new("UserIdentifier", validationResult.Identifier!),
            new(ClaimTypes.AuthenticationMethod, "ApiKey")
        };

        // Add role claims
        foreach (var role in validationResult.Roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        // Add scope claims
        foreach (var scope in validationResult.Scopes)
        {
            claims.Add(new Claim("scope", scope));
        }

        return claims;
    }
}