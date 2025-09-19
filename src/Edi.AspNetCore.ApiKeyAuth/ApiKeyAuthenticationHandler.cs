using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Edi.AspNetCore.ApiKeyAuth;

public class ApiKeyAuthenticationHandler(
    IOptionsMonitor<ApiKeyAuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) :
    AuthenticationHandler<ApiKeyAuthenticationSchemeOptions>(options, logger, encoder)
{
    private const string ApiKeyHeaderName = "X-API-Key";
    private const string ApiKeyQueryName = "apikey";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var apiKey = GetApiKeyFromRequest();

        if (string.IsNullOrEmpty(apiKey))
        {
            return Task.FromResult(AuthenticateResult.Fail("API Key not found"));
        }

        var apiKeys = Context.RequestServices.GetRequiredService<IConfiguration>()
            .GetSection("ApiKeys").Get<List<ApiKeyConfig>>();

        if (apiKeys == null)
        {
            return Task.FromResult(AuthenticateResult.Fail("API Key configuration error"));
        }

        var matchedApiKey = apiKeys.FirstOrDefault(ak => ak.Key == apiKey);

        if (matchedApiKey == null)
        {
            return Task.FromResult(AuthenticateResult.Fail("Invalid API Key"));
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, matchedApiKey.Identifier),
            new Claim("ApiKey", apiKey),
            new Claim("UserIdentifier", matchedApiKey.Identifier)
        };

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        Logger.LogInformation("API Key authenticated for user: {UserIdentifier}", matchedApiKey.Identifier);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    private string GetApiKeyFromRequest()
    {
        // Check query string first
        if (Request.Query.TryGetValue(ApiKeyQueryName, out var queryApiKey))
        {
            return queryApiKey.FirstOrDefault();
        }

        // Check headers
        if (Request.Headers.TryGetValue(ApiKeyHeaderName, out var headerApiKey))
        {
            return headerApiKey.FirstOrDefault();
        }

        if (Request.Headers.TryGetValue("ApiKey", out var altHeaderApiKey))
        {
            return altHeaderApiKey.FirstOrDefault();
        }

        return null;
    }
}