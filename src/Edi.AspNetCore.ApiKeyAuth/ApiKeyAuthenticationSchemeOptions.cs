using Microsoft.AspNetCore.Authentication;

namespace Edi.AspNetCore.ApiKeyAuth;

public class ApiKeyAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
    public const string DefaultScheme = "ApiKey";
    public string Scheme => DefaultScheme;
    public string AuthenticationType = DefaultScheme;
    
    /// <summary>
    /// Allow API key authentication via query string parameters (less secure)
    /// </summary>
    public bool AllowQueryStringAuth { get; set; } = false;
    
    /// <summary>
    /// Custom header names to check for API keys
    /// </summary>
    public string[] CustomHeaderNames { get; set; } = [];
    
    /// <summary>
    /// Enable detailed logging for debugging
    /// </summary>
    public bool EnableDetailedLogging { get; set; } = false;
    
    /// <summary>
    /// Cache API key validation results for better performance
    /// </summary>
    public bool EnableCaching { get; set; } = true;
    
    /// <summary>
    /// Cache duration for API key validation results
    /// </summary>
    public TimeSpan CacheDuration { get; set; } = TimeSpan.FromMinutes(5);
}