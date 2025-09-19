using Microsoft.AspNetCore.Authentication;

namespace Edi.AspNetCore.ApiKeyAuth;

public class ApiKeyAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
    public const string DefaultScheme = "ApiKey";
    public string Scheme => DefaultScheme;
    public string AuthenticationType = DefaultScheme;
}