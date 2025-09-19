using Microsoft.Extensions.DependencyInjection;

namespace Edi.AspNetCore.ApiKeyAuth;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddApiKeyAuthentication(this IServiceCollection services)
    {
        services.AddAuthentication(ApiKeyAuthenticationSchemeOptions.DefaultScheme)
            .AddScheme<ApiKeyAuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
                ApiKeyAuthenticationSchemeOptions.DefaultScheme, options => { });

        services.AddAuthorization();

        return services;
    }
}