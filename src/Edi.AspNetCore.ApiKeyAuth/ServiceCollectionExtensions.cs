using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Edi.AspNetCore.ApiKeyAuth.Security;
using Edi.AspNetCore.ApiKeyAuth.Services;

namespace Edi.AspNetCore.ApiKeyAuth;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddApiKeyAuthentication(this IServiceCollection services)
    {
        return services.AddApiKeyAuthentication(options => { });
    }

    public static IServiceCollection AddApiKeyAuthentication(
        this IServiceCollection services,
        Action<ApiKeyAuthenticationSchemeOptions> configureOptions)
    {
        services.AddAuthentication(ApiKeyAuthenticationSchemeOptions.DefaultScheme)
            .AddScheme<ApiKeyAuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
                ApiKeyAuthenticationSchemeOptions.DefaultScheme, configureOptions);

        services.AddAuthorization();
        services.AddMemoryCache();

        // Register core services
        services.AddScoped<IApiKeyValidationService, ApiKeyValidationService>();
        services.AddSingleton<IApiKeyHasher, ApiKeyHasher>();
        services.AddSingleton<IRateLimitService, MemoryRateLimitService>();

        return services;
    }

    public static IServiceCollection AddApiKeyAuthentication<TValidationService>(
        this IServiceCollection services,
        Action<ApiKeyAuthenticationSchemeOptions> configureOptions = null)
        where TValidationService : class, IApiKeyValidationService
    {
        services.AddAuthentication(ApiKeyAuthenticationSchemeOptions.DefaultScheme)
            .AddScheme<ApiKeyAuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
                ApiKeyAuthenticationSchemeOptions.DefaultScheme, configureOptions ?? (_ => { }));

        services.AddAuthorization();
        services.AddMemoryCache();

        // Register custom validation service
        services.AddScoped<IApiKeyValidationService, TValidationService>();
        services.AddSingleton<IApiKeyHasher, ApiKeyHasher>();
        services.AddSingleton<IRateLimitService, MemoryRateLimitService>();

        return services;
    }
}