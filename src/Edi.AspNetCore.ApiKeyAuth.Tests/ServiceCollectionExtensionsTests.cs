using Edi.AspNetCore.ApiKeyAuth.Security;
using Edi.AspNetCore.ApiKeyAuth.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Edi.AspNetCore.ApiKeyAuth.Tests;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddApiKeyAuthentication_RegistersRequiredServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddApiKeyAuthentication();

        Assert.Contains(services, sd => sd.ServiceType == typeof(IApiKeyValidationService));
        Assert.Contains(services, sd => sd.ServiceType == typeof(IApiKeyHasher));
        Assert.Contains(services, sd => sd.ServiceType == typeof(IRateLimitService));
    }

    [Fact]
    public void AddApiKeyAuthentication_RegistersServicesWithCorrectLifetime()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddApiKeyAuthentication();

        var validationDescriptor = services.First(sd => sd.ServiceType == typeof(IApiKeyValidationService));
        var hasherDescriptor = services.First(sd => sd.ServiceType == typeof(IApiKeyHasher));
        var rateLimitDescriptor = services.First(sd => sd.ServiceType == typeof(IRateLimitService));

        Assert.Equal(ServiceLifetime.Scoped, validationDescriptor.Lifetime);
        Assert.Equal(ServiceLifetime.Singleton, hasherDescriptor.Lifetime);
        Assert.Equal(ServiceLifetime.Singleton, rateLimitDescriptor.Lifetime);
    }

    [Fact]
    public void AddApiKeyAuthentication_RegistersCorrectImplementationTypes()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddApiKeyAuthentication();

        var validationDescriptor = services.First(sd => sd.ServiceType == typeof(IApiKeyValidationService));
        var hasherDescriptor = services.First(sd => sd.ServiceType == typeof(IApiKeyHasher));
        var rateLimitDescriptor = services.First(sd => sd.ServiceType == typeof(IRateLimitService));

        Assert.Equal(typeof(ApiKeyValidationService), validationDescriptor.ImplementationType);
        Assert.Equal(typeof(ApiKeyHasher), hasherDescriptor.ImplementationType);
        Assert.Equal(typeof(MemoryRateLimitService), rateLimitDescriptor.ImplementationType);
    }

    [Fact]
    public void AddApiKeyAuthentication_WithCustomValidationService_RegistersCustomService()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddApiKeyAuthentication<CustomValidationService>();

        var descriptor = services.First(sd => sd.ServiceType == typeof(IApiKeyValidationService));

        Assert.Equal(typeof(CustomValidationService), descriptor.ImplementationType);
    }

    [Fact]
    public void AddApiKeyAuthentication_WithCustomValidationService_StillRegistersOtherServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddApiKeyAuthentication<CustomValidationService>();

        Assert.Contains(services, sd => sd.ServiceType == typeof(IApiKeyHasher));
        Assert.Contains(services, sd => sd.ServiceType == typeof(IRateLimitService));
    }

    [Fact]
    public void AddApiKeyAuthentication_DefaultOverload_CallsParameterizedOverload()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        var result = services.AddApiKeyAuthentication();

        Assert.Same(services, result);
        Assert.Contains(services, sd => sd.ServiceType == typeof(IApiKeyValidationService));
    }

    private class CustomValidationService : IApiKeyValidationService
    {
        public Task<ApiKeyValidationResult> ValidateApiKeyAsync(string apiKey, string ipAddress = null!, CancellationToken cancellationToken = default)
            => Task.FromResult(new ApiKeyValidationResult());

        public Task<bool> IsRateLimitExceededAsync(string identifier, CancellationToken cancellationToken = default)
            => Task.FromResult(false);
    }
}
