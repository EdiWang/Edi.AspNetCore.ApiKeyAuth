using System.Security.Cryptography;
using Edi.AspNetCore.ApiKeyAuth.Security;

namespace Edi.AspNetCore.ApiKeyAuth;

public static class KeyGenerator
{
    private static readonly ApiKeyHasher Hasher = new();

    public static KeyPair CreateKeyPair()
    {
        var api = GenerateApiKey();
        var hashedApiKey = HashApiKey(api);
        return new KeyPair(api, hashedApiKey);
    }

    public static string GenerateApiKey(int lengthInBytes = 32)
    {
        var bytes = RandomNumberGenerator.GetBytes(lengthInBytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static string HashApiKey(string apiKey) => Hasher.HashApiKey(apiKey);
}

public class KeyPair(string apiKey, string hashedApiKey)
{
    public string ApiKey { get; set; } = apiKey;
    public string HashedApiKey { get; set; } = hashedApiKey;
}