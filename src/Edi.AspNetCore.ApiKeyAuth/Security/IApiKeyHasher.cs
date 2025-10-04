namespace Edi.AspNetCore.ApiKeyAuth.Security;

public interface IApiKeyHasher
{
    string HashApiKey(string apiKey);
    bool VerifyApiKey(string apiKey, string hashedApiKey);
}