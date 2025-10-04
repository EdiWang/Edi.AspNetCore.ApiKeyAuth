using System.Security.Cryptography;
using System.Text;

namespace Edi.AspNetCore.ApiKeyAuth.Security;

public class ApiKeyHasher : IApiKeyHasher
{
    private const int SaltSize = 32;
    private const int HashSize = 64;
    private const int Iterations = 100000;

    public string HashApiKey(string apiKey)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(apiKey),
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            HashSize);

        return Convert.ToBase64String(salt.Concat(hash).ToArray());
    }

    public bool VerifyApiKey(string apiKey, string hashedApiKey)
    {
        try
        {
            var hashBytes = Convert.FromBase64String(hashedApiKey);
            var salt = hashBytes.Take(SaltSize).ToArray();
            var hash = hashBytes.Skip(SaltSize).ToArray();

            var computedHash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(apiKey),
                salt,
                Iterations,
                HashAlgorithmName.SHA256,
                HashSize);

            return CryptographicOperations.FixedTimeEquals(hash, computedHash);
        }
        catch
        {
            return false;
        }
    }
}