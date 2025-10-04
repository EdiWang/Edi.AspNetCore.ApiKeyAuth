using System.Security.Cryptography;
using System.Text;

namespace Edi.AspNetCore.ApiKeyAuth;

public static class KeyGenerator
{
    public static string GenerateApiKey()
    {
        var guid = Guid.NewGuid().ToString("N");
        return guid;
    }

    public static string HashApiKey(string apiKey)
    {
        const int SaltSize = 32;
        const int HashSize = 64;
        const int Iterations = 100000;

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(apiKey),
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            HashSize);

        return Convert.ToBase64String(salt.Concat(hash).ToArray());
    }
}
