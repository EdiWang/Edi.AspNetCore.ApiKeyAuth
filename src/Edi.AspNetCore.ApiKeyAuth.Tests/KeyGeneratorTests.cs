using Edi.AspNetCore.ApiKeyAuth.Security;

namespace Edi.AspNetCore.ApiKeyAuth.Tests;

public class KeyGeneratorTests
{
    [Fact]
    public void GenerateApiKey_DefaultLength_ReturnsHexStringOf64Chars()
    {
        var key = KeyGenerator.GenerateApiKey();

        Assert.NotNull(key);
        Assert.NotEmpty(key);
        Assert.Equal(64, key.Length); // 32 bytes = 64 hex chars
    }

    [Fact]
    public void GenerateApiKey_ReturnsLowercaseHex()
    {
        var key = KeyGenerator.GenerateApiKey();

        Assert.Equal(key, key.ToLowerInvariant());
        Assert.True(key.All(c => "0123456789abcdef".Contains(c)));
    }

    [Theory]
    [InlineData(16, 32)]
    [InlineData(32, 64)]
    [InlineData(64, 128)]
    public void GenerateApiKey_CustomLength_ReturnsCorrectLength(int lengthInBytes, int expectedHexLength)
    {
        var key = KeyGenerator.GenerateApiKey(lengthInBytes);

        Assert.Equal(expectedHexLength, key.Length);
    }

    [Fact]
    public void GenerateApiKey_ProducesUniqueKeys()
    {
        var keys = Enumerable.Range(0, 100).Select(_ => KeyGenerator.GenerateApiKey()).ToHashSet();

        Assert.Equal(100, keys.Count);
    }

    [Fact]
    public void CreateKeyPair_ReturnsValidPair()
    {
        var pair = KeyGenerator.CreateKeyPair();

        Assert.NotNull(pair);
        Assert.NotNull(pair.ApiKey);
        Assert.NotEmpty(pair.ApiKey);
        Assert.NotNull(pair.HashedApiKey);
        Assert.NotEmpty(pair.HashedApiKey);
    }

    [Fact]
    public void CreateKeyPair_HashedKeyCanVerifyApiKey()
    {
        var pair = KeyGenerator.CreateKeyPair();
        var hasher = new ApiKeyHasher();

        var isValid = hasher.VerifyApiKey(pair.ApiKey, pair.HashedApiKey);

        Assert.True(isValid);
    }

    [Fact]
    public void CreateKeyPair_DifferentPairsHaveDifferentKeys()
    {
        var pair1 = KeyGenerator.CreateKeyPair();
        var pair2 = KeyGenerator.CreateKeyPair();

        Assert.NotEqual(pair1.ApiKey, pair2.ApiKey);
        Assert.NotEqual(pair1.HashedApiKey, pair2.HashedApiKey);
    }

    [Fact]
    public void HashApiKey_ReturnsNonEmptyString()
    {
        var hash = KeyGenerator.HashApiKey("test-key");

        Assert.NotNull(hash);
        Assert.NotEmpty(hash);
    }

    [Fact]
    public void HashApiKey_ResultIsValidBase64()
    {
        var hash = KeyGenerator.HashApiKey("test-key");

        var bytes = Convert.FromBase64String(hash);
        Assert.True(bytes.Length > 0);
    }
}
