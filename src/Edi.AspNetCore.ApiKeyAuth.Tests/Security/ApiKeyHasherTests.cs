using Edi.AspNetCore.ApiKeyAuth.Security;

namespace Edi.AspNetCore.ApiKeyAuth.Tests.Security;

public class ApiKeyHasherTests
{
    private readonly ApiKeyHasher _hasher;

    public ApiKeyHasherTests()
    {
        _hasher = new ApiKeyHasher();
    }

    [Fact]
    public void HashApiKey_WithValidApiKey_ReturnsBase64Hash()
    {
        // Arrange
        var apiKey = "test-api-key-12345";

        // Act
        var hashedKey = _hasher.HashApiKey(apiKey);

        // Assert
        Assert.NotNull(hashedKey);
        Assert.NotEmpty(hashedKey);

        // Verify it's valid Base64
        var bytes = Convert.FromBase64String(hashedKey);
        Assert.Equal(96, bytes.Length); // 32 (salt) + 64 (hash) = 96 bytes
    }

    [Fact]
    public void HashApiKey_SameApiKey_ProducesDifferentHashes()
    {
        // Arrange
        var apiKey = "test-api-key";

        // Act
        var hash1 = _hasher.HashApiKey(apiKey);
        var hash2 = _hasher.HashApiKey(apiKey);

        // Assert
        Assert.NotEqual(hash1, hash2); // Different salts should produce different hashes
    }

    [Fact]
    public void VerifyApiKey_WithCorrectApiKey_ReturnsTrue()
    {
        // Arrange
        var apiKey = "test-api-key-12345";
        var hashedKey = _hasher.HashApiKey(apiKey);

        // Act
        var result = _hasher.VerifyApiKey(apiKey, hashedKey);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void VerifyApiKey_WithIncorrectApiKey_ReturnsFalse()
    {
        // Arrange
        var correctApiKey = "correct-api-key";
        var incorrectApiKey = "incorrect-api-key";
        var hashedKey = _hasher.HashApiKey(correctApiKey);

        // Act
        var result = _hasher.VerifyApiKey(incorrectApiKey, hashedKey);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void VerifyApiKey_WithInvalidBase64Hash_ReturnsFalse()
    {
        // Arrange
        var apiKey = "test-api-key";
        var invalidHash = "invalid-base64-hash!@#";

        // Act
        var result = _hasher.VerifyApiKey(apiKey, invalidHash);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void VerifyApiKey_WithEmptyApiKey_ReturnsFalse()
    {
        // Arrange
        var apiKey = "test-api-key";
        var hashedKey = _hasher.HashApiKey(apiKey);

        // Act
        var result = _hasher.VerifyApiKey(string.Empty, hashedKey);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void VerifyApiKey_WithNullApiKey_ReturnsFalse()
    {
        // Arrange
        var apiKey = "test-api-key";
        var hashedKey = _hasher.HashApiKey(apiKey);

        // Act
        var result = _hasher.VerifyApiKey(null, hashedKey);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void VerifyApiKey_WithMalformedHash_ReturnsFalse()
    {
        // Arrange
        var apiKey = "test-api-key";
        var validHash = _hasher.HashApiKey(apiKey);
        var malformedHash = validHash.Substring(0, validHash.Length - 10); // Truncate hash

        // Act
        var result = _hasher.VerifyApiKey(apiKey, malformedHash);

        // Assert
        Assert.False(result);
    }

    [Theory]
    [InlineData("simple-key")]
    [InlineData("complex-key!@#$%^&*()")]
    [InlineData("unicode-key-≤‚ ‘")]
    [InlineData("long-key-with-many-characters-1234567890-abcdefghijklmnopqrstuvwxyz")]
    public void HashAndVerify_WithVariousApiKeys_WorksCorrectly(string apiKey)
    {
        // Act
        var hashedKey = _hasher.HashApiKey(apiKey);
        var isValid = _hasher.VerifyApiKey(apiKey, hashedKey);

        // Assert
        Assert.True(isValid);
    }
}