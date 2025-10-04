using Edi.AspNetCore.ApiKeyAuth.Services;

namespace Edi.AspNetCore.ApiKeyAuth.Tests.Services;

public class MemoryRateLimitServiceTests : IDisposable
{
    private readonly MemoryRateLimitService _service;

    public MemoryRateLimitServiceTests()
    {
        _service = new MemoryRateLimitService();
    }

    [Fact]
    public async Task IsRateLimitExceededAsync_WithinLimits_ReturnsFalse()
    {
        // Arrange
        var identifier = "test-identifier";

        // Act
        var result = await _service.IsRateLimitExceededAsync(identifier);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task IsRateLimitExceededAsync_WithNullIdentifier_ThrowsArgumentNullException()
    {
        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(() => _service.IsRateLimitExceededAsync(null!));
    }

    [Fact]
    public async Task IsRateLimitExceededAsync_ExceedsMinuteLimit_ReturnsTrue()
    {
        // Arrange
        var identifier = "test-identifier-minute";

        // Act - Make 61 requests (exceeds the 60/minute limit)
        bool lastResult = false;
        for (int i = 0; i < 61; i++)
        {
            lastResult = await _service.IsRateLimitExceededAsync(identifier);
        }

        // Assert
        Assert.True(lastResult);
    }

    [Fact]
    public async Task IsRateLimitExceededAsync_DifferentIdentifiers_IndependentLimits()
    {
        // Arrange
        var identifier1 = "test-identifier-1";
        var identifier2 = "test-identifier-2";

        // Act - Make 60 requests for identifier1 (at limit)
        for (int i = 0; i < 60; i++)
        {
            await _service.IsRateLimitExceededAsync(identifier1);
        }

        // Test that identifier2 is still within limits
        var result1 = await _service.IsRateLimitExceededAsync(identifier1); // Should exceed
        var result2 = await _service.IsRateLimitExceededAsync(identifier2); // Should be fine

        // Assert
        Assert.True(result1);
        Assert.False(result2);
    }

    [Fact]
    public async Task IsRateLimitExceededAsync_WithCancellationToken_RespectsToken()
    {
        // Arrange
        var identifier = "test-identifier";
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act & Assert
        await Assert.ThrowsAsync<TaskCanceledException>(() => 
            _service.IsRateLimitExceededAsync(identifier, cts.Token));
    }

    [Fact]
    public async Task IsRateLimitExceededAsync_ConsecutiveCalls_ProperlyTracksUsage()
    {
        // Arrange
        var identifier = "test-identifier-tracking";

        // Act - Make several calls within limit
        var results = new List<bool>();
        for (int i = 0; i < 59; i++) // Stay under the 60/minute limit
        {
            results.Add(await _service.IsRateLimitExceededAsync(identifier));
        }

        // Assert - All should be false (within limits)
        Assert.All(results, result => Assert.False(result));

        // Act - One more call should still be within limit
        var finalWithinLimit = await _service.IsRateLimitExceededAsync(identifier);
        Assert.False(finalWithinLimit);

        // Act - Next call should exceed limit
        var exceedsLimit = await _service.IsRateLimitExceededAsync(identifier);
        Assert.True(exceedsLimit);
    }

    [Theory]
    [InlineData("identifier-1")]
    [InlineData("identifier-2")]
    [InlineData("different-key")]
    public async Task IsRateLimitExceededAsync_MultipleIdentifiers_EachHasIndependentLimits(string identifier)
    {
        // Act
        var result = await _service.IsRateLimitExceededAsync(identifier);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task IncrementUsageAsync_CompletesSuccessfully()
    {
        // Arrange
        var identifier = "test-identifier";

        // Act & Assert - Should not throw
        await _service.IncrementUsageAsync(identifier);
    }

    [Fact]
    public async Task IncrementUsageAsync_WithCancellationToken_CompletesSuccessfully()
    {
        // Arrange
        var identifier = "test-identifier";
        using var cts = new CancellationTokenSource();

        // Act & Assert - Should not throw
        await _service.IncrementUsageAsync(identifier, cts.Token);
    }

    [Fact]
    public async Task IncrementUsageAsync_WithNullIdentifier_CompletesSuccessfully()
    {
        // Act & Assert - Should not throw (method doesn't actually use the identifier)
        await _service.IncrementUsageAsync(null!);
    }

    [Fact]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Act & Assert - Should not throw
        _service.Dispose();
        _service.Dispose(); // Second call should not throw
    }

    [Fact]
    public async Task IsRateLimitExceededAsync_StressTest_HandlesHighConcurrency()
    {
        // Arrange
        var identifier = "stress-test-identifier";
        var tasks = new List<Task<bool>>();
        var concurrentRequests = 50;

        // Act - Create concurrent requests
        for (int i = 0; i < concurrentRequests; i++)
        {
            tasks.Add(_service.IsRateLimitExceededAsync(identifier));
        }

        var results = await Task.WhenAll(tasks);

        // Assert - Most should succeed, but some might fail due to rate limiting
        var successCount = results.Count(r => !r);
        var failureCount = results.Count(r => r);

        Assert.True(successCount > 0, "At least some requests should succeed");
        Assert.True(successCount + failureCount == concurrentRequests, "All requests should be accounted for");
    }

    [Fact]
    public async Task IsRateLimitExceededAsync_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var service = new MemoryRateLimitService();
        service.Dispose();

        // Act & Assert
        await Assert.ThrowsAsync<ObjectDisposedException>(() => 
            service.IsRateLimitExceededAsync("test"));
    }

    public void Dispose()
    {
        _service.Dispose();
    }
}