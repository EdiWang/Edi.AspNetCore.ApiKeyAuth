using System.ComponentModel.DataAnnotations;

namespace Edi.AspNetCore.ApiKeyAuth.Models;

public class ApiKeyConfig
{
    [Required]
    public string Identifier { get; set; } = string.Empty;
    
    [Required]
    public string Key { get; set; } = string.Empty;
    
    public string[] Roles { get; set; } = [];
    
    public string[] Scopes { get; set; } = [];
    
    public DateTime? ExpiresAt { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    public string Description { get; set; }
    
    public RateLimitConfig RateLimit { get; set; }
    
    public IpWhitelistConfig IpWhitelist { get; set; }
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? LastUsedAt { get; set; }
    
    public string HashedKey { get; set; }
}

public class RateLimitConfig
{
    public int RequestsPerMinute { get; set; } = 60;
    public int RequestsPerHour { get; set; } = 1000;
    public int RequestsPerDay { get; set; } = 10000;
}

public class IpWhitelistConfig
{
    public bool Enabled { get; set; } = false;
    public string[] AllowedIpAddresses { get; set; } = [];
    public string[] AllowedCidrRanges { get; set; } = [];
}