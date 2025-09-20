# Edi.AspNetCore.ApiKeyAuth

A simple and flexible API Key authentication library for ASP.NET Core applications.

## Features

- 🔑 API Key authentication via headers or query parameters
- 🏗️ Easy integration with ASP.NET Core's authentication system
- ⚙️ Configurable API keys through `appsettings.json`
- 📊 Built-in logging support
- 🎯 Multiple .NET versions support (.NET 8.0 and .NET 9.0)

## Installation

Install the package via NuGet:

```bash
dotnet add package Edi.AspNetCore.ApiKeyAuth
```

Or via Package Manager Console:

```powershell
Install-Package Edi.AspNetCore.ApiKeyAuth
```

## Quick Start

### 1. Configure API Keys

Add your API keys to `appsettings.json`:

```json
{
  "ApiKeys": [
    {
      "Identifier": "MyApp",
      "Key": "your-secret-api-key-here"
    },
    {
      "Identifier": "AnotherClient", 
      "Key": "another-secret-key"
    }
  ]
}
```

### 2. Register Services

In your `Program.cs` or `Startup.cs`:

```csharp
using Edi.AspNetCore.ApiKeyAuth;

var builder = WebApplication.CreateBuilder(args);

// Add API Key authentication
builder.Services.AddApiKeyAuthentication();

var app = builder.Build();

// Enable authentication and authorization
app.UseAuthentication();
app.UseAuthorization();

app.Run();
```

### 3. Protect Your Endpoints

Use the `[Authorize]` attribute on controllers or actions:

```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize(AuthenticationSchemes = "ApiKey")]
public class SecureController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        var userIdentifier = User.FindFirst("UserIdentifier")?.Value;
        return Ok($"Hello {userIdentifier}!");
    }
}
```

## Usage

### Authentication Methods

The library supports API key authentication through multiple methods:

#### 1. Header Authentication

```bash
curl -H "X-API-Key: your-secret-api-key-here" https://yourapi.com/api/secure
```

Alternative header name:
```bash
curl -H "ApiKey: your-secret-api-key-here" https://yourapi.com/api/secure
```

#### 2. Query Parameter Authentication

```bash
curl "https://yourapi.com/api/secure?apikey=your-secret-api-key-here"
```

### Accessing User Information

Once authenticated, you can access user information through claims:

```csharp
[HttpGet]
[Authorize(AuthenticationSchemes = "ApiKey")]
public IActionResult GetUserInfo()
{
    var userIdentifier = User.FindFirst("UserIdentifier")?.Value;
    var apiKey = User.FindFirst("ApiKey")?.Value;
    var userName = User.Identity?.Name;
    
    return Ok(new { UserIdentifier = userIdentifier, UserName = userName });
}
```
