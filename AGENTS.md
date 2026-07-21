# Copilot Instructions for Edi.AspNetCore.ApiKeyAuth

This repository contains a small ASP.NET Core authentication library for API key based authentication. Keep changes focused on the package surface, authentication behavior, security properties, and the existing xUnit test style.

## Project Shape

- Main library: `src/Edi.AspNetCore.ApiKeyAuth/`.
- Tests: `src/Edi.AspNetCore.ApiKeyAuth.Tests/`.
- Solution file: `src/Edi.AspNetCore.ApiKeyAuth.slnx`.
- Target framework is `net10.0`; implicit usings are enabled.
- Public namespace is `Edi.AspNetCore.ApiKeyAuth`, with sub-namespaces for `Models`, `Security`, and `Services`.
- Build outputs under `bin/` and `obj/` are generated artifacts. Do not edit them.

## Common Commands

Run commands from the repository root unless there is a reason to work inside `src/`:

```powershell
dotnet restore src/Edi.AspNetCore.ApiKeyAuth.slnx
dotnet build src/Edi.AspNetCore.ApiKeyAuth.slnx -c Debug
dotnet test src/Edi.AspNetCore.ApiKeyAuth.slnx -c Debug
```

Use the test command after changing authentication, validation, hashing, rate limiting, service registration, or public configuration behavior.

## Coding Style

- Prefer concise C# 12/.NET 10 style already used in the codebase: primary constructors where they are already natural, collection expressions like `[]`, async APIs, and dependency injection.
- Keep interfaces small and behavior explicit. Existing extension points are `IApiKeyValidationService`, `IApiKeyHasher`, and `IRateLimitService`.
- Preserve the existing service lifetimes unless a change is intentional and covered by tests: validation service is scoped; hasher and rate limiter are singleton.
- Avoid broad refactors when implementing feature changes. This package is small, so readable direct code is preferred over new abstractions unless they remove real duplication.
- Add comments only for non-obvious security or protocol decisions.

## Authentication Behavior

- The default scheme name is `ApiKey`; preserve `ApiKeyAuthenticationSchemeOptions.DefaultScheme` as the source of truth.
- API key lookup precedence is: `Authorization: Bearer ...`, `X-API-Key`, `ApiKey`, configured custom headers, then query string only when `AllowQueryStringAuth` is enabled.
- Query string authentication is less secure and must remain disabled by default.
- Successful authentication creates claims for `ClaimTypes.Name`, `UserIdentifier`, `ClaimTypes.AuthenticationMethod`, roles via `ClaimTypes.Role`, and scopes via `scope`.
- Challenge and forbidden responses currently write simple 401/403 bodies. If changing these, update handler tests and README examples as needed.

## Security Rules

- Never log raw API keys, hashed API keys, salts, or bearer tokens.
- Prefer `HashedKey` over plain text `Key`; plain text keys exist for legacy support only.
- Keep API key comparison resistant to timing attacks. Use `CryptographicOperations.FixedTimeEquals` for plain text comparisons and PBKDF2 verification through `IApiKeyHasher` for hashed keys.
- `ApiKeyHasher` uses a random 32-byte salt, 64-byte hash, PBKDF2-SHA256, and 100000 iterations. Do not weaken these parameters casually.
- Cache keys must not contain raw API keys. Use deterministic hashes for cache keys, as `ApiKeyValidationService` does.
- Do not manually trust `X-Forwarded-For` or `X-Real-IP` in the authentication handler. Use `HttpContext.Connection.RemoteIpAddress`; applications behind proxies should configure ASP.NET Core Forwarded Headers middleware.
- Preserve cancellation token flow for validation and rate limiting paths.

## Configuration Model

- API keys are read from the `ApiKeys` configuration section into `ApiKeyConfig`.
- `ApiKeyConfig` supports identifier, legacy key, hashed key, roles, scopes, expiration, active flag, description, rate limits, IP whitelist, and created timestamp.
- Validation should continue to check, in order: required key input, matching configured key, active flag, expiration, IP whitelist, and rate limits.
- Rate limit configuration is per API key when available, falling back to defaults in `MemoryRateLimitService`.

## Testing Expectations

- Tests use xUnit, Moq, and the Arrange/Act/Assert layout.
- Follow the naming pattern `MethodName_Scenario_ExpectedResult` for new tests.
- Use `[Theory]` with `[InlineData]` for simple input matrices.
- Use `DefaultHttpContext` for authentication handler tests and in-memory configuration for validation service tests.
- Add or update tests for every behavior change in authentication source precedence, claims, hashing, validation failures, IP whitelist handling, rate limiting, DI registration, or public options.
- For security-sensitive fixes, include negative tests, not only success-path tests.

## Documentation

- Update `README.md` when public setup, configuration shape, supported headers, generated key format, claims, or package usage changes.
- Keep examples consistent with the current recommendation: hashed keys preferred, query string authentication disabled unless explicitly needed, and `UseAuthentication()` before `UseAuthorization()`.