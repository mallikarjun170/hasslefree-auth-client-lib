# HassleFree Auth Client Library

Production-ready Spring Boot 3+ auth client library for **access-grant / permission-based** authorization.

## Design choices

- JWT validation is handled by **Spring Security Resource Server**.
- This library **does not** validate JWT signatures.
- This library adapts `Authentication/Jwt` into immutable `AuthContext`.
- Authorization checks are permission/access-grant based only.

## Public API

- `com.hasslefree.auth.client.context.AuthContext` (immutable)
- `com.hasslefree.auth.client.access.Permission`
- `com.hasslefree.auth.client.access.AccessGrant`
- `com.hasslefree.auth.client.authz.Authz`
  - `has(...)`
  - `hasAny(...)`
  - `hasAll(...)`
  - `requireAny(...)`
  - `requireAll(...)`
- Exceptions:
  - `UnauthorizedException`
  - `ForbiddenException`
  - `BadRequestException`

## Spring starter integration

Auto-config registers:

- `AuthContextArgumentResolver` for injecting `AuthContext`
- optional `AuthContextRequestFilter` (request-scoped attribute)
- `@RequireGrants` enforcement via AOP aspect

Enable Spring Resource Server in each service (required):

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://cognito-idp.us-east-1.amazonaws.com/<userPoolId>
```

Library properties:

```yaml
hasslefree:
  auth:
    claims:
      subject-key: sub
      principal-key: sub
      email-key: email
      access-grant-keys: [permissions, access_grants, scope, scp]
      required-claim-keys: [sub]
      issuer: https://cognito-idp.us-east-1.amazonaws.com/<userPoolId>
      audience: <client-id>
      validate-issuer: false
      validate-audience: false
    web:
      argument-resolver-enabled: true
      request-filter-enabled: false
      request-attribute-name: hasslefree.auth.context
    enforcement:
      enabled: true
```

## Usage in app-service

```java
import com.hasslefree.auth.client.context.AuthContext;
import com.hasslefree.auth.client.spring.annotation.CurrentAuthContext;
import com.hasslefree.auth.client.spring.annotation.RequireGrants;

@RestController
@RequestMapping("/api/properties")
class PropertyController {

  @GetMapping("/{id}")
  @RequireGrants(anyOf = {"property.read"})
  PropertyDto getProperty(@PathVariable String id, @CurrentAuthContext AuthContext authContext) {
    // authContext.subject(), authContext.permissions(), authContext.claims()
    return service.read(id, authContext.subject());
  }
}
```

## Usage in auth-service

```java
import com.hasslefree.auth.client.context.AuthContext;
import com.hasslefree.auth.client.spring.annotation.CurrentAuthContext;
import com.hasslefree.auth.client.authz.Authz;

@RestController
@RequestMapping("/api/me")
class MeController {

  @GetMapping
  MeResponse me(@CurrentAuthContext AuthContext authContext) {
    Authz.requireAny(authContext, "profile.read", "tenant.read");
    return meService.buildResponse(authContext.subject());
  }
}
```

## Migration notes

- Replace `AuthenticationContext` with `AuthContext`.
- Remove custom JWT token validators/filters.
- Keep JWT validation in Spring Resource Server only.
- Replace privilege checks with permission/access-grant checks.
- Prefer `@CurrentAuthContext` for parameter injection.
- Optional: `@RequireGrants(anyOf=..., allOf=...)` for method enforcement.

## Error response standard

This library exposes exceptions and does not enforce HTTP response mapping.
Map exceptions in each service to `application/problem+json` (recommended).
