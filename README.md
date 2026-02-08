# HassleFree Auth Client Library

Spring Boot 3+ library for permission and access-grant based authorization.

## Scope and Principles

- JWT validation is done by Spring Security Resource Server.
- This library does not validate JWT signatures.
- This library adapts verified `Authentication`/`Jwt` to immutable `AuthContext`.
- Authorization is permission/access-grant based only (no roles).

## Public API

- `com.hasslefree.auth.client.context.AuthContext`
- `com.hasslefree.auth.client.access.Permission`
- `com.hasslefree.auth.client.access.AccessGrant`
- `com.hasslefree.auth.client.authorization.Authorization`
  - `has(...)`, `hasAny(...)`, `hasAll(...)`
  - `requireAny(...)`, `requireAll(...)`
- `com.hasslefree.auth.client.authorization.AuthorizationClient`

Exceptions:
- `UnauthorizedException`
- `ForbiddenException`
- `BadRequestException`

## Spring Boot Auto-Configuration

Registered automatically:
- `AuthContextArgumentResolver` (`@CurrentAuthContext AuthContext`)
- Optional `AuthContextRequestFilter`
- `@RequireGrants` AOP enforcement
- `AuthorizationClient` (service-to-service permission check client)

Auto-configuration imports:
- `com.hasslefree.auth.client.spring.config.AuthClientAutoConfiguration`
- `com.hasslefree.auth.client.config.AuthorizationClientAutoConfiguration`

## Configuration

### 1) Resource Server (required in each service)

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://cognito-idp.us-east-1.amazonaws.com/<userPoolId>
```

### 2) Auth-context extraction and enforcement

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

### 3) Authorization client (optional, for remote permission checks)

```yaml
hasslefree:
  auth:
    authorization-client:
      base-url: http://localhost:8080
      internal-api-key: ${AUTHORIZATION_INTERNAL_API_KEY}
      cache:
        ttl-seconds: 60
        max-size: 10000
```

## Multi-Service Usage

### app-service (business API service)

Use request-context injection plus declarative checks:

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
    return service.read(id, authContext.subject());
  }
}
```

Use `AuthorizationClient` only when you need centralized remote check semantics:

```java
import com.hasslefree.auth.client.authorization.AuthorizationClient;

boolean allowed = authorizationClient.checkPermission(userId, "PROPERTY", propertyId, "PROPERTY_READ");
```

### auth-service

Use the same context model and helper API in internal endpoints:

```java
import com.hasslefree.auth.client.authorization.Authorization;
import com.hasslefree.auth.client.context.AuthContext;
import com.hasslefree.auth.client.spring.annotation.CurrentAuthContext;

@GetMapping("/api/me")
MeResponse me(@CurrentAuthContext AuthContext authContext) {
  Authorization.requireAny(authContext, "profile.read", "tenant.read");
  return meService.buildResponse(authContext.subject());
}
```

### Any additional service

Adopt in this order:
1. Enable Spring Resource Server JWT validation.
2. Add `hasslefree.auth.*` claim extraction config.
3. Replace custom principal objects with `AuthContext`.
4. Enforce grants via `@RequireGrants` and/or `Authorization` helpers.
5. Add `AuthorizationClient` config only if remote checks are needed.

## Migration Notes

- Use `Authorization` (not `Authz`) naming.
- Use `AuthorizationClient` + `hasslefree.auth.authorization-client.*` properties.
- Remove any role-based checks; enforce permissions/access-grants only.
- Keep exception-to-HTTP mapping in each service (recommended: `application/problem+json`).
