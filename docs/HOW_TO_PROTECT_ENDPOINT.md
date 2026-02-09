# How To Protect An Endpoint

Use `@RequireGrants` on controller methods (or class-level) to enforce grants before business logic.

## 1) Add annotation

```java
import com.hasslefree.auth.client.spring.annotation.RequireGrants;

@GetMapping("/api/v1/properties")
@RequireGrants(anyOf = {"PROPERTY_READ", "PROPERTY_MANAGE"})
public ResponseEntity<?> listProperties(...) { ... }
```

`anyOf`: user must have at least one grant.  
`allOf`: user must have all listed grants.

## 2) Ensure service wiring

- Include `com.hasslefree:auth-client-lib`.
- Include `spring-boot-starter-aop` (required for AOP interception).
- Keep `hasslefree.auth.enforcement.enabled=true` (default).

## 3) Token expectations

Token must contain:
- `sub` (or configured subject claim)
- grants in one of: `permissions`, `access_grants`, `scope`, `scp`

## 4) Error behavior

- Missing/invalid token -> `401`
- Valid token but missing required grants -> `403`
