# HassleFree Auth Client Library - Copilot Instructions

## Scope & Purpose

`auth-client-lib` is a **shared, reusable Java authentication library** for JWT validation and role management. It is consumed by `auth-service` and `app-service` as a Maven dependency. **Do not add Spring Boot application code, controllers, or ECS deployment logic here.**

## Architecture & Key Components

**Public API** (`src/main/java/com/hasslefree/auth/`):
- `JwtTokenValidator` - Core class for validating AWS Cognito JWTs; validates signature, expiration, issuer, audience
- `TokenContext` - Value object holding parsed user info (userId, username, roles, claims)
- `JwtTokenParser` - Low-level JWT parsing without validation; extracts claims safely
- `RoleChecker` - Utility for role-based access checks (e.g., `hasRole(ADMIN)`)
- `InvalidTokenException`, `TokenExpiredException` - Custom exceptions thrown on validation failures

**Interfaces & Contracts:**
- All public methods return value objects or throw exceptions; avoid returning raw `Map` or internal state
- Defensive design: Null-safe, empty-string safe, malformed-token tolerant
- Thread-safe: JwtTokenValidator is stateless and reusable across requests

## Build & Test Workflows

```bash
./mvnw clean package                    # Compile, unit tests, code quality checks
./mvnw test                            # Unit tests only (mocked Cognito responses)
./mvnw verify                          # Full build with Checkstyle, SpotBugs, JaCoCo coverage
```

**Profiles & CI Integration:**
- No Spring profiles—library is framework-agnostic
- CI runs Checkstyle, SpotBugs, and JaCoCo (90%+ coverage enforced)
- Artifacts published to AWS CodeArtifact (domain: `hasslefree`, repository: `maven`)

## Code Organization & Patterns

**Directory Structure:**
```
src/main/java/com/hasslefree/auth/
├── JwtTokenValidator.java          # Main validator (delegated by services)
├── TokenContext.java               # Return type for token info
├── JwtTokenParser.java             # Internal parsing logic
├── RoleChecker.java                # Role utility methods
├── exception/
│   ├── InvalidTokenException.java
│   └── TokenExpiredException.java
└── config/
    └── CognitoConfig.java          # Cognito JWKS caching config
```

**Key Patterns:**
1. **Immutable Value Objects**: `TokenContext` is immutable; use builder if needed
2. **Fail-Fast**: Invalid tokens throw immediately; don't return nulls or false positives
3. **Stateless Validators**: `JwtTokenValidator` is thread-safe; reuse instances across requests
4. **Defensive Input Handling**: Handle null tokens, empty strings, and malformed JWTs gracefully
5. **Comprehensive Javadoc**: Every public method documented; include `@throws` for exceptions

**Example Usage (from consuming services):**
```java
// In auth-service or app-service
JwtTokenValidator validator = new JwtTokenValidator(
    "us-east-1", 
    "us-east-1_Ugq1P6hFH", 
    "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Ugq1P6hFH/.well-known/jwks.json"
);

try {
    TokenContext ctx = validator.validateAndExtractToken(jwtToken);
    if (ctx.hasRole("ADMIN")) { /* ... */ }
} catch (InvalidTokenException e) {
    return ResponseEntity.status(401).build();
} catch (TokenExpiredException e) {
    return ResponseEntity.status(403).build();
}
```

## External Dependencies & Constraints

1. **AWS Cognito Integration**
   - Validates JWTs issued by Cognito user pool: `us-east-1_Ugq1P6hFH`
   - Fetches and caches JWKS from Cognito endpoint
   - Library does NOT call AWS SDK directly; only validates tokens

2. **No Spring Boot Dependency**
   - Library must be usable in non-Spring applications
   - No `@Bean`, `@Component`, or Spring annotations in core classes
   - Tests can use Spring for convenience, but core code is framework-agnostic

3. **Maven & Artifact Publication**
   - Built and published via GitHub Actions CI (`.github/workflows/publish-codeartifact.yml`)
   - Version controlled in `pom.xml`; use semantic versioning (e.g., `1.0.0`, `1.0.1-SNAPSHOT`)

## Project-Specific Conventions

1. **Exception Design**: Create specific exception types (`InvalidTokenException`, `TokenExpiredException`); include root cause for debugging
2. **Logging**: Use SLF4J; log at DEBUG level for token parsing, WARN for validation failures
3. **Testing**: Unit tests use Mockito for JWKS responses; no external API calls; aim for 90%+ code coverage
4. **Javadoc**: All public APIs fully documented with examples and exception documentation
5. **Code Quality**: Checkstyle enforces Google style; SpotBugs flags potential bugs; no warnings allowed

## Cross-Component Communication

- **Used by**: `auth-service` (filter/validator), `app-service` (auth middleware)
- **Not used in**: Infrastructure, CI/CD, database schema
- **Changes trigger**: Rebuild and re-publish artifact to CodeArtifact; services must upgrade dependency version

## Common Tasks

- **Add new claim extraction**: Update `TokenContext` immutable class, add accessor method, add unit test
- **Add role validation method**: Add to `RoleChecker`; ensure method name is clear (e.g., `isAdminOrOwner()`)
- **Update Cognito JWKS endpoint**: Modify `CognitoConfig` JWKS URL; update tests to mock new endpoint
- **Publish new version**: Increment `pom.xml` version, merge to main, CI automatically publishes to CodeArtifact
- **Fix validation logic**: Update `JwtTokenValidator` validation method; run `mvn verify` to ensure no test/coverage regressions
