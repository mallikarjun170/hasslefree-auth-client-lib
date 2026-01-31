# HassleFree Auth Client Library

A shared authentication and authorization library for HassleFree microservices.

## ⚠️ IMPORTANT: Migration to Spring OAuth2 Resource Server

**This library has been updated to work with Spring Security's OAuth2 Resource Server.**

### Old Approach (Deprecated)
```java
// ❌ DO NOT USE: Custom JWT filter with direct header parsing
@Bean
public JwtAuthenticationFilter jwtAuthenticationFilter() {
    return new JwtAuthenticationFilter(jwtTokenValidator);
}
```

### New Approach (Recommended)
```java
// ✅ USE: Spring OAuth2 Resource Server
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt());
        return http.build();
    }
}
```

---

## Quick Start

### 1. Add Dependencies

```xml
<dependencies>
    <!-- HassleFree Auth Client Library -->
    <dependency>
        <groupId>com.hasslefree</groupId>
        <artifactId>auth-client-lib</artifactId>
        <version>1.0-SNAPSHOT</version>
    </dependency>
    
    <!-- Spring Security OAuth2 Resource Server -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    </dependency>
</dependencies>
```

### 2. Configure Application

```yaml
# application.yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          # AWS Cognito JWKS URL
          jwk-set-uri: https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json
          # Example: https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABC123/.well-known/jwks.json
```

### 3. Configure Security

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(customJwtConverter())
                )
            );
        return http.build();
    }
    
    @Bean
    public Converter<Jwt, AbstractAuthenticationToken> customJwtConverter() {
        return jwt -> {
            // Extract custom:userId as principal name
            String principalName = jwt.getClaimAsString("custom:userId");
            if (principalName == null) {
                principalName = jwt.getSubject();
            }
            return new JwtAuthenticationToken(jwt, Collections.emptyList(), principalName);
        };
    }
}
```

### 4. Use @AuthContext in Controllers

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @GetMapping("/profile")
    public ResponseEntity<UserProfile> getProfile(@AuthContext AuthenticationContext authContext) {
        String userId = authContext.getUserId();
        String email = authContext.getEmail();
        // Use authenticated user info...
        return ResponseEntity.ok(userProfile);
    }
}
```

### 5. Enable @AuthContext Resolver

```java
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new AuthContextResolver());
    }
}
```

---

## How It Works

### Authentication Flow

1. **Client** sends request with `Authorization: Bearer <JWT>` header
2. **Spring Security** validates JWT:
   - Signature (using public keys from JWKS URL)
   - Expiration (`exp` claim)
   - Issuer (`iss` claim)
3. **JWT** is placed in `SecurityContext` as `JwtAuthenticationToken`
4. **AuthContextResolver** extracts claims from verified JWT
5. **Controller** receives `@AuthContext AuthenticationContext`

### What Changed?

| Component | Old Behavior | New Behavior |
|-----------|-------------|--------------|
| **JWT Validation** | Custom filter with manual validation | Spring Security validates automatically |
| **Security Boundary** | Custom `JwtAuthenticationFilter` | Standard `OAuth2ResourceServerConfigurer` |
| **@AuthContext** | Parsed Authorization header | Reads from `SecurityContext` |
| **Claims Access** | Direct header parsing (risky) | Verified `Jwt` object from SecurityContext |

---

## API Reference

### `@AuthContext` Annotation

Injects authenticated user context into controller methods.

```java
@GetMapping("/example")
public ResponseEntity<String> example(@AuthContext AuthenticationContext authContext) {
    String userId = authContext.getUserId();      // from custom:userId claim
    String email = authContext.getEmail();        // from email claim
    String username = authContext.getUsername();  // from username claim
    Set<UserRole> roles = authContext.getRoles(); // from cognito:groups (optional)
    return ResponseEntity.ok("Hello, " + username);
}
```

### `AuthenticationContext` Fields

```java
public class AuthenticationContext {
    private String userId;                    // Custom:userId (UUID)
    private String username;                  // Username from JWT
    private String email;                     // Email from JWT
    private Set<UserRole> roles;              // Roles (TENANT, OWNER, MANAGER, ADMIN)
    private String accessToken;               // Masked token (for logging)
    private Long tokenExpirationTime;         // Token expiration (milliseconds)
}
```

### `AuthContextExtractor` Utility

Extract context from Spring Security's verified JWT:

```java
// Recommended: Use with Spring OAuth2 Resource Server
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
if (auth instanceof JwtAuthenticationToken) {
    Jwt jwt = ((JwtAuthenticationToken) auth).getToken();
    AuthenticationContext context = AuthContextExtractor.extractFromJwt(jwt);
}

// Legacy: Direct token parsing (no validation)
@Deprecated
AuthenticationContext context = AuthContextExtractor.extractFromToken(authHeader);
```

---

## Migration Guide

### For Existing Services Using Custom JWT Filter

**Step 1: Remove Custom JWT Filter**

```java
// ❌ Remove these beans
@Bean
public JwtAuthenticationFilter jwtAuthenticationFilter() { ... }

@Bean
public JwtTokenValidator jwtTokenValidator() { ... }
```

**Step 2: Add OAuth2 Resource Server Configuration**

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: https://cognito-idp.us-east-1.amazonaws.com/{userPoolId}/.well-known/jwks.json
```

**Step 3: Update SecurityConfig**

```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(authz -> authz
            .requestMatchers("/api/**").authenticated()
        )
        .oauth2ResourceServer(oauth2 -> oauth2.jwt());  // Add this
    return http.build();
}
```

**Step 4: No Changes to Controllers**

`@AuthContext` continues to work! The resolver automatically detects Spring Security's JWT.

---

## Security Best Practices

1. **Use HTTPS**: Always use HTTPS in production
2. **Validate Issuer**: Ensure `iss` claim matches your Cognito User Pool
3. **Short Token Lifetimes**: Configure Cognito tokens to expire in 1 hour or less
4. **Rotate Keys**: AWS Cognito automatically rotates signing keys
5. **Monitor Failed Attempts**: Log authentication failures for security auditing

---

## Troubleshooting

### Problem: 401 Unauthorized

**Cause**: JWT validation failed

**Solutions**:
- Check `jwk-set-uri` is correct
- Verify token is not expired (`exp` claim)
- Ensure token was issued by correct User Pool (`iss` claim)
- Check network connectivity to JWKS endpoint

### Problem: @AuthContext is null

**Cause**: Resolver cannot extract JWT from SecurityContext

**Solutions**:
- Verify Spring Security is configured as OAuth2 Resource Server
- Check `Authorization: Bearer <token>` header is present
- Enable debug logging: `logging.level.com.hasslefree.auth=DEBUG`

### Problem: Custom:userId claim missing

**Cause**: JWT doesn't contain `custom:userId` claim

**Solutions**:
- Add `custom:userId` as a custom attribute in Cognito
- Map `custom:userId` in Pre Token Generation Lambda Trigger
- Fallback: Resolver uses `sub` claim if `custom:userId` missing

---

## Deprecated Components

The following components are kept for backward compatibility but should NOT be used in new code:

- `JwtAuthenticationFilter` → Use Spring OAuth2 Resource Server
- `JwtTokenValidator` → Use Spring's automatic JWT validation
- `AuthContextExtractor.extractFromToken(String)` → Use `extractFromJwt(Jwt)`

---

## Support

For issues or questions, contact the HassleFree platform team.
