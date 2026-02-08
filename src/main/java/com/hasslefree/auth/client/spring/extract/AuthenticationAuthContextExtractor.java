package com.hasslefree.auth.client.spring.extract;

import com.hasslefree.auth.client.access.AccessGrant;
import com.hasslefree.auth.client.context.AuthContext;
import com.hasslefree.auth.client.error.BadRequestException;
import com.hasslefree.auth.client.error.UnauthorizedException;
import com.hasslefree.auth.client.spring.config.AuthClientProperties;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Extracts AuthContext from Spring Security Authentication/Jwt.
 */
public class AuthenticationAuthContextExtractor {

  private final AuthClientProperties properties;
  private final AccessGrantClaimParser grantClaimParser;

  public AuthenticationAuthContextExtractor(
      AuthClientProperties properties, AccessGrantClaimParser grantClaimParser) {
    this.properties = properties;
    this.grantClaimParser = grantClaimParser;
  }

  public Optional<AuthContext> fromAuthentication(Authentication authentication) {
    if (authentication == null) {
      return Optional.empty();
    }

    Object principal = authentication.getPrincipal();
    if (principal instanceof Jwt jwt) {
      return Optional.of(fromJwt(jwt));
    }

    if (authentication.getCredentials() instanceof Jwt jwtCredentials) {
      return Optional.of(fromJwt(jwtCredentials));
    }

    return Optional.empty();
  }

  public AuthContext fromJwt(Jwt jwt) {
    if (jwt == null) {
      throw new UnauthorizedException("JWT is required");
    }

    Map<String, Object> claims = jwt.getClaims();
    validateRequiredClaims(claims, properties.getClaims().getRequiredClaimKeys());
    validateIssuer(jwt);
    validateAudience(jwt);

    String subject = requiredClaimAsString(jwt, properties.getClaims().getSubjectKey(), "subject");
    String principal = claimAsString(jwt, properties.getClaims().getPrincipalKey());
    if (principal == null || principal.isBlank()) {
      principal = subject;
    }

    String email = claimAsString(jwt, properties.getClaims().getEmailKey());
    Set<AccessGrant> grants = extractAccessGrants(claims, properties.getClaims().getAccessGrantKeys());

    return new AuthContext(subject, principal, email, grants, claims);
  }

  private void validateRequiredClaims(Map<String, Object> claims, List<String> requiredKeys) {
    if (requiredKeys == null || requiredKeys.isEmpty()) {
      return;
    }
    for (String key : requiredKeys) {
      if (key == null || key.isBlank()) {
        continue;
      }
      Object value = claims.get(key);
      if (value == null || String.valueOf(value).isBlank()) {
        throw new UnauthorizedException("Missing required claim: " + key);
      }
    }
  }

  private void validateIssuer(Jwt jwt) {
    AuthClientProperties.Claims claimsProperties = properties.getClaims();
    if (!claimsProperties.isValidateIssuer()) {
      return;
    }
    String expected = claimsProperties.getIssuer();
    if (expected == null || expected.isBlank()) {
      throw new BadRequestException("hasslefree.auth.claims.issuer must be set when validateIssuer=true");
    }
    String actual = jwt.getIssuer() == null ? null : jwt.getIssuer().toString();
    if (!expected.equals(actual)) {
      throw new UnauthorizedException("Invalid issuer claim");
    }
  }

  private void validateAudience(Jwt jwt) {
    AuthClientProperties.Claims claimsProperties = properties.getClaims();
    if (!claimsProperties.isValidateAudience()) {
      return;
    }
    String expected = claimsProperties.getAudience();
    if (expected == null || expected.isBlank()) {
      throw new BadRequestException("hasslefree.auth.claims.audience must be set when validateAudience=true");
    }
    List<String> audiences = jwt.getAudience();
    if (audiences == null || audiences.stream().noneMatch(expected::equals)) {
      throw new UnauthorizedException("Invalid audience claim");
    }
  }

  private Set<AccessGrant> extractAccessGrants(Map<String, Object> claims, List<String> keys) {
    if (keys == null || keys.isEmpty()) {
      return Set.of();
    }
    for (String key : keys) {
      if (key == null || key.isBlank()) {
        continue;
      }
      Object raw = claims.get(key);
      Set<AccessGrant> parsed = grantClaimParser.parse(raw);
      if (!parsed.isEmpty()) {
        return parsed;
      }
    }
    return Set.of();
  }

  private String requiredClaimAsString(Jwt jwt, String key, String label) {
    String value = claimAsString(jwt, key);
    if (value == null || value.isBlank()) {
      throw new UnauthorizedException("Missing required " + label + " claim");
    }
    return value;
  }

  private String claimAsString(Jwt jwt, String key) {
    if (key == null || key.isBlank()) {
      return null;
    }
    Object value = jwt.getClaims().get(key);
    if (value == null) {
      return null;
    }
    String stringValue = String.valueOf(value).trim();
    return stringValue.isEmpty() ? null : stringValue;
  }
}
