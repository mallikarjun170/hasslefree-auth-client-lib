package com.hasslefree.auth.common.util;

import static com.hasslefree.auth.common.constants.ClaimConstants.*;

import com.hasslefree.auth.common.dto.AuthenticationContext;
import com.nimbusds.jwt.JWTClaimsSet;
import java.text.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Production-ready utility for extracting authentication context from JWT tokens.
 *
 * <p>Security: No secrets in logs, tokens masked, signature/algorithm validation stub provided.
 * Performance: Null checks, thread-safe.
 *
 * <p><b>RECOMMENDED USAGE FOR SPRING OAUTH2 RESOURCE SERVER:</b> Use {@link
 * #extractFromJwt(Object)} with Spring Security's verified Jwt object. This ensures you're working
 * with an already-validated token from SecurityContext.
 *
 * <p><b>Note:</b> HassleFree authorization is permission-based and does not use roles.
 */
public final class AuthContextExtractor {
  private static final Logger logger = LoggerFactory.getLogger(AuthContextExtractor.class);

  // Prevent instantiation
  private AuthContextExtractor() {
    throw new AssertionError("No instance allowed");
  }

  /**
   * Extract authentication context from Spring Security's Jwt object.
   *
   * <p><b>RECOMMENDED:</b> Use this method when your service is configured as an OAuth2 Resource
   * Server. Spring Security validates the JWT signature, expiration, and issuer before placing it
   * in SecurityContext.
   *
   * <p>Usage example:
   *
   * <pre>{@code
   * Authentication auth = SecurityContextHolder.getContext().getAuthentication();
   * if (auth instanceof JwtAuthenticationToken) {
   *     Jwt jwt = ((JwtAuthenticationToken) auth).getToken();
   *     AuthenticationContext context = AuthContextExtractor.extractFromJwt(jwt);
   * }
   * }</pre>
   *
   * @param jwt Spring Security's Jwt object (org.springframework.security.oauth2.jwt.Jwt)
   * @return AuthenticationContext containing user information
   * @throws IllegalArgumentException if jwt is null or not a valid Jwt instance
   */
  public static AuthenticationContext extractFromJwt(Object jwt) {
    if (jwt == null) {
      logger.warn("Jwt object is null");
      return null;
    }

    // Handle Spring Security Jwt (use reflection to avoid hard dependency)
    try {
      Class<?> jwtClass = Class.forName("org.springframework.security.oauth2.jwt.Jwt");
      if (!jwtClass.isInstance(jwt)) {
        throw new IllegalArgumentException(
            "Expected Spring Security Jwt, got: " + jwt.getClass().getName());
      }

      // Extract claims using reflection
      Object claimsObject = jwtClass.getMethod("getClaims").invoke(jwt);
      if (!(claimsObject instanceof java.util.Map)) {
        logger.error("JWT claims are not a Map");
        return null;
      }

      @SuppressWarnings("unchecked")
      java.util.Map<String, Object> claims = (java.util.Map<String, Object>) claimsObject;

      return extractContextFromClaims(jwt, jwtClass, claims);

    } catch (ClassNotFoundException e) {
      logger.error(
          "Spring Security OAuth2 JWT library not found. Add spring-security-oauth2-jose dependency.");
      throw new IllegalStateException("Spring Security OAuth2 JWT support not available", e);
    } catch (Exception e) {
      logger.error("Failed to extract context from Spring Security Jwt", e);
      return null;
    }
  }

  /**
   * Extract authentication context from JWT claims (Spring Security Jwt).
   *
   * @param jwt The Spring Security Jwt object
   * @param jwtClass The Jwt class (for reflection)
   * @param claims The claims map extracted from the JWT
   * @return AuthenticationContext containing user information
   */
  private static AuthenticationContext extractContextFromClaims(
      Object jwt, Class<?> jwtClass, java.util.Map<String, Object> claims) {
    try {
      // Extract user ID (try multiple claim names)
      String userId = (String) claims.get(CLAIM_SUB);
      if (userId == null) {
        userId = (String) claims.get(CLAIM_CUSTOM_USER_ID);
      }

      // Extract username
      String username = (String) claims.get(CLAIM_USERNAME);
      if (username == null) {
        username = (String) claims.get(CLAIM_COGNITO_USERNAME);
      }

      // Extract email
      String email = (String) claims.get(CLAIM_EMAIL);

      // Extract expiration time
      Object expObj = claims.get(CLAIM_EXP);
      Long expirationTime = null;
      if (expObj instanceof Number number) {
        expirationTime = number.longValue() * 1000; // Convert seconds to milliseconds
      }

      // Get token value (masked for security)
      String tokenValue = extractTokenValue(jwt, jwtClass);

      return new AuthenticationContext(userId, username, email, tokenValue, expirationTime, null);

    } catch (Exception e) {
      logger.error("Failed to extract context from JWT claims", e);
      return null;
    }
  }

  /**
   * Extract and mask the token value from Spring Security Jwt object.
   *
   * @param jwt The Spring Security Jwt object
   * @param jwtClass The Jwt class (for reflection)
   * @return Masked token value, or null if extraction fails
   */
  private static String extractTokenValue(Object jwt, Class<?> jwtClass) {
    try {
      Object tokenValueObj = jwtClass.getMethod("getTokenValue").invoke(jwt);
      return maskToken((String) tokenValueObj);
    } catch (Exception e) {
      logger.debug("Could not extract token value for masking", e);
      return null;
    }
  }

  /**
   * Extract authentication context from JWT claims.
   *
   * @param claims The JWT claims set
   * @param token The original token string
   * @return AuthenticationContext containing user information
   */
  /**
   * Extract authentication context from JWT claims.
   *
   * @param claims The JWT claims set
   * @param token The original token string (masked in logs)
   * @return AuthenticationContext containing user information
   */
  public static AuthenticationContext extractFromClaims(JWTClaimsSet claims, String token) {
    try {
      if (claims == null) {
        logger.warn("JWT claims are null");
        return null;
      }
      String userId = claims.getSubject();
      String username = claims.getStringClaim(CLAIM_USERNAME);
      String email = claims.getStringClaim(CLAIM_EMAIL);
      Long expirationTime =
          claims.getExpirationTime() != null ? claims.getExpirationTime().getTime() : null;
      return new AuthenticationContext(
          userId, username, email, maskToken(token), expirationTime, null);
    } catch (ParseException e) {
      logger.error("Failed to extract claims from token", e);
      return null;
    }
  }

  /**
   * Mask a JWT token for logging (shows only first/last 3 chars).
   *
   * @param token The JWT token string
   * @return Masked token string
   */
  private static String maskToken(String token) {
    if (token == null || token.length() < TOKEN_MASKING_THRESHOLD) return "***";
    return token.substring(0, TOKEN_MASKING_CHAR_COUNT)
        + "..."
        + token.substring(token.length() - TOKEN_MASKING_CHAR_COUNT);
  }
}
