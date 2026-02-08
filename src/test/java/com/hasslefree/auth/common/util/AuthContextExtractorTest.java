package com.hasslefree.auth.common.util;

import static org.junit.jupiter.api.Assertions.*;

import com.hasslefree.auth.common.dto.AuthenticationContext;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.Date;
import org.junit.jupiter.api.Test;

class AuthContextExtractorTest {
  @Test
  void extractFromClaims_nullClaims_returnsNull() {
    assertNull(AuthContextExtractor.extractFromClaims(null, "token"));
  }

  @Test
  void extractFromClaims_validClaims_returnsContext() throws Exception {
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject("user123")
            .claim("username", "testuser")
            .claim("email", "test@example.com")
            .expirationTime(new Date(System.currentTimeMillis() + 10000))
            .build();
    AuthenticationContext ctx = AuthContextExtractor.extractFromClaims(claims, "token");
    assertNotNull(ctx);
    assertEquals("user123", ctx.getUserId());
    assertEquals("testuser", ctx.getUsername());
    assertEquals("test@example.com", ctx.getEmail());
  }

  @Test
  void extractFromJwt_nullJwt_returnsNull() {
    assertNull(AuthContextExtractor.extractFromJwt(null));
  }

  @Test
  void extractFromJwt_withInvalidObject_returnsNull() {
    // Test with object that doesn't match Spring Security Jwt class
    String invalidJwt = "not-a-jwt-object";

    // Should log error and return null (exception is caught internally)
    AuthenticationContext result = AuthContextExtractor.extractFromJwt(invalidJwt);
    assertNull(result);
  }

  // Note: Cannot properly test extractFromJwt with mock objects without loading Spring Security's
  // Jwt class
  // Integration tests with real Spring Security context should be used for full testing
}
