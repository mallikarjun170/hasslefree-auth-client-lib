package com.hasslefree.auth.common.util;

import com.hasslefree.auth.common.dto.AuthenticationContext;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class AuthContextExtractorTest {
    @Test
    void extractFromClaims_nullClaims_returnsNull() {
        assertNull(AuthContextExtractor.extractFromClaims(null, "token"));
    }

    @Test
    void extractFromToken_nullOrEmpty_returnsNull() {
        assertNull(AuthContextExtractor.extractFromToken(null));
        assertNull(AuthContextExtractor.extractFromToken(""));
    }

    @Test
    void extractFromClaims_validClaims_returnsContext() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
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
}
