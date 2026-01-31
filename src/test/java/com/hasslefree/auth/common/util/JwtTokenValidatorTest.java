package com.hasslefree.auth.common.util;

import com.hasslefree.auth.common.exception.AuthenticationException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenValidatorTest {

    @Test
    void validateToken_nullOrEmpty_returnsFalse() {
        JwtTokenValidator validator = new JwtTokenValidator("us-east-1", "dummyPool", "https://dummy/jwks.json");
        assertFalse(validator.validateToken(null), "Null token should be invalid");
        assertFalse(validator.validateToken("   "), "Empty token should be invalid");
    }

    @Test
    void getUsernameFromToken_invalidToken_throwsAuthenticationException() {
        JwtTokenValidator validator = new JwtTokenValidator("us-east-1", "dummyPool", "https://dummy/jwks.json");
        assertThrows(AuthenticationException.class, () -> validator.getUsernameFromToken("not-a-jwt"));
    }

    @Test
    void getUserIdFromToken_invalidToken_throwsAuthenticationException() {
        JwtTokenValidator validator = new JwtTokenValidator("us-east-1", "dummyPool", "https://dummy/jwks.json");
        assertThrows(AuthenticationException.class, () -> validator.getUserIdFromToken("not-a-jwt"));
    }

    // More tests for valid/expired tokens can be added with proper JWT mocking
}
