package com.hasslefree.auth.common.util;

import com.hasslefree.auth.common.exception.InvalidTokenException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenValidatorTest {

    @Test
    void validateToken_nullOrEmpty_throwsInvalidTokenException() {
        JwtTokenValidator validator = new JwtTokenValidator("us-east-1", "dummyPool", "https://dummy/jwks.json");
        assertThrows(InvalidTokenException.class, () -> validator.validateToken(null));
        assertThrows(InvalidTokenException.class, () -> validator.validateToken("   "));
    }

    @Test
    void getUsernameFromToken_invalidToken_throwsInvalidTokenException() {
        JwtTokenValidator validator = new JwtTokenValidator("us-east-1", "dummyPool", "https://dummy/jwks.json");
        assertThrows(InvalidTokenException.class, () -> validator.getUsernameFromToken("not-a-jwt"));
    }

    @Test
    void getUserIdFromToken_invalidToken_throwsInvalidTokenException() {
        JwtTokenValidator validator = new JwtTokenValidator("us-east-1", "dummyPool", "https://dummy/jwks.json");
        assertThrows(InvalidTokenException.class, () -> validator.getUserIdFromToken("not-a-jwt"));
    }

    // More tests for valid/expired tokens can be added with proper JWT mocking
}
