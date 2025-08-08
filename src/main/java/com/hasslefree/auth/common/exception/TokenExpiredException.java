package com.hasslefree.auth.common.exception;

/**
 * Exception thrown when JWT token is expired.
 */
public class TokenExpiredException extends AuthenticationException {
    public TokenExpiredException(String message) {
        super(message);
    }
    public TokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
