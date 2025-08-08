package com.hasslefree.auth.common.exception;

/**
 * Exception thrown when JWT token is invalid or malformed.
 */
public class InvalidTokenException extends AuthenticationException {
    public InvalidTokenException(String message) {
        super(message);
    }
    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
