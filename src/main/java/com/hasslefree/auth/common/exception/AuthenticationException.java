package com.hasslefree.auth.common.exception;

/**
 * Base exception class for authentication-related errors.
 * This can be used across all microservices for consistent error handling.
 */
public class AuthenticationException extends RuntimeException {
    public AuthenticationException(String message) {
        super(message);
    }
    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
