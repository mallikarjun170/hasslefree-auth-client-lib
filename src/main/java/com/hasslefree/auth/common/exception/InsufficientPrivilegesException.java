package com.hasslefree.auth.common.exception;

/**
 * Exception thrown when user lacks sufficient privileges for an operation.
 */
public class InsufficientPrivilegesException extends AuthenticationException {
    
    public InsufficientPrivilegesException(String message) {
        super(message);
    }
    
    public InsufficientPrivilegesException(String message, Throwable cause) {
        super(message, cause);
    }
}
