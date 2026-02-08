package com.hasslefree.auth.client.error;

/**
 * Thrown when an authenticated principal is missing required access grants.
 */
public class ForbiddenException extends RuntimeException {

  public ForbiddenException(String message) {
    super(message);
  }

  public ForbiddenException(String message, Throwable cause) {
    super(message, cause);
  }
}
