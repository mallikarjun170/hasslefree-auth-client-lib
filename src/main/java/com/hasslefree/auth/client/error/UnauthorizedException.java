package com.hasslefree.auth.client.error;

/**
 * Thrown when no valid authenticated principal context is available.
 */
public class UnauthorizedException extends RuntimeException {

  public UnauthorizedException(String message) {
    super(message);
  }

  public UnauthorizedException(String message, Throwable cause) {
    super(message, cause);
  }
}
