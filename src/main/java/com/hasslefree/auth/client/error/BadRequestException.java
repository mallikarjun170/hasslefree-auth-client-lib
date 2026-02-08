package com.hasslefree.auth.client.error;

/**
 * Thrown when auth inputs/configuration are invalid.
 */
public class BadRequestException extends RuntimeException {

  public BadRequestException(String message) {
    super(message);
  }

  public BadRequestException(String message, Throwable cause) {
    super(message, cause);
  }
}
