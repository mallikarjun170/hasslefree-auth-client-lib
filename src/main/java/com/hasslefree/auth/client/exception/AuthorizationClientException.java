package com.hasslefree.auth.client.exception;

/** Signals failures while interacting with the authorization service. */
public class AuthorizationClientException extends RuntimeException {
  public AuthorizationClientException(String message, Throwable cause) {
    super(message, cause);
  }
}
