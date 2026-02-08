package com.hasslefree.auth.client.exception;

/** Signals failures while interacting with the authz service. */
public class AuthzClientException extends RuntimeException {
  public AuthzClientException(String message, Throwable cause) {
    super(message, cause);
  }
}
