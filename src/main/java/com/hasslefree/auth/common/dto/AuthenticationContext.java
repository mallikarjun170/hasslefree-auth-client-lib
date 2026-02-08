package com.hasslefree.auth.common.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Represents the authentication context for a user across all services. This contains all the
 * essential information extracted from JWT tokens.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationContext {
  private String userId;
  private String username;
  private String email;

  private String accessToken;
  private Long tokenExpirationTime;
  private RequestMetadata metadata;

  public boolean isTokenExpired() {
    return tokenExpirationTime != null && System.currentTimeMillis() > tokenExpirationTime;
  }

  @Override
  public String toString() {
    return "AuthenticationContext{"
        + "userId='"
        + userId
        + '\''
        + ", username='"
        + username
        + '\''
        + ", email='"
        + email
        + '\''
        + ", accessToken='***MASKED***'"
        + ", tokenExpired="
        + isTokenExpired()
        + ", metadata="
        + metadata
        + '}';
  }
}
