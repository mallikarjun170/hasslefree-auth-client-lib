package com.hasslefree.auth.client.spring.context;

import com.hasslefree.auth.client.spring.config.AuthClientProperties;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/** Resolves the current authenticated user UUID from JWT claims. */
public class CurrentUserIdProvider {

  private final CurrentAuthContextProvider currentAuthContextProvider;
  private final AuthClientProperties properties;

  public CurrentUserIdProvider(
      CurrentAuthContextProvider currentAuthContextProvider, AuthClientProperties properties) {
    this.currentAuthContextProvider = currentAuthContextProvider;
    this.properties = properties;
  }

  public UUID requireCurrentUserId() {
    String claimName = properties.getUserIdClaim();
    boolean allowFallbackSubUuid = properties.isAllowFallbackSubUuid();

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (!(authentication instanceof JwtAuthenticationToken jwtAuthenticationToken)) {
      throw new AccessDeniedException("JWT authentication with claim '" + claimName + "' is required");
    }

    String claimValue = jwtAuthenticationToken.getToken().getClaimAsString(claimName);
    if (claimValue != null && !claimValue.isBlank()) {
      return parseUuid(claimValue.trim())
          .orElseThrow(
              () ->
                  new AccessDeniedException(
                      "Invalid user-id claim '" + claimName + "': expected UUID"));
    }

    if (!allowFallbackSubUuid) {
      throw new AccessDeniedException("Missing required user-id claim '" + claimName + "'");
    }

    Optional<com.hasslefree.auth.client.context.AuthContext> authContext =
        currentAuthContextProvider.current();
    return Optional.ofNullable(authentication.getName())
        .filter(name -> !name.isBlank())
        .map(String::trim)
        .flatMap(this::parseUuid)
        .or(() -> authContext.map(com.hasslefree.auth.client.context.AuthContext::principal).flatMap(this::parseUuid))
        .or(() -> authContext.map(com.hasslefree.auth.client.context.AuthContext::subject).flatMap(this::parseUuid))
        .orElseThrow(() -> new AccessDeniedException("Authenticated user id is not available"));
  }

  private Optional<UUID> parseUuid(String value) {
    try {
      return Optional.of(UUID.fromString(value));
    } catch (IllegalArgumentException ex) {
      return Optional.empty();
    }
  }
}
