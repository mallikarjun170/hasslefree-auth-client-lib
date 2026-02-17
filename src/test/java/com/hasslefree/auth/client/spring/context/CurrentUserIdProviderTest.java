package com.hasslefree.auth.client.spring.context;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.hasslefree.auth.client.context.AuthContext;
import com.hasslefree.auth.client.spring.config.AuthClientProperties;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

class CurrentUserIdProviderTest {

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void strictClaimParsingRequiresValidUserIdClaim() {
    AuthClientProperties properties = new AuthClientProperties();
    properties.setUserIdClaim("custom:userId");
    properties.setAllowFallbackSubUuid(false);
    CurrentAuthContextProvider provider = mock(CurrentAuthContextProvider.class);
    CurrentUserIdProvider currentUserIdProvider = new CurrentUserIdProvider(provider, properties);

    JwtAuthenticationToken authentication =
        new JwtAuthenticationToken(
            Jwt.withTokenValue("t")
                .header("alg", "none")
                .claim("custom:userId", UUID.randomUUID().toString())
                .claim("sub", "sub-1")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build());
    SecurityContextHolder.getContext().setAuthentication(authentication);

    assertThat(currentUserIdProvider.requireCurrentUserId()).isNotNull();
  }

  @Test
  void strictClaimParsingFailsWhenClaimMissing() {
    AuthClientProperties properties = new AuthClientProperties();
    properties.setUserIdClaim("custom:userId");
    properties.setAllowFallbackSubUuid(false);
    CurrentAuthContextProvider provider = mock(CurrentAuthContextProvider.class);
    CurrentUserIdProvider currentUserIdProvider = new CurrentUserIdProvider(provider, properties);

    JwtAuthenticationToken authentication =
        new JwtAuthenticationToken(
            Jwt.withTokenValue("t")
                .header("alg", "none")
                .claim("sub", UUID.randomUUID().toString())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build());
    SecurityContextHolder.getContext().setAuthentication(authentication);

    assertThatThrownBy(currentUserIdProvider::requireCurrentUserId)
        .hasMessageContaining("Missing required user-id claim");
  }

  @Test
  void fallbackUsesSubjectWhenEnabled() {
    UUID userId = UUID.randomUUID();
    AuthClientProperties properties = new AuthClientProperties();
    properties.setAllowFallbackSubUuid(true);
    CurrentAuthContextProvider provider = mock(CurrentAuthContextProvider.class);
    when(provider.current())
        .thenReturn(
            Optional.of(
                new AuthContext(
                    "jti",
                    userId.toString(),
                    userId.toString(),
                    List.of(),
                    Map.of())));
    CurrentUserIdProvider currentUserIdProvider = new CurrentUserIdProvider(provider, properties);

    JwtAuthenticationToken authentication =
        new JwtAuthenticationToken(
            Jwt.withTokenValue("t")
                .header("alg", "none")
                .claim("sub", userId.toString())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build());
    SecurityContextHolder.getContext().setAuthentication(authentication);

    assertThat(currentUserIdProvider.requireCurrentUserId()).isEqualTo(userId);
  }
}
