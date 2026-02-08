package com.hasslefree.auth.client.spring.extract;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.hasslefree.auth.client.context.AuthContext;
import com.hasslefree.auth.client.error.UnauthorizedException;
import com.hasslefree.auth.client.spring.config.AuthClientProperties;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

class AuthenticationAuthContextExtractorTest {

  private final AuthClientProperties properties = new AuthClientProperties();
  private final AuthenticationAuthContextExtractor extractor =
      new AuthenticationAuthContextExtractor(properties, new AccessGrantClaimParser());

  @Test
  void fromAuthentication_extractsAuthContextFromJwtPrincipal() {
    Jwt jwt =
        new Jwt(
            "token",
            Instant.now(),
            Instant.now().plusSeconds(300),
            Map.of("alg", "none"),
            Map.of(
                "sub", "user-1",
                "email", "user@example.com",
                "permissions", List.of("property.read", "property.write")));

    AuthContext context =
        extractor
            .fromAuthentication(new TestingAuthenticationToken(jwt, null))
            .orElseThrow();

    assertThat(context.subject()).isEqualTo("user-1");
    assertThat(context.principal()).isEqualTo("user-1");
    assertThat(context.email()).isEqualTo("user@example.com");
    assertThat(context.hasPermission("property.read")).isTrue();
    assertThat(context.hasPermission("property.write")).isTrue();
  }

  @Test
  void fromJwt_usesScopeWhenPermissionsClaimIsMissing() {
    Jwt jwt =
        new Jwt(
            "token",
            Instant.now(),
            Instant.now().plusSeconds(300),
            Map.of("alg", "none"),
            Map.of("sub", "user-1", "scope", "invoice.read invoice.write"));

    AuthContext context = extractor.fromJwt(jwt);

    assertThat(context.hasPermission("invoice.read")).isTrue();
    assertThat(context.hasPermission("invoice.write")).isTrue();
  }

  @Test
  void fromJwt_throwsWhenRequiredClaimMissing() {
    Jwt jwt =
        new Jwt(
            "token",
            Instant.now(),
            Instant.now().plusSeconds(300),
            Map.of("alg", "none"),
            Map.of("email", "missing-sub@example.com"));

    assertThatThrownBy(() -> extractor.fromJwt(jwt))
        .isInstanceOf(UnauthorizedException.class)
        .hasMessageContaining("Missing required claim");
  }
}
