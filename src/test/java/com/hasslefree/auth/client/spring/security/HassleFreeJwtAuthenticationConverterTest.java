package com.hasslefree.auth.client.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.hasslefree.auth.client.spring.config.AuthClientProperties;
import com.hasslefree.auth.client.spring.extract.AccessGrantClaimParser;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

class HassleFreeJwtAuthenticationConverterTest {

  @Test
  void usesCustomUserIdAsPrincipalInStrictMode() {
    String userId = UUID.randomUUID().toString();
    AuthClientProperties properties = new AuthClientProperties();
    properties.setAllowFallbackSubUuid(false);
    HassleFreeJwtAuthenticationConverter converter =
        new HassleFreeJwtAuthenticationConverter(properties, new AccessGrantClaimParser());

    JwtAuthenticationToken authentication =
        (JwtAuthenticationToken)
            converter.convert(
                jwtBuilder()
                    .subject("cognito-sub")
                    .claim("custom:userId", userId)
                    .claim("permissions", List.of("PROPERTY_READ", "ORG_UPDATE"))
                    .build());

    assertThat(authentication.getName()).isEqualTo(userId);
    assertThat(authentication.getAuthorities())
        .extracting("authority")
        .containsExactly("PROPERTY_READ", "ORG_UPDATE");
  }

  @Test
  void rejectsMissingCustomUserIdInStrictMode() {
    AuthClientProperties properties = new AuthClientProperties();
    properties.setAllowFallbackSubUuid(false);
    HassleFreeJwtAuthenticationConverter converter =
        new HassleFreeJwtAuthenticationConverter(properties, new AccessGrantClaimParser());

    assertThatThrownBy(() -> converter.convert(jwtBuilder().subject(UUID.randomUUID().toString()).build()))
        .isInstanceOf(OAuth2AuthenticationException.class)
        .hasMessageContaining("Missing required user-id claim");
  }

  @Test
  void supportsSubFallbackWhenEnabled() {
    String subject = UUID.randomUUID().toString();
    AuthClientProperties properties = new AuthClientProperties();
    properties.setAllowFallbackSubUuid(true);
    HassleFreeJwtAuthenticationConverter converter =
        new HassleFreeJwtAuthenticationConverter(properties, new AccessGrantClaimParser());

    JwtAuthenticationToken authentication =
        (JwtAuthenticationToken) converter.convert(jwtBuilder().subject(subject).build());

    assertThat(authentication.getName()).isEqualTo(subject);
  }

  private Jwt.Builder jwtBuilder() {
    return Jwt.withTokenValue("token")
        .header("alg", "none")
        .issuedAt(Instant.now())
        .expiresAt(Instant.now().plusSeconds(300));
  }
}
