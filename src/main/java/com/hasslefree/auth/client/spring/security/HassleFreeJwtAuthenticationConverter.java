package com.hasslefree.auth.client.spring.security;

import com.hasslefree.auth.client.access.AccessGrant;
import com.hasslefree.auth.client.spring.config.AuthClientProperties;
import com.hasslefree.auth.client.spring.extract.AccessGrantClaimParser;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.StringUtils;

/**
 * Shared JWT converter for HassleFree services.
 *
 * <p>By default, principal is resolved from custom:userId claim and fallback to sub is disabled.
 */
public class HassleFreeJwtAuthenticationConverter
    implements Converter<Jwt, AbstractAuthenticationToken> {

  private static final OAuth2Error INVALID_TOKEN =
      new OAuth2Error("invalid_token", "Missing required user-id claim", null);

  private final AuthClientProperties properties;
  private final AccessGrantClaimParser accessGrantClaimParser;

  public HassleFreeJwtAuthenticationConverter(
      AuthClientProperties properties, AccessGrantClaimParser accessGrantClaimParser) {
    this.properties = properties;
    this.accessGrantClaimParser = accessGrantClaimParser;
  }

  @Override
  public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
    String principalName = resolvePrincipalName(jwt);
    Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
    return new JwtAuthenticationToken(jwt, authorities, principalName);
  }

  private String resolvePrincipalName(Jwt jwt) {
    String claimName = properties.getUserIdClaim();
    String userIdClaimValue = claimAsString(jwt, claimName);
    if (StringUtils.hasText(userIdClaimValue)) {
      return userIdClaimValue;
    }

    if (!properties.isAllowFallbackSubUuid()) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(
              INVALID_TOKEN.getErrorCode(),
              "Missing required user-id claim '" + claimName + "'",
              INVALID_TOKEN.getUri()));
    }

    String principalClaim = claimAsString(jwt, properties.getClaims().getPrincipalKey());
    if (StringUtils.hasText(principalClaim)) {
      return principalClaim;
    }
    if (StringUtils.hasText(jwt.getSubject())) {
      return jwt.getSubject();
    }
    throw new OAuth2AuthenticationException(
        new OAuth2Error(
            INVALID_TOKEN.getErrorCode(),
            "Authenticated principal is not available",
            INVALID_TOKEN.getUri()));
  }

  private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
    List<String> keys = properties.getClaims().getAccessGrantKeys();
    if (keys == null || keys.isEmpty()) {
      return List.of();
    }

    Set<String> authorities = new LinkedHashSet<>();
    for (String key : keys) {
      if (!StringUtils.hasText(key)) {
        continue;
      }
      Object rawClaim = jwt.getClaims().get(key);
      Set<AccessGrant> grants = accessGrantClaimParser.parse(rawClaim);
      if (grants.isEmpty()) {
        continue;
      }
      for (AccessGrant grant : grants) {
        authorities.add(grant.permission().value().toUpperCase(Locale.ROOT));
      }
      break;
    }

    if (authorities.isEmpty()) {
      return List.of();
    }

    List<GrantedAuthority> grantedAuthorities = new ArrayList<>(authorities.size());
    for (String authority : authorities) {
      grantedAuthorities.add(new SimpleGrantedAuthority(authority));
    }
    return grantedAuthorities;
  }

  private String claimAsString(Jwt jwt, String key) {
    if (!StringUtils.hasText(key)) {
      return null;
    }
    Object value = jwt.getClaims().get(key);
    if (value == null) {
      return null;
    }
    String normalized = String.valueOf(value).trim();
    return normalized.isEmpty() ? null : normalized;
  }
}
