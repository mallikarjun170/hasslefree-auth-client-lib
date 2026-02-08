package com.hasslefree.auth.common.resolver;

import com.hasslefree.auth.client.filter.CorrelationIdFilter;
import com.hasslefree.auth.common.annotation.AuthContext;
import com.hasslefree.auth.common.dto.AuthenticationContext;
import com.hasslefree.auth.common.dto.RequestMetadata;
import com.hasslefree.auth.common.util.AuthContextExtractor;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Resolver to inject AuthenticationContext into controller methods.
 *
 * <p><b>UPDATED for Spring OAuth2 Resource Server:</b> This resolver now reads from Spring
 * Security's SecurityContext instead of parsing the Authorization header directly. Spring Resource
 * Server validates the JWT signature, expiration, and issuer before placing it in SecurityContext.
 *
 * <p>Usage in controllers:
 *
 * <pre>{@code
 * @GetMapping("/example")
 * public ResponseEntity<String> example(@AuthContext AuthenticationContext authContext) {
 *     String userId = authContext.getUserId();
 *     // ...
 * }
 * }</pre>
 *
 * <p><b>Migration note:</b> Old behavior: Parsed Authorization header directly (no validation). New
 * behavior: Reads verified JWT from Spring Security's SecurityContext (validated by Resource
 * Server).
 */
public class AuthContextResolver implements HandlerMethodArgumentResolver {

  private static final Logger logger = LoggerFactory.getLogger(AuthContextResolver.class);
  private final boolean allowLegacyHeaderParsing;

  public AuthContextResolver() {
    this(false);
  }

  public AuthContextResolver(boolean allowLegacyHeaderParsing) {
    this.allowLegacyHeaderParsing = allowLegacyHeaderParsing;
  }

  @Override
  public boolean supportsParameter(@NonNull MethodParameter parameter) {
    return parameter.hasParameterAnnotation(AuthContext.class)
        && AuthenticationContext.class.isAssignableFrom(parameter.getParameterType());
  }

  @Override
  public Object resolveArgument(
      @NonNull MethodParameter parameter,
      @Nullable ModelAndViewContainer mavContainer,
      @NonNull NativeWebRequest webRequest,
      @Nullable WebDataBinderFactory binderFactory)
      throws Exception {

    HttpServletRequest request = webRequest.getNativeRequest(HttpServletRequest.class);
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    if (authentication != null) {
      try {
        Class<?> jwtAuthTokenClass =
            Class.forName(
                "org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken");
        if (jwtAuthTokenClass.isInstance(authentication)) {
          Object jwt = jwtAuthTokenClass.getMethod("getToken").invoke(authentication);
          AuthenticationContext context = AuthContextExtractor.extractFromJwt(jwt);
          if (context != null) {
            logger.debug(
                "Resolved AuthenticationContext from SecurityContext JWT for user: {}",
                context.getUserId());
            return enrichWithMetadata(context, request);
          }
        }
      } catch (ClassNotFoundException e) {
        logger.debug("Spring OAuth2 JWT classes not found, falling back to header parsing");
      } catch (Exception e) {
        logger.warn("Failed to extract context from SecurityContext", e);
      }
    }

    if (!allowLegacyHeaderParsing) {
      logger.warn(
          "SecurityContext did not provide JWT authentication; legacy header parsing is disabled");
      return null;
    }

    logger.debug("Falling back to Authorization header parsing (legacy mode)");
    if (request == null) {
      logger.warn("HttpServletRequest is null, cannot resolve AuthenticationContext");
      return null;
    }
    String authHeader = request.getHeader("Authorization");
    if (authHeader == null || authHeader.isBlank()) {
      logger.debug("Authorization header is missing");
      return null;
    }

    try {
      String token = authHeader;
      if (authHeader.startsWith("Bearer ")) {
        token = authHeader.substring(7);
      }
      SignedJWT signedJWT = SignedJWT.parse(token);
      JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
      AuthenticationContext context = AuthContextExtractor.extractFromClaims(claims, token);
      if (context != null) {
        logger.debug(
            "Resolved AuthenticationContext from Authorization header (legacy) for user: {}",
            context.getUserId());
      }
      return enrichWithMetadata(context, request);
    } catch (Exception e) {
      logger.error("Failed to parse JWT token from Authorization header", e);
      return null;
    }
  }

  private AuthenticationContext enrichWithMetadata(
      AuthenticationContext context, HttpServletRequest request) {
    if (context == null || request == null) {
      return context;
    }
    RequestMetadata metadata =
        RequestMetadata.builder()
            .correlationId(resolveCorrelationId(request))
            .remoteIp(resolveRemoteIp(request))
            .userAgent(request.getHeader("User-Agent"))
            .build();
    context.setMetadata(metadata);
    return context;
  }

  private String resolveCorrelationId(HttpServletRequest request) {
    Object attr = request.getAttribute(CorrelationIdFilter.CORRELATION_ID_ATTR);
    if (attr instanceof String str && !str.isBlank()) {
      return str;
    }
    return request.getHeader(CorrelationIdFilter.CORRELATION_ID_HEADER);
  }

  private String resolveRemoteIp(HttpServletRequest request) {
    String forwarded = request.getHeader("X-Forwarded-For");
    if (forwarded != null && !forwarded.isBlank()) {
      return forwarded.split(",")[0].trim();
    }
    return request.getRemoteAddr();
  }
}
