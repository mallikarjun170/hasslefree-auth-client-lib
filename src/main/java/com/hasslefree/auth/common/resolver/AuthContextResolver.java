package com.hasslefree.auth.common.resolver;

import com.hasslefree.auth.common.annotation.AuthContext;
import com.hasslefree.auth.common.dto.AuthenticationContext;
import com.hasslefree.auth.common.util.AuthContextExtractor;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Resolver to inject AuthenticationContext into controller methods.
 * 
 * <p><b>UPDATED for Spring OAuth2 Resource Server:</b>
 * This resolver now reads from Spring Security's SecurityContext instead of parsing the Authorization header directly.
 * Spring Resource Server validates the JWT signature, expiration, and issuer before placing it in SecurityContext.
 * 
 * <p>Usage in controllers:
 * <pre>{@code
 * @GetMapping("/example")
 * public ResponseEntity<String> example(@AuthContext AuthenticationContext authContext) {
 *     String userId = authContext.getUserId();
 *     // ...
 * }
 * }</pre>
 * 
 * <p><b>Migration note:</b>
 * Old behavior: Parsed Authorization header directly (no validation).
 * New behavior: Reads verified JWT from Spring Security's SecurityContext (validated by Resource Server).
 */
public class AuthContextResolver implements HandlerMethodArgumentResolver {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthContextResolver.class);

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
            @Nullable WebDataBinderFactory binderFactory) throws Exception {
        
        // STEP 1: Try to extract from Spring Security's SecurityContext (RECOMMENDED)
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null) {
            try {
                // Check if it's a JwtAuthenticationToken (Spring OAuth2 Resource Server)
                Class<?> jwtAuthTokenClass = Class.forName("org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken");
                if (jwtAuthTokenClass.isInstance(authentication)) {
                    // Extract Jwt from JwtAuthenticationToken
                    Object jwt = jwtAuthTokenClass.getMethod("getToken").invoke(authentication);
                    AuthenticationContext context = AuthContextExtractor.extractFromJwt(jwt);
                    if (context != null) {
                        logger.debug("Resolved AuthenticationContext from SecurityContext JWT for user: {}", context.getUserId());
                        return context;
                    }
                }
            } catch (ClassNotFoundException e) {
                logger.debug("Spring OAuth2 JWT classes not found, falling back to header parsing");
            } catch (Exception e) {
                logger.warn("Failed to extract context from SecurityContext", e);
            }
        }
        
        // STEP 2: FALLBACK - Parse Authorization header directly (LEGACY)
        // This is kept for backward compatibility with services that don't use Spring OAuth2 Resource Server yet
        logger.debug("Falling back to Authorization header parsing (legacy mode)");
        HttpServletRequest request = webRequest.getNativeRequest(HttpServletRequest.class);
        if (request == null) {
            logger.warn("HttpServletRequest is null, cannot resolve AuthenticationContext");
            return null;
        }
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || authHeader.isBlank()) {
            logger.debug("Authorization header is missing");
            return null;
        }
        
        @SuppressWarnings("deprecation")
        AuthenticationContext context = AuthContextExtractor.extractFromToken(authHeader);
        if (context != null) {
            logger.debug("Resolved AuthenticationContext from Authorization header (legacy) for user: {}", context.getUserId());
        }
        return context;
    }
}
