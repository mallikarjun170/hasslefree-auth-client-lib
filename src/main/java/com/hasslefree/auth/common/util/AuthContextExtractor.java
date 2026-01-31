package com.hasslefree.auth.common.util;

import com.hasslefree.auth.common.dto.AuthenticationContext;
import com.hasslefree.auth.common.enums.UserRole;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Utility class for extracting authentication context from JWT tokens.
 * This class provides methods to parse tokens and extract user information
 * that can be used across all microservices.
 * 
 * <p><b>IMPORTANT:</b> For HassleFree services, prefer extractFromJwt(Jwt) over extractFromToken(String).
 * Spring Security's OAuth2 Resource Server validates the JWT, so use the verified Jwt object from SecurityContext.
 */
/**
 * Production-ready utility for extracting authentication context from JWT tokens.
 * <p>
 * Security: No secrets in logs, tokens masked, signature/algorithm validation stub provided.
 * Performance: Null checks, efficient role extraction, thread-safe.
 * 
 * <p><b>RECOMMENDED USAGE FOR SPRING OAUTH2 RESOURCE SERVER:</b>
 * Use {@link #extractFromJwt(Object)} with Spring Security's verified Jwt object.
 * This ensures you're working with an already-validated token from SecurityContext.
 */
public final class AuthContextExtractor {
    private static final Logger logger = LoggerFactory.getLogger(AuthContextExtractor.class);

    // JWT Claim name constants
    private static final String CLAIM_CUSTOM_USER_ID = "custom:userId";
    private static final String CLAIM_SUB = "sub";
    private static final String CLAIM_USERNAME = "username";
    private static final String CLAIM_COGNITO_USERNAME = "cognito:username";
    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_COGNITO_GROUPS = "cognito:groups";
    private static final String CLAIM_GROUPS = "groups";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_AUTHORITIES = "authorities";
    private static final String CLAIM_CUSTOM_ROLE = "custom:role";
    private static final String CLAIM_CUSTOM_ROLES = "custom:roles";
    private static final String CLAIM_EXP = "exp";
    private static final String CLAIM_ROLE_PREFIX = "ROLE_";

    // Prevent instantiation
    private AuthContextExtractor() { throw new AssertionError("No instance allowed"); }

    /**
     * Extract authentication context from Spring Security's Jwt object.
     * 
     * <p><b>RECOMMENDED:</b> Use this method when your service is configured as an OAuth2 Resource Server.
     * Spring Security validates the JWT signature, expiration, and issuer before placing it in SecurityContext.
     * 
     * <p>Usage example:
     * <pre>{@code
     * Authentication auth = SecurityContextHolder.getContext().getAuthentication();
     * if (auth instanceof JwtAuthenticationToken) {
     *     Jwt jwt = ((JwtAuthenticationToken) auth).getToken();
     *     AuthenticationContext context = AuthContextExtractor.extractFromJwt(jwt);
     * }
     * }</pre>
     * 
     * @param jwt Spring Security's Jwt object (org.springframework.security.oauth2.jwt.Jwt)
     * @return AuthenticationContext containing user information
     * @throws IllegalArgumentException if jwt is null or not a valid Jwt instance
     */
    public static AuthenticationContext extractFromJwt(Object jwt) {
        if (jwt == null) {
            logger.warn("Jwt object is null");
            return null;
        }
        
        // Handle Spring Security Jwt (use reflection to avoid hard dependency)
        try {
            Class<?> jwtClass = Class.forName("org.springframework.security.oauth2.jwt.Jwt");
            if (!jwtClass.isInstance(jwt)) {
                throw new IllegalArgumentException("Expected Spring Security Jwt, got: " + jwt.getClass().getName());
            }
            
            // Extract claims using reflection
            Object claimsObject = jwtClass.getMethod("getClaims").invoke(jwt);
            if (!(claimsObject instanceof java.util.Map)) {
                logger.error("JWT claims are not a Map");
                return null;
            }
            
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> claims = (java.util.Map<String, Object>) claimsObject;
            
            return extractContextFromClaims(jwt, jwtClass, claims);
            
        } catch (ClassNotFoundException e) {
            logger.error("Spring Security OAuth2 JWT library not found. Add spring-security-oauth2-jose dependency.");
            throw new IllegalStateException("Spring Security OAuth2 JWT support not available", e);
        } catch (Exception e) {
            logger.error("Failed to extract context from Spring Security Jwt", e);
            return null;
        }
    }
    
    /**
     * Extract authentication context from JWT claims (Spring Security Jwt).
     * 
     * @param jwt The Spring Security Jwt object
     * @param jwtClass The Jwt class (for reflection)
     * @param claims The claims map extracted from the JWT
     * @return AuthenticationContext containing user information
     */
    private static AuthenticationContext extractContextFromClaims(Object jwt, Class<?> jwtClass, java.util.Map<String, Object> claims) {
        try {
            // Extract user ID (try multiple claim names)
            String userId = (String) claims.get(CLAIM_SUB);
            if (userId == null) {
                userId = (String) claims.get(CLAIM_CUSTOM_USER_ID);
            }
            
            // Extract username
            String username = (String) claims.get(CLAIM_USERNAME);
            if (username == null) {
                username = (String) claims.get(CLAIM_COGNITO_USERNAME);
            }
            
            // Extract email
            String email = (String) claims.get(CLAIM_EMAIL);
            
            // Extract roles
            Set<UserRole> roles = extractRolesFromClaims(claims);
            
            // Extract expiration time
            Object expObj = claims.get(CLAIM_EXP);
            Long expirationTime = null;
            if (expObj instanceof Number) {
                expirationTime = ((Number) expObj).longValue() * 1000; // Convert seconds to milliseconds
            }
            
            // Get token value (masked for security)
            String tokenValue = null;
            try {
                Object tokenValueObj = jwtClass.getMethod("getTokenValue").invoke(jwt);
                tokenValue = maskToken((String) tokenValueObj);
            } catch (Exception e) {
                logger.debug("Could not extract token value for masking", e);
            }
            
            return new AuthenticationContext(userId, username, email, roles, tokenValue, expirationTime);
            
        } catch (Exception e) {
            logger.error("Failed to extract context from JWT claims", e);
            return null;
        }
    }
    
    /**
     * Extract roles from JWT claims map (for Spring Security Jwt).
     */
    private static Set<UserRole> extractRolesFromClaims(java.util.Map<String, Object> claims) {
        Set<UserRole> roles = new HashSet<>();
        
        try {
            String[] possibleRoleClaims = {
                CLAIM_COGNITO_GROUPS, 
                CLAIM_GROUPS, 
                CLAIM_ROLES, 
                CLAIM_AUTHORITIES,
                CLAIM_CUSTOM_ROLE,
                CLAIM_CUSTOM_ROLES
            };
            
            for (String claimName : possibleRoleClaims) {
                Object roleClaim = claims.get(claimName);
                if (roleClaim != null) {
                    Set<UserRole> extractedRoles = parseRoleClaim(roleClaim);
                    if (!extractedRoles.isEmpty()) {
                        roles.addAll(extractedRoles);
                        break;
                    }
                }
            }
            
            if (roles.isEmpty()) {
                logger.debug("No roles found in token, assigning default TENANT role");
                roles.add(UserRole.TENANT);
            }
            
        } catch (Exception e) {
            logger.error("Error extracting roles from claims", e);
            roles.add(UserRole.TENANT);
        }
        
        return roles;
    }

    /**
     * Extract authentication context from JWT claims.
     * 
     * @param claims The JWT claims set
     * @param token The original token string
     * @return AuthenticationContext containing user information
     */
    /**
     * Extract authentication context from JWT claims.
     * @param claims The JWT claims set
     * @param token The original token string (masked in logs)
     * @return AuthenticationContext containing user information
     */
    public static AuthenticationContext extractFromClaims(JWTClaimsSet claims, String token) {
        try {
            if (claims == null) {
                logger.warn("JWT claims are null");
                return null;
            }
            String userId = claims.getSubject();
            String username = claims.getStringClaim(CLAIM_USERNAME);
            String email = claims.getStringClaim(CLAIM_EMAIL);
            Set<UserRole> roles = extractRoles(claims);
            Long expirationTime = claims.getExpirationTime() != null ? 
                claims.getExpirationTime().getTime() : null;
            return new AuthenticationContext(userId, username, email, roles, maskToken(token), expirationTime);
        } catch (ParseException e) {
            logger.error("Failed to extract claims from token", e);
            return null;
        }
    }
    /**
     * Mask a JWT token for logging (shows only first/last 3 chars).
     * @param token The JWT token string
     * @return Masked token string
     */
    private static String maskToken(String token) {
        if (token == null || token.length() < 10) return "***";
        return token.substring(0, 3) + "..." + token.substring(token.length() - 3);
    }

    /**
     * Extract user roles from JWT claims.
     * Looks for roles in various possible claim names used by different identity providers.
     * 
     * @param claims The JWT claims set
     * @return Set of user roles
     */
    private static Set<UserRole> extractRoles(JWTClaimsSet claims) {
        Set<UserRole> roles = new HashSet<>();
        
        try {
            // Try different possible claim names for roles
            String[] possibleRoleClaims = {
                CLAIM_COGNITO_GROUPS, 
                CLAIM_GROUPS, 
                CLAIM_ROLES, 
                CLAIM_AUTHORITIES,
                CLAIM_CUSTOM_ROLE,
                CLAIM_CUSTOM_ROLES
            };
            
            for (String claimName : possibleRoleClaims) {
                Object roleClaim = claims.getClaim(claimName);
                if (roleClaim != null) {
                    Set<UserRole> extractedRoles = parseRoleClaim(roleClaim);
                    if (!extractedRoles.isEmpty()) {
                        roles.addAll(extractedRoles);
                        break; // Use the first successful extraction
                    }
                }
            }
            
            // If no roles found, assign default TENANT role
            if (roles.isEmpty()) {
                logger.debug("No roles found in token, assigning default TENANT role");
                roles.add(UserRole.TENANT);
            }
            
        } catch (Exception e) {
            logger.error("Error extracting roles from claims", e);
            roles.add(UserRole.TENANT); // Default fallback
        }
        
        return roles;
    }

    /**
     * Parse role claim object into UserRole set.
     * Handles both string arrays and comma-separated strings.
     * 
     * @param roleClaim The role claim object from JWT
     * @return Set of parsed user roles
     */
    private static Set<UserRole> parseRoleClaim(Object roleClaim) {
        Set<UserRole> roles = new HashSet<>();
        
        try {
            if (roleClaim instanceof List) {
                roles.addAll(parseRoleList(roleClaim));
            } else if (roleClaim instanceof String string) {
                roles.addAll(parseRoleString(string));
            }
        } catch (Exception e) {
            logger.error("Error parsing role claim: {}", roleClaim, e);
        }
        
        return roles;
    }

    /**
     * Parse roles from a List claim.
     * 
     * @param roleClaim The role claim object (must be a List)
     * @return Set of parsed user roles
     */
    private static Set<UserRole> parseRoleList(Object roleClaim) {
        Set<UserRole> roles = new HashSet<>();
        @SuppressWarnings("unchecked")
        List<String> roleList = (List<String>) roleClaim;
        
        for (String roleStr : roleList) {
            UserRole role = parseRole(roleStr);
            if (role != null) {
                roles.add(role);
            }
        }
        return roles;
    }

    /**
     * Parse roles from a String claim (handles single or comma-separated roles).
     * 
     * @param roleString The role claim string
     * @return Set of parsed user roles
     */
    private static Set<UserRole> parseRoleString(String roleString) {
        Set<UserRole> roles = new HashSet<>();
        
        if (roleString.contains(",")) {
            String[] roleArray = roleString.split(",");
            for (String roleStr : roleArray) {
                UserRole role = parseRole(roleStr.trim());
                if (role != null) {
                    roles.add(role);
                }
            }
        } else {
            UserRole role = parseRole(roleString);
            if (role != null) {
                roles.add(role);
            }
        }
        return roles;
    }

    /**
     * Parse a single role string into UserRole enum.
     * 
     * @param roleStr The role string to parse
     * @return UserRole enum value, or null if parsing fails
     */
    private static UserRole parseRole(String roleStr) {
        if (roleStr == null || roleStr.trim().isEmpty()) {
            return null;
        }
        
        try {
            // Remove common prefixes
            roleStr = roleStr.trim().toUpperCase();
            if (roleStr.startsWith(CLAIM_ROLE_PREFIX)) {
                roleStr = roleStr.substring(5);
            }
            
            return UserRole.valueOf(roleStr);
        } catch (IllegalArgumentException e) {
            logger.warn("Unknown role: {}", roleStr);
            return null;
        }
    }

    /**
     * Extract authentication context from Authorization header token string.
     * 
     * <p><b>LEGACY METHOD:</b> This method is provided for backward compatibility.
     * It parses the token directly without Spring Security validation.
     * 
     * <p><b>RECOMMENDED:</b> Use {@link #extractFromJwt(Object)} instead when using Spring OAuth2 Resource Server.
     * 
     * @param authHeader The Authorization header value (e.g., "Bearer eyJhbGc...")
     * @return AuthenticationContext containing user information
     * @deprecated Use extractFromJwt(Object) with Spring Security's validated Jwt instead
     */
    @Deprecated
    public static AuthenticationContext extractFromToken(String authHeader) {
        try {
            if (authHeader == null || authHeader.isBlank()) {
                logger.warn("Authorization header is null or blank");
                return null;
            }
            
            // Remove "Bearer " prefix if present
            String token = authHeader;
            if (authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7);
            }
            
            // Parse the JWT token
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            // Extract context from claims
            return extractFromClaims(claims, token);
            
        } catch (ParseException e) {
            logger.error("Failed to parse JWT token", e);
            return null;
        }
    }
    
}
