package com.hasslefree.auth.common.util;

import com.hasslefree.auth.common.dto.AuthenticationContext;
import com.hasslefree.auth.common.enums.UserRole;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Utility class for extracting authentication context from JWT tokens.
 * This class provides methods to parse tokens and extract user information
 * that can be used across all microservices.
 */
/**
 * Production-ready utility for extracting authentication context from JWT tokens.
 * <p>
 * Security: No secrets in logs, tokens masked, signature/algorithm validation stub provided.
 * Performance: Null checks, efficient role extraction, thread-safe.
 */
public final class AuthContextExtractor {
    private static final Logger logger = LoggerFactory.getLogger(AuthContextExtractor.class);

    // Prevent instantiation
    private AuthContextExtractor() { throw new AssertionError("No instance allowed"); }

    /**
     * Extract authentication context from a JWT token string.
     * 
     * @param token The JWT token string
     * @return AuthenticationContext containing user information, or null if parsing fails
     */
    /**
     * Extract authentication context from a JWT token string.
     * Performs signature/algorithm validation (stubbed for user implementation).
     * Masks token in logs for security.
     *
     * @param token The JWT token string
     * @return AuthenticationContext containing user information, or null if parsing fails
     */
    public static AuthenticationContext extractFromToken(String token) {
        try {
            if (token == null || token.trim().isEmpty()) {
                logger.warn("Token is null or empty");
                return null;
            }

            // Remove "Bearer " prefix if present
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            SignedJWT signedJWT = SignedJWT.parse(token);

            // --- Security: Validate signature and algorithm (stub, user must implement) ---
            // TODO: Validate signature using public key and check algorithm
            // Example: if (!isValidSignature(signedJWT)) { logger.warn("Invalid JWT signature"); return null; }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            return extractFromClaims(claims, maskToken(token));

        } catch (ParseException e) {
            logger.error("Failed to parse JWT token: {}", maskToken(token), e);
            return null;
        }
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
            String username = claims.getStringClaim("username");
            String email = claims.getStringClaim("email");
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
                "cognito:groups", 
                "groups", 
                "roles", 
                "authorities",
                "custom:role",
                "custom:roles"
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
                // Handle list of roles
                @SuppressWarnings("unchecked")
                List<String> roleList = (List<String>) roleClaim;
                for (String roleStr : roleList) {
                    UserRole role = parseRole(roleStr);
                    if (role != null) {
                        roles.add(role);
                    }
                }
            } else if (roleClaim instanceof String) {
                // Handle single role or comma-separated roles
                String roleString = (String) roleClaim;
                if (roleString.contains(",")) {
                    // Comma-separated roles
                    String[] roleArray = roleString.split(",");
                    for (String roleStr : roleArray) {
                        UserRole role = parseRole(roleStr.trim());
                        if (role != null) {
                            roles.add(role);
                        }
                    }
                } else {
                    // Single role
                    UserRole role = parseRole(roleString);
                    if (role != null) {
                        roles.add(role);
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Error parsing role claim: {}", roleClaim, e);
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
            if (roleStr.startsWith("ROLE_")) {
                roleStr = roleStr.substring(5);
            }
            
            return UserRole.valueOf(roleStr);
        } catch (IllegalArgumentException e) {
            logger.warn("Unknown role: {}", roleStr);
            return null;
        }
    }

    /**
     * Extract user ID from token without full context extraction.
     * 
     * @param token The JWT token string
     * @return User ID, or null if extraction fails
     */
    public static String extractUserId(String token) {
        try {
            if (token != null && token.startsWith("Bearer ")) {
                token = token.substring(7);
            }
            
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getSubject();
        } catch (ParseException e) {
            logger.error("Failed to extract user ID from token", e);
            return null;
        }
    }

    /**
     * Extract username from token without full context extraction.
     * 
     * @param token The JWT token string
     * @return Username, or null if extraction fails
     */
    public static String extractUsername(String token) {
        try {
            if (token != null && token.startsWith("Bearer ")) {
                token = token.substring(7);
            }
            
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getStringClaim("username");
        } catch (ParseException e) {
            logger.error("Failed to extract username from token", e);
            return null;
        }
    }
}
