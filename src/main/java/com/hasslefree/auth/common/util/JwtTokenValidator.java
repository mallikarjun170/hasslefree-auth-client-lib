package com.hasslefree.auth.common.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.hasslefree.auth.common.exception.InvalidTokenException;
import com.hasslefree.auth.common.exception.TokenExpiredException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utility for validating and extracting claims from JWT tokens, especially AWS Cognito JWTs.
 * <p>
 * Handles signature verification, claim validation, and provides helper methods for extracting user info.
 * Defensive against null/empty tokens and malformed input.
 * Thread-safe for concurrent use.
 */
public class JwtTokenValidator {
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenValidator.class);
    private final Map<String, RSAKey> jwkCache = new ConcurrentHashMap<>();
    private JWKSet jwkSet;
    private long jwkSetLastUpdated = 0;
    private static final long JWK_SET_CACHE_DURATION = 24 * 60 * 60 * 1000L; // 24 hours
    private final String region;
    private final String userPoolId;
    private final String jwksUrl;

    /**
     * Create a new validator for a specific Cognito region, user pool, and JWKS URL.
     *
     * @param region AWS region (e.g., "us-east-1")
     * @param userPoolId Cognito user pool ID
     * @param jwksUrl JWKS endpoint URL
     */
    public JwtTokenValidator(String region, String userPoolId, String jwksUrl) {
        this.region = region;
        this.userPoolId = userPoolId;
        this.jwksUrl = jwksUrl;
    }

    /**
     * Validate a JWT token for signature, expiration, issuer, audience, and token use.
     *
     * @param token JWT token string (may be null/empty)
     * @return true if valid, false if invalid or malformed
     */
    /**
     * Validate a JWT token for signature, expiration, issuer, audience, and token use.
     * Throws custom exceptions for invalid or expired tokens.
     *
     * @param token JWT token string (may be null/empty)
     * @throws InvalidTokenException if the token is invalid or malformed
     * @throws TokenExpiredException if the token is expired
     * @return true if valid
     */
    public boolean validateToken(String token) throws InvalidTokenException, TokenExpiredException {
        if (token == null || token.trim().isEmpty()) {
            throw new InvalidTokenException("Token is null or empty");
        }
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // Verify the signature
            if (!verifySignature(signedJWT)) {
                throw new InvalidTokenException("Token signature verification failed");
            }

            // Verify token claims
            return verifyTokenClaims(signedJWT.getJWTClaimsSet());

        } catch (ParseException e) {
            throw new InvalidTokenException("Failed to parse JWT token", e);
        }
    }

    /**
     * Verify the signature of a parsed JWT using the JWKS.
     *
     * @param signedJWT Parsed JWT
     * @return true if signature is valid, false otherwise
     */
    private boolean verifySignature(SignedJWT signedJWT) {
        try {
            String keyId = signedJWT.getHeader().getKeyID();
            RSAKey rsaKey = getRSAKey(keyId);

            if (rsaKey == null) {
                logger.warn("RSA key not found for key ID: {}", keyId);
                return false;
            }

            JWSVerifier verifier = new RSASSAVerifier(rsaKey);
            return signedJWT.verify(verifier);

        } catch (JOSEException e) {
            logger.error("Error verifying JWT signature", e);
            return false;
        }
    }

    /**
     * Get the RSA public key for a given key ID from the JWKS, using cache if possible.
     *
     * @param keyId Key ID from JWT header
     * @return RSAKey or null if not found
     */
    private RSAKey getRSAKey(String keyId) {
        // Check cache first
        RSAKey cachedKey = jwkCache.get(keyId);
        if (cachedKey != null) {
            return cachedKey;
        }

        // Refresh JWK Set if needed
        if (shouldRefreshJWKSet()) {
            refreshJWKSet();
        }

        // Find the key in the JWK Set
        if (jwkSet != null) {
            JWK jwk = jwkSet.getKeyByKeyId(keyId);
            if (jwk instanceof RSAKey) {
                RSAKey rsaKey = (RSAKey) jwk;
                jwkCache.put(keyId, rsaKey);
                return rsaKey;
            }
        }

        return null;
    }

    /**
     * Determine if the JWKS should be refreshed from the remote endpoint.
     *
     * @return true if refresh is needed
     */
    private boolean shouldRefreshJWKSet() {
        return jwkSet == null || (System.currentTimeMillis() - jwkSetLastUpdated) > JWK_SET_CACHE_DURATION;
    }

    /**
     * Refresh the JWKS from the remote endpoint and update the cache.
     */
    private void refreshJWKSet() {
        try {
            jwkSet = JWKSet.load(URI.create(jwksUrl).toURL());
            jwkSetLastUpdated = System.currentTimeMillis();
            jwkCache.clear(); // Clear cache when JWK set is refreshed
            logger.info("JWK Set refreshed successfully");
        } catch (Exception e) {
            logger.error("Failed to refresh JWK Set", e);
        }
    }

    /**
     * Validate standard claims in the JWT (expiration, issuer, audience, token use).
     *
     * @param claims JWT claims set
     * @return true if all claims are valid, false otherwise
     */
    private boolean verifyTokenClaims(JWTClaimsSet claims) throws InvalidTokenException, TokenExpiredException {
        try {
            // Check token expiration
            Date expirationTime = claims.getExpirationTime();
            if (expirationTime != null && expirationTime.before(new Date())) {
                throw new TokenExpiredException("Token has expired");
            }

            // Check issuer
            String expectedIssuer = String.format("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolId);
            String actualIssuer = claims.getIssuer();
            if (!expectedIssuer.equals(actualIssuer)) {
                throw new InvalidTokenException("Invalid token issuer. Expected: " + expectedIssuer + ", Actual: " + actualIssuer);
            }

            // Check audience (client_id)
            if (!claims.getAudience().contains(userPoolId)) {
                throw new InvalidTokenException("Invalid token audience");
            }

            // Check token use (should be 'access' for access tokens)
            String tokenUse = (String) claims.getClaim("token_use");
            if (!"access".equals(tokenUse) && !"id".equals(tokenUse)) {
                throw new InvalidTokenException("Invalid token use: " + tokenUse);
            }

            return true;

        } catch (TokenExpiredException | InvalidTokenException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidTokenException("Error verifying token claims", e);
        }
    }

    /**
     * Extract the username claim from a JWT token.
     *
     * @param token JWT token string
     * @return Username, or null if not present or token invalid
     */
    /**
     * Extract the username claim from a JWT token.
     *
     * @param token JWT token string
     * @return Username
     * @throws InvalidTokenException if the token is invalid or malformed
     */
    public String getUsernameFromToken(String token) throws InvalidTokenException {
        try {
            JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();
            return claims.getStringClaim("username");
        } catch (ParseException e) {
            throw new InvalidTokenException("Failed to extract username from token", e);
        }
    }

    /**
     * Extract the user ID (subject) from a JWT token.
     *
     * @param token JWT token string
     * @return User ID (subject), or null if not present or token invalid
     */
    /**
     * Extract the user ID (subject) from a JWT token.
     *
     * @param token JWT token string
     * @return User ID (subject)
     * @throws InvalidTokenException if the token is invalid or malformed
     */
    public String getUserIdFromToken(String token) throws InvalidTokenException {
        try {
            JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();
            return claims.getSubject();
        } catch (ParseException e) {
            throw new InvalidTokenException("Failed to extract user ID from token", e);
        }
    }
}
