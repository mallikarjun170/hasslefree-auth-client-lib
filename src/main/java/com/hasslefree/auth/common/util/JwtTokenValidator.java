package com.hasslefree.auth.common.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class JwtTokenValidator {
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenValidator.class);
    private final Map<String, RSAKey> jwkCache = new ConcurrentHashMap<>();
    private JWKSet jwkSet;
    private long jwkSetLastUpdated = 0;
    private static final long JWK_SET_CACHE_DURATION = 24 * 60 * 60 * 1000L; // 24 hours
    private final String region;
    private final String userPoolId;
    private final String jwksUrl;

    public JwtTokenValidator(String region, String userPoolId, String jwksUrl) {
        this.region = region;
        this.userPoolId = userPoolId;
        this.jwksUrl = jwksUrl;
    }

    public boolean validateToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // Verify the signature
            if (!verifySignature(signedJWT)) {
                logger.warn("Token signature verification failed");
                return false;
            }

            // Verify token claims
            return verifyTokenClaims(signedJWT.getJWTClaimsSet());

        } catch (ParseException e) {
            logger.error("Failed to parse JWT token", e);
            return false;
        }
    }

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

    private boolean shouldRefreshJWKSet() {
        return jwkSet == null || (System.currentTimeMillis() - jwkSetLastUpdated) > JWK_SET_CACHE_DURATION;
    }

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

    private boolean verifyTokenClaims(JWTClaimsSet claims) {
        try {
            // Check token expiration
            Date expirationTime = claims.getExpirationTime();
            if (expirationTime != null && expirationTime.before(new Date())) {
                logger.warn("Token has expired");
                return false;
            }

            // Check issuer
            String expectedIssuer = String.format("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolId);
            String actualIssuer = claims.getIssuer();
            if (!expectedIssuer.equals(actualIssuer)) {
                logger.warn("Invalid token issuer. Expected: {}, Actual: {}", expectedIssuer, actualIssuer);
                return false;
            }

            // Check audience (client_id)
            if (!claims.getAudience().contains(userPoolId)) {
                logger.warn("Invalid token audience");
                return false;
            }

            // Check token use (should be 'access' for access tokens)
            String tokenUse = (String) claims.getClaim("token_use");
            if (!"access".equals(tokenUse) && !"id".equals(tokenUse)) {
                logger.warn("Invalid token use: {}", tokenUse);
                return false;
            }

            return true;

        } catch (Exception e) {
            logger.error("Error verifying token claims", e);
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        try {
            JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();
            return claims.getStringClaim("username");
        } catch (ParseException e) {
            logger.error("Failed to extract username from token", e);
        }
        return null;
    }

    public String getUserIdFromToken(String token) {
        try {
            JWTClaimsSet claims = SignedJWT.parse(token).getJWTClaimsSet();
            return claims.getSubject();
        } catch (ParseException e) {
            logger.error("Failed to extract user ID from token", e);
        }
        return null;
    }
}
