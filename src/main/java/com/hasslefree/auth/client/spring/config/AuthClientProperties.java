package com.hasslefree.auth.client.spring.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Properties for auth context extraction and access-grant enforcement.
 */
@ConfigurationProperties(prefix = "hasslefree.auth")
public class AuthClientProperties {

  private final Claims claims = new Claims();
  private final Web web = new Web();
  private final Enforcement enforcement = new Enforcement();
  private String userIdClaim = "custom:userId";
  private boolean allowFallbackSubUuid;

  public Claims getClaims() {
    return claims;
  }

  public Web getWeb() {
    return web;
  }

  public Enforcement getEnforcement() {
    return enforcement;
  }

  public String getUserIdClaim() {
    return userIdClaim;
  }

  public void setUserIdClaim(String userIdClaim) {
    this.userIdClaim = userIdClaim;
  }

  public boolean isAllowFallbackSubUuid() {
    return allowFallbackSubUuid;
  }

  public void setAllowFallbackSubUuid(boolean allowFallbackSubUuid) {
    this.allowFallbackSubUuid = allowFallbackSubUuid;
  }

  public static class Claims {
    private String subjectKey = "sub";
    private String principalKey = "sub";
    private String emailKey = "email";
    private List<String> accessGrantKeys =
        new ArrayList<>(List.of("permissions", "access_grants", "scope", "scp"));
    private List<String> requiredClaimKeys = new ArrayList<>(List.of("sub"));
    private String issuer;
    private String audience;
    private boolean validateIssuer;
    private boolean validateAudience;

    public String getSubjectKey() {
      return subjectKey;
    }

    public void setSubjectKey(String subjectKey) {
      this.subjectKey = subjectKey;
    }

    public String getPrincipalKey() {
      return principalKey;
    }

    public void setPrincipalKey(String principalKey) {
      this.principalKey = principalKey;
    }

    public String getEmailKey() {
      return emailKey;
    }

    public void setEmailKey(String emailKey) {
      this.emailKey = emailKey;
    }

    public List<String> getAccessGrantKeys() {
      return accessGrantKeys;
    }

    public void setAccessGrantKeys(List<String> accessGrantKeys) {
      this.accessGrantKeys = accessGrantKeys;
    }

    public List<String> getRequiredClaimKeys() {
      return requiredClaimKeys;
    }

    public void setRequiredClaimKeys(List<String> requiredClaimKeys) {
      this.requiredClaimKeys = requiredClaimKeys;
    }

    public String getIssuer() {
      return issuer;
    }

    public void setIssuer(String issuer) {
      this.issuer = issuer;
    }

    public String getAudience() {
      return audience;
    }

    public void setAudience(String audience) {
      this.audience = audience;
    }

    public boolean isValidateIssuer() {
      return validateIssuer;
    }

    public void setValidateIssuer(boolean validateIssuer) {
      this.validateIssuer = validateIssuer;
    }

    public boolean isValidateAudience() {
      return validateAudience;
    }

    public void setValidateAudience(boolean validateAudience) {
      this.validateAudience = validateAudience;
    }
  }

  public static class Web {
    private boolean argumentResolverEnabled = true;
    private boolean requestFilterEnabled;
    private String requestAttributeName = "hasslefree.auth.context";

    public boolean isArgumentResolverEnabled() {
      return argumentResolverEnabled;
    }

    public void setArgumentResolverEnabled(boolean argumentResolverEnabled) {
      this.argumentResolverEnabled = argumentResolverEnabled;
    }

    public boolean isRequestFilterEnabled() {
      return requestFilterEnabled;
    }

    public void setRequestFilterEnabled(boolean requestFilterEnabled) {
      this.requestFilterEnabled = requestFilterEnabled;
    }

    public String getRequestAttributeName() {
      return requestAttributeName;
    }

    public void setRequestAttributeName(String requestAttributeName) {
      this.requestAttributeName = requestAttributeName;
    }
  }

  public static class Enforcement {
    private boolean enabled = true;

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }
  }
}
