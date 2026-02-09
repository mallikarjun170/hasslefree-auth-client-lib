package com.hasslefree.auth.client.context;

import com.hasslefree.auth.client.access.AccessGrant;
import com.hasslefree.auth.client.access.Permission;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable authentication and authorization context derived from a verified token.
 */
public final class AuthContext {

  private final String subject;
  private final String principal;
  private final String email;
  private final String userId;
  private final String tenantId;
  private final String orgId;
  private final String propertyId;
  private final Set<AccessGrant> accessGrants;
  private final Set<Permission> permissions;
  private final Set<String> grants;
  private final Map<String, Object> claims;

  public AuthContext(
      String subject,
      String principal,
      String email,
      Collection<AccessGrant> accessGrants,
      Map<String, Object> claims) {
    this.subject = requireNonBlank(subject, "subject is required");
    this.principal = requireNonBlank(principal, "principal is required");
    this.email = normalize(email);
    this.accessGrants = toImmutableGrantSet(accessGrants);
    this.permissions = extractPermissions(this.accessGrants);
    this.claims = claims == null ? Map.of() : Collections.unmodifiableMap(Map.copyOf(claims));
    this.userId = resolveUserId(this.subject, this.principal, this.claims);
    this.tenantId = firstClaim(this.claims, "tenantId", "tenant_id", "tenant");
    this.orgId = firstClaim(this.claims, "orgId", "org_id", "organizationId", "organization_id");
    this.propertyId = firstClaim(this.claims, "propertyId", "property_id");
    this.grants = extractGrantStrings(this.permissions);
  }

  public String subject() {
    return subject;
  }

  public String principal() {
    return principal;
  }

  public String email() {
    return email;
  }

  public String userId() {
    return userId;
  }

  public String tenantId() {
    return tenantId;
  }

  public String orgId() {
    return orgId;
  }

  public String propertyId() {
    return propertyId;
  }

  public Set<AccessGrant> accessGrants() {
    return accessGrants;
  }

  public Set<Permission> permissions() {
    return permissions;
  }

  public Set<String> grants() {
    return grants;
  }

  public Map<String, Object> claims() {
    return claims;
  }

  public boolean hasPermission(Permission permission) {
    Objects.requireNonNull(permission, "permission is required");
    return permissions.contains(permission);
  }

  public boolean hasPermission(String permission) {
    return hasPermission(Permission.of(permission));
  }

  private static Set<Permission> extractPermissions(Set<AccessGrant> grants) {
    LinkedHashSet<Permission> set = new LinkedHashSet<>();
    for (AccessGrant grant : grants) {
      set.add(grant.permission());
    }
    return Collections.unmodifiableSet(set);
  }

  private static Set<String> extractGrantStrings(Set<Permission> permissions) {
    LinkedHashSet<String> normalized = new LinkedHashSet<>();
    for (Permission permission : permissions) {
      normalized.add(permission.value().toUpperCase(Locale.ROOT));
    }
    return Collections.unmodifiableSet(normalized);
  }

  private static Set<AccessGrant> toImmutableGrantSet(Collection<AccessGrant> grants) {
    if (grants == null || grants.isEmpty()) {
      return Set.of();
    }
    LinkedHashSet<AccessGrant> set = new LinkedHashSet<>();
    for (AccessGrant grant : grants) {
      set.add(Objects.requireNonNull(grant, "access grant is required"));
    }
    return Collections.unmodifiableSet(set);
  }

  private static String requireNonBlank(String value, String message) {
    String normalized = normalize(value);
    if (normalized == null) {
      throw new IllegalArgumentException(message);
    }
    return normalized;
  }

  private static String normalize(String value) {
    if (value == null) {
      return null;
    }
    String normalized = value.trim();
    return normalized.isEmpty() ? null : normalized;
  }

  private static String resolveUserId(String subject, String principal, Map<String, Object> claims) {
    String claimedUserId = firstClaim(claims, "custom:userId", "userId", "user_id", "uid");
    if (claimedUserId != null) {
      return claimedUserId;
    }
    return principal != null ? principal : subject;
  }

  private static String firstClaim(Map<String, Object> claims, String... keys) {
    for (String key : keys) {
      Object value = claims.get(key);
      if (value == null) {
        continue;
      }
      String normalized = normalize(String.valueOf(value));
      if (normalized != null) {
        return normalized;
      }
    }
    return null;
  }
}
