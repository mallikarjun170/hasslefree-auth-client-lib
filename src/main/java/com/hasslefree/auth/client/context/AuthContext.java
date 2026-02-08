package com.hasslefree.auth.client.context;

import com.hasslefree.auth.client.access.AccessGrant;
import com.hasslefree.auth.client.access.Permission;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
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
  private final Set<AccessGrant> accessGrants;
  private final Set<Permission> permissions;
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

  public Set<AccessGrant> accessGrants() {
    return accessGrants;
  }

  public Set<Permission> permissions() {
    return permissions;
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
}
