package com.hasslefree.auth.client.authz;

import com.hasslefree.auth.client.access.Permission;
import com.hasslefree.auth.client.context.AuthContext;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Evaluates access grants and permission requirements against an AuthContext.
 */
public class AccessGrantEvaluator {

  public boolean has(AuthContext context, Permission permission) {
    return context != null && permission != null && context.hasPermission(permission);
  }

  public boolean has(AuthContext context, String permission) {
    return context != null && permission != null && context.hasPermission(permission);
  }

  public boolean hasAny(AuthContext context, Collection<String> requiredPermissions) {
    Set<Permission> required = normalize(requiredPermissions);
    if (required.isEmpty()) {
      return true;
    }
    if (context == null) {
      return false;
    }
    for (Permission permission : required) {
      if (context.hasPermission(permission)) {
        return true;
      }
    }
    return false;
  }

  public boolean hasAll(AuthContext context, Collection<String> requiredPermissions) {
    Set<Permission> required = normalize(requiredPermissions);
    if (required.isEmpty()) {
      return true;
    }
    if (context == null) {
      return false;
    }
    for (Permission permission : required) {
      if (!context.hasPermission(permission)) {
        return false;
      }
    }
    return true;
  }

  private Set<Permission> normalize(Collection<String> permissions) {
    if (permissions == null || permissions.isEmpty()) {
      return Set.of();
    }
    LinkedHashSet<Permission> normalized = new LinkedHashSet<>();
    for (String permission : permissions) {
      if (permission != null && !permission.isBlank()) {
        normalized.add(Permission.of(permission));
      }
    }
    return normalized;
  }

  public Set<String> missing(AuthContext context, Collection<String> requiredPermissions) {
    Objects.requireNonNull(requiredPermissions, "requiredPermissions is required");
    LinkedHashSet<String> missing = new LinkedHashSet<>();
    for (String permission : requiredPermissions) {
      if (permission == null || permission.isBlank()) {
        continue;
      }
      Permission normalized = Permission.of(permission);
      if (context == null || !context.hasPermission(normalized)) {
        missing.add(normalized.value());
      }
    }
    return missing;
  }
}
