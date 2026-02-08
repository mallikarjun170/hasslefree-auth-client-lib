package com.hasslefree.auth.client.access;

import java.util.Objects;

/**
 * A permission grant, optionally scoped to a resource.
 */
public record AccessGrant(Permission permission, String resourceType, String resourceId) {

  public AccessGrant {
    Objects.requireNonNull(permission, "permission is required");
    resourceType = normalize(resourceType);
    resourceId = normalize(resourceId);
  }

  public static AccessGrant global(String permission) {
    return new AccessGrant(Permission.of(permission), null, null);
  }

  public static AccessGrant global(Permission permission) {
    return new AccessGrant(permission, null, null);
  }

  private static String normalize(String value) {
    if (value == null) {
      return null;
    }
    String normalized = value.trim();
    return normalized.isEmpty() ? null : normalized;
  }
}
