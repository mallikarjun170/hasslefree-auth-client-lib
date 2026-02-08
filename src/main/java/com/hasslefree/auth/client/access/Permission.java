package com.hasslefree.auth.client.access;

import java.util.Locale;
import java.util.Objects;

/**
 * Canonical permission identifier used for access-grant based authorization.
 */
public record Permission(String value) {

  public Permission {
    Objects.requireNonNull(value, "permission value is required");
    value = normalize(value);
  }

  public static Permission of(String value) {
    return new Permission(value);
  }

  private static String normalize(String raw) {
    String normalized = raw.trim();
    if (normalized.isEmpty()) {
      throw new IllegalArgumentException("permission value is required");
    }
    return normalized.toLowerCase(Locale.ROOT);
  }
}
