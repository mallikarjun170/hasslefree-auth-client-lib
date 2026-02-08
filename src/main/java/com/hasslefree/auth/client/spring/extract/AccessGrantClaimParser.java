package com.hasslefree.auth.client.spring.extract;

import com.hasslefree.auth.client.access.AccessGrant;
import com.hasslefree.auth.client.access.Permission;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Parses raw token claims into canonical access grants.
 */
public class AccessGrantClaimParser {

  public Set<AccessGrant> parse(Object rawClaimValue) {
    if (rawClaimValue == null) {
      return Set.of();
    }

    LinkedHashSet<AccessGrant> grants = new LinkedHashSet<>();
    if (rawClaimValue instanceof String stringClaim) {
      parseDelimited(stringClaim, grants);
      return grants;
    }

    if (rawClaimValue instanceof Collection<?> collection) {
      for (Object item : collection) {
        parseSingle(item, grants);
      }
      return grants;
    }

    parseSingle(rawClaimValue, grants);
    return grants;
  }

  private void parseSingle(Object item, Set<AccessGrant> grants) {
    if (item == null) {
      return;
    }
    if (item instanceof String permissionValue) {
      parseDelimited(permissionValue, grants);
      return;
    }
    if (item instanceof Map<?, ?> mapItem) {
      parseStructuredGrant(mapItem, grants);
    }
  }

  private void parseStructuredGrant(Map<?, ?> rawGrant, Set<AccessGrant> grants) {
    Object permissionRaw = firstPresent(rawGrant, List.of("permission", "code", "grant"));
    if (!(permissionRaw instanceof String permissionValue) || permissionValue.isBlank()) {
      return;
    }

    String resourceType = asNullableString(firstPresent(rawGrant, List.of("resourceType", "resource_type")));
    String resourceId = asNullableString(firstPresent(rawGrant, List.of("resourceId", "resource_id")));

    grants.add(new AccessGrant(Permission.of(permissionValue), resourceType, resourceId));
  }

  private void parseDelimited(String value, Set<AccessGrant> grants) {
    String trimmed = value.trim();
    if (trimmed.isEmpty()) {
      return;
    }
    String[] tokens = trimmed.split("[\\s,]+");
    for (String token : tokens) {
      if (!token.isBlank()) {
        grants.add(AccessGrant.global(Permission.of(token)));
      }
    }
  }

  private Object firstPresent(Map<?, ?> source, Collection<String> keys) {
    for (String key : keys) {
      if (source.containsKey(key)) {
        return source.get(key);
      }
    }
    return null;
  }

  private String asNullableString(Object value) {
    if (value == null) {
      return null;
    }
    String normalized = String.valueOf(value).trim();
    return normalized.isEmpty() ? null : normalized;
  }
}
