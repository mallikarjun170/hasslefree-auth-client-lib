package com.hasslefree.auth.client.spring.authorization;

import com.hasslefree.auth.client.authorization.AuthorizationClient;
import com.hasslefree.auth.client.spring.context.CurrentUserIdProvider;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/** Helper bean for SpEL authorization checks, exposed as {@code hfGrants}. */
public class HfGrantsService {

  private static final Set<String> VALID_SCOPE_TYPES = Set.of("SYSTEM", "ORG", "PROPERTY", "UNIT");
  private static final String REQUEST_CACHE_ATTRIBUTE =
      HfGrantsService.class.getName() + ".requestCache";

  private final AuthorizationClient authorizationClient;
  private final CurrentUserIdProvider currentUserIdProvider;

  public HfGrantsService(
      AuthorizationClient authorizationClient, CurrentUserIdProvider currentUserIdProvider) {
    this.authorizationClient = authorizationClient;
    this.currentUserIdProvider = currentUserIdProvider;
  }

  public boolean has(UUID scopeId, String scopeType, String permissionCode) {
    String normalizedScopeType = normalizeScopeType(scopeType);
    validateScopeId(normalizedScopeType, scopeId);
    validatePermissionCode(permissionCode);

    UUID userId = currentUserIdProvider.requireCurrentUserId();
    String cacheKey = normalizedScopeType + ":" + scopeId + ":" + permissionCode;

    Boolean cached = requestCache().get(cacheKey);
    if (cached != null) {
      return cached;
    }

    boolean allowed =
        authorizationClient.checkPermission(userId, normalizedScopeType, scopeId, permissionCode);
    requestCache().put(cacheKey, allowed);
    return allowed;
  }

  public boolean hasSystem(String permissionCode) {
    return has(null, "SYSTEM", permissionCode);
  }

  public boolean hasAny(UUID scopeId, String scopeType, String scopedPerm, String anyPerm) {
    return hasSystem(anyPerm) || has(scopeId, scopeType, scopedPerm);
  }

  private String normalizeScopeType(String scopeType) {
    if (scopeType == null || scopeType.isBlank()) {
      throw new IllegalArgumentException("scopeType is required");
    }
    String normalized = scopeType.trim().toUpperCase();
    if (!VALID_SCOPE_TYPES.contains(normalized)) {
      throw new IllegalArgumentException("Unsupported scopeType: " + scopeType);
    }
    return normalized;
  }

  private void validateScopeId(String scopeType, UUID scopeId) {
    if ("SYSTEM".equals(scopeType)) {
      if (scopeId != null) {
        throw new IllegalArgumentException("scopeId must be null for SYSTEM scope");
      }
      return;
    }
    if (scopeId == null) {
      throw new IllegalArgumentException("scopeId is required for scopeType " + scopeType);
    }
  }

  private void validatePermissionCode(String permissionCode) {
    if (permissionCode == null || permissionCode.isBlank()) {
      throw new IllegalArgumentException("permissionCode is required");
    }
  }

  @SuppressWarnings("unchecked")
  private Map<String, Boolean> requestCache() {
    RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
    if (requestAttributes == null) {
      return new HashMap<>();
    }

    Object existing =
        requestAttributes.getAttribute(REQUEST_CACHE_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
    if (existing instanceof Map<?, ?> map) {
      return (Map<String, Boolean>) map;
    }

    Map<String, Boolean> map = new HashMap<>();
    requestAttributes.setAttribute(REQUEST_CACHE_ATTRIBUTE, map, RequestAttributes.SCOPE_REQUEST);
    return map;
  }
}
