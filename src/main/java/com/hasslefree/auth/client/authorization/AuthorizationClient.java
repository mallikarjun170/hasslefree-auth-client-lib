package com.hasslefree.auth.client.authorization;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.hasslefree.auth.client.config.AuthorizationClientProperties;
import com.hasslefree.auth.client.exception.AuthorizationClientException;
import com.hasslefree.auth.common.dto.PermissionCheckRequest;
import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

@RequiredArgsConstructor
@Slf4j
public class AuthorizationClient {

  private final WebClient webClient;
  private final AuthorizationClientProperties properties;

  private Cache<String, Boolean> permissionCache;

  @PostConstruct
  private void initCache() {
    Duration ttl = Duration.ofSeconds(properties.getCache().getTtlSeconds());
    this.permissionCache =
        Caffeine.newBuilder()
            .maximumSize(properties.getCache().getMaxSize())
            .expireAfterWrite(ttl)
            .build();
  }

  public boolean checkPermission(
      UUID userId, String resourceType, UUID resourceId, String permissionCode) {
    validate(userId, resourceType, resourceId, permissionCode);
    String cacheKey = buildCacheKey(userId, resourceType, resourceId, permissionCode);
    return permissionCache.get(
        cacheKey, key -> callAuthorizationService(userId, resourceType, resourceId, permissionCode));
  }

  private boolean callAuthorizationService(
      UUID userId, String resourceType, UUID resourceId, String permissionCode) {
    PermissionCheckRequest request =
        new PermissionCheckRequest(userId, permissionCode, resourceType, resourceId);

    try {
      webClient
          .post()
          .uri(permissionCheckUri())
          .contentType(MediaType.APPLICATION_JSON)
          .header("X-Internal-Api-Key", properties.getInternalApiKey())
          .bodyValue(request)
          .retrieve()
          .toBodilessEntity()
          .block();
      return true;
    } catch (WebClientResponseException ex) {
      if (ex.getStatusCode() == HttpStatus.FORBIDDEN) {
        log.debug(
            "Authorization denied for user {} on {}:{} ({})",
            userId,
            resourceType,
            resourceId,
            permissionCode);
        return false;
      }
      throw new AuthorizationClientException("Unexpected authorization response", ex);
    } catch (WebClientRequestException ex) {
      throw new AuthorizationClientException("Failed to call authorization service", ex);
    }
  }

  private void validate(UUID userId, String resourceType, UUID resourceId, String permissionCode) {
    if (userId == null) {
      throw new IllegalArgumentException("userId is required");
    }
    if (resourceType == null || resourceType.isBlank()) {
      throw new IllegalArgumentException("resourceType is required");
    }
    if (!"SYSTEM".equalsIgnoreCase(resourceType.trim()) && resourceId == null) {
      throw new IllegalArgumentException("resourceId is required for non-SYSTEM resourceType");
    }
    if (permissionCode == null || permissionCode.isBlank()) {
      throw new IllegalArgumentException("permissionCode is required");
    }
  }

  private String buildCacheKey(
      UUID userId, String resourceType, UUID resourceId, String permissionCode) {
    return userId + ":" + resourceType + ":" + resourceId + ":" + permissionCode;
  }

  private String permissionCheckUri() {
    String base = properties.getBaseUrl();
    if (base.endsWith("/")) {
      base = base.substring(0, base.length() - 1);
    }
    return base + "/v1/internal/permissions/check";
  }
}
