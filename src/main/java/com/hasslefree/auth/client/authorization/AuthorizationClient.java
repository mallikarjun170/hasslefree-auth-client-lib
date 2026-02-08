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
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

@RequiredArgsConstructor
@Slf4j
public class AuthorizationClient {

  private final RestTemplate restTemplate;
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
    HttpHeaders headers = new HttpHeaders();
    headers.set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
    headers.set("X-Internal-Api-Key", properties.getInternalApiKey());
    HttpEntity<PermissionCheckRequest> entity = new HttpEntity<>(request, headers);

    try {
      restTemplate.postForEntity(permissionCheckUri(), entity, Void.class);
      return true;
    } catch (HttpClientErrorException ex) {
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
    } catch (RestClientException ex) {
      throw new AuthorizationClientException("Failed to call authorization service", ex);
    }
  }

  private void validate(UUID userId, String resourceType, UUID resourceId, String permissionCode) {
    if (userId == null) {
      throw new IllegalArgumentException("userId is required");
    }
    if (resourceId == null) {
      throw new IllegalArgumentException("resourceId is required");
    }
    if (resourceType == null || resourceType.isBlank()) {
      throw new IllegalArgumentException("resourceType is required");
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
    return base + "/internal/permissions/check";
  }
}
