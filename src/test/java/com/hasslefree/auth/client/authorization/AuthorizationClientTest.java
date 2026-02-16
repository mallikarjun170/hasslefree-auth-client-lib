package com.hasslefree.auth.client.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.hasslefree.auth.client.config.AuthorizationClientProperties;
import com.hasslefree.auth.common.dto.PermissionCheckRequest;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

class AuthorizationClientTest {

  private RestTemplate restTemplate;

  private AuthorizationClientProperties properties;
  private AuthorizationClient client;

  @BeforeEach
  void setUp() {
    restTemplate = mock(RestTemplate.class);
    properties = new AuthorizationClientProperties();
    properties.setBaseUrl("http://auth-service/");
    properties.setInternalApiKey("internal-key");
    properties.getCache().setTtlSeconds(60);
    properties.getCache().setMaxSize(1000);

    client = new AuthorizationClient(restTemplate, properties);
    ReflectionTestUtils.invokeMethod(client, "initCache");
  }

  @Test
  void checkPermissionAllowsSystemResourceWithoutResourceIdAndUsesV1Path() {
    UUID userId = UUID.randomUUID();
    when(restTemplate.postForEntity(any(String.class), any(HttpEntity.class), eq(Void.class)))
        .thenReturn(ResponseEntity.ok().build());

    boolean allowed = client.checkPermission(userId, "SYSTEM", null, "ORG_READ");

    assertThat(allowed).isTrue();
    ArgumentCaptor<HttpEntity<PermissionCheckRequest>> entityCaptor = ArgumentCaptor.forClass(HttpEntity.class);
    verify(restTemplate)
        .postForEntity(
            eq("http://auth-service/v1/internal/permissions/check"), entityCaptor.capture(), eq(Void.class));
    PermissionCheckRequest payload = entityCaptor.getValue().getBody();
    assertThat(payload).isNotNull();
    assertThat(payload.getResourceType()).isEqualTo("SYSTEM");
    assertThat(payload.getResourceId()).isNull();
  }

  @Test
  void checkPermissionRejectsNonSystemResourceWithoutResourceId() {
    assertThatThrownBy(
            () -> client.checkPermission(UUID.randomUUID(), "PROPERTY", null, "PROPERTY_READ"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("resourceId is required for non-SYSTEM resourceType");
  }
}
