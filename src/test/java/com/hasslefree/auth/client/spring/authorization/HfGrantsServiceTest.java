package com.hasslefree.auth.client.spring.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.hasslefree.auth.client.authorization.AuthorizationClient;
import com.hasslefree.auth.client.spring.context.CurrentUserIdProvider;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

class HfGrantsServiceTest {

  @AfterEach
  void tearDown() {
    RequestContextHolder.resetRequestAttributes();
  }

  @Test
  void systemScopeRejectsNonNullScopeId() {
    AuthorizationClient authorizationClient = Mockito.mock(AuthorizationClient.class);
    CurrentUserIdProvider currentUserIdProvider = Mockito.mock(CurrentUserIdProvider.class);
    HfGrantsService service = new HfGrantsService(authorizationClient, currentUserIdProvider);

    assertThatThrownBy(() -> service.has(UUID.randomUUID(), "SYSTEM", "ACCESS_GRANT_READ"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("scopeId must be null");
  }

  @Test
  void requestScopeCachingAvoidsDuplicateAuthorizationCalls() {
    AuthorizationClient authorizationClient = Mockito.mock(AuthorizationClient.class);
    CurrentUserIdProvider currentUserIdProvider = Mockito.mock(CurrentUserIdProvider.class);
    HfGrantsService service = new HfGrantsService(authorizationClient, currentUserIdProvider);
    UUID userId = UUID.randomUUID();
    UUID scopeId = UUID.randomUUID();

    when(currentUserIdProvider.requireCurrentUserId()).thenReturn(userId);
    when(authorizationClient.checkPermission(userId, "PROPERTY", scopeId, "PROPERTY_READ"))
        .thenReturn(true);

    RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
    assertThat(service.has(scopeId, "PROPERTY", "PROPERTY_READ")).isTrue();
    assertThat(service.has(scopeId, "PROPERTY", "PROPERTY_READ")).isTrue();

    verify(authorizationClient, times(1)).checkPermission(userId, "PROPERTY", scopeId, "PROPERTY_READ");
  }
}
