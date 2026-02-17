package com.hasslefree.auth.client.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.hasslefree.auth.client.config.AuthorizationClientProperties;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

class AuthorizationClientTest {

  private AuthorizationClientProperties properties;
  private AuthorizationClient client;
  private AtomicReference<ClientRequest> capturedRequest;

  @BeforeEach
  void setUp() {
    capturedRequest = new AtomicReference<>();
    ExchangeFunction exchangeFunction =
        request -> {
          capturedRequest.set(request);
          return Mono.just(ClientResponse.create(HttpStatus.OK).build());
        };
    WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();

    properties = new AuthorizationClientProperties();
    properties.setBaseUrl("http://auth-service/");
    properties.setInternalApiKey("internal-key");
    properties.getCache().setTtlSeconds(60);
    properties.getCache().setMaxSize(1000);

    client = new AuthorizationClient(webClient, properties);
    ReflectionTestUtils.invokeMethod(client, "initCache");
  }

  @Test
  void checkPermissionAllowsSystemResourceWithoutResourceIdAndUsesV1Path() {
    UUID userId = UUID.randomUUID();

    boolean allowed = client.checkPermission(userId, "SYSTEM", null, "ORG_READ");

    assertThat(allowed).isTrue();
    ClientRequest request = capturedRequest.get();
    assertThat(request).isNotNull();
    assertThat(request.url().toString()).isEqualTo("http://auth-service/v1/internal/permissions/check");
    assertThat(request.method().name()).isEqualTo("POST");
    assertThat(request.headers().getFirst("X-Internal-Api-Key")).isEqualTo("internal-key");
  }

  @Test
  void checkPermissionRejectsNonSystemResourceWithoutResourceId() {
    assertThatThrownBy(
            () -> client.checkPermission(UUID.randomUUID(), "PROPERTY", null, "PROPERTY_READ"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("resourceId is required for non-SYSTEM resourceType");
  }
}
