package com.hasslefree.auth.client.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Configuration properties for the Authz HTTP client. */
@ConfigurationProperties(prefix = "authz")
@Validated
@Data
public class AuthzClientProperties {

  @NotBlank private String baseUrl;

  @NotBlank private String internalApiKey;

  private Cache cache = new Cache();

  @Data
  public static class Cache {
    @Min(1)
    private int ttlSeconds = 60;

    @Min(1)
    private int maxSize = 10000;
  }
}
