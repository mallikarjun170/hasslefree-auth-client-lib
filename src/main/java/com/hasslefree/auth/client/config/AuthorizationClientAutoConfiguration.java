package com.hasslefree.auth.client.config;

import com.hasslefree.auth.client.authorization.AuthorizationClient;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

/** Auto-configuration for the Authorization HTTP client. */
@AutoConfiguration
@ConditionalOnProperty(prefix = "hasslefree.auth.authorization-client", name = "base-url")
@EnableConfigurationProperties(AuthorizationClientProperties.class)
public class AuthorizationClientAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public RestTemplate restTemplate(RestTemplateBuilder builder) {
    return builder.build();
  }

  @Bean
  @ConditionalOnMissingBean
  public AuthorizationClient authorizationClient(RestTemplate restTemplate, AuthorizationClientProperties properties) {
    return new AuthorizationClient(restTemplate, properties);
  }
}
