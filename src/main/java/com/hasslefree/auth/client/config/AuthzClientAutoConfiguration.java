package com.hasslefree.auth.client.config;

import com.hasslefree.auth.client.authz.AuthzClient;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

/** Auto-configuration for the Authz HTTP client. */
@AutoConfiguration
@ConditionalOnProperty(prefix = "authz", name = "base-url")
@EnableConfigurationProperties(AuthzClientProperties.class)
public class AuthzClientAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public RestTemplate restTemplate(RestTemplateBuilder builder) {
    return builder.build();
  }

  @Bean
  @ConditionalOnMissingBean
  public AuthzClient authzClient(RestTemplate restTemplate, AuthzClientProperties properties) {
    return new AuthzClient(restTemplate, properties);
  }
}
