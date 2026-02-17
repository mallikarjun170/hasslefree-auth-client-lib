package com.hasslefree.auth.client.config;

import com.hasslefree.auth.client.authorization.AuthorizationClient;
import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

/** Auto-configuration for the Authorization HTTP client. */
@AutoConfiguration
@ConditionalOnProperty(prefix = "hasslefree.auth.authorization-client", name = "base-url")
@EnableConfigurationProperties(AuthorizationClientProperties.class)
public class AuthorizationClientAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public WebClient authorizationWebClient(
      WebClient.Builder builder, AuthorizationClientProperties properties) {
    HttpClient httpClient =
        HttpClient.create()
            .option(
                ChannelOption.CONNECT_TIMEOUT_MILLIS, properties.getTimeout().getConnectTimeoutMs())
            .responseTimeout(Duration.ofMillis(properties.getTimeout().getResponseTimeoutMs()))
            .doOnConnected(
                connection ->
                    connection.addHandlerLast(
                        new ReadTimeoutHandler(
                            properties.getTimeout().getReadTimeoutMs(), TimeUnit.MILLISECONDS)));

    return builder.clientConnector(new ReactorClientHttpConnector(httpClient)).build();
  }

  @Bean
  @ConditionalOnMissingBean
  public AuthorizationClient authorizationClient(
      WebClient authorizationWebClient, AuthorizationClientProperties properties) {
    return new AuthorizationClient(authorizationWebClient, properties);
  }
}
