package com.hasslefree.auth.client.spring.config;

import com.hasslefree.auth.client.authorization.AccessGrantEvaluator;
import com.hasslefree.auth.client.spring.aspect.RequireGrantsAspect;
import com.hasslefree.auth.client.spring.context.CurrentAuthContextProvider;
import com.hasslefree.auth.client.spring.extract.AccessGrantClaimParser;
import com.hasslefree.auth.client.spring.extract.AuthenticationAuthContextExtractor;
import com.hasslefree.auth.client.spring.web.AuthContextArgumentResolver;
import com.hasslefree.auth.client.spring.web.AuthContextRequestFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Auto-configuration for auth context extraction and access-grant enforcement.
 */
@AutoConfiguration
@ConditionalOnClass({Authentication.class, Jwt.class})
@EnableConfigurationProperties(AuthClientProperties.class)
public class AuthClientAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public AccessGrantClaimParser accessGrantClaimParser() {
    return new AccessGrantClaimParser();
  }

  @Bean
  @ConditionalOnMissingBean
  public AuthenticationAuthContextExtractor authenticationAuthContextExtractor(
      AuthClientProperties properties, AccessGrantClaimParser parser) {
    return new AuthenticationAuthContextExtractor(properties, parser);
  }

  @Bean
  @ConditionalOnMissingBean
  public CurrentAuthContextProvider currentAuthContextProvider(
      AuthenticationAuthContextExtractor extractor) {
    return new CurrentAuthContextProvider(extractor);
  }

  @Bean
  @ConditionalOnMissingBean
  public AccessGrantEvaluator accessGrantEvaluator() {
    return new AccessGrantEvaluator();
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(
      prefix = "hasslefree.auth.web",
      name = "argument-resolver-enabled",
      havingValue = "true",
      matchIfMissing = true)
  public AuthContextArgumentResolver authContextArgumentResolver(
      CurrentAuthContextProvider provider, AuthClientProperties properties) {
    return new AuthContextArgumentResolver(provider, properties.getWeb().getRequestAttributeName());
  }

  @Bean
  @ConditionalOnBean(AuthContextArgumentResolver.class)
  @ConditionalOnMissingBean(name = "authContextWebMvcConfigurer")
  public WebMvcConfigurer authContextWebMvcConfigurer(AuthContextArgumentResolver resolver) {
    return new WebMvcConfigurer() {
      @Override
      public void addArgumentResolvers(java.util.List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(resolver);
      }
    };
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = "hasslefree.auth.web", name = "request-filter-enabled", havingValue = "true")
  public FilterRegistrationBean<AuthContextRequestFilter> authContextRequestFilter(
      CurrentAuthContextProvider provider, AuthClientProperties properties) {
    FilterRegistrationBean<AuthContextRequestFilter> registrationBean = new FilterRegistrationBean<>();
    registrationBean.setFilter(
        new AuthContextRequestFilter(provider, properties.getWeb().getRequestAttributeName()));
    registrationBean.setOrder(Ordered.LOWEST_PRECEDENCE - 10);
    return registrationBean;
  }

  @Bean
  @ConditionalOnClass(name = "org.aspectj.lang.ProceedingJoinPoint")
  @ConditionalOnMissingBean
  @ConditionalOnProperty(
      prefix = "hasslefree.auth.enforcement",
      name = "enabled",
      havingValue = "true",
      matchIfMissing = true)
  public RequireGrantsAspect requireGrantsAspect(
      AccessGrantEvaluator evaluator, CurrentAuthContextProvider provider) {
    return new RequireGrantsAspect(evaluator, provider);
  }
}
