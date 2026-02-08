package com.hasslefree.auth.client.spring.web;

import com.hasslefree.auth.client.context.AuthContext;
import com.hasslefree.auth.client.error.UnauthorizedException;
import com.hasslefree.auth.client.spring.annotation.CurrentAuthContext;
import com.hasslefree.auth.client.spring.context.CurrentAuthContextProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Injects {@link AuthContext} into controller method parameters.
 */
public class AuthContextArgumentResolver implements HandlerMethodArgumentResolver {

  private final CurrentAuthContextProvider authContextProvider;
  private final String requestAttributeName;

  public AuthContextArgumentResolver(
      CurrentAuthContextProvider authContextProvider, String requestAttributeName) {
    this.authContextProvider = authContextProvider;
    this.requestAttributeName = requestAttributeName;
  }

  @Override
  public boolean supportsParameter(@NonNull MethodParameter parameter) {
    return AuthContext.class.isAssignableFrom(parameter.getParameterType())
        && parameter.hasParameterAnnotation(CurrentAuthContext.class);
  }

  @Override
  public Object resolveArgument(
      @NonNull MethodParameter parameter,
      @Nullable ModelAndViewContainer mavContainer,
      @NonNull NativeWebRequest webRequest,
      @Nullable WebDataBinderFactory binderFactory) {

    HttpServletRequest request = webRequest.getNativeRequest(HttpServletRequest.class);
    if (request != null) {
      Object requestScopedContext = request.getAttribute(requestAttributeName);
      if (requestScopedContext instanceof AuthContext authContext) {
        return authContext;
      }
    }

    return authContextProvider
        .current()
        .orElseThrow(() -> new UnauthorizedException("No authenticated principal available"));
  }
}
