package com.hasslefree.auth.client.spring.web;

import com.hasslefree.auth.client.context.AuthContext;
import com.hasslefree.auth.client.spring.context.CurrentAuthContextProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Optionally stores AuthContext on HttpServletRequest for downstream components.
 */
public class AuthContextRequestFilter extends OncePerRequestFilter {

  private final CurrentAuthContextProvider authContextProvider;
  private final String requestAttributeName;

  public AuthContextRequestFilter(
      CurrentAuthContextProvider authContextProvider, String requestAttributeName) {
    this.authContextProvider = authContextProvider;
    this.requestAttributeName = requestAttributeName;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    Object existing = request.getAttribute(requestAttributeName);
    if (!(existing instanceof AuthContext)) {
      authContextProvider.current().ifPresent(context -> request.setAttribute(requestAttributeName, context));
    }
    filterChain.doFilter(request, response);
  }
}
