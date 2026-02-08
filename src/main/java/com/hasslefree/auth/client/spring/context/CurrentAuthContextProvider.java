package com.hasslefree.auth.client.spring.context;

import com.hasslefree.auth.client.context.AuthContext;
import com.hasslefree.auth.client.error.UnauthorizedException;
import com.hasslefree.auth.client.spring.extract.AuthenticationAuthContextExtractor;
import java.util.Optional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Provides access to the current request's AuthContext.
 */
public class CurrentAuthContextProvider {

  private final AuthenticationAuthContextExtractor extractor;

  public CurrentAuthContextProvider(AuthenticationAuthContextExtractor extractor) {
    this.extractor = extractor;
  }

  public Optional<AuthContext> current() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    return extractor.fromAuthentication(authentication);
  }

  public AuthContext required() {
    return current().orElseThrow(() -> new UnauthorizedException("No authenticated principal available"));
  }
}
