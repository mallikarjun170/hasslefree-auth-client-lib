package com.hasslefree.auth.client.authz;

import com.hasslefree.auth.client.context.AuthContext;
import com.hasslefree.auth.client.error.ForbiddenException;
import com.hasslefree.auth.client.error.UnauthorizedException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;

/**
 * Static helper methods for permission/access-grant checks.
 */
public final class Authz {

  private static final AccessGrantEvaluator EVALUATOR = new AccessGrantEvaluator();

  private Authz() {}

  public static boolean has(AuthContext context, String permission) {
    return EVALUATOR.has(context, permission);
  }

  public static boolean hasAny(AuthContext context, String... permissions) {
    return EVALUATOR.hasAny(context, Arrays.asList(permissions));
  }

  public static boolean hasAll(AuthContext context, String... permissions) {
    return EVALUATOR.hasAll(context, Arrays.asList(permissions));
  }

  public static AuthContext requireAny(AuthContext context, String... permissions) {
    return requireAny(context, Arrays.asList(permissions));
  }

  public static AuthContext requireAny(AuthContext context, Collection<String> permissions) {
    if (context == null) {
      throw new UnauthorizedException("Authentication context is required");
    }
    if (!EVALUATOR.hasAny(context, permissions)) {
      throw new ForbiddenException("Missing required permission (anyOf): " + permissions);
    }
    return context;
  }

  public static AuthContext requireAll(AuthContext context, String... permissions) {
    return requireAll(context, Arrays.asList(permissions));
  }

  public static AuthContext requireAll(AuthContext context, Collection<String> permissions) {
    if (context == null) {
      throw new UnauthorizedException("Authentication context is required");
    }
    if (!EVALUATOR.hasAll(context, permissions)) {
      Set<String> missing = EVALUATOR.missing(context, permissions);
      throw new ForbiddenException("Missing required permissions (allOf): " + missing);
    }
    return context;
  }
}
