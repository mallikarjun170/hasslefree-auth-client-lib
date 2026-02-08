package com.hasslefree.auth.client.spring.aspect;

import com.hasslefree.auth.client.authorization.AccessGrantEvaluator;
import com.hasslefree.auth.client.context.AuthContext;
import com.hasslefree.auth.client.error.BadRequestException;
import com.hasslefree.auth.client.error.ForbiddenException;
import com.hasslefree.auth.client.spring.annotation.RequireGrants;
import com.hasslefree.auth.client.spring.context.CurrentAuthContextProvider;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;

/**
 * Aspect-based enforcement for {@link RequireGrants}.
 */
@Aspect
public class RequireGrantsAspect {

  private final AccessGrantEvaluator evaluator;
  private final CurrentAuthContextProvider authContextProvider;

  public RequireGrantsAspect(
      AccessGrantEvaluator evaluator, CurrentAuthContextProvider authContextProvider) {
    this.evaluator = evaluator;
    this.authContextProvider = authContextProvider;
  }

  @Around("@annotation(com.hasslefree.auth.client.spring.annotation.RequireGrants) || @within(com.hasslefree.auth.client.spring.annotation.RequireGrants)")
  public Object enforce(ProceedingJoinPoint joinPoint) throws Throwable {
    RequireGrants policy = resolvePolicy(joinPoint);
    List<String> anyOf = Arrays.asList(policy.anyOf());
    List<String> allOf = Arrays.asList(policy.allOf());

    if (anyOf.isEmpty() && allOf.isEmpty()) {
      throw new BadRequestException("@RequireGrants requires anyOf and/or allOf values");
    }

    AuthContext context = resolveContext(joinPoint.getArgs());

    if (!anyOf.isEmpty() && !evaluator.hasAny(context, anyOf)) {
      throw new ForbiddenException("Missing required permission from anyOf: " + anyOf);
    }

    if (!allOf.isEmpty() && !evaluator.hasAll(context, allOf)) {
      Set<String> missing = evaluator.missing(context, allOf);
      throw new ForbiddenException("Missing required permissions from allOf: " + missing);
    }

    return joinPoint.proceed();
  }

  private AuthContext resolveContext(Object[] args) {
    for (Object arg : args) {
      if (arg instanceof AuthContext authContext) {
        return authContext;
      }
    }
    return authContextProvider.required();
  }

  private RequireGrants resolvePolicy(ProceedingJoinPoint joinPoint) {
    Method method = ((MethodSignature) joinPoint.getSignature()).getMethod();
    RequireGrants methodAnnotation = method.getAnnotation(RequireGrants.class);
    if (methodAnnotation != null) {
      return methodAnnotation;
    }
    Class<?> targetType = joinPoint.getTarget().getClass();
    RequireGrants classAnnotation = targetType.getAnnotation(RequireGrants.class);
    if (classAnnotation != null) {
      return classAnnotation;
    }
    throw new BadRequestException("@RequireGrants pointcut matched without an annotation instance");
  }
}
