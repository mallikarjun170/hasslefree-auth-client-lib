package com.hasslefree.auth.client.spring.aspect;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.hasslefree.auth.client.access.AccessGrant;
import com.hasslefree.auth.client.authorization.AccessGrantEvaluator;
import com.hasslefree.auth.client.context.AuthContext;
import com.hasslefree.auth.client.error.ForbiddenException;
import com.hasslefree.auth.client.spring.annotation.RequireGrants;
import com.hasslefree.auth.client.spring.context.CurrentAuthContextProvider;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.Test;

class RequireGrantsAspectTest {

  @Test
  void enforce_allowsInvocationWhenPolicySatisfied() throws Throwable {
    CurrentAuthContextProvider provider = mock(CurrentAuthContextProvider.class);
    RequireGrantsAspect aspect = new RequireGrantsAspect(new AccessGrantEvaluator(), provider);

    AuthContext context =
        new AuthContext(
            "subject-1",
            "principal-1",
            "user@example.com",
            List.of(AccessGrant.global("property.read"), AccessGrant.global("property.write")),
            Map.of());

    when(provider.required()).thenReturn(context);

    ProceedingJoinPoint joinPoint = joinPointFor("securedRead");
    when(joinPoint.proceed()).thenReturn("ok");

    Object result = aspect.enforce(joinPoint);

    assertThat(result).isEqualTo("ok");
  }

  @Test
  void enforce_blocksInvocationWhenPolicyNotSatisfied() throws Throwable {
    CurrentAuthContextProvider provider = mock(CurrentAuthContextProvider.class);
    RequireGrantsAspect aspect = new RequireGrantsAspect(new AccessGrantEvaluator(), provider);

    AuthContext context =
        new AuthContext(
            "subject-1",
            "principal-1",
            "user@example.com",
            List.of(AccessGrant.global("property.read")),
            Map.of());

    when(provider.required()).thenReturn(context);

    ProceedingJoinPoint joinPoint = joinPointFor("securedWrite");

    assertThatThrownBy(() -> aspect.enforce(joinPoint))
        .isInstanceOf(ForbiddenException.class)
        .hasMessageContaining("property.write");
  }

  private ProceedingJoinPoint joinPointFor(String methodName) throws NoSuchMethodException {
    Method method = SampleSecuredService.class.getMethod(methodName);
    MethodSignature signature = mock(MethodSignature.class);
    when(signature.getMethod()).thenReturn(method);

    ProceedingJoinPoint joinPoint = mock(ProceedingJoinPoint.class);
    when(joinPoint.getSignature()).thenReturn(signature);
    when(joinPoint.getTarget()).thenReturn(new SampleSecuredService());
    when(joinPoint.getArgs()).thenReturn(new Object[0]);
    return joinPoint;
  }

  private static class SampleSecuredService {

    @RequireGrants(anyOf = {"property.read"})
    public String securedRead() {
      return "ok";
    }

    @RequireGrants(allOf = {"property.read", "property.write"})
    public String securedWrite() {
      return "ok";
    }
  }
}
