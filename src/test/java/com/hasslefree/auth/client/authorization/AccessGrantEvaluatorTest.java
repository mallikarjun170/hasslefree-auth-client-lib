package com.hasslefree.auth.client.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.hasslefree.auth.client.access.AccessGrant;
import com.hasslefree.auth.client.context.AuthContext;
import com.hasslefree.auth.client.error.ForbiddenException;
import com.hasslefree.auth.client.error.UnauthorizedException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AccessGrantEvaluatorTest {

  private final AccessGrantEvaluator evaluator = new AccessGrantEvaluator();

  @Test
  void hasAnyAndHasAll_coverEdgeCases() {
    AuthContext context =
        new AuthContext(
            "subject-1",
            "principal-1",
            "user@example.com",
            List.of(AccessGrant.global("property.read"), AccessGrant.global("property.write")),
            Map.of());

    assertThat(evaluator.hasAny(context, List.of("property.read", "invoice.read"))).isTrue();
    assertThat(evaluator.hasAny(context, List.of("invoice.read", "invoice.write"))).isFalse();
    assertThat(evaluator.hasAll(context, List.of("property.read", "property.write"))).isTrue();
    assertThat(evaluator.hasAll(context, List.of("property.read", "invoice.read"))).isFalse();
    assertThat(evaluator.hasAll(context, List.of())).isTrue();
    assertThat(evaluator.hasAny(null, List.of("property.read"))).isFalse();
    assertThat(evaluator.hasAny(context, java.util.Arrays.asList("  ", null))).isTrue();
    assertThat(evaluator.hasAll(context, List.of("PROPERTY.READ"))).isTrue();
  }

  @Test
  void authorizationRequireHelpers_throwExpectedExceptions() {
    AuthContext context =
        new AuthContext(
            "subject-1",
            "principal-1",
            "user@example.com",
            List.of(AccessGrant.global("property.read")),
            Map.of());

    assertThat(Authorization.requireAll(context, "property.read")).isSameAs(context);

    assertThatThrownBy(() -> Authorization.requireAll(context, "property.read", "property.write"))
        .isInstanceOf(ForbiddenException.class)
        .hasMessageContaining("property.write");

    assertThatThrownBy(() -> Authorization.requireAny(null, "property.read"))
        .isInstanceOf(UnauthorizedException.class);
  }
}
