package com.hasslefree.auth.client.context;

import static org.assertj.core.api.Assertions.assertThat;

import com.hasslefree.auth.client.access.AccessGrant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuthContextTest {

  @Test
  void exposesUserScopeAndGrantStrings() {
    AuthContext context =
        new AuthContext(
            "sub-1",
            "principal-1",
            "user@example.com",
            List.of(AccessGrant.global("property_read"), AccessGrant.global("tenant_create")),
            Map.of(
                "custom:userId", "user-123",
                "tenantId", "tenant-1",
                "orgId", "org-9",
                "propertyId", "property-42"));

    assertThat(context.userId()).isEqualTo("user-123");
    assertThat(context.tenantId()).isEqualTo("tenant-1");
    assertThat(context.orgId()).isEqualTo("org-9");
    assertThat(context.propertyId()).isEqualTo("property-42");
    assertThat(context.grants()).containsExactlyInAnyOrder("PROPERTY_READ", "TENANT_CREATE");
  }
}
