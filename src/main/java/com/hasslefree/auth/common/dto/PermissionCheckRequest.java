package com.hasslefree.auth.common.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Payload used by services when querying the auth service for permission checks. */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PermissionCheckRequest {

  @NotNull private UUID userId;

  @NotBlank private String permissionCode;

  @NotBlank private String resourceType;

  private UUID resourceId;

  @AssertTrue(message = "resourceId is required unless resourceType is SYSTEM")
  public boolean isResourceIdValid() {
    if (resourceType == null || resourceType.isBlank()) {
      return true;
    }
    return "SYSTEM".equalsIgnoreCase(resourceType.trim()) || resourceId != null;
  }
}
