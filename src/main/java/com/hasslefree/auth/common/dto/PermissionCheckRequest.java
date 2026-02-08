package com.hasslefree.auth.common.dto;

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

  @NotNull private UUID resourceId;
}
