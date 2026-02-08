package com.hasslefree.auth.common.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Metadata extracted from the incoming HTTP request for auditing and tracing. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RequestMetadata {
  private String correlationId;
  private String remoteIp;
  private String userAgent;
}
