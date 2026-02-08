package com.hasslefree.auth.client.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.Map;
import lombok.Builder;
import lombok.Value;

@Value
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiErrorResponse {
  Instant timestamp;
  int status;
  String error;
  String message;
  String path;
  String correlationId;
  Map<String, String> validationErrors;
}
