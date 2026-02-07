package com.hasslefree.auth.client.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Value;

import java.time.Instant;
import java.util.Map;

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
