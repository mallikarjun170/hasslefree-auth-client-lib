package com.hasslefree.auth.client.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

/** Writes RFC7807-compatible error payloads for security filters/handlers. */
public class ProblemDetailsResponseWriter {

  public static final MediaType PROBLEM_JSON_MEDIA_TYPE =
      MediaType.parseMediaType("application/problem+json");

  private final ObjectMapper objectMapper;

  public ProblemDetailsResponseWriter(ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  public void write(
      HttpServletRequest request,
      HttpServletResponse response,
      HttpStatus status,
      String title,
      String detail)
      throws IOException {
    response.setStatus(status.value());
    response.setContentType(PROBLEM_JSON_MEDIA_TYPE.toString());
    response.setCharacterEncoding("UTF-8");

    ApiErrorResponse payload =
        ApiErrorResponse.builder()
            .type("https://hasslefree.dev/problems/http-" + status.value())
            .title(title)
            .status(status.value())
            .detail(detail)
            .instance(request.getRequestURI())
            .traceId(resolveTraceId(request))
            .build();

    objectMapper.writeValue(response.getWriter(), payload);
  }

  private String resolveTraceId(HttpServletRequest request) {
    String traceId = MDC.get("traceId");
    if (traceId != null && !traceId.isBlank()) {
      return traceId;
    }
    Object correlationId = request.getAttribute("correlationId");
    if (correlationId != null) {
      return correlationId.toString();
    }
    return UUID.randomUUID().toString();
  }
}
