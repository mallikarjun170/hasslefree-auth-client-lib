package com.hasslefree.auth.client.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hasslefree.auth.client.filter.CorrelationIdFilter;
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
  private static final String TRACEPARENT_HEADER = "traceparent";

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
            .correlationId(resolveCorrelationId(request))
            .build();

    objectMapper.writeValue(response.getWriter(), payload);
  }

  private String resolveTraceId(HttpServletRequest request) {
    String traceId = MDC.get("traceId");
    if (traceId != null && !traceId.isBlank()) {
      return traceId;
    }
    String traceparentTraceId = resolveTraceparentTraceId(request);
    if (traceparentTraceId != null && !traceparentTraceId.isBlank()) {
      return traceparentTraceId;
    }
    String correlationId = resolveCorrelationId(request);
    if (correlationId != null && !correlationId.isBlank()) {
      return correlationId;
    }
    return UUID.randomUUID().toString();
  }

  private String resolveCorrelationId(HttpServletRequest request) {
    String correlationId = MDC.get(CorrelationIdFilter.CORRELATION_ID_MDC_KEY);
    if (correlationId != null && !correlationId.isBlank()) {
      return correlationId;
    }
    String headerId = request.getHeader(CorrelationIdFilter.CORRELATION_ID_HEADER);
    if (headerId != null && !headerId.isBlank()) {
      return headerId;
    }
    Object attr = request.getAttribute(CorrelationIdFilter.CORRELATION_ID_ATTR);
    return attr != null ? attr.toString() : null;
  }

  private String resolveTraceparentTraceId(HttpServletRequest request) {
    String traceparent = request.getHeader(TRACEPARENT_HEADER);
    if (traceparent == null || traceparent.isBlank()) {
      return null;
    }
    String[] parts = traceparent.trim().split("-");
    if (parts.length < 4) {
      return null;
    }
    String traceId = parts[1];
    return traceId.matches("^[0-9a-fA-F]{32}$") ? traceId.toLowerCase() : null;
  }
}
