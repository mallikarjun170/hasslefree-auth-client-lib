package com.hasslefree.auth.client.exception;

import com.hasslefree.auth.client.api.ApiErrorResponse;
import com.hasslefree.auth.client.filter.CorrelationIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;

public abstract class BaseApiExceptionHandler {

  protected static final MediaType PROBLEM_JSON_MEDIA_TYPE =
      MediaType.parseMediaType("application/problem+json");
  private static final Logger logger = LoggerFactory.getLogger(BaseApiExceptionHandler.class);

  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<ApiErrorResponse> handleHttpMessageNotReadable(
      HttpMessageNotReadableException ex, HttpServletRequest request) {
    String message =
        "Malformed JSON request: "
            + (ex.getMostSpecificCause() != null
                ? ex.getMostSpecificCause().getMessage()
                : ex.getMessage());
    return buildErrorResponse(HttpStatus.BAD_REQUEST, "Bad Request", message, request, null);
  }

  @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
  public ResponseEntity<ApiErrorResponse> handleMethodNotAllowed(
      HttpRequestMethodNotSupportedException ex, HttpServletRequest request) {
    String supportedMethods;
    var supportedHttpMethods = ex.getSupportedHttpMethods();
    if (supportedHttpMethods != null && !supportedHttpMethods.isEmpty()) {
      supportedMethods =
          String.join(", ", supportedHttpMethods.stream().map(HttpMethod::name).toList());
    } else {
      supportedMethods = "None";
    }
    String message =
        String.format(
            "Request method '%s' is not supported for this endpoint. Supported methods: %s",
            ex.getMethod(), supportedMethods);
    return buildErrorResponse(
        HttpStatus.METHOD_NOT_ALLOWED, "Method Not Allowed", message, request, null);
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiErrorResponse> handleValidationExceptions(
      MethodArgumentNotValidException ex, HttpServletRequest request) {
    List<ApiErrorResponse.InvalidParam> invalidParams =
        ex.getBindingResult().getAllErrors().stream()
            .map(
                error ->
                    ApiErrorResponse.InvalidParam.builder()
                        .name(
                            error instanceof FieldError fieldError
                                ? fieldError.getField()
                                : "request")
                        .reason(error.getDefaultMessage())
                        .build())
            .toList();
    return buildErrorResponse(
        HttpStatus.BAD_REQUEST,
        "Validation failed",
        "Request validation failed",
        request,
        invalidParams);
  }

  @ExceptionHandler(IllegalArgumentException.class)
  public ResponseEntity<ApiErrorResponse> handleIllegalArgument(
      IllegalArgumentException ex, HttpServletRequest request) {
    logger.warn("Bad request: {}", ex.getMessage());
    return buildErrorResponse(
        HttpStatus.BAD_REQUEST, "Bad Request", ex.getMessage(), request, null);
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ApiErrorResponse> handleInternalError(
      Exception ex, HttpServletRequest request) {
    String correlationId = UUID.randomUUID().toString();
    MDC.put("errorId", correlationId);
    String sanitizedPath = sanitizeUri(request.getRequestURI());
    logger.error("Unexpected exception [{}] for request: {}", correlationId, sanitizedPath, ex);
    ResponseEntity<ApiErrorResponse> response =
        buildErrorResponse(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "An unexpected error occurred",
            request,
            null);
    MDC.remove("errorId");
    return response;
  }

  protected ResponseEntity<ApiErrorResponse> buildErrorResponse(
      HttpStatus status,
      String title,
      String detail,
      HttpServletRequest request,
      List<ApiErrorResponse.InvalidParam> invalidParams) {
    String traceId = resolveTraceId(request);
    ApiErrorResponse response =
        ApiErrorResponse.builder()
            .type(problemTypeFor(status))
            .title(title)
            .status(status.value())
            .detail(detail)
            .instance(sanitizeUri(extractPath(request)))
            .traceId(traceId)
            .invalidParams(invalidParams)
            .build();
    return ResponseEntity.status(status)
        .header(HttpHeaders.CONTENT_TYPE, PROBLEM_JSON_MEDIA_TYPE.toString())
        .body(response);
  }

  protected String resolveCorrelationId(HttpServletRequest request) {
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

  protected String resolveTraceId(HttpServletRequest request) {
    String traceId = MDC.get("traceId");
    if (traceId != null && !traceId.isBlank()) {
      return traceId;
    }
    String correlationId = resolveCorrelationId(request);
    if (correlationId != null && !correlationId.isBlank()) {
      return correlationId;
    }
    return UUID.randomUUID().toString();
  }

  protected String problemTypeFor(HttpStatus status) {
    return "https://hasslefree.dev/problems/http-" + status.value();
  }

  protected String sanitizeUri(String description) {
    if (description == null) {
      return "";
    }
    return description.replaceAll(
        "(?i)(token|password|secret|key|authorization)=[^;\\s&]*", "$1=***");
  }

  protected String extractPath(HttpServletRequest request) {
    return request.getRequestURI();
  }
}
