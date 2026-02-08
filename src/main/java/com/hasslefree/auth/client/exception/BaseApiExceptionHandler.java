package com.hasslefree.auth.client.exception;

import com.hasslefree.auth.client.api.ApiErrorResponse;
import com.hasslefree.auth.client.filter.CorrelationIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;

public abstract class BaseApiExceptionHandler {

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
    Map<String, String> errors = new HashMap<>();
    ex.getBindingResult()
        .getAllErrors()
        .forEach(
            error -> {
              String fieldName = ((FieldError) error).getField();
              String errorMessage = error.getDefaultMessage();
              errors.put(fieldName, errorMessage);
            });
    return buildErrorResponse(
        HttpStatus.BAD_REQUEST, "Validation Failed", "Invalid input parameters", request, errors);
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
      String error,
      String message,
      HttpServletRequest request,
      Map<String, String> validationErrors) {
    ApiErrorResponse response =
        ApiErrorResponse.builder()
            .timestamp(Instant.now())
            .status(status.value())
            .error(error)
            .message(message)
            .path(sanitizeUri(extractPath(request)))
            .correlationId(resolveCorrelationId(request))
            .validationErrors(validationErrors)
            .build();
    return ResponseEntity.status(status).body(response);
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
