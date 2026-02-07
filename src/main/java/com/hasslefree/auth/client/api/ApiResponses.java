package com.hasslefree.auth.client.api;

import com.hasslefree.auth.client.filter.CorrelationIdFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.MDC;

import java.time.Instant;

public final class ApiResponses {

    private ApiResponses() {
    }

    public static <T> ApiResponse<T> ok(T data, HttpServletRequest request) {
        return ApiResponse.<T>builder()
                .timestamp(Instant.now())
                .correlationId(resolveCorrelationId(request))
                .data(data)
                .build();
    }

    private static String resolveCorrelationId(HttpServletRequest request) {
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
}
