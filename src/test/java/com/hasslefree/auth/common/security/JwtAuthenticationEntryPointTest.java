package com.hasslefree.auth.common.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;

class JwtAuthenticationEntryPointTest {

    private JwtAuthenticationEntryPoint entryPoint;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private AuthenticationException authException;
    private ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        entryPoint = new JwtAuthenticationEntryPoint();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        authException = new AuthenticationException("Test auth failure") {};
        request.setRequestURI("/api/protected");
    }

    @Test
    void commence_ShouldReturnUnauthorizedJson() throws Exception {
        entryPoint.commence(request, response, authException);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(response.getContentType()).isEqualTo("application/json");

        String content = response.getContentAsString();
        Map<String, Object> json = mapper.readValue(content, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
        assertThat(json).containsKeys("timestamp", "status", "error", "message", "path");
        assertThat(json.get("status")).isEqualTo(401);
        assertThat(json.get("message")).isEqualTo("Authentication required");
        assertThat(json.get("path")).isEqualTo("/api/protected");
    }
}
