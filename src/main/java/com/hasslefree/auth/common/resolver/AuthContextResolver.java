package com.hasslefree.auth.common.resolver;

import com.hasslefree.auth.common.annotation.AuthContext;
import com.hasslefree.auth.common.dto.AuthenticationContext;
import com.hasslefree.auth.common.util.AuthContextExtractor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Resolver to inject AuthenticationContext into controller methods.
 */
public class AuthContextResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(@NonNull MethodParameter parameter) {
        return parameter.hasParameterAnnotation(AuthContext.class)
                && AuthenticationContext.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(
            @NonNull MethodParameter parameter,
            @Nullable ModelAndViewContainer mavContainer,
            @NonNull NativeWebRequest webRequest,
            @Nullable WebDataBinderFactory binderFactory) throws Exception {
        HttpServletRequest request = webRequest.getNativeRequest(HttpServletRequest.class);
        if (request == null) {
            return null;
        }
        String authHeader = request.getHeader("Authorization");
        return AuthContextExtractor.extractFromToken(authHeader);
    }
}
