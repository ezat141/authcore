package com.authcore.apikey;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Authenticates machine callers presenting an {@code X-API-Key} header.
 *
 * <p>A request without the header passes straight through untouched, so the bearer-token
 * path still works on the same endpoints. A request <em>with</em> a bad header fails
 * immediately rather than falling through — otherwise a typo'd key would surface as a
 * confusing "no credentials" 401 instead of "bad credentials".
 */
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    public static final String HEADER_NAME = "X-API-Key";

    private final AuthenticationManager authenticationManager;
    private final AuthenticationEntryPointFailureHandler failureHandler =
            new AuthenticationEntryPointFailureHandler(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));

    public ApiKeyAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String rawKey = request.getHeader(HEADER_NAME);
        if (!StringUtils.hasText(rawKey)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Authentication authentication =
                    authenticationManager.authenticate(new ApiKeyAuthenticationToken(rawKey));

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            filterChain.doFilter(request, response);
        } catch (AuthenticationException ex) {
            SecurityContextHolder.clearContext();
            failureHandler.onAuthenticationFailure(request, response, ex);
        }
    }
}
