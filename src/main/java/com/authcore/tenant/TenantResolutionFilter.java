package com.authcore.tenant;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Works out which tenant a request belongs to, before authentication runs.
 *
 * <p>Resolution order, most explicit first:
 * <ol>
 *   <li><b>Subdomain</b> — {@code acme.authcore.local}. The production shape.</li>
 *   <li><b>{@code X-Tenant} header</b> — for API clients that share one hostname.</li>
 *   <li><b>{@code tenant} query parameter</b> — so the browser flow is demonstrable on
 *       plain {@code localhost} without touching DNS or a hosts file.</li>
 *   <li><b>Session</b> — see below.</li>
 *   <li><b>Default</b>.</li>
 * </ol>
 *
 * <p>The session step is what makes the browser flow work at all. A user hits
 * {@code /oauth2/authorize?tenant=acme}, is redirected to {@code /login}, and posts the
 * form back — and that POST carries none of the original request's tenant hints. Without
 * remembering the tenant across those hops, the login would resolve against the default
 * tenant and fail for every non-default user. Resolution is therefore sticky for the
 * session once established.
 */
public class TenantResolutionFilter extends OncePerRequestFilter {

    public static final String HEADER_NAME = "X-Tenant";
    public static final String PARAMETER_NAME = "tenant";
    private static final String SESSION_ATTRIBUTE = "AUTHCORE_TENANT";

    private final TenantService tenantService;

    public TenantResolutionFilter(TenantService tenantService) {
        this.tenantService = tenantService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String tenant = resolve(request);
            TenantContext.set(tenant);
            filterChain.doFilter(request, response);
        } finally {
            // Tomcat reuses threads; a tenant left behind would be inherited by the
            // next unrelated request on the same thread.
            TenantContext.clear();
        }
    }

    private String resolve(HttpServletRequest request) {
        String fromRequest = firstNonBlank(
                subdomainOf(request.getServerName()),
                request.getHeader(HEADER_NAME),
                request.getParameter(PARAMETER_NAME));

        if (fromRequest != null && tenantService.exists(fromRequest)) {
            rememberForBrowserFlow(request, fromRequest);
            return fromRequest;
        }

        String fromSession = fromSession(request);
        if (fromSession != null) {
            return fromSession;
        }

        return TenantContext.DEFAULT_TENANT;
    }

    /**
     * {@code acme.authcore.local} -> {@code acme}; {@code localhost} -> null.
     * Two-label hosts have no subdomain to speak of.
     */
    private static String subdomainOf(String serverName) {
        if (!StringUtils.hasText(serverName)) {
            return null;
        }
        int firstDot = serverName.indexOf('.');
        if (firstDot <= 0) {
            return null;
        }
        String candidate = serverName.substring(0, firstDot);
        return "www".equalsIgnoreCase(candidate) ? null : candidate;
    }

    /**
     * Creates the session if needed so the tenant survives the login redirect. Skipped
     * for {@code /api/**}, which is deliberately stateless — those callers send their
     * tenant on every request and must not be handed a cookie.
     */
    private static void rememberForBrowserFlow(HttpServletRequest request, String tenant) {
        if (request.getRequestURI().startsWith("/api/")) {
            return;
        }
        request.getSession(true).setAttribute(SESSION_ATTRIBUTE, tenant);
    }

    private static String fromSession(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object value = session.getAttribute(SESSION_ATTRIBUTE);
        return value != null ? value.toString() : null;
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value;
            }
        }
        return null;
    }
}
