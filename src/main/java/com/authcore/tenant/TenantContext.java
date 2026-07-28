package com.authcore.tenant;

/**
 * Holds the tenant for the request currently being served.
 *
 * <p>A {@code ThreadLocal} is not the first choice for passing state, but
 * {@link org.springframework.security.core.userdetails.UserDetailsService#loadUserByUsername(String)}
 * takes a username and nothing else. Spring resolves the user deep inside the
 * authentication machinery, far from anything holding the request, so the tenant has to
 * travel out of band. {@link TenantResolutionFilter} sets it and clears it in a finally
 * block so nothing leaks onto a pooled thread.
 */
public final class TenantContext {

    public static final String DEFAULT_TENANT = "default";

    private static final ThreadLocal<String> CURRENT = new ThreadLocal<>();

    private TenantContext() {
    }

    public static void set(String tenantSlug) {
        CURRENT.set(tenantSlug);
    }

    /** Never null — an unresolved request is treated as the default tenant. */
    public static String get() {
        String tenant = CURRENT.get();
        return tenant != null ? tenant : DEFAULT_TENANT;
    }

    public static boolean isResolved() {
        return CURRENT.get() != null;
    }

    public static void clear() {
        CURRENT.remove();
    }
}
