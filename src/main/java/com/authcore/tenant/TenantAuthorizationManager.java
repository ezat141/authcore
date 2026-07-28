package com.authcore.tenant;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.function.Supplier;

/**
 * Rejects a token used against a tenant other than the one it was issued for.
 *
 * <p>Scoping the user lookup stops someone <em>authenticating</em> across tenants, but it
 * says nothing about a token that has already been issued. Without this check, a valid
 * token from tenant A would work perfectly against tenant B's data, because it is
 * correctly signed and unexpired — the signature proves the token is genuine, not that it
 * is being used where it belongs.
 *
 * <p>Requests carrying no tenant claim (client-credentials tokens, API keys) are left to
 * the other rules in the chain; those callers are not tenant-bound, so there is nothing
 * here to compare.
 */
public class TenantAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final AuthorizationManager<RequestAuthorizationContext> delegate;

    public TenantAuthorizationManager(AuthorizationManager<RequestAuthorizationContext> delegate) {
        this.delegate = delegate;
    }

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
                                         RequestAuthorizationContext context) {
        AuthorizationResult result = delegate.authorize(authentication, context);
        if (result == null || !result.isGranted()) {
            return result;
        }

        String tokenTenant = tenantClaimOf(authentication.get());
        if (tokenTenant == null) {
            return result;
        }

        String requestTenant = TenantContext.get();
        if (!tokenTenant.equals(requestTenant)) {
            return new AuthorizationDecision(false);
        }
        return result;
    }

    private static String tenantClaimOf(Authentication authentication) {
        if (!(authentication instanceof JwtAuthenticationToken jwtAuthentication)) {
            return null;
        }
        Jwt jwt = jwtAuthentication.getToken();
        Object claim = jwt.getClaim("tenant");
        return claim != null ? claim.toString() : null;
    }
}
