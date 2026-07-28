package com.authcore.token;

import com.authcore.tenant.TenantContext;
import com.authcore.user.AuthCoreUserPrincipal;
import com.authcore.user.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Set;

/**
 * Adds {@code roles} and {@code permissions} claims to access tokens.
 *
 * <p>Without these a resource server can only see {@code scope}, which says what the
 * <em>client</em> was allowed to ask for — not what the <em>user</em> is allowed to do.
 * A resource server that wants to authorize on the user's actual capabilities would
 * otherwise have to call back here on every request.
 *
 * <p>Only access tokens are touched. The ID token describes who the user is, not what
 * they may do, and client-credentials tokens have no user at all — for those the
 * {@code scope} claim is already the complete answer.
 */
public class AuthCoreTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final UserRepository userRepository;

    public AuthCoreTokenCustomizer(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return;
        }

        String principalName = context.getPrincipal().getName();
        String tenant = tenantOf(context);
        if (tenant == null) {
            // No authenticated user behind this token (client credentials). Scope is
            // already the whole story there.
            return;
        }

        userRepository.findByTenantSlugAndUsername(tenant, principalName).ifPresent(user -> {
            // Pins the token to the tenant it was issued for, so a resource server can
            // reject a token replayed against a different tenant without a lookup.
            context.getClaims().claim("tenant", user.getTenantSlug());

            Set<String> roles = user.roleNames();
            Set<String> permissions = user.permissionNames();

            // Claims are omitted rather than emitted empty — an absent claim is
            // unambiguous, an empty array invites "did the lookup fail?".
            if (!roles.isEmpty()) {
                context.getClaims().claim("roles", roles);
            }
            if (!permissions.isEmpty()) {
                context.getClaims().claim("permissions", permissions);
            }
        });
    }

    /**
     * Takes the tenant from the authenticated principal, not from the current request.
     *
     * <p>This runs while handling {@code /oauth2/token}, which the client's backend or a
     * CLI issues — no subdomain, no {@code X-Tenant} header, no session. Reading
     * {@link TenantContext} here quietly yields the default tenant and mislabels every
     * token. The principal was resolved during login, in the tenant that actually
     * authenticated the user, so it is the only trustworthy source at this point.
     */
    private static String tenantOf(JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();
        if (principal != null && principal.getPrincipal() instanceof AuthCoreUserPrincipal user) {
            return user.getTenantSlug();
        }
        return null;
    }
}
