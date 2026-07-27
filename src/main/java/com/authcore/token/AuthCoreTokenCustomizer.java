package com.authcore.token;

import com.authcore.user.UserRepository;
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
        userRepository.findByUsername(principalName).ifPresent(user -> {
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
}
