package com.authcore.token;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Authenticates a public client on the <em>refresh_token</em> grant.
 *
 * <p>Spring's {@code PublicClientAuthenticationConverter} only recognises a public
 * client while a {@code code_verifier} is present — i.e. during the authorization-code
 * exchange. A refresh request carries no {@code code_verifier}, so a public client
 * has no way to authenticate and the token endpoint answers 401. Stock SAS never
 * hits this because it refuses public-client refresh tokens in the first place;
 * once {@link RotatingRefreshTokenGenerator} issues them, this gap has to be filled.
 *
 * <p>The emitted token carries a private {@link #PUBLIC_REFRESH sentinel method} rather
 * than {@link ClientAuthenticationMethod#NONE}. That keeps every stock provider out of
 * the way: they switch on the method and return {@code null} for anything they don't
 * own, so none of them run their PKCE-only code path against a request that has no code.
 */
public final class PublicRefreshTokenAuthenticationConverter implements AuthenticationConverter {

    /** Marks a token that only {@link PublicRefreshTokenAuthenticationProvider} should handle. */
    static final ClientAuthenticationMethod PUBLIC_REFRESH =
            new ClientAuthenticationMethod("authcore_public_refresh");

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return null;
        }
        if (!AuthorizationGrantType.REFRESH_TOKEN.getValue()
                .equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
            return null;
        }

        // A confidential client sends credentials — Basic header or client_secret. Leave
        // those to the stock converters; this path is only for genuinely public clients.
        if (request.getHeader("Authorization") != null
                || StringUtils.hasText(request.getParameter(OAuth2ParameterNames.CLIENT_SECRET))) {
            return null;
        }

        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId)) {
            return null;
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        request.getParameterMap().forEach((key, values) -> {
            if (!OAuth2ParameterNames.CLIENT_ID.equals(key)) {
                additionalParameters.put(key, values.length == 1 ? values[0] : values);
            }
        });

        return new OAuth2ClientAuthenticationToken(
                clientId, PUBLIC_REFRESH, null, additionalParameters);
    }
}
