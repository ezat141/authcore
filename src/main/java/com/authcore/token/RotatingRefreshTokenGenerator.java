package com.authcore.token;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;
import java.util.Base64;

/**
 * Issues refresh tokens to public clients, which Spring's stock
 * {@code OAuth2RefreshTokenGenerator} refuses to do.
 *
 * <p>That refusal dates from a time when a public client had no safe way to hold a
 * long-lived credential. OAuth 2.0 Security BCP §4.14 now allows it on the condition
 * that tokens are rotated on every use and reuse of a retired token is detected and
 * punished. {@link ReuseDetectingOAuth2AuthorizationService} is that condition being
 * met, so the refusal no longer buys us anything — it just pushes SPAs toward worse
 * alternatives like long-lived access tokens or a token-holding backend proxy.
 *
 * <p>Everything else matches the stock generator, including the 96-byte token length.
 */
public final class RotatingRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private final StringKeyGenerator refreshTokenGenerator =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return null;
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(
                context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());

        return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
    }
}
