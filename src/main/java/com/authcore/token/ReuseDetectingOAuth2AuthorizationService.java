package com.authcore.token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Wraps the real {@link OAuth2AuthorizationService} to add refresh-token reuse detection.
 *
 * <p>With rotation enabled, each refresh produces a new token and retires the old one.
 * A retired token showing up again means someone is holding a copy they should not have —
 * most likely a stolen token — and we cannot tell the thief from the victim. So we revoke
 * the entire rotation family, forcing both parties back through a full login.
 *
 * <p>This is the behaviour recommended by OAuth 2.0 Security BCP §4.14.2.
 */
public class ReuseDetectingOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final Logger log = LoggerFactory.getLogger(ReuseDetectingOAuth2AuthorizationService.class);

    private final OAuth2AuthorizationService delegate;
    private final RefreshTokenFamilyStore familyStore;

    public ReuseDetectingOAuth2AuthorizationService(OAuth2AuthorizationService delegate,
                                                    RefreshTokenFamilyStore familyStore) {
        this.delegate = delegate;
        this.familyStore = familyStore;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (isRefreshTokenLookup(tokenType)) {
            RefreshTokenRecord record = familyStore.findByTokenHash(sha256(token)).orElse(null);
            if (record != null && record.consumed()) {
                revokeFamily(record);
                // Returning null makes SAS answer the request with invalid_grant.
                return null;
            }
        }
        return delegate.findByToken(token, tokenType);
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        delegate.save(authorization);
        trackRefreshToken(authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        delegate.remove(authorization);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return delegate.findById(id);
    }

    private void trackRefreshToken(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
        if (refreshToken == null) {
            return;
        }

        String authorizationId = authorization.getId();
        String tokenHash = sha256(refreshToken.getToken().getTokenValue());

        // A rotated token stays in the family it came from; a fresh login starts a new one.
        String familyId = familyStore.findFamilyIdByAuthorizationId(authorizationId)
                .orElseGet(() -> UUID.randomUUID().toString());

        familyStore.markSupersededAsConsumed(authorizationId, tokenHash);
        familyStore.record(tokenHash, familyId, authorizationId, authorization.getPrincipalName());
    }

    private void revokeFamily(RefreshTokenRecord record) {
        log.warn("Refresh token reuse detected for principal '{}' (family {}). Revoking the whole family.",
                record.principalName(), record.familyId());

        for (String authorizationId : familyStore.findAuthorizationIds(record.familyId())) {
            OAuth2Authorization authorization = delegate.findById(authorizationId);
            if (authorization != null) {
                delegate.remove(authorization);
            }
        }
        familyStore.deleteFamily(record.familyId());
    }

    private static boolean isRefreshTokenLookup(OAuth2TokenType tokenType) {
        return tokenType == null || OAuth2TokenType.REFRESH_TOKEN.equals(tokenType);
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is required but unavailable", ex);
        }
    }
}
