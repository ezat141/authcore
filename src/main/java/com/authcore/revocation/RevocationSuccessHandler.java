package com.authcore.revocation;

import com.authcore.token.RefreshTokenFamilyStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

/**
 * Extends {@code /oauth2/revoke} to cover self-contained tokens.
 *
 * <p>Out of the box, revocation marks the stored authorization invalid. That is enough
 * for anything checked against the store on use, and does nothing at all for a JWT that
 * a resource server validates by signature alone — the endpoint would return 200 while
 * the token kept working everywhere it mattered. This closes that gap by adding the
 * token's {@code jti} to the deny-list.
 *
 * <p>Revoking a refresh token also destroys its rotation family. A refresh token is
 * usually revoked because it is believed compromised, and rotation means the holder may
 * already have exchanged it for a successor; leaving the family alive would revoke the
 * one token the attacker no longer needs.
 */
public class RevocationSuccessHandler implements AuthenticationSuccessHandler {

    private final RevocationService revocationService;
    private final RefreshTokenFamilyStore refreshTokenFamilyStore;
    private final AuthenticationSuccessHandler delegate;

    public RevocationSuccessHandler(RevocationService revocationService,
                                    RefreshTokenFamilyStore refreshTokenFamilyStore,
                                    AuthenticationSuccessHandler delegate) {
        this.revocationService = revocationService;
        this.refreshTokenFamilyStore = refreshTokenFamilyStore;
        this.delegate = delegate;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws java.io.IOException,
            jakarta.servlet.ServletException {
        if (authentication instanceof OAuth2TokenRevocationAuthenticationToken revocation) {
            String tokenValue = revocation.getToken();
            if (StringUtils.hasText(tokenValue)) {
                boolean denyListed = revocationService.revoke(tokenValue);
                if (!denyListed) {
                    // Not a JWT, so it is a refresh token: take out the whole family.
                    revokeRefreshFamily(tokenValue);
                }
            }
        }
        // The RFC 7009 response is the delegate's job; ours is the side effect.
        delegate.onAuthenticationSuccess(request, response, authentication);
    }

    private void revokeRefreshFamily(String refreshTokenValue) {
        refreshTokenFamilyStore.findByTokenHash(RefreshTokenFamilyStore.hash(refreshTokenValue))
                .ifPresent(record -> refreshTokenFamilyStore.deleteFamily(record.familyId()));
    }
}
