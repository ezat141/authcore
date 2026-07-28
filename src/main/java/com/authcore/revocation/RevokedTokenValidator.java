package com.authcore.revocation;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Rejects a token that has been revoked, however valid its signature.
 *
 * <p>Added alongside the default validators rather than replacing them — the expiry and
 * issuer checks still have to run. Revocation is an extra reason to refuse a token, not a
 * substitute for the usual ones.
 *
 * <p>A token with no {@code jti} cannot be revoked individually and is passed through
 * here. Every token this server issues carries one; the check is for tokens minted
 * elsewhere and trusted by configuration.
 */
public class RevokedTokenValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error REVOKED = new OAuth2Error(
            "invalid_token",
            "The token has been revoked",
            "https://datatracker.ietf.org/doc/html/rfc7009");

    private final RevocationService revocationService;

    public RevokedTokenValidator(RevocationService revocationService) {
        this.revocationService = revocationService;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        return revocationService.isRevoked(token.getId())
                ? OAuth2TokenValidatorResult.failure(REVOKED)
                : OAuth2TokenValidatorResult.success();
    }
}
