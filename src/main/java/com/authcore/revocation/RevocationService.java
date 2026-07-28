package com.authcore.revocation;

import com.nimbusds.jwt.JWTParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

/**
 * A deny-list for tokens that have been revoked before their natural expiry.
 *
 * <p>Self-contained JWTs are the reason this has to exist. A resource server validates a
 * token by checking a signature, which proves the token was issued and not altered — it
 * cannot express "and the user has since logged out" or "and this token was stolen".
 * Without a shared deny-list, revocation would not take effect until the token expired,
 * so the only lever left would be issuing very short tokens and hoping.
 *
 * <p>Redis rather than the database because this is read on every single API request
 * across every resource server, and because entries expire on their own. The TTL is set
 * to the token's remaining lifetime: a revoked token is uninteresting once it would have
 * expired anyway, so the deny-list stays bounded no matter how much is revoked.
 *
 * <p>Storing the {@code jti} rather than the token means the deny-list holds no
 * credentials — leaking it reveals which tokens were revoked, not how to use any.
 */
@Service
public class RevocationService {

    private static final Logger log = LoggerFactory.getLogger(RevocationService.class);
    private static final String KEY_PREFIX = "authcore:revoked:jti:";
    /** Guards against a zero or negative TTL if a token is revoked at the moment it expires. */
    private static final Duration MINIMUM_TTL = Duration.ofSeconds(1);

    private final StringRedisTemplate redis;

    public RevocationService(StringRedisTemplate redis) {
        this.redis = redis;
    }

    /**
     * Revokes a token given its raw value.
     *
     * <p>The token is parsed, not verified — it arrives from the revocation endpoint,
     * which has already authenticated the client and matched the token to a stored
     * authorization. Re-verifying here would add nothing.
     *
     * @return true if something was revoked
     */
    public boolean revoke(String tokenValue) {
        try {
            var claims = JWTParser.parse(tokenValue).getJWTClaimsSet();
            String jti = claims.getJWTID();
            Date expiresAt = claims.getExpirationTime();

            if (jti == null) {
                // An opaque refresh token, not a JWT. SAS has already invalidated it in
                // the store, and refresh tokens are checked against that store on use,
                // so there is nothing for the deny-list to add.
                return false;
            }
            revokeJti(jti, expiresAt != null ? expiresAt.toInstant() : Instant.now().plusSeconds(300));
            return true;
        } catch (Exception ex) {
            // Not a JWT we can read. Opaque tokens revoke through the stored
            // authorization, so this is expected rather than exceptional.
            log.debug("Token could not be parsed as a JWT; leaving revocation to the store", ex);
            return false;
        }
    }

    public void revokeJti(String jti, Instant expiresAt) {
        Duration ttl = Duration.between(Instant.now(), expiresAt);
        if (ttl.compareTo(MINIMUM_TTL) < 0) {
            ttl = MINIMUM_TTL;
        }
        redis.opsForValue().set(KEY_PREFIX + jti, "revoked", ttl);
        log.info("Revoked token {} (deny-listed for {}s)", jti, ttl.toSeconds());
    }

    public boolean isRevoked(String jti) {
        return jti != null && Boolean.TRUE.equals(redis.hasKey(KEY_PREFIX + jti));
    }
}
