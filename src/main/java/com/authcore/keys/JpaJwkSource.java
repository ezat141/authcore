package com.authcore.keys;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Serves signing keys from the database instead of generating them per process.
 *
 * <p><b>Order is part of the contract.</b> The active key is always first. During a
 * rotation two keys match the encoder's "which key signs RS256?" query, and
 * {@code NimbusJwtEncoder} resolves that tie with the selector configured alongside it
 * ({@code List::getFirst}). Returning the keys in a different order would quietly move
 * new signatures onto a retired key — tokens would still verify, so nothing would look
 * broken, but the retirement would never actually take effect.
 *
 * <p>Retired keys stay in every other answer, which is what makes rotation safe: a
 * verifier asking for the {@code kid} on an older token still finds it, and the JWKS
 * endpoint keeps publishing it until the last token it signed has expired.
 *
 * <p>Keys are cached, since this sits on the path of every sign and verify. The cache has
 * a short TTL plus an explicit invalidation hook: rotation on this instance takes effect
 * at once, while another instance notices within the TTL. That lag is safe in the only
 * direction it can occur — a stale instance keeps signing with a key that is still
 * published and still verifies. The dangerous case, a verifier that has not yet seen a
 * new key, cannot arise, because a key is published before it signs anything.
 */
public class JpaJwkSource implements JWKSource<SecurityContext> {

    private static final Duration CACHE_TTL = Duration.ofSeconds(30);

    private final SigningKeyService signingKeyService;

    private volatile List<JWK> cachedKeys = List.of();
    private volatile Instant cachedAt = Instant.EPOCH;

    public JpaJwkSource(SigningKeyService signingKeyService) {
        this.signingKeyService = signingKeyService;
    }

    @Override
    public List<JWK> get(JWKSelector selector, SecurityContext context) {
        return selector.select(new JWKSet(currentKeys()));
    }

    /** Called after a local rotation so the new key signs the very next token. */
    public void invalidate() {
        this.cachedAt = Instant.EPOCH;
    }

    private List<JWK> currentKeys() {
        if (Instant.now().isBefore(cachedAt.plus(CACHE_TTL))) {
            return cachedKeys;
        }
        List<JWK> keys = List.copyOf(signingKeyService.loadJwks());
        this.cachedKeys = keys;
        this.cachedAt = Instant.now();
        return keys;
    }
}
