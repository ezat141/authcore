package com.authcore;

import com.authcore.revocation.RevocationService;
import com.authcore.revocation.RevokedTokenValidator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Revocation against a real Redis, since the whole mechanism is the round trip.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class RevocationTest {

    @Autowired
    private RevocationService revocationService;

    @Test
    void aTokenIsNotRevokedUntilItIsRevoked() {
        assertThat(revocationService.isRevoked(UUID.randomUUID().toString())).isFalse();
    }

    @Test
    void revokingAJtiTakesEffectImmediately() {
        String jti = UUID.randomUUID().toString();

        revocationService.revokeJti(jti, Instant.now().plusSeconds(300));

        assertThat(revocationService.isRevoked(jti)).isTrue();
    }

    @Test
    void revokingOneTokenLeavesOthersAlone() {
        String revoked = UUID.randomUUID().toString();
        String untouched = UUID.randomUUID().toString();

        revocationService.revokeJti(revoked, Instant.now().plusSeconds(300));

        assertThat(revocationService.isRevoked(revoked)).isTrue();
        assertThat(revocationService.isRevoked(untouched)).isFalse();
    }

    @Test
    void aNullJtiIsNotTreatedAsRevoked() {
        // A token without a jti cannot be revoked individually; it must not be
        // rejected on the strength of a missing claim.
        assertThat(revocationService.isRevoked(null)).isFalse();
    }

    @Test
    void theValidatorRejectsARevokedTokenAndPassesAnythingElse() {
        String revokedJti = UUID.randomUUID().toString();
        String liveJti = UUID.randomUUID().toString();
        revocationService.revokeJti(revokedJti, Instant.now().plusSeconds(300));

        RevokedTokenValidator validator = new RevokedTokenValidator(revocationService);

        assertThat(validator.validate(jwtWithId(revokedJti)).hasErrors()).isTrue();
        assertThat(validator.validate(jwtWithId(liveJti)).hasErrors()).isFalse();
    }

    @Test
    void anOpaqueTokenIsLeftToTheStoreRatherThanDenyListed() {
        // Refresh tokens are not JWTs; they are checked against the stored authorization
        // on every use, so the deny-list has nothing to contribute.
        assertThat(revocationService.revoke("not-a-jwt-at-all")).isFalse();
    }

    private static Jwt jwtWithId(String jti) {
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("ezzat")
                .jti(jti)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .build();
    }
}
