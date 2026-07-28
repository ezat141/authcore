package com.authcore;

import com.authcore.keys.JpaJwkSource;
import com.authcore.keys.SigningKey;
import com.authcore.keys.SigningKeyService;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Rotation is only useful if it is safe to run. These pin the property that makes it so:
 * a retired key keeps verifying its own tokens.
 */
@SpringBootTest
@Import(TestcontainersConfiguration.class)
class SigningKeyRotationTest {

    @Autowired
    private SigningKeyService signingKeyService;

    @Autowired
    private JpaJwkSource jwkSource;

    @Test
    void thereIsExactlyOneActiveKeyToBeginWith() {
        List<SigningKey> keys = signingKeyService.findAll();

        assertThat(keys).isNotEmpty();
        assertThat(countActive(keys)).isEqualTo(1);
    }

    @Test
    void rotationRetiresTheOldKeyAndPublishesBoth() throws Exception {
        String kidBefore = activeKid();

        SigningKey rotated = signingKeyService.rotate();
        jwkSource.invalidate();

        assertThat(rotated.getKid()).isNotEqualTo(kidBefore);
        assertThat(activeKid()).isEqualTo(rotated.getKid());

        // The whole point: the old key is still served, so tokens it signed still verify.
        List<String> published = publishedKids();
        assertThat(published).contains(rotated.getKid(), kidBefore);

        // And it is genuinely retired, not merely still around.
        SigningKey previous = signingKeyService.findAll().stream()
                .filter(key -> key.getKid().equals(kidBefore))
                .findFirst()
                .orElseThrow();
        assertThat(previous.getStatus()).isEqualTo(SigningKey.Status.RETIRING);
    }

    @Test
    void theActiveKeyIsOfferedFirstSoNewTokensUseIt() throws Exception {
        signingKeyService.rotate();
        jwkSource.invalidate();

        // The encoder signs with the first matching key, so ordering is what keeps
        // new tokens on the current key rather than a retired one.
        assertThat(publishedKids().get(0)).isEqualTo(activeKid());
    }

    /**
     * Regression cover for a defect that only appeared once a rotation had happened.
     *
     * <p>With two keys published, {@code NimbusJwtEncoder} finds both acceptable for
     * RS256 and, by default, refuses to sign rather than choose — so the first rotation
     * made every token request fail with a 401. The worst possible failure mode: rotation
     * is what an operator reaches for during a suspected key compromise, and it would
     * have taken the token endpoint down at exactly that moment.
     *
     * <p>This drives the real encoder rather than asserting anything about how it queries
     * the source. The original test guessed at the matcher, guessed wrong, and would have
     * passed against a fix that did not actually work.
     */
    @Test
    void tokensAreStillSignedAfterRotationAndUseTheNewKey() {
        signingKeyService.rotate();
        signingKeyService.rotate();
        jwkSource.invalidate();

        Jwt signed = encoder().encode(JwtEncoderParameters.from(
                JwtClaimsSet.builder()
                        .subject("rotation-probe")
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(60))
                        .build()));

        assertThat(signed.getHeaders().get("kid")).isEqualTo(activeKid());
    }

    @Test
    void aVerificationQueryCanStillFindARetiredKey() throws Exception {
        String retiredKid = activeKid();
        signingKeyService.rotate();
        jwkSource.invalidate();

        // How the decoder asks: by the kid in the token header.
        JWKSelector byKid = new JWKSelector(new JWKMatcher.Builder().keyID(retiredKid).build());

        assertThat(jwkSource.get(byKid, null))
                .singleElement()
                .extracting(JWK::getKeyID)
                .isEqualTo(retiredKid);
    }

    /** Mirrors how the application builds its encoder, tie-break included. */
    private JwtEncoder encoder() {
        NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        jwtEncoder.setJwkSelector(List::getFirst);
        return jwtEncoder;
    }

    @Test
    void repeatedRotationKeepsOneActiveKeyAndAccumulatesRetiredOnes() {
        int retiredBefore = signingKeyService.findAll().size() - 1;

        signingKeyService.rotate();
        signingKeyService.rotate();
        jwkSource.invalidate();

        List<SigningKey> keys = signingKeyService.findAll();
        assertThat(countActive(keys)).isEqualTo(1);
        assertThat(keys.size() - 1).isEqualTo(retiredBefore + 2);
    }

    private String activeKid() {
        return signingKeyService.findAll().stream()
                .filter(key -> key.getStatus() == SigningKey.Status.ACTIVE)
                .map(SigningKey::getKid)
                .findFirst()
                .orElseThrow();
    }

    private List<String> publishedKids() throws Exception {
        List<JWK> jwks = jwkSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
        return jwks.stream().map(JWK::getKeyID).toList();
    }

    private static long countActive(List<SigningKey> keys) {
        return keys.stream().filter(key -> key.getStatus() == SigningKey.Status.ACTIVE).count();
    }
}
