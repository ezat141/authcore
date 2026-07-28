package com.authcore.keys;

import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Owns the lifecycle of signing keys: creation, rotation, and eventual removal.
 */
@Service
public class SigningKeyService {

    private static final Logger log = LoggerFactory.getLogger(SigningKeyService.class);
    private static final int RSA_KEY_SIZE = 2048;

    private final SigningKeyRepository repository;
    private final KeyCipher keyCipher;

    public SigningKeyService(SigningKeyRepository repository, KeyCipher keyCipher) {
        this.repository = repository;
        this.keyCipher = keyCipher;
    }

    /** Creates the first key if the table is empty. Safe to call on every boot. */
    @Transactional
    public void initialize() {
        if (repository.findByStatus(SigningKey.Status.ACTIVE).isPresent()) {
            return;
        }
        SigningKey created = repository.save(generate(SigningKey.Status.ACTIVE));
        log.info("Created initial signing key {}", created.getKid());
    }

    /**
     * Retires the current key and promotes a freshly generated one.
     *
     * <p>The old key keeps its public half published, so tokens it signed continue to
     * verify until they expire. Deleting it here instead would reject every token issued
     * in the last few minutes — rotation would become an outage, and an operator facing
     * a suspected key compromise would hesitate to run it.
     */
    @Transactional
    public SigningKey rotate() {
        repository.findByStatus(SigningKey.Status.ACTIVE).ifPresent(current -> {
            current.retire();
            // Flushed before the insert below, or the partial unique index rejects a
            // second ACTIVE row.
            repository.saveAndFlush(current);
            log.info("Retired signing key {}", current.getKid());
        });

        SigningKey created = repository.save(generate(SigningKey.Status.ACTIVE));
        log.info("Activated signing key {}", created.getKid());
        return created;
    }

    /**
     * Drops retired keys whose tokens can no longer be valid.
     *
     * <p>The grace period must exceed the longest token lifetime, otherwise a token that
     * has not yet expired loses the key that verifies it.
     */
    @Transactional
    public int purgeRetired(Duration gracePeriod) {
        List<SigningKey> expired = repository.findAllByStatusAndRetiredAtBefore(
                SigningKey.Status.RETIRING, Instant.now().minus(gracePeriod));
        expired.forEach(key -> log.info("Purging retired signing key {}", key.getKid()));
        repository.deleteAll(expired);
        return expired.size();
    }

    /**
     * Every key that should appear in JWKS, active first.
     *
     * <p>Order matters: the JWS encoder signs with the first key matching its selector,
     * so an active-first list is what keeps new tokens on the current key.
     */
    @Transactional(readOnly = true)
    public List<RSAKey> loadJwks() {
        List<RSAKey> keys = new ArrayList<>();
        repository.findByStatus(SigningKey.Status.ACTIVE).map(this::toRsaKey).ifPresent(keys::add);
        repository.findAllByStatusOrderByCreatedAtDesc(SigningKey.Status.RETIRING)
                .forEach(key -> keys.add(toRsaKey(key)));
        return keys;
    }

    @Transactional(readOnly = true)
    public List<SigningKey> findAll() {
        List<SigningKey> keys = new ArrayList<>();
        repository.findByStatus(SigningKey.Status.ACTIVE).ifPresent(keys::add);
        keys.addAll(repository.findAllByStatusOrderByCreatedAtDesc(SigningKey.Status.RETIRING));
        return keys;
    }

    private SigningKey generate(SigningKey.Status status) {
        KeyPair keyPair = generateRsaKeyPair();
        return new SigningKey(
                UUID.randomUUID().toString(),
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                keyCipher.encrypt(keyPair.getPrivate().getEncoded()),
                status);
    }

    private RSAKey toRsaKey(SigningKey key) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(key.getPublicKey())));
            RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(
                    new PKCS8EncodedKeySpec(keyCipher.decrypt(key.getPrivateKey())));

            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(key.getKid())
                    .build();
        } catch (Exception ex) {
            throw new IllegalStateException("Could not materialise signing key " + key.getKid(), ex);
        }
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(RSA_KEY_SIZE);
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Could not generate RSA key pair", ex);
        }
    }
}
