package com.authcore.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * Replaces a client secret while keeping the old one working for a grace period.
 */
@Service
public class ClientSecretRotationService {

    private static final Logger log = LoggerFactory.getLogger(ClientSecretRotationService.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final RegisteredClientRepository registeredClientRepository;
    private final ClientSecretRotationStore rotationStore;
    private final PasswordEncoder passwordEncoder;
    private final Duration overlapWindow;

    public ClientSecretRotationService(
            RegisteredClientRepository registeredClientRepository,
            ClientSecretRotationStore rotationStore,
            PasswordEncoder passwordEncoder,
            @Value("${authcore.clients.secret-rotation-overlap:PT24H}") Duration overlapWindow) {
        this.registeredClientRepository = registeredClientRepository;
        this.rotationStore = rotationStore;
        this.passwordEncoder = passwordEncoder;
        this.overlapWindow = overlapWindow;
    }

    /**
     * Issues a new secret and keeps the outgoing one valid for the overlap window.
     *
     * @return the new secret in clear text — the only time it can ever be read
     */
    public RotationResult rotate(String clientId) {
        RegisteredClient existing = registeredClientRepository.findByClientId(clientId);
        if (existing == null) {
            throw new IllegalArgumentException("Unknown client: " + clientId);
        }
        if (existing.getClientSecret() == null) {
            // A public client has no secret to rotate, and quietly giving it one would
            // change how it authenticates.
            throw new IllegalArgumentException("Client " + clientId + " is public and has no secret");
        }

        Instant acceptedUntil = Instant.now().plus(overlapWindow);
        rotationStore.record(clientId, existing.getClientSecret(), acceptedUntil);

        String newSecret = generateSecret();
        registeredClientRepository.save(
                RegisteredClient.from(existing)
                        .clientSecret(passwordEncoder.encode(newSecret))
                        .build());

        log.info("Rotated secret for client {}; previous secret accepted until {}",
                clientId, acceptedUntil);

        return new RotationResult(newSecret, acceptedUntil);
    }

    /** Ends any overlap immediately. Used when the old secret is known to have leaked. */
    public int revokePreviousSecrets(String clientId) {
        int revoked = rotationStore.revokePreviousSecrets(clientId);
        if (revoked > 0) {
            log.warn("Revoked {} superseded secret(s) for client {} ahead of schedule", revoked, clientId);
        }
        return revoked;
    }

    private static String generateSecret() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public record RotationResult(String newSecret, Instant previousSecretAcceptedUntil) {
    }
}
