package com.authcore.keys;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "signing_keys")
public class SigningKey {

    public enum Status {
        /** The one key currently signing new tokens. */
        ACTIVE,
        /** No longer signs, but still published so its tokens keep verifying. */
        RETIRING
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** The {@code kid} in the JWT header; how a verifier picks the right key. */
    @Column(nullable = false, unique = true, length = 64)
    private String kid;

    @Column(name = "public_key", nullable = false, columnDefinition = "TEXT")
    private String publicKey;

    @Column(name = "private_key", nullable = false, columnDefinition = "TEXT")
    private String privateKey;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Status status;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "retired_at")
    private Instant retiredAt;

    protected SigningKey() {
    }

    public SigningKey(String kid, String publicKey, String privateKey, Status status) {
        this.kid = kid;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.status = status;
    }

    public UUID getId() { return id; }

    public String getKid() { return kid; }

    public String getPublicKey() { return publicKey; }

    public String getPrivateKey() { return privateKey; }

    public Status getStatus() { return status; }

    public void retire() {
        this.status = Status.RETIRING;
        this.retiredAt = Instant.now();
    }

    public Instant getCreatedAt() { return createdAt; }

    public Instant getRetiredAt() { return retiredAt; }
}
