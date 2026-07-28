package com.authcore.client;

import org.springframework.jdbc.core.JdbcOperations;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

/**
 * Persistence for superseded client secrets that are still briefly accepted.
 */
public class ClientSecretRotationStore {

    private final JdbcOperations jdbc;

    public ClientSecretRotationStore(JdbcOperations jdbc) {
        this.jdbc = jdbc;
    }

    public void record(String clientId, String previousSecretHash, Instant expiresAt) {
        jdbc.update("""
                INSERT INTO client_secret_rotations (client_id, previous_secret, expires_at)
                VALUES (?, ?, ?)
                """, clientId, previousSecretHash, Timestamp.from(expiresAt));
    }

    /** Only unexpired entries; a lapsed secret must never be offered for comparison. */
    public List<String> findAcceptedPreviousSecrets(String clientId) {
        return jdbc.queryForList("""
                SELECT previous_secret FROM client_secret_rotations
                WHERE client_id = ? AND expires_at > NOW()
                """, String.class, clientId);
    }

    public int purgeExpired() {
        return jdbc.update("DELETE FROM client_secret_rotations WHERE expires_at <= NOW()");
    }

    /** Ends the overlap early — the move after a secret is known to have leaked. */
    public int revokePreviousSecrets(String clientId) {
        return jdbc.update("DELETE FROM client_secret_rotations WHERE client_id = ?", clientId);
    }
}
