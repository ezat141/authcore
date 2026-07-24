package com.authcore.token;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;

import java.util.List;
import java.util.Optional;

/**
 * Persistence for refresh-token rotation lineage.
 *
 * <p>Tokens are stored as SHA-256 hashes — a leaked database must not hand an
 * attacker usable refresh tokens.
 */
public class RefreshTokenFamilyStore {

    private static final RowMapper<RefreshTokenRecord> ROW_MAPPER = (rs, rowNum) -> new RefreshTokenRecord(
            rs.getString("token_hash"),
            rs.getString("family_id"),
            rs.getString("authorization_id"),
            rs.getString("principal_name"),
            rs.getBoolean("consumed"));

    private final JdbcOperations jdbc;

    public RefreshTokenFamilyStore(JdbcOperations jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<RefreshTokenRecord> findByTokenHash(String tokenHash) {
        List<RefreshTokenRecord> results = jdbc.query(
                "SELECT * FROM refresh_token_family WHERE token_hash = ?", ROW_MAPPER, tokenHash);
        return results.stream().findFirst();
    }

    public Optional<String> findFamilyIdByAuthorizationId(String authorizationId) {
        List<String> results = jdbc.queryForList(
                "SELECT family_id FROM refresh_token_family WHERE authorization_id = ? LIMIT 1",
                String.class, authorizationId);
        return results.stream().findFirst();
    }

    public List<String> findAuthorizationIds(String familyId) {
        return jdbc.queryForList(
                "SELECT DISTINCT authorization_id FROM refresh_token_family WHERE family_id = ?",
                String.class, familyId);
    }

    public void record(String tokenHash, String familyId, String authorizationId, String principalName) {
        jdbc.update("""
                INSERT INTO refresh_token_family (token_hash, family_id, authorization_id, principal_name)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (token_hash) DO NOTHING
                """, tokenHash, familyId, authorizationId, principalName);
    }

    /** Marks every earlier refresh token of this authorization as spent, keeping only the newest live. */
    public void markSupersededAsConsumed(String authorizationId, String currentTokenHash) {
        jdbc.update(
                "UPDATE refresh_token_family SET consumed = TRUE WHERE authorization_id = ? AND token_hash <> ?",
                authorizationId, currentTokenHash);
    }

    public void deleteFamily(String familyId) {
        jdbc.update("DELETE FROM refresh_token_family WHERE family_id = ?", familyId);
    }
}
