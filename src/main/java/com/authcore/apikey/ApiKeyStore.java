package com.authcore.apikey;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.LinkedHashSet;
import java.util.Arrays;

public class ApiKeyStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final RowMapper<ApiKey> ROW_MAPPER = (rs, rowNum) -> new ApiKey(
            rs.getString("id"),
            rs.getString("name"),
            rs.getString("key_prefix"),
            parseScopes(rs.getString("scopes")),
            rs.getBoolean("enabled"),
            rs.getTimestamp("expires_at") == null ? null : rs.getTimestamp("expires_at").toInstant());

    private final JdbcOperations jdbc;

    public ApiKeyStore(JdbcOperations jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<ApiKey> findByRawKey(String rawKey) {
        List<ApiKey> results = jdbc.query(
                "SELECT * FROM api_keys WHERE key_hash = ?", ROW_MAPPER, sha256(rawKey));
        return results.stream().findFirst();
    }

    public boolean existsByName(String name) {
        Integer count = jdbc.queryForObject(
                "SELECT COUNT(*) FROM api_keys WHERE name = ?", Integer.class, name);
        return count != null && count > 0;
    }

    public void save(String name, String rawKey, Set<String> scopes, Instant expiresAt) {
        jdbc.update("""
                INSERT INTO api_keys (name, key_hash, key_prefix, scopes, expires_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (key_hash) DO NOTHING
                """,
                name,
                sha256(rawKey),
                rawKey.substring(0, Math.min(12, rawKey.length())),
                String.join(",", scopes),
                expiresAt == null ? null : java.sql.Timestamp.from(expiresAt));
    }

    public void touchLastUsed(String id) {
        jdbc.update("UPDATE api_keys SET last_used_at = NOW() WHERE id = ?::uuid", id);
    }

    /** Generates a key with an identifiable prefix — makes leaked keys greppable. */
    public static String generateKey() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return "ak_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static Set<String> parseScopes(String raw) {
        if (raw == null || raw.isBlank()) {
            return Set.of();
        }
        return new LinkedHashSet<>(Arrays.asList(raw.split(",")));
    }

    static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is required but unavailable", ex);
        }
    }
}
