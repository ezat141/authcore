-- API keys for machine callers that are not OAuth2 clients (CI jobs, internal
-- services, scripts). These skip the token dance entirely: one long-lived
-- credential presented on every request.
--
-- Stored as SHA-256 rather than bcrypt. Passwords need a slow hash because they
-- are low-entropy and guessable; an API key here is 32 random bytes, so brute
-- force is not the threat model and we need an indexed O(1) lookup by hash.
CREATE TABLE api_keys (
    id           UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(100)  NOT NULL,
    key_hash     VARCHAR(64)   NOT NULL UNIQUE,
    -- First few chars of the key, kept in clear so a human can identify which
    -- key a log line refers to without the key itself being recoverable.
    key_prefix   VARCHAR(16)   NOT NULL,
    scopes       VARCHAR(1000) NOT NULL DEFAULT '',
    enabled      BOOLEAN       NOT NULL DEFAULT TRUE,
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_key_hash ON api_keys (key_hash);
