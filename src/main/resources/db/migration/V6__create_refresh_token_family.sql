-- Tracks the rotation lineage of refresh tokens so that replaying a token we
-- already consumed can be recognised as theft rather than an ordinary bad token.
--
-- SAS overwrites the refresh token on the authorization row when it rotates, so
-- the old value is gone by the time an attacker replays it. Keeping our own
-- hashed record is what makes reuse detection possible at all.
CREATE TABLE refresh_token_family (
    token_hash       VARCHAR(64)  PRIMARY KEY,
    family_id        VARCHAR(36)  NOT NULL,
    authorization_id VARCHAR(100) NOT NULL,
    principal_name   VARCHAR(200) NOT NULL,
    consumed         BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_token_family_family ON refresh_token_family (family_id);
CREATE INDEX idx_refresh_token_family_auth   ON refresh_token_family (authorization_id);
