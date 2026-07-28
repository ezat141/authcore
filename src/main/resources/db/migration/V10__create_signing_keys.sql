-- Signing keys outlive the process.
--
-- Until now the RSA pair was generated at startup, so every restart silently
-- invalidated every token already in the wild: same issuer, same claims, but no
-- key left that could verify the signature.
--
-- Rotation needs two live keys at once. A key stops signing the moment it is
-- retired, but tokens it already signed stay valid until they expire, so its
-- public half must remain published. That overlap is what makes rotation a
-- non-event rather than a mass logout.
CREATE TABLE signing_keys (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    kid         VARCHAR(64)  NOT NULL UNIQUE,
    public_key  TEXT         NOT NULL,
    -- PKCS#8, encrypted at rest. See KeyCipher.
    private_key TEXT         NOT NULL,
    status      VARCHAR(20)  NOT NULL CHECK (status IN ('ACTIVE', 'RETIRING')),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    retired_at  TIMESTAMPTZ
);

-- Exactly one key may sign at a time. Enforced here rather than in application
-- code because a second ACTIVE key is a correctness bug no caller could detect:
-- tokens would verify either way, and which key signed them would be a race.
CREATE UNIQUE INDEX idx_signing_keys_one_active
    ON signing_keys (status)
    WHERE status = 'ACTIVE';

CREATE INDEX idx_signing_keys_status ON signing_keys (status);
