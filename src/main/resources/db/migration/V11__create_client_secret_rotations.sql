-- Lets a client secret be replaced without an outage.
--
-- Rotating in place is atomic on the server and emphatically not atomic in the
-- fleet: the instant the new secret is stored, every deployed instance still
-- holding the old one starts failing authentication. In practice that means a
-- secret is rotated only during a maintenance window, or -- far more often --
-- never, which is the outcome rotation was supposed to prevent.
--
-- Keeping the previous secret valid for a while turns rotation into two
-- independent steps: rotate now, redeploy the clients at leisure, and the old
-- secret lapses on its own.
--
-- A separate table rather than extra columns on oauth2_registered_client: that
-- table's shape is defined by Spring's JdbcRegisteredClientRepository, which
-- reads and writes a fixed column list. Anything added there would be ignored
-- on save and silently lost on the next update.
CREATE TABLE client_secret_rotations (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       VARCHAR(100) NOT NULL,
    -- Hashed, exactly like the live secret. An expiring credential is still a
    -- credential while it lasts.
    previous_secret VARCHAR(200) NOT NULL,
    rotated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ  NOT NULL
);

CREATE INDEX idx_client_secret_rotations_lookup
    ON client_secret_rotations (client_id, expires_at);
