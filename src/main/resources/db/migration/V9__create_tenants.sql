-- Multi-tenancy: many isolated organisations sharing one server.
--
-- Scoping choices, which are not all the same:
--   users  -> tenant-scoped. alice@acme and alice@globex are different people who
--             happen to share a username, so uniqueness moves to (tenant, username).
--   roles  -> tenant-scoped. Acme's ROLE_ADMIN must not grant anything at Globex,
--             so each tenant owns its own bundles.
--   permissions -> global. These are a capability vocabulary ("payments:write"),
--             not policy; every tenant draws from the same dictionary.
--   clients -> global. One SPA serving many tenants is the ordinary SaaS shape;
--             the tenant comes from who logs in, not from which app asked.
CREATE TABLE tenants (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    slug       VARCHAR(50)  NOT NULL UNIQUE,
    name       VARCHAR(100) NOT NULL,
    enabled    BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

INSERT INTO tenants (slug, name) VALUES
    ('default', 'Default Tenant'),
    ('acme',    'Acme Corporation');

-- Existing rows predate tenancy; they belong to 'default' so nothing breaks.
ALTER TABLE users ADD COLUMN tenant_id UUID REFERENCES tenants(id);
UPDATE users SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default');
ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_key;
ALTER TABLE users ADD CONSTRAINT users_tenant_username_key UNIQUE (tenant_id, username);
CREATE INDEX idx_users_tenant ON users (tenant_id);

ALTER TABLE roles ADD COLUMN tenant_id UUID REFERENCES tenants(id);
UPDATE roles SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default');
ALTER TABLE roles ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_name_key;
ALTER TABLE roles ADD CONSTRAINT roles_tenant_name_key UNIQUE (tenant_id, name);
CREATE INDEX idx_roles_tenant ON roles (tenant_id);
