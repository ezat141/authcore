-- M0 placeholder migration.
-- Real schema (users, clients, tenants) lands in M2.
-- Flyway requires at least one migration to be present on startup.
CREATE TABLE IF NOT EXISTS flyway_placeholder (id SERIAL PRIMARY KEY);
