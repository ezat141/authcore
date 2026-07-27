-- Replaces the flat user_authorities string set with real RBAC.
--
-- The flat model could not answer "which users can write payments?" without a
-- string scan, and granting a new capability meant editing every user's row.
-- Users get roles; roles carry permissions; permissions are what code checks.
CREATE TABLE roles (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(50)  NOT NULL UNIQUE,
    description VARCHAR(255)
);

CREATE TABLE permissions (
    id          UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(100)  NOT NULL UNIQUE,
    description VARCHAR(255)
);

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id)       ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Carry existing assignments across rather than dropping them on the floor.
INSERT INTO roles (name, description)
SELECT DISTINCT authority, 'Migrated from user_authorities'
FROM user_authorities
WHERE authority LIKE 'ROLE_%'
ON CONFLICT (name) DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT ua.user_id, r.id
FROM user_authorities ua
JOIN roles r ON r.name = ua.authority
WHERE ua.authority LIKE 'ROLE_%'
ON CONFLICT DO NOTHING;

DROP TABLE user_authorities;
