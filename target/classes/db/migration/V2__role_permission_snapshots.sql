-- Local read-model of role -> permission mappings, synchronized from user-service
-- via RabbitMQ. Lets auth-service compute effective permissions when issuing tokens.

CREATE TABLE role_permission_snapshots (
    id              uuid PRIMARY KEY,
    role_code       VARCHAR(50)  NOT NULL,
    permission_code VARCHAR(100) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      uuid,
    updated_at      TIMESTAMPTZ,
    updated_by      uuid,
    version         BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uk_role_perm_snapshot UNIQUE (role_code, permission_code)
);
CREATE INDEX idx_role_perm_snapshot_role ON role_permission_snapshots (role_code);