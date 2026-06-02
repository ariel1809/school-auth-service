-- Auth service schema

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE auth_users (
    id                      uuid PRIMARY KEY,
    email                   VARCHAR(255) NOT NULL,
    password_hash           VARCHAR(100) NOT NULL,
    full_name               VARCHAR(200),
    enabled                 BOOLEAN NOT NULL DEFAULT TRUE,
    email_verified          BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enabled             BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret              VARCHAR(64),
    failed_login_attempts   INT NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    last_login_at           TIMESTAMPTZ,
    last_login_ip           VARCHAR(64),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by              uuid,
    updated_at              TIMESTAMPTZ,
    updated_by              uuid,
    version                 BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX uk_auth_users_email ON auth_users (LOWER(email));

CREATE TABLE refresh_tokens (
    id          uuid PRIMARY KEY,
    user_id     uuid NOT NULL,
    token_hash  VARCHAR(100) NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    user_agent  VARCHAR(500),
    ip_address  VARCHAR(64),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  uuid,
    updated_at  TIMESTAMPTZ,
    updated_by  uuid,
    version     BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uk_refresh_tokens_hash UNIQUE (token_hash),
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES auth_users (id) ON DELETE CASCADE
);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id);

CREATE TABLE password_reset_tokens (
    id          uuid PRIMARY KEY,
    user_id     uuid NOT NULL,
    token_hash  VARCHAR(100) NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  uuid,
    updated_at  TIMESTAMPTZ,
    updated_by  uuid,
    version     BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uk_password_reset_tokens_hash UNIQUE (token_hash),
    CONSTRAINT fk_password_reset_user FOREIGN KEY (user_id) REFERENCES auth_users (id) ON DELETE CASCADE
);
CREATE INDEX idx_password_reset_user ON password_reset_tokens (user_id);

CREATE TABLE user_role_snapshots (
    id          uuid PRIMARY KEY,
    user_id     uuid NOT NULL,
    role_code   VARCHAR(50) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  uuid,
    updated_at  TIMESTAMPTZ,
    updated_by  uuid,
    version     BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT uk_user_role_snapshot UNIQUE (user_id, role_code),
    CONSTRAINT fk_user_role_snapshot_user FOREIGN KEY (user_id) REFERENCES auth_users (id) ON DELETE CASCADE
);