-- Amnezia Web Panel — PostgreSQL 17 schema

CREATE TABLE IF NOT EXISTS servers (
    position INTEGER PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    ssh_port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL DEFAULT '',
    password TEXT,
    private_key TEXT,
    server_info JSONB NOT NULL DEFAULT '{}'::jsonb,
    protocols JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ,
    telegram_id TEXT,
    email TEXT,
    description TEXT,
    traffic_limit BIGINT NOT NULL DEFAULT 0,
    traffic_used BIGINT NOT NULL DEFAULT 0,
    traffic_total BIGINT NOT NULL DEFAULT 0,
    traffic_reset_strategy TEXT NOT NULL DEFAULT 'never',
    last_reset_at TIMESTAMPTZ,
    expiration_date TIMESTAMPTZ,
    expire_after_first_use BOOLEAN NOT NULL DEFAULT FALSE,
    expiration_days INTEGER NOT NULL DEFAULT 0,
    remnawave_uuid TEXT,
    xui_email TEXT,
    share_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    share_token TEXT,
    share_password_hash TEXT
);

CREATE TABLE IF NOT EXISTS user_connections (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT '',
    client_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    xui_panel_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ,
    last_bytes BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_user_connections_user_id ON user_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_user_connections_server_id ON user_connections(server_id);

CREATE TABLE IF NOT EXISTS api_tokens (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL DEFAULT '',
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);

CREATE TABLE IF NOT EXISTS settings (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    data JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS tunnel_state (
    provider TEXT PRIMARY KEY,
    data JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS invite_links (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    token TEXT NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    max_uses INTEGER NOT NULL DEFAULT 1,
    used_count INTEGER NOT NULL DEFAULT 0,
    user_id UUID,
    protocol TEXT NOT NULL DEFAULT 'awg',
    server_id INTEGER NOT NULL DEFAULT 0,
    xui_inbound_id INTEGER NOT NULL DEFAULT 0,
    xui_panel_id TEXT NOT NULL DEFAULT '',
    password_hash TEXT,
    expires_at TIMESTAMPTZ,
    duration_days INTEGER NOT NULL DEFAULT 0,
    note TEXT,
    created_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_invite_links_token ON invite_links(token);

INSERT INTO settings (id, data) VALUES (1, '{}'::jsonb)
ON CONFLICT (id) DO NOTHING;
