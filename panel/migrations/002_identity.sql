CREATE TABLE identity_control (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    bootstrap_hash bytea CHECK (bootstrap_hash IS NULL OR octet_length(bootstrap_hash) = 32),
    bootstrap_expires_at timestamptz,
    bootstrap_consumed_at timestamptz,
    CHECK ((bootstrap_hash IS NULL) = (bootstrap_expires_at IS NULL))
);
INSERT INTO identity_control(singleton) VALUES (true);

CREATE TABLE admins (
    id uuid PRIMARY KEY,
    username text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9_.-]{2,63}$'),
    password_hash text NOT NULL,
    role text NOT NULL CHECK (role IN ('owner', 'access_operator', 'infrastructure_operator', 'support', 'auditor')),
    disabled boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE admin_sessions (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash) = 32),
    admin_id uuid NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    admin_revision bigint NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX admin_sessions_admin ON admin_sessions(admin_id);
CREATE INDEX admin_sessions_expiry ON admin_sessions(expires_at);

-- No raw IP, attempted username, password or bearer is retained here.
CREATE TABLE identity_rate_limits (
    bucket_hash bytea PRIMARY KEY CHECK (octet_length(bucket_hash) = 32),
    window_started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    attempts integer NOT NULL CHECK (attempts > 0 AND attempts <= 1000000)
);
CREATE INDEX identity_rate_limits_expiry ON identity_rate_limits(window_started_at);
