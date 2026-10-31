CREATE TABLE jobs (
    id uuid PRIMARY KEY,
    actor_id text NOT NULL CHECK (actor_id = 'system' OR actor_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    kind text NOT NULL CHECK (kind IN ('system.check')),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND payload = '{}'::jsonb),
    payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','succeeded','failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10 AND attempts <= max_attempts),
    worker_id text,
    lease_token uuid,
    lease_until timestamptz,
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    finished_at timestamptz,
    error_code text CHECK (error_code IN ('lease_expired','system_check_failed','worker_error')),
    UNIQUE (actor_id,kind,idempotency_key),
    CHECK ((status = 'running') = (worker_id IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL)),
    CHECK (status = 'running' OR (worker_id IS NULL AND lease_token IS NULL AND lease_until IS NULL)),
    CHECK ((status IN ('succeeded','failed')) = (finished_at IS NOT NULL)),
    CHECK (status <> 'failed' OR error_code IS NOT NULL)
);
CREATE INDEX jobs_claim_pending ON jobs (available_at,created_at,id) WHERE status = 'pending';
CREATE INDEX jobs_claim_expired ON jobs (lease_until,id) WHERE status = 'running';
CREATE INDEX jobs_history ON jobs (created_at DESC,id DESC);

CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    actor_id text NOT NULL CHECK (actor_id IN ('system','worker','anonymous') OR actor_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    action text NOT NULL CHECK (action IN (
        'job.enqueued','job.succeeded','job.retry_scheduled','job.failed',
        'identity.bootstrap_prepared','identity.bootstrap_completed','identity.login_succeeded',
        'identity.login_failed','identity.logout','identity.sessions_revoked',
        'identity.admin_created','identity.admin_updated')),
    target_id text NOT NULL CHECK (target_id = '' OR target_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    outcome text NOT NULL CHECK (outcome IN ('accepted','succeeded','failed')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX audit_events_history ON audit_events (created_at DESC,id DESC);
CREATE FUNCTION reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events_are_immutable' USING ERRCODE = '55000';
END;
$$;
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_mutation();

CREATE TABLE system_check_results (
    job_id uuid PRIMARY KEY REFERENCES jobs(id),
    schema_version integer NOT NULL CHECK (schema_version > 0),
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
