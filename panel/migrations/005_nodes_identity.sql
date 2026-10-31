CREATE TABLE nodes_authority_state(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32));
CREATE TABLE nodes_registry(
 id uuid PRIMARY KEY,name text NOT NULL CHECK(length(name) BETWEEN 2 AND 80),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN('pending','active','revoked')),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision BETWEEN 1 AND 9007199254740991),
 serial text UNIQUE,public_key bytea CHECK(octet_length(public_key)=32),certificate_expires_at timestamptz,
 current_boot_id uuid,last_seen_at timestamptz,inventory jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((serial IS NULL)=(public_key IS NULL)),CHECK((serial IS NULL)=(certificate_expires_at IS NULL)),
 CHECK(state<>'active' OR serial IS NOT NULL),CHECK((last_seen_at IS NULL)=(inventory IS NULL))
);
CREATE INDEX nodes_registry_history ON nodes_registry(created_at DESC,id DESC);
CREATE TABLE nodes_enrollments(
 id uuid PRIMARY KEY,node_id uuid NOT NULL REFERENCES nodes_registry(id),
 token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),expires_at timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false,used_at timestamptz,request_id uuid,csr_hash bytea CHECK(octet_length(csr_hash)=32),certificate_response jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),CHECK((used_at IS NULL)=(certificate_response IS NULL)),CHECK((used_at IS NULL)=(request_id IS NULL)),CHECK((used_at IS NULL)=(csr_hash IS NULL))
);
CREATE INDEX nodes_enrollments_owner ON nodes_enrollments(node_id,created_at);
CREATE TABLE nodes_admin_mutations(
 actor_id uuid NOT NULL,route text NOT NULL,target_id text NOT NULL,idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),result_ciphertext bytea NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(actor_id,route,target_id,idempotency_key)
);
CREATE TABLE nodes_heartbeat_boots(
 node_id uuid NOT NULL REFERENCES nodes_registry(id),boot_id uuid NOT NULL,
 sequence bigint NOT NULL CHECK(sequence BETWEEN 1 AND 9007199254740991),request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),response jsonb NOT NULL,
 PRIMARY KEY(node_id,boot_id)
);
ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK(action IN(
 'job.enqueued','job.succeeded','job.retry_scheduled','job.failed',
 'identity.bootstrap_prepared','identity.bootstrap_completed','identity.login_succeeded','identity.login_failed',
 'identity.logout','identity.sessions_revoked','identity.admin_created','identity.admin_updated',
 'access.user_created','access.user_state','access.entitlement_changed','access.block_added','access.block_cleared',
 'access.challenge_created','access.device_registered','access.device_revoked','access.credential_rotated','access.entitlement_expired',
 'node.created','node.enrollment_created','node.enrolled','node.revoked'));
