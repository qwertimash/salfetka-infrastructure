CREATE TABLE nodes_signer_state(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32));
CREATE TABLE nodes_commands(
 operation_id uuid PRIMARY KEY,node_id uuid NOT NULL REFERENCES nodes_registry(id),
 authority_epoch bigint NOT NULL CHECK(authority_epoch=1),generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 body text NOT NULL CHECK(octet_length(body)<=4096),signature text NOT NULL,command_sha256 text NOT NULL,
 created_at timestamptz NOT NULL,deadline_at timestamptz NOT NULL,
 CHECK(deadline_at>created_at AND deadline_at<=created_at+interval '10 minutes'),UNIQUE(node_id,generation)
);
CREATE TABLE nodes_command_receipts(
 operation_id uuid PRIMARY KEY REFERENCES nodes_commands(operation_id),node_id uuid NOT NULL REFERENCES nodes_registry(id),
 generation bigint NOT NULL,body text NOT NULL,body_sha256 bytea NOT NULL CHECK(octet_length(body_sha256)=32),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(node_id,generation)
);
CREATE TABLE nodes_control_state(
 node_id uuid PRIMARY KEY REFERENCES nodes_registry(id),desired_generation bigint NOT NULL DEFAULT 0 CHECK(desired_generation>=0),
 observed_generation bigint NOT NULL DEFAULT 0 CHECK(observed_generation>=0),
 observed_operation_id uuid REFERENCES nodes_commands(operation_id),CHECK(observed_generation<=desired_generation)
);
CREATE TABLE nodes_control_mutations(
 actor_id uuid NOT NULL,route text NOT NULL,target_id uuid NOT NULL REFERENCES nodes_registry(id),idempotency_key text NOT NULL,
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),result_body text NOT NULL,
 PRIMARY KEY(actor_id,route,target_id,idempotency_key)
);
CREATE FUNCTION reject_node_control_snapshot_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'node_control_snapshots_are_immutable' USING ERRCODE='55000'; END;
$$;
CREATE TRIGGER nodes_commands_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON nodes_commands FOR EACH STATEMENT EXECUTE FUNCTION reject_node_control_snapshot_mutation();
CREATE TRIGGER nodes_command_receipts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON nodes_command_receipts FOR EACH STATEMENT EXECUTE FUNCTION reject_node_control_snapshot_mutation();
CREATE TRIGGER nodes_control_mutations_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON nodes_control_mutations FOR EACH STATEMENT EXECUTE FUNCTION reject_node_control_snapshot_mutation();
ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK(action IN(
 'job.enqueued','job.succeeded','job.retry_scheduled','job.failed',
 'identity.bootstrap_prepared','identity.bootstrap_completed','identity.login_succeeded','identity.login_failed',
 'identity.logout','identity.sessions_revoked','identity.admin_created','identity.admin_updated',
 'access.user_created','access.user_state','access.entitlement_changed','access.block_added','access.block_cleared',
 'access.challenge_created','access.device_registered','access.device_revoked','access.credential_rotated','access.entitlement_expired',
 'node.created','node.enrollment_created','node.enrolled','node.revoked','node.command_created','node.command_recorded'));
