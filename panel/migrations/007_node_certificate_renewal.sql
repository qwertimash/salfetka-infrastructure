-- Renewal keeps the old certificate valid only until its original NotAfter.
-- Immutable per-parent issuance makes lost-response retries deadline preserving.
CREATE TABLE nodes_certificate_renewals (
 node_id uuid NOT NULL REFERENCES nodes_registry(id),
 previous_serial text NOT NULL,
 previous_expires_at timestamptz NOT NULL,
 serial text NOT NULL UNIQUE,
 expires_at timestamptz NOT NULL,
 csr_hash bytea NOT NULL CHECK(octet_length(csr_hash)=32),
 response text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(node_id,previous_serial),
 CHECK(expires_at>previous_expires_at), CHECK(serial<>previous_serial)
);
CREATE TRIGGER nodes_certificate_renewals_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON nodes_certificate_renewals FOR EACH STATEMENT EXECUTE FUNCTION reject_node_control_snapshot_mutation();
ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK(action IN(
 'job.enqueued','job.succeeded','job.retry_scheduled','job.failed',
 'identity.bootstrap_prepared','identity.bootstrap_completed','identity.login_succeeded','identity.login_failed',
 'identity.logout','identity.sessions_revoked','identity.admin_created','identity.admin_updated',
 'access.user_created','access.user_state','access.entitlement_changed','access.block_added','access.block_cleared',
 'access.challenge_created','access.device_registered','access.device_revoked','access.credential_rotated','access.entitlement_expired',
 'node.created','node.enrollment_created','node.enrolled','node.revoked','node.command_created','node.command_recorded','node.certificate_renewed'));
