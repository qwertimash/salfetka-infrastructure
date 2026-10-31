-- Server-only issuance storage. B2 outbox remains pending until actual engine ACK.
CREATE TABLE nodes_vpn_installations (
 node_id uuid PRIMARY KEY REFERENCES nodes_registry(id),
 installation_id uuid NOT NULL UNIQUE,
 group_id uuid NOT NULL REFERENCES access_groups(id),
 enabled boolean NOT NULL,
 generation bigint NOT NULL DEFAULT 0 CHECK(generation BETWEEN 0 AND 9007199254740991),
 engine_epoch text CHECK(engine_epoch ~ '^[0-9a-f]{32}$'),
 projection_sha256 text CHECK(projection_sha256 ~ '^[0-9a-f]{64}$'),
 policy_expires_at timestamptz,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE nodes_vpn_policies (
 node_id uuid NOT NULL REFERENCES nodes_vpn_installations(node_id),
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 engine_epoch text NOT NULL CHECK(engine_epoch ~ '^[0-9a-f]{32}$'),
 policy_ciphertext bytea NOT NULL CHECK(octet_length(policy_ciphertext) BETWEEN 30 AND 131200),
 policy_sha256 text NOT NULL CHECK(policy_sha256 ~ '^[0-9a-f]{64}$'),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes'),
 PRIMARY KEY(node_id,generation)
);
CREATE TRIGGER nodes_vpn_policies_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON nodes_vpn_policies FOR EACH STATEMENT EXECUTE FUNCTION reject_node_control_snapshot_mutation();
ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK(action IN(
 'job.enqueued','job.succeeded','job.retry_scheduled','job.failed',
 'identity.bootstrap_prepared','identity.bootstrap_completed','identity.login_succeeded','identity.login_failed',
 'identity.logout','identity.sessions_revoked','identity.admin_created','identity.admin_updated',
 'access.user_created','access.user_state','access.entitlement_changed','access.block_added','access.block_cleared',
 'access.challenge_created','access.device_registered','access.device_revoked','access.credential_rotated','access.entitlement_expired',
 'node.created','node.enrollment_created','node.enrolled','node.revoked','node.command_created','node.command_recorded','node.certificate_renewed','node.vpn_configured','node.vpn_policy_issued'));
