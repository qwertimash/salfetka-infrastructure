CREATE TABLE infrastructure_servers (
 id uuid PRIMARY KEY,
 name text NOT NULL CHECK(length(name) BETWEEN 2 AND 80),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE nodes_registry ADD COLUMN server_id uuid REFERENCES infrastructure_servers(id);
CREATE INDEX nodes_registry_server ON nodes_registry(server_id,id);
CREATE TABLE nodes_vpn_config_versions (
 node_id uuid NOT NULL REFERENCES nodes_registry(id),
 revision bigint NOT NULL CHECK(revision>0),
 body_ciphertext bytea NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(node_id,revision)
);
CREATE TRIGGER nodes_vpn_config_versions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON nodes_vpn_config_versions FOR EACH STATEMENT EXECUTE FUNCTION reject_catalog_version_mutation();

ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK(action IN(
 'job.enqueued','job.succeeded','job.retry_scheduled','job.failed',
 'identity.bootstrap_prepared','identity.bootstrap_completed','identity.login_succeeded','identity.login_failed',
 'identity.logout','identity.sessions_revoked','identity.admin_created','identity.admin_updated',
 'access.user_created','access.user_state','access.entitlement_changed','access.block_added','access.block_cleared',
 'access.challenge_created','access.device_registered','access.device_revoked','access.credential_rotated','access.entitlement_expired',
 'node.created','node.enrollment_created','node.enrolled','node.revoked','node.command_created','node.command_recorded','node.certificate_renewed','node.vpn_configured','node.vpn_policy_issued','access.vpn_config_exported',
 'source.create','source.accept','source.refresh','source.pause','source.refreshed',
 'builder.save','subscription.stage','subscription.publish','subscription.check','subscription.rollback','subscription.rotate','subscription.revoke','subscription.link',
 'infrastructure.server_created','access.invite_created','subscription_set.save','subscription_set.assign','subscription_set.unassign','subscription_set.publish','subscription_set.link'));
