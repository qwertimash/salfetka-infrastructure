CREATE TABLE builder_drafts (
 id uuid PRIMARY KEY,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE builder_versions (
 draft_id uuid NOT NULL REFERENCES builder_drafts(id),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000),
 body_ciphertext bytea NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(draft_id,revision)
);
CREATE TABLE builder_mutations (
 actor_id uuid NOT NULL,
 idempotency_key text NOT NULL,
 request_hash bytea NOT NULL,
 draft_id uuid NOT NULL,
 revision bigint NOT NULL,
 PRIMARY KEY(actor_id,idempotency_key),
 FOREIGN KEY(draft_id,revision) REFERENCES builder_versions(draft_id,revision)
);
CREATE TRIGGER builder_versions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON builder_versions FOR EACH STATEMENT EXECUTE FUNCTION reject_catalog_version_mutation();
CREATE TRIGGER builder_mutations_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON builder_mutations FOR EACH STATEMENT EXECUTE FUNCTION reject_catalog_version_mutation();
ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK(action IN(
 'job.enqueued','job.succeeded','job.retry_scheduled','job.failed',
 'identity.bootstrap_prepared','identity.bootstrap_completed','identity.login_succeeded','identity.login_failed',
 'identity.logout','identity.sessions_revoked','identity.admin_created','identity.admin_updated',
 'access.user_created','access.user_state','access.entitlement_changed','access.block_added','access.block_cleared',
 'access.challenge_created','access.device_registered','access.device_revoked','access.credential_rotated','access.entitlement_expired',
 'node.created','node.enrollment_created','node.enrolled','node.revoked','node.command_created','node.command_recorded','node.certificate_renewed','node.vpn_configured','node.vpn_policy_issued','access.vpn_config_exported',
 'source.create','source.accept','source.refresh','source.pause','source.refreshed',
 'builder.save','subscription.stage','subscription.publish','subscription.check','subscription.rollback','subscription.rotate','subscription.revoke','subscription.link'));
