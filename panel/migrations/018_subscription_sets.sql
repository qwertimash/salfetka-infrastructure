-- Administrative composition only. Existing delivery IDs/tokens are untouched.
CREATE TABLE subscription_sets (
 id uuid PRIMARY KEY,
 draft_id uuid NOT NULL UNIQUE REFERENCES builder_drafts(id),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(id,draft_id)
);
CREATE TABLE subscription_set_versions (
 set_id uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000),
 draft_id uuid NOT NULL,
 draft_revision bigint NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(set_id,revision),
 FOREIGN KEY(set_id,draft_id) REFERENCES subscription_sets(id,draft_id),
 FOREIGN KEY(draft_id,draft_revision) REFERENCES builder_versions(draft_id,revision)
);
ALTER TABLE subscription_sets ADD FOREIGN KEY(id,revision)
 REFERENCES subscription_set_versions(set_id,revision) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE account_set_assignments (
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES access_users(id),
 set_id uuid NOT NULL REFERENCES subscription_sets(id),
 state text NOT NULL CHECK(state IN ('active','revoked')),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(user_id,set_id)
);
CREATE INDEX account_set_assignments_by_set ON account_set_assignments(set_id,id);
CREATE TABLE subscription_set_mutations (
 actor_id uuid NOT NULL,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
 result jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(actor_id,idempotency_key)
);
CREATE TRIGGER subscription_set_versions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON subscription_set_versions FOR EACH STATEMENT EXECUTE FUNCTION reject_catalog_version_mutation();
CREATE TRIGGER subscription_set_mutations_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON subscription_set_mutations FOR EACH STATEMENT EXECUTE FUNCTION reject_catalog_version_mutation();

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
 'subscription_set.save','subscription_set.assign','subscription_set.unassign'));
