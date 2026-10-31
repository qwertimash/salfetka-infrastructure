ALTER TABLE account_set_assignments ADD UNIQUE(id,user_id);
ALTER TABLE account_set_assignments ADD COLUMN token_hash bytea UNIQUE;
ALTER TABLE account_set_assignments ADD COLUMN token_ciphertext bytea;
ALTER TABLE account_set_assignments ADD CHECK((token_hash IS NULL)=(token_ciphertext IS NULL));
ALTER TABLE account_set_assignments ADD CHECK(token_hash IS NULL OR octet_length(token_hash)=32);
ALTER TABLE subscriptions ADD COLUMN assignment_id uuid;
ALTER TABLE subscriptions ADD COLUMN assignment_revision bigint;
ALTER TABLE subscriptions ADD CHECK((assignment_id IS NULL)=(assignment_revision IS NULL));
ALTER TABLE subscriptions ADD FOREIGN KEY(assignment_id,user_id) REFERENCES account_set_assignments(id,user_id);
ALTER TABLE subscriptions DROP CONSTRAINT subscriptions_device_id_key;
CREATE UNIQUE INDEX subscriptions_legacy_device ON subscriptions(device_id) WHERE assignment_id IS NULL;
CREATE UNIQUE INDEX subscriptions_assigned_device ON subscriptions(assignment_id,assignment_revision,device_id) WHERE assignment_id IS NOT NULL;

CREATE TABLE set_publications (
 id uuid PRIMARY KEY, set_id uuid NOT NULL, revision bigint NOT NULL,
 actor_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(set_id,revision) REFERENCES subscription_set_versions(set_id,revision),
 UNIQUE(set_id,revision), UNIQUE(set_id,id)
);
ALTER TABLE subscription_sets ADD COLUMN published_id uuid;
ALTER TABLE subscription_sets ADD FOREIGN KEY(id,published_id) REFERENCES set_publications(set_id,id);
CREATE TABLE set_publication_targets (
 publication_id uuid NOT NULL REFERENCES set_publications(id),
 assignment_id uuid NOT NULL, assignment_revision bigint NOT NULL,
 user_id uuid NOT NULL, device_id uuid NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','retry','published','cancelled')),
 attempts bigint NOT NULL DEFAULT 0,
 next_attempt timestamptz NOT NULL DEFAULT clock_timestamp(),
 last_code text NOT NULL DEFAULT '',
 access_revision bigint NOT NULL DEFAULT 0,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(publication_id,assignment_id,assignment_revision,device_id),
 FOREIGN KEY(assignment_id,user_id) REFERENCES account_set_assignments(id,user_id),
 FOREIGN KEY(user_id,device_id) REFERENCES access_devices(user_id,id)
);
CREATE INDEX set_targets_due ON set_publication_targets(next_attempt) WHERE state IN ('pending','retry');
CREATE TRIGGER set_publications_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON set_publications FOR EACH STATEMENT EXECUTE FUNCTION reject_catalog_version_mutation();
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
 'subscription_set.save','subscription_set.assign','subscription_set.unassign','subscription_set.publish','subscription_set.link'));
