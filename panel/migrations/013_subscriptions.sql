CREATE TABLE subscriptions (
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES access_users(id),
 device_id uuid NOT NULL UNIQUE,
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 next_release bigint NOT NULL DEFAULT 1 CHECK(next_release>0 AND next_release<=9007199254740991),
 active_release uuid,
 token_hash bytea UNIQUE,
 token_ciphertext bytea,
 token_revision bigint NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(user_id,device_id) REFERENCES access_devices(user_id,id),
 CHECK((token_hash IS NULL)=(token_ciphertext IS NULL)),
 CHECK(token_hash IS NULL OR octet_length(token_hash)=32)
);
CREATE TABLE subscription_releases (
 id uuid PRIMARY KEY,
 subscription_id uuid NOT NULL REFERENCES subscriptions(id),
 number bigint NOT NULL CHECK(number>0 AND number<=9007199254740991),
 base_revision bigint NOT NULL,
 access_revision bigint NOT NULL,
 policy_epoch bigint NOT NULL,
 credential_id uuid NOT NULL REFERENCES access_credentials(id),
 recipe_ciphertext bytea NOT NULL,
 artifact_ciphertext bytea NOT NULL,
 digest text NOT NULL CHECK(length(digest)=64),
 preview jsonb NOT NULL,
 provenance jsonb NOT NULL,
 rollback_of uuid REFERENCES subscription_releases(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(subscription_id,number), UNIQUE(subscription_id,id)
);
ALTER TABLE subscriptions ADD FOREIGN KEY(id,active_release) REFERENCES subscription_releases(subscription_id,id);
CREATE TABLE subscription_release_status (
 release_id uuid PRIMARY KEY REFERENCES subscription_releases(id),
 state text NOT NULL CHECK(state IN ('staged','partial','healthy','published')),
 checks jsonb NOT NULL DEFAULT '[]',
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE subscription_mutations (
 actor_id uuid NOT NULL,
 idempotency_key text NOT NULL,
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
 result jsonb NOT NULL,
 PRIMARY KEY(actor_id,idempotency_key)
);
CREATE TRIGGER subscription_releases_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON subscription_releases FOR EACH STATEMENT EXECUTE FUNCTION reject_catalog_version_mutation();
CREATE TRIGGER subscription_mutations_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON subscription_mutations FOR EACH STATEMENT EXECUTE FUNCTION reject_catalog_version_mutation();
ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK(action IN(
 'job.enqueued','job.succeeded','job.retry_scheduled','job.failed',
 'identity.bootstrap_prepared','identity.bootstrap_completed','identity.login_succeeded','identity.login_failed',
 'identity.logout','identity.sessions_revoked','identity.admin_created','identity.admin_updated',
 'access.user_created','access.user_state','access.entitlement_changed','access.block_added','access.block_cleared',
 'access.challenge_created','access.device_registered','access.device_revoked','access.credential_rotated','access.entitlement_expired',
 'node.created','node.enrollment_created','node.enrolled','node.revoked','node.command_created','node.command_recorded','node.certificate_renewed','node.vpn_configured','node.vpn_policy_issued','access.vpn_config_exported',
 'source.create','source.accept','source.refresh','source.pause','source.refreshed',
 'subscription.stage','subscription.publish','subscription.check','subscription.rollback','subscription.rotate','subscription.revoke','subscription.link'));
