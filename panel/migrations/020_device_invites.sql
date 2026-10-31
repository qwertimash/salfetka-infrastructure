-- One-time onboarding authorization, separate from permanent assignment URLs.
CREATE TABLE access_device_invites (
 id uuid PRIMARY KEY,
 assignment_id uuid NOT NULL REFERENCES account_set_assignments(id),
 assignment_revision bigint NOT NULL CHECK (assignment_revision > 0),
 user_id uuid NOT NULL REFERENCES access_users(id),
 actor_id uuid NOT NULL,
 idempotency_key text NOT NULL,
 token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash)=32),
 token_ciphertext bytea NOT NULL,
 expires_at timestamptz NOT NULL,
 device_id uuid REFERENCES access_devices(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(actor_id,idempotency_key)
);
CREATE INDEX access_device_invites_user ON access_device_invites(user_id,expires_at);

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
 'access.invite_created','subscription_set.save','subscription_set.assign','subscription_set.unassign','subscription_set.publish','subscription_set.link'));
