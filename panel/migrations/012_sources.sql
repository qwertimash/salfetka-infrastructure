CREATE TABLE catalog_sources (
 id uuid PRIMARY KEY,
 name text NOT NULL CHECK(length(name) BETWEEN 2 AND 80),
 kind text NOT NULL CHECK(kind IN ('upload','url')),
 url_ciphertext bytea,
 revision bigint NOT NULL DEFAULT 1 CHECK(revision > 0),
 current_version uuid,
 candidate_version uuid,
 paused boolean NOT NULL DEFAULT false,
 error_code text,
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 16),
 next_fetch_at timestamptz,
 lease_id uuid,
 lease_until timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((kind='url')=(url_ciphertext IS NOT NULL)),
 CHECK((lease_id IS NULL)=(lease_until IS NULL))
);
CREATE TABLE catalog_versions (
 id uuid PRIMARY KEY,
 source_id uuid NOT NULL REFERENCES catalog_sources(id),
 body_ciphertext bytea NOT NULL,
 preview jsonb NOT NULL,
 digest text NOT NULL CHECK(length(digest)=64),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(source_id,id)
);
ALTER TABLE catalog_sources ADD FOREIGN KEY(id,current_version) REFERENCES catalog_versions(source_id,id);
ALTER TABLE catalog_sources ADD FOREIGN KEY(id,candidate_version) REFERENCES catalog_versions(source_id,id);
CREATE INDEX catalog_refresh_due ON catalog_sources(next_fetch_at) WHERE kind='url' AND NOT paused;
CREATE TABLE catalog_drafts (
 id uuid PRIMARY KEY,
 actor_id uuid NOT NULL,
 body_ciphertext bytea NOT NULL,
 preview jsonb NOT NULL,
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '15 minutes',
 source_id uuid REFERENCES catalog_sources(id)
);
CREATE TABLE catalog_mutations (
 actor_id uuid NOT NULL,
 idempotency_key text NOT NULL,
 request_hash bytea NOT NULL,
 result jsonb NOT NULL,
 PRIMARY KEY(actor_id,idempotency_key)
);
CREATE FUNCTION reject_catalog_version_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'catalog_versions_are_immutable' USING ERRCODE='55000'; END;
$$;
CREATE TRIGGER catalog_versions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON catalog_versions FOR EACH STATEMENT EXECUTE FUNCTION reject_catalog_version_mutation();
CREATE TRIGGER catalog_mutations_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON catalog_mutations FOR EACH STATEMENT EXECUTE FUNCTION reject_catalog_version_mutation();

ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK(action IN(
 'job.enqueued','job.succeeded','job.retry_scheduled','job.failed',
 'identity.bootstrap_prepared','identity.bootstrap_completed','identity.login_succeeded','identity.login_failed',
 'identity.logout','identity.sessions_revoked','identity.admin_created','identity.admin_updated',
 'access.user_created','access.user_state','access.entitlement_changed','access.block_added','access.block_cleared',
 'access.challenge_created','access.device_registered','access.device_revoked','access.credential_rotated','access.entitlement_expired',
 'node.created','node.enrollment_created','node.enrolled','node.revoked','node.command_created','node.command_recorded','node.certificate_renewed','node.vpn_configured','node.vpn_policy_issued','access.vpn_config_exported','source.create','source.accept','source.refresh','source.pause','source.refreshed'));
