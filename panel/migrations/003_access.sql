CREATE TABLE access_groups (
 id uuid PRIMARY KEY, name text NOT NULL CHECK(length(name) BETWEEN 1 AND 80), enabled boolean NOT NULL DEFAULT true
);
INSERT INTO access_groups(id,name) VALUES('00000000-0000-4000-8000-000000000001','Основная');
CREATE TABLE access_users (
 id uuid PRIMARY KEY, name text NOT NULL CHECK(length(name) BETWEEN 2 AND 80),
 state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','suspended','deleted')),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0), policy_epoch bigint NOT NULL DEFAULT 1 CHECK(policy_epoch>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX access_users_history ON access_users(created_at DESC,id DESC);
CREATE TABLE access_entitlements (
 user_id uuid PRIMARY KEY REFERENCES access_users(id), state text NOT NULL CHECK(state IN ('active','expired','revoked','refunded')),
 expires_at timestamptz NOT NULL, device_limit integer NOT NULL CHECK(device_limit BETWEEN 1 AND 100),
 group_id uuid NOT NULL REFERENCES access_groups(id), quota_bytes bigint CHECK(quota_bytes>0 AND quota_bytes<=1000000000000000),
 revision bigint NOT NULL CHECK(revision>0)
);
CREATE INDEX access_entitlements_expiring ON access_entitlements(expires_at,user_id) WHERE state='active';
CREATE TABLE access_devices (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES access_users(id), name text NOT NULL CHECK(length(name) BETWEEN 2 AND 80),
 state text NOT NULL CHECK(state IN ('registered','revoked')), public_key bytea NOT NULL UNIQUE CHECK(octet_length(public_key)=32),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(user_id,id)
);
CREATE INDEX access_devices_owner ON access_devices(user_id,id);
CREATE TABLE access_credentials (
 id uuid PRIMARY KEY, user_id uuid NOT NULL, device_id uuid NOT NULL,
 version bigint NOT NULL CHECK(version>0), state text NOT NULL CHECK(state IN ('active','revoked')),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext)>32), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(user_id,device_id) REFERENCES access_devices(user_id,id), UNIQUE(device_id,version)
);
CREATE UNIQUE INDEX access_credentials_active ON access_credentials(device_id) WHERE state='active';
CREATE TABLE access_blocks (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES access_users(id), scope text NOT NULL CHECK(scope IN ('user','device')),
 device_id uuid, reason text NOT NULL CHECK(reason IN ('policy','abuse','security','manual')),
 active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), cleared_at timestamptz,
 CHECK((scope='user' AND device_id IS NULL) OR (scope='device' AND device_id IS NOT NULL)),
 CHECK(active=(cleared_at IS NULL)), FOREIGN KEY(user_id,device_id) REFERENCES access_devices(user_id,id)
);
CREATE UNIQUE INDEX access_blocks_one_user ON access_blocks(user_id) WHERE active AND scope='user';
CREATE UNIQUE INDEX access_blocks_one_device ON access_blocks(device_id) WHERE active AND scope='device';
CREATE TABLE access_challenges (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES access_users(id), public_key bytea NOT NULL CHECK(octet_length(public_key)=32),
 signing_message text NOT NULL CHECK(length(signing_message)<1024), expires_at timestamptz NOT NULL, used_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX access_challenges_owner ON access_challenges(user_id,created_at);
CREATE TABLE access_mutations (
 actor_id uuid NOT NULL, route text NOT NULL CHECK(length(route) BETWEEN 1 AND 200), target_id text NOT NULL,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32), result jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(actor_id,route,target_id,idempotency_key)
);
CREATE TABLE access_outbox (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES access_users(id), revision bigint NOT NULL CHECK(revision>0),
 policy_epoch bigint NOT NULL CHECK(policy_epoch>0), kind text NOT NULL CHECK(kind IN ('access.reconcile')),
 status text NOT NULL DEFAULT 'pending' CHECK(status='pending'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(user_id,revision)
);
-- No agent ACK exists in B2. Pending intent must never be interpreted as applied.
ALTER TABLE audit_events DROP CONSTRAINT audit_events_action_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_check CHECK(action IN (
 'job.enqueued','job.succeeded','job.retry_scheduled','job.failed',
 'identity.bootstrap_prepared','identity.bootstrap_completed','identity.login_succeeded','identity.login_failed',
 'identity.logout','identity.sessions_revoked','identity.admin_created','identity.admin_updated',
 'access.user_created','access.user_state','access.entitlement_changed','access.block_added','access.block_cleared',
 'access.challenge_created','access.device_registered','access.device_revoked','access.credential_rotated','access.entitlement_expired'));
CREATE TABLE access_key_state (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), encrypted_check bytea NOT NULL
);
