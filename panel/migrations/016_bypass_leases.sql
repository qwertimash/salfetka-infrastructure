-- Inactive C1 foundation. No existing VPN policy/credential is changed.
CREATE TABLE bypass_accounts (
 user_id uuid PRIMARY KEY REFERENCES access_users(id),
 generation bigint NOT NULL DEFAULT 0 CHECK(generation BETWEEN 0 AND 9007199254740991),
 clock_watermark timestamptz NOT NULL
);
CREATE TABLE bypass_leases (
 user_id uuid NOT NULL REFERENCES bypass_accounts(user_id),
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 request_id uuid NOT NULL,
 device_id uuid NOT NULL,
 credential_id uuid NOT NULL REFERENCES access_credentials(id),
 node_id uuid NOT NULL REFERENCES nodes_registry(id),
 installation_id uuid NOT NULL,
 engine_epoch text NOT NULL CHECK(engine_epoch ~ '^[0-9a-f]{32}$'),
 state text NOT NULL CHECK(state IN('pending','active','draining','replaced','closed')),
 reason text NOT NULL DEFAULT '' CHECK(reason IN('','session_replaced','session_closed')),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision BETWEEN 1 AND 9007199254740991),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>created_at),
 PRIMARY KEY(user_id,generation), UNIQUE(user_id,request_id),
 FOREIGN KEY(user_id,device_id) REFERENCES access_devices(user_id,id),
 CHECK((state IN('draining','replaced'))=(reason='session_replaced')),
 CHECK((state='closed')=(reason='session_closed'))
);
-- A draining lease remains a blocker even after its timestamp expires.
CREATE UNIQUE INDEX bypass_one_blocker ON bypass_leases(user_id) WHERE state IN('active','draining');
CREATE UNIQUE INDEX bypass_one_pending ON bypass_leases(user_id) WHERE state='pending';
CREATE INDEX bypass_node_drain ON bypass_leases(node_id,installation_id,engine_epoch) WHERE state='draining';
