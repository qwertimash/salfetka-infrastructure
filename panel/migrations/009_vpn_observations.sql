-- Applied receipts and cumulative snapshots are distinct from desired policies.
CREATE TABLE nodes_vpn_receipts (
 node_id uuid NOT NULL,
 generation bigint NOT NULL,
 body text NOT NULL CHECK(octet_length(body) <= 65536),
 body_sha256 bytea NOT NULL CHECK(octet_length(body_sha256)=32),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(node_id,generation),
 FOREIGN KEY(node_id,generation) REFERENCES nodes_vpn_policies(node_id,generation)
);
CREATE TRIGGER nodes_vpn_receipts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON nodes_vpn_receipts FOR EACH STATEMENT EXECUTE FUNCTION reject_node_control_snapshot_mutation();
CREATE TABLE nodes_vpn_observations (
 node_id uuid PRIMARY KEY REFERENCES nodes_vpn_installations(node_id),
 generation bigint NOT NULL,
 engine_epoch text NOT NULL CHECK(engine_epoch ~ '^[0-9a-f]{32}$'),
 sequence bigint NOT NULL CHECK(sequence BETWEEN 1 AND 9007199254740991),
 body text NOT NULL CHECK(octet_length(body) <= 131072),
 body_sha256 bytea NOT NULL CHECK(octet_length(body_sha256)=32),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(node_id,generation) REFERENCES nodes_vpn_receipts(node_id,generation)
);
