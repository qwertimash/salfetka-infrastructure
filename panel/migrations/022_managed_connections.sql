-- Logical connection IDs reuse the existing policy/grant scope, never certificates.
-- Legacy physical node IDs and their URLs are not rewritten.
ALTER TABLE nodes_registry ADD COLUMN owner_node_id uuid REFERENCES nodes_registry(id);
ALTER TABLE nodes_registry DROP CONSTRAINT nodes_registry_check2;
ALTER TABLE nodes_registry ADD CONSTRAINT nodes_registry_active_identity CHECK(state<>'active' OR serial IS NOT NULL OR owner_node_id IS NOT NULL);
ALTER TABLE nodes_registry ADD CONSTRAINT nodes_registry_connection_identity CHECK(owner_node_id IS NULL OR (owner_node_id<>id AND server_id IS NOT NULL AND serial IS NULL AND public_key IS NULL AND certificate_expires_at IS NULL AND last_seen_at IS NULL AND inventory IS NULL AND state<>'pending'));
CREATE INDEX nodes_registry_owner ON nodes_registry(owner_node_id,id);
CREATE TABLE server_nodes (
 server_id uuid PRIMARY KEY REFERENCES infrastructure_servers(id),
 node_id uuid NOT NULL UNIQUE REFERENCES nodes_registry(id),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision BETWEEN 1 AND 9007199254740991)
);
CREATE FUNCTION guard_managed_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND (NEW.owner_node_id IS DISTINCT FROM OLD.owner_node_id OR (OLD.owner_node_id IS NOT NULL AND NEW.server_id IS DISTINCT FROM OLD.server_id)) THEN
  RAISE EXCEPTION 'immutable managed owner';
 END IF;
 IF NEW.owner_node_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM server_nodes s JOIN nodes_registry n ON n.id=s.node_id WHERE s.node_id=NEW.owner_node_id AND s.server_id=NEW.server_id AND n.owner_node_id IS NULL AND n.server_id=NEW.server_id) THEN
  RAISE EXCEPTION 'invalid managed owner';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER managed_identity_guard BEFORE INSERT OR UPDATE ON nodes_registry FOR EACH ROW EXECUTE FUNCTION guard_managed_identity();
CREATE FUNCTION guard_server_node() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND (NEW.node_id<>OLD.node_id OR NEW.server_id<>OLD.server_id) THEN RAISE EXCEPTION 'immutable server identity'; END IF;
 IF NOT EXISTS(SELECT 1 FROM nodes_registry WHERE id=NEW.node_id AND server_id=NEW.server_id AND owner_node_id IS NULL) THEN RAISE EXCEPTION 'invalid physical identity'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER server_node_guard BEFORE INSERT OR UPDATE ON server_nodes FOR EACH ROW EXECUTE FUNCTION guard_server_node();
CREATE TABLE managed_connection_versions (
 connection_id uuid NOT NULL REFERENCES nodes_registry(id),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
 configuration_ciphertext bytea NOT NULL,
 trusted_ca_pem text NOT NULL DEFAULT '',
 configuration_sha256 text NOT NULL CHECK(configuration_sha256 ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(connection_id,revision)
);
CREATE TRIGGER managed_connection_versions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON managed_connection_versions FOR EACH STATEMENT EXECUTE FUNCTION reject_catalog_version_mutation();
CREATE TABLE managed_connections (
 connection_id uuid PRIMARY KEY REFERENCES nodes_registry(id),
 revision bigint NOT NULL,
 FOREIGN KEY(connection_id,revision) REFERENCES managed_connection_versions(connection_id,revision)
);
CREATE TABLE managed_connection_observations (
 node_id uuid PRIMARY KEY REFERENCES server_nodes(node_id),
 boot_id uuid NOT NULL,
 sequence bigint NOT NULL CHECK(sequence BETWEEN 1 AND 9007199254740991),
 plan_revision bigint NOT NULL CHECK(plan_revision>0),
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
 body jsonb NOT NULL,
 received_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
