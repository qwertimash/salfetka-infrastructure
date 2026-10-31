-- Opt-in personal-room admission. Existing installations are unchanged.
CREATE TABLE account_rooms (
 installation_id uuid NOT NULL REFERENCES nodes_vpn_installations(installation_id),
 user_id uuid NOT NULL REFERENCES access_users(id),
 room_id text NOT NULL UNIQUE CHECK(room_id ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(installation_id,user_id)
);
