ALTER TABLE nodes_vpn_installations ADD COLUMN endpoint jsonb CHECK(endpoint IS NULL OR octet_length(endpoint::text)<=20000);
