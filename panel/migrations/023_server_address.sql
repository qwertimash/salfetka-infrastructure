ALTER TABLE infrastructure_servers ADD COLUMN address text NOT NULL DEFAULT '' CHECK(length(address)<=45);
