-- Existing installations keep their current configuration until explicitly edited.
ALTER TABLE infrastructure_servers ADD COLUMN domain text NOT NULL DEFAULT '' CHECK(length(domain)<=253);
