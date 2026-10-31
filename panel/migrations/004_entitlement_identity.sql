-- Forward-only identity addition. Existing B2 rights retain state, expiry, quota,
-- ownership and revisions; no credential or policy is restored by this migration.
ALTER TABLE access_entitlements ADD COLUMN id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE access_entitlements ADD CONSTRAINT access_entitlements_id_key UNIQUE(id);
ALTER TABLE access_entitlements ALTER COLUMN id DROP DEFAULT;
