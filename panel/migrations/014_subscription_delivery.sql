-- Mobile clients include valid_until in their revision fingerprint. Persist a
-- separate monotonic wire revision and lease; never change that field under the
-- same revision, and never require manual publication just to renew a lease.
CREATE TABLE subscription_delivery (
 subscription_id uuid PRIMARY KEY REFERENCES subscriptions(id),
 release_id uuid,
 revision bigint NOT NULL DEFAULT 0 CHECK(revision BETWEEN 0 AND 9007199254740991),
 valid_until timestamptz,
 FOREIGN KEY(subscription_id,release_id) REFERENCES subscription_releases(subscription_id,id),
 CHECK((release_id IS NULL)=(valid_until IS NULL))
);
-- Earlier B6 alpha responses used the release number on the wire. Start above
-- every number they could have delivered; do not restore an old client revision.
INSERT INTO subscription_delivery(subscription_id,revision)
 SELECT id,next_release-1 FROM subscriptions;
