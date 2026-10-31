package releases

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"salfetka/panel/internal/access"
	"salfetka/panel/internal/audit"
	"salfetka/panel/internal/compiler"
	"salfetka/panel/internal/database"
	"salfetka/panel/internal/identity"
	"salfetka/panel/internal/importer"
	"salfetka/panel/internal/nodes"
	"salfetka/panel/internal/roomroute"
)

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{16,128}$`)

func (s *Store) detail(ctx context.Context, tx pgx.Tx, user, device string) (Detail, error) {
	var out Detail
	e := tx.QueryRow(ctx, `SELECT id::text,user_id::text,device_id::text,revision,active_release::text,token_hash IS NOT NULL,token_revision FROM subscriptions WHERE user_id=$1 AND device_id=$2 AND assignment_id IS NOT DISTINCT FROM NULLIF($3,'')::uuid AND assignment_revision IS NOT DISTINCT FROM NULLIF($4::bigint,0)`, user, device, s.AssignmentID, s.AssignmentRevision).Scan(&out.Subscription.ID, &out.Subscription.UserID, &out.Subscription.DeviceID, &out.Subscription.Revision, &out.Subscription.ActiveRelease, &out.Subscription.TokenActive, &out.Subscription.TokenRevision)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, ErrUnavailable
	}
	if e != nil {
		return out, e
	}
	out.Releases = []Release{}
	rows, e := tx.Query(ctx, `SELECT r.id::text,r.number,s.state,r.digest,r.preview,r.provenance,s.checks,r.created_at FROM subscription_releases r JOIN subscription_release_status s ON s.release_id=r.id WHERE r.subscription_id=$1 ORDER BY r.number DESC LIMIT 100`, out.Subscription.ID)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var r Release
		var p, c []byte
		if e = rows.Scan(&r.ID, &r.Number, &r.State, &r.Digest, &p, &r.Provenance, &c, &r.CreatedAt); e != nil {
			return out, e
		}
		if json.Unmarshal(p, &r.Preview) != nil || json.Unmarshal(c, &r.Checks) != nil {
			return out, ErrUnavailable
		}
		out.Releases = append(out.Releases, r)
	}
	return out, rows.Err()
}
func (s *Store) DetailTx(ctx context.Context, tx pgx.Tx, user, device string) (Detail, error) {
	if !database.ValidID(user) || !database.ValidID(device) {
		return Detail{}, ErrInvalid
	}
	return s.detail(ctx, tx, user, device)
}
func (s *Store) permitted(ctx context.Context, tx pgx.Tx, user, device string) (access.Detail, access.Credential, error) {
	if _, e := tx.Exec(ctx, "SELECT id FROM access_users WHERE id=$1 FOR SHARE", user); e != nil {
		return access.Detail{}, access.Credential{}, e
	}
	if s.AssignmentID != "" {
		var state string
		var revision int64
		if e := tx.QueryRow(ctx, "SELECT state,revision FROM account_set_assignments WHERE id=$1 AND user_id=$2 FOR SHARE", s.AssignmentID, user).Scan(&state, &revision); e != nil || state != "active" || revision != s.AssignmentRevision {
			return access.Detail{}, access.Credential{}, ErrDenied
		}
	}
	d, e := s.Access.DetailTx(ctx, tx, user)
	if e != nil {
		return d, access.Credential{}, ErrDenied
	}
	var now time.Time
	if e = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return d, access.Credential{}, e
	}
	if !d.Decision.Allowed || d.Entitlement == nil || !d.Entitlement.ExpiresAt.After(now) {
		return d, access.Credential{}, ErrDenied
	}
	for _, dev := range d.Devices {
		if dev.ID == device && dev.Decision.Allowed && dev.Credential != nil {
			return d, *dev.Credential, nil
		}
	}
	return d, access.Credential{}, ErrDenied
}
func validateRecipe(r Recipe) error {
	if !utf8.ValidString(r.Title) || utf8.RuneCountInString(r.Title) > 80 || strings.TrimSpace(r.Title) != r.Title || strings.ContainsAny(r.Title, "\r\n\x00") {
		return ErrInvalid
	}
	if len(r.Sources) > 16 || len(r.Sources) > 0 && (r.SourceID != "" || r.VersionID != "" || !r.ExternalCredentials) {
		return ErrInvalid
	}
	seenSources := map[string]bool{}
	for _, source := range r.Sources {
		if !database.ValidID(source.ID) || !database.ValidID(source.VersionID) || seenSources[source.ID] {
			return ErrInvalid
		}
		seenSources[source.ID] = true
	}
	if r.MaxVersion < 1 || r.MaxVersion > 2 || len(r.Engines) < 1 || len(r.Engines) > 3 || len(r.NodeIDs) > 32 || len(r.Network) > 16384 || len(r.Locations) > 32768 {
		return ErrInvalid
	}
	engines := map[string]bool{}
	for _, e := range r.Engines {
		if (e != "xray" && e != "olcrtc" && e != "openflux") || engines[e] {
			return ErrInvalid
		}
		engines[e] = true
	}
	if r.SourceID != "" {
		if !database.ValidID(r.SourceID) || !database.ValidID(r.VersionID) || !r.ExternalCredentials {
			return ErrInvalid
		}
	} else if len(r.Sources) == 0 && (r.VersionID != "" || r.ExternalCredentials || len(r.NodeIDs) == 0) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, id := range r.NodeIDs {
		if !database.ValidID(id) || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	return nil
}

type frozen struct {
	Recipe     Recipe
	Source     *compiler.Source
	Sources    []compiler.Source
	Nodes      []compiler.Node
	Access     access.Detail
	Credential access.Credential
	Checks     []Check
	Now        time.Time
}

func (s *Store) freeze(ctx context.Context, tx pgx.Tx, user, device string, r Recipe, historical bool) (frozen, error) {
	f := frozen{Recipe: r, Checks: []Check{}}
	f.Recipe.NodeBindings = map[string]string{}
	if e := validateRecipe(r); e != nil {
		return f, e
	}
	if e := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&f.Now); e != nil {
		return f, e
	}
	// All node locks precede the user lock, matching B4 policy issuance.
	ids := append([]string{}, r.NodeIDs...)
	sort.Strings(ids)
	states := map[string]struct {
		config              json.RawMessage
		title, group, state string
	}{}
	for _, id := range ids {
		st, e := s.Nodes.VPNStatusTx(ctx, tx, id)
		if e != nil {
			return f, e
		}
		if st.Installation == nil || !st.Installation.Enabled || st.Installation.Endpoint == nil || !st.Installation.Endpoint.Valid() {
			return f, ErrUnavailable
		}
		var name string
		if e = tx.QueryRow(ctx, "SELECT name FROM nodes_registry WHERE id=$1", id).Scan(&name); e != nil {
			return f, e
		}
		// Only metadata is captured before all node locks have been acquired.
		endpoint, _ := json.Marshal(st.Installation.Endpoint)
		binding := sha256.Sum256([]byte(id + ":" + st.Installation.InstallationID + ":" + st.Installation.GroupID + ":" + string(endpoint)))
		digest := hex.EncodeToString(binding[:])
		if historical && r.NodeBindings[id] != digest {
			return f, ErrConflict
		}
		f.Recipe.NodeBindings[id] = digest
		states[id] = struct {
			config              json.RawMessage
			title, group, state string
		}{endpoint, name, st.Installation.GroupID, st.State}
	}
	var e error
	f.Access, f.Credential, e = s.permitted(ctx, tx, user, device)
	if e != nil {
		return f, e
	}
	for _, id := range r.NodeIDs {
		st, e := s.Nodes.VPNStatusTx(ctx, tx, id)
		if e != nil {
			return f, e
		}
		data := states[id]
		grant, key, e := s.Access.VPNCredentialTx(ctx, tx, user, device, id, data.group, st.Installation.Endpoint.Backend)
		if e != nil {
			return f, e
		}
		ready := st.State == "applied" && st.Observed != nil
		found := false
		if st.Observed != nil {
			for _, usage := range st.Observed.Usage {
				if usage.GrantID == grant && usage.Active && (usage.Ready == nil || *usage.Ready) {
					found = true
				}
			}
		}
		check := Check{NodeID: id, State: st.State}
		if ready && found {
			check.State = "healthy"
		} else if ready {
			check.State = "grant_pending"
		}
		f.Checks = append(f.Checks, check)
		config, e := nodes.PersonalClientConfig(ctx, tx, *st.Installation.Endpoint, key, st.Installation.InstallationID, user, !historical)
		if e != nil {
			if errors.Is(e, roomroute.ErrCapacity) {
				return f, ErrCapacity
			}
			return f, e
		}
		f.Nodes = append(f.Nodes, compiler.Node{ID: id, Title: data.title, Engine: st.Installation.Endpoint.Engine(), Config: config})
	}
	if r.SourceID != "" {
		source, e := s.Catalog.FrozenTx(ctx, tx, r.SourceID, r.VersionID, historical, f.Now)
		if e != nil {
			return f, e
		}
		f.Source = &source
	}
	for _, ref := range r.Sources {
		source, e := s.Catalog.FrozenTx(ctx, tx, ref.ID, ref.VersionID, historical, f.Now)
		if e != nil {
			return f, e
		}
		f.Sources = append(f.Sources, source)
	}
	return f, nil
}
func (f frozen) build(id string, number int64) (compiler.Artifact, error) {
	title := f.Recipe.Title
	if title == "" {
		title = "САЛФЕТКА VPN"
	}
	return compiler.Build(compiler.Input{Blueprint: f.Recipe.Blueprint, ID: id, Revision: number, Title: title, Now: f.Now, ExpiresAt: f.Access.Entitlement.ExpiresAt, LeaseUntil: f.Now.Truncate(time.Minute).Add(24 * time.Hour), Source: f.Source, Sources: f.Sources, Network: f.Recipe.Network, Locations: f.Recipe.Locations, Nodes: f.Nodes, MaxVersion: f.Recipe.MaxVersion, Engines: f.Recipe.Engines})
}
func policyBytes(b []byte) []byte {
	v, e := jsonObject(b)
	if e != nil {
		return nil
	}
	delete(v, "valid_until")
	delete(v, "subscription")
	out, _ := json.Marshal(v)
	return out
}
func jsonObject(b []byte) (map[string]json.RawMessage, error) {
	var v map[string]json.RawMessage
	e := json.Unmarshal(b, &v)
	return v, e
}
func (s *Store) loadRecipe(ctx context.Context, tx pgx.Tx, sub, release string) (Recipe, error) {
	var cipher []byte
	if e := tx.QueryRow(ctx, "SELECT recipe_ciphertext FROM subscription_releases WHERE id=$1 AND subscription_id=$2", release, sub).Scan(&cipher); e != nil {
		return Recipe{}, ErrInvalid
	}
	b, e := s.Vault.OpenSource(cipher, "release-recipe:"+sub+":"+release)
	if e != nil {
		return Recipe{}, e
	}
	defer clear(b)
	var r Recipe
	if json.Unmarshal(b, &r) != nil {
		return r, ErrUnavailable
	}
	return r, nil
}
func (s *Store) MutateTx(ctx context.Context, tx pgx.Tx, m Mutation) (Detail, bool, error) {
	if !database.ValidID(m.Actor) || !database.ValidID(m.UserID) || !database.ValidID(m.DeviceID) || !keyPattern.MatchString(m.Key) || s.Vault == nil {
		return Detail{}, false, ErrInvalid
	}
	raw, _ := json.Marshal(struct {
		Mutation   Mutation
		Assignment string
		Generation int64
	}{m, s.AssignmentID, s.AssignmentRevision})
	if s.AssignmentID == "" {
		raw, _ = json.Marshal(m)
	}
	hash := sha256.Sum256(raw)
	if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,61))", m.Actor+":"+m.Key); e != nil {
		return Detail{}, false, e
	}
	var savedHash, body []byte
	e := tx.QueryRow(ctx, "SELECT request_hash,result FROM subscription_mutations WHERE actor_id=$1 AND idempotency_key=$2", m.Actor, m.Key).Scan(&savedHash, &body)
	if e == nil {
		if !bytes.Equal(savedHash, hash[:]) {
			return Detail{}, false, ErrConflict
		}
		var out Detail
		e = json.Unmarshal(body, &out)
		return out, true, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return Detail{}, false, e
	}
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,62))", m.DeviceID); e != nil {
		return Detail{}, false, e
	}
	d, e := s.detail(ctx, tx, m.UserID, m.DeviceID)
	absent := errors.Is(e, ErrUnavailable)
	if e != nil && !absent {
		return Detail{}, false, e
	}
	if absent {
		if m.Operation != "stage" || m.Revision != 0 {
			return Detail{}, false, ErrConflict
		}
	} else if d.Subscription.Revision != m.Revision {
		return Detail{}, false, ErrConflict
	}
	sub := d.Subscription.ID
	if absent {
		sub, e = database.NewID()
		if e != nil {
			return Detail{}, false, e
		}
	}
	switch m.Operation {
	case "stage", "rollback":
		var recipe Recipe
		if m.Operation == "stage" {
			if m.Recipe == nil || m.ReleaseID != "" {
				return Detail{}, false, ErrInvalid
			}
			recipe = *m.Recipe
			if len(recipe.NodeBindings) > 0 {
				return Detail{}, false, ErrInvalid
			}
		} else {
			if m.Recipe != nil || !database.ValidID(m.ReleaseID) {
				return Detail{}, false, ErrInvalid
			}
			recipe, e = s.loadRecipe(ctx, tx, sub, m.ReleaseID)
			if e != nil {
				return Detail{}, false, e
			}
		}
		f, e := s.freeze(ctx, tx, m.UserID, m.DeviceID, recipe, m.Operation == "rollback")
		if e != nil {
			return Detail{}, false, e
		}
		if absent {
			if _, e = tx.Exec(ctx, "INSERT INTO subscriptions(id,user_id,device_id,assignment_id,assignment_revision) VALUES($1,$2,$3,NULLIF($4,'')::uuid,NULLIF($5::bigint,0))", sub, m.UserID, m.DeviceID, s.AssignmentID, s.AssignmentRevision); e != nil {
				return Detail{}, false, e
			}
		}
		var number, base int64
		if e = tx.QueryRow(ctx, "SELECT next_release,revision FROM subscriptions WHERE id=$1 FOR UPDATE", sub).Scan(&number, &base); e != nil {
			return Detail{}, false, e
		}
		// Keep one integer of headroom for next_release; history reads remain bounded.
		if number >= 9007199254740991 {
			return Detail{}, false, ErrCapacity
		}
		artifact, e := f.build(sub, number)
		if e != nil {
			return Detail{}, false, e
		}
		id, e := database.NewID()
		if e != nil {
			return Detail{}, false, e
		}
		rb, _ := json.Marshal(f.Recipe)
		rc, e := s.Vault.SealSource(rb, "release-recipe:"+sub+":"+id)
		clear(rb)
		if e != nil {
			return Detail{}, false, e
		}
		ac, e := s.Vault.SealSource(artifact.Body, "release-artifact:"+sub+":"+id)
		clear(artifact.Body)
		if e != nil {
			return Detail{}, false, e
		}
		preview, _ := json.Marshal(artifact.Preview)
		provenance := map[string]any{"group_id": f.Access.Entitlement.GroupID, "compiler": compiler.Version, "geo_index_digest": compiler.GeoDigest(), "validation": "schema_semantics_and_managed_observation", "schema_digests": importer.SchemaDigests(), "node_binding_digests": f.Recipe.NodeBindings, "managed_runtime_profile": "b8-typed-owned-backends", "external_runtime_validation": "not_performed", "schema_max": recipe.MaxVersion, "engines": recipe.Engines, "credential_version": f.Credential.Version, "external_credentials": recipe.ExternalCredentials, "node_ids": recipe.NodeIDs}
		if m.DraftID != "" {
			provenance["builder_draft"] = m.DraftID
			provenance["builder_revision"] = m.DraftRevision
		}
		if f.Source != nil {
			provenance["source_id"] = f.Source.ID
			provenance["source_version"] = f.Source.VersionID
			provenance["source_digest"] = f.Source.Digest
			provenance["source_valid_until"] = f.Source.ValidUntil
			provenance["source_expires_at"] = f.Source.ExpiresAt
		}
		if len(f.Sources) > 0 {
			sources := []map[string]string{}
			var valid, expires *time.Time
			for _, source := range f.Sources {
				sources = append(sources, map[string]string{"id": source.ID, "version_id": source.VersionID, "digest": source.Digest})
				if source.ValidUntil != nil && (valid == nil || source.ValidUntil.Before(*valid)) {
					valid = source.ValidUntil
				}
				if source.ExpiresAt != nil && (expires == nil || source.ExpiresAt.Before(*expires)) {
					expires = source.ExpiresAt
				}
			}
			provenance["sources"] = sources
			provenance["source_valid_until"] = valid
			provenance["source_expires_at"] = expires
		}
		prov, _ := json.Marshal(provenance)
		var rollback any
		if m.Operation == "rollback" {
			rollback = m.ReleaseID
		}
		_, e = tx.Exec(ctx, `INSERT INTO subscription_releases(id,subscription_id,number,base_revision,access_revision,policy_epoch,credential_id,recipe_ciphertext,artifact_ciphertext,digest,preview,provenance,rollback_of) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, id, sub, number, base+1, f.Access.User.Revision, f.Access.User.PolicyEpoch, f.Credential.ID, rc, ac, artifact.Digest, preview, prov, rollback)
		if e != nil {
			return Detail{}, false, e
		}
		checks, _ := json.Marshal(f.Checks)
		if _, e = tx.Exec(ctx, "INSERT INTO subscription_release_status(release_id,state,checks) VALUES($1,'staged',$2)", id, checks); e != nil {
			return Detail{}, false, e
		}
		_, e = tx.Exec(ctx, "UPDATE subscriptions SET next_release=next_release+1,revision=revision+1 WHERE id=$1", sub)
	case "publish", "check":
		if m.Recipe != nil || !database.ValidID(m.ReleaseID) {
			return Detail{}, false, ErrInvalid
		}
		recipe, e := s.loadRecipe(ctx, tx, sub, m.ReleaseID)
		if e != nil {
			return Detail{}, false, e
		}
		f, e := s.freeze(ctx, tx, m.UserID, m.DeviceID, recipe, true)
		if e != nil {
			return Detail{}, false, e
		}
		var number, base, revision, epoch int64
		var credential string
		var cipher []byte
		e = tx.QueryRow(ctx, "SELECT number,base_revision,access_revision,policy_epoch,credential_id::text,artifact_ciphertext FROM subscription_releases WHERE id=$1 AND subscription_id=$2", m.ReleaseID, sub).Scan(&number, &base, &revision, &epoch, &credential, &cipher)
		if e != nil {
			return Detail{}, false, e
		}
		if revision != f.Access.User.Revision || epoch != f.Access.User.PolicyEpoch || credential != f.Credential.ID || base != d.Subscription.Revision {
			return Detail{}, false, ErrConflict
		}
		previous, e := s.Vault.OpenSource(cipher, "release-artifact:"+sub+":"+m.ReleaseID)
		if e != nil {
			return Detail{}, false, e
		}
		defer clear(previous)
		actual, e := f.build(sub, number)
		if e != nil {
			return Detail{}, false, e
		}
		defer clear(actual.Body)
		if !bytes.Equal(policyBytes(previous), policyBytes(actual.Body)) {
			return Detail{}, false, ErrConflict
		}
		state := "healthy"
		for _, c := range f.Checks {
			if c.State != "healthy" {
				state = "partial"
			}
		}
		ready := state == "healthy"
		if len(f.Checks) == 0 {
			state = "staged"
		} // External structures do not prove node health.
		if ready && m.Operation == "publish" {
			state = "published"
			tag, e := tx.Exec(ctx, "UPDATE subscriptions SET active_release=$2,revision=revision+1 WHERE id=$1 AND revision=$3", sub, m.ReleaseID, base)
			if e != nil {
				return Detail{}, false, e
			}
			if tag.RowsAffected() != 1 {
				return Detail{}, false, ErrConflict
			}
		}
		checks, _ := json.Marshal(f.Checks)
		_, e = tx.Exec(ctx, "UPDATE subscription_release_status SET state=$2,checks=$3,updated_at=clock_timestamp() WHERE release_id=$1", m.ReleaseID, state, checks)
	case "rotate", "revoke":
		if absent || m.Recipe != nil || m.ReleaseID != "" {
			return Detail{}, false, ErrInvalid
		}
		if m.TokenRevision != d.Subscription.TokenRevision {
			return Detail{}, false, ErrConflict
		}
		var hashValue, cipherValue any
		if m.Operation == "rotate" {
			if _, _, e = s.permitted(ctx, tx, m.UserID, m.DeviceID); e != nil {
				return Detail{}, false, e
			}
			token, e := identity.RandomToken()
			if e != nil {
				return Detail{}, false, e
			}
			h := sha256.Sum256([]byte(token))
			c, e := s.Vault.Seal([]byte(token), "subscription-token:"+sub)
			if e != nil {
				return Detail{}, false, e
			}
			hashValue, cipherValue = h[:], c
		}
		// Token rotation is independent of config assignment CAS and VPN credentials.
		_, e = tx.Exec(ctx, "UPDATE subscriptions SET token_hash=$2,token_ciphertext=$3,token_revision=token_revision+1 WHERE id=$1", sub, hashValue, cipherValue)
	default:
		return Detail{}, false, ErrInvalid
	}
	if e != nil {
		return Detail{}, false, e
	}
	out, e := s.detail(ctx, tx, m.UserID, m.DeviceID)
	if e != nil {
		return Detail{}, false, e
	}
	body, _ = json.Marshal(out)
	if _, e = tx.Exec(ctx, "INSERT INTO subscription_mutations(actor_id,idempotency_key,request_hash,result) VALUES($1,$2,$3,$4)", m.Actor, m.Key, hash[:], body); e != nil {
		return Detail{}, false, e
	}
	if e = audit.Append(ctx, tx, m.Actor, "subscription."+m.Operation, sub, "accepted"); e != nil {
		return Detail{}, false, e
	}
	return out, false, nil
}
