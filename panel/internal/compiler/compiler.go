// Package compiler assembles private subscription artifacts from frozen inputs.
// It never provisions credentials, fetches sources or silently drops connections.
package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"salfetka/panel/internal/importer"
)

const Version = "b8.1"

var ErrInvalid = errors.New("release_invalid")
var ErrMapping = errors.New("release_mapping_required")
var ErrPolicyConflict = errors.New("release_policy_conflict")
var ErrCapability = errors.New("release_capability")

type Object = map[string]any

type Source struct {
	ID         string          `json:"id"`
	VersionID  string          `json:"version_id"`
	Digest     string          `json:"digest"`
	Format     string          `json:"format"`
	Normalized json.RawMessage `json:"normalized"`
	ValidUntil *time.Time      `json:"valid_until,omitempty"`
	ExpiresAt  *time.Time      `json:"expires_at,omitempty"`
}
type Node struct {
	Engine string
	ID     string
	Title  string
	Config json.RawMessage
}
type Input struct {
	Blueprint                  *Blueprint
	ID                         string
	Revision                   int64
	Title                      string
	Now, ExpiresAt, LeaseUntil time.Time
	Sources                    []Source
	Source                     *Source
	// Mapping is required for imports that do not declare network/location policy.
	Network    json.RawMessage
	Locations  json.RawMessage
	Nodes      []Node
	MaxVersion int
	Engines    []string
}
type Artifact struct {
	Body    []byte
	Digest  string
	Preview importer.Preview
}

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func earlier(a time.Time, b *time.Time) time.Time {
	if b != nil && b.Before(a) {
		return *b
	}
	return a
}

func Build(in Input) (Artifact, error) {
	if in.Blueprint != nil {
		var e error
		in, e = compose(in)
		if e != nil {
			return Artifact{}, e
		}
	}
	if len(in.Sources) > 0 {
		source, e := merged(in)
		if e != nil {
			return Artifact{}, e
		}
		in.Source = source
		in.Sources = nil
	}
	if in.Revision < 1 || in.Revision > 9007199254740991 || in.Now.IsZero() || !in.ExpiresAt.After(in.Now) || !in.LeaseUntil.After(in.Now) {
		return Artifact{}, ErrInvalid
	}
	m := Object{"format": "salfetka.subscription", "version": 1, "id": in.ID, "revision": in.Revision}
	connections := []any{}
	var locations any
	lease, expiry := in.LeaseUntil, in.ExpiresAt
	if in.Source != nil {
		src := in.Source
		v, e := importer.Decode(src.Normalized)
		if e != nil {
			return Artifact{}, e
		}
		lease = earlier(lease, src.ValidUntil)
		lease = earlier(lease, src.ExpiresAt)
		switch src.Format {
		case "manifest":
			source, ok := v.(map[string]any)
			if !ok {
				return Artifact{}, ErrInvalid
			}
			m = source
			var okConnections bool
			connections, okConnections = m["connections"].([]any)
			if !okConnections {
				return Artifact{}, ErrInvalid
			}
			locations = m["locations"]
			if len(in.Network) > 0 || len(in.Locations) > 0 {
				return Artifact{}, ErrInvalid
			}
		case "catalog":
			source, ok := v.(map[string]any)
			if !ok {
				return Artifact{}, ErrInvalid
			}
			profiles, ok := source["profiles"].([]any)
			if !ok {
				return Artifact{}, ErrInvalid
			}
			locs := []any{}
			for _, p := range profiles {
				item, ok := p.(map[string]any)
				if !ok {
					return Artifact{}, ErrInvalid
				}
				connections = append(connections, Object{"id": item["id"], "engine": item["engine"], "settings": item["settings"]})
				locs = append(locs, Object{"id": item["id"], "mode": item["mode"], "kind": "location", "title": item["name"], "country": item["exit_country"], "connection_ids": []any{item["id"]}, "selection": Object{"type": "first_working"}})
			}
			locations = locs
			m["network"] = Object{"dns_servers": source["dns_servers"], "probe": source["probe"]}
			if len(in.Network) > 0 || len(in.Locations) > 0 {
				return Artifact{}, ErrInvalid
			}
		case "uri", "base64", "xray":
			records, ok := v.([]any)
			if !ok {
				return Artifact{}, ErrInvalid
			}
			for i, item := range records {
				if src.Format == "xray" {
					connections = append(connections, Object{"id": recordID(i), "engine": "xray", "settings": Object{"xray_config": item}})
				} else {
					r, ok := item.(map[string]any)
					if !ok {
						return Artifact{}, ErrInvalid
					}
					connections = append(connections, Object{"id": r["id"], "engine": "xray", "settings": r["settings"]})
				}
			}
		default:
			return Artifact{}, ErrInvalid
		}
	}
	if _, ok := m["network"]; !ok {
		if len(in.Network) == 0 {
			return Artifact{}, ErrMapping
		}
		v, e := importer.Decode(in.Network)
		if e != nil {
			return Artifact{}, e
		}
		m["network"] = v
	}
	if locations == nil && len(in.Locations) > 0 {
		v, e := importer.Decode(in.Locations)
		if e != nil {
			return Artifact{}, e
		}
		locations = v
	}
	if locations == nil {
		locations = []any{}
	}
	locs, ok := locations.([]any)
	if !ok {
		return Artifact{}, ErrInvalid
	}
	for _, node := range in.Nodes {
		config, e := importer.Decode(node.Config)
		if e != nil {
			return Artifact{}, e
		}
		id := "node-" + node.ID
		engine, settings, mode, e := nodeSettings(node.Engine, config)
		if e != nil {
			return Artifact{}, e
		}
		connections = append(connections, Object{"id": id, "engine": engine, "settings": settings})
		selection := "native"
		if mode == "bypass" {
			selection = "first_working"
		}
		locs = append(locs, Object{"id": id, "mode": mode, "kind": "location", "title": node.Title, "connection_ids": []any{id}, "selection": Object{"type": selection}})
	}
	// The paid entitlement and cache lease are independent. Shared upstream traffic
	// is not attributable to this customer and must not be copied into their stats.
	m["id"], m["revision"] = in.ID, in.Revision
	m["subscription"] = Object{"title": in.Title, "expires_at": expiry.UTC().Format(time.RFC3339Nano)}
	lease = earlier(lease, &expiry)
	m["valid_until"] = lease.UTC().Format(time.RFC3339Nano)
	m["connections"], m["locations"] = connections, locs
	b, e := json.Marshal(m)
	if e != nil {
		return Artifact{}, ErrInvalid
	}
	r, e := importer.Parse(b, in.Now)
	if e != nil {
		return Artifact{}, e
	}
	version := 1
	if n, ok := m["version"].(json.Number); ok && n.String() == "2" {
		version = 2
	}
	if in.MaxVersion < version {
		return Artifact{}, ErrCapability
	}
	allowed := map[string]bool{}
	for _, engine := range in.Engines {
		allowed[engine] = true
	}
	for _, p := range r.Preview.Profiles {
		if !allowed[p.Engine] {
			return Artifact{}, ErrCapability
		}
	}
	sum := sha256.Sum256(r.Normalized)
	return Artifact{Body: r.Normalized, Digest: hex.EncodeToString(sum[:]), Preview: r.Preview}, nil
}

func nodeSettings(engine string, config any) (string, any, string, error) {
	switch engine {
	case "", "xray":
		return "xray", Object{"xray_config": config}, "vpn", nil
	case "olcrtc":
		return engine, config, "bypass", nil
	default:
		return "", nil, "", ErrInvalid
	}
}
