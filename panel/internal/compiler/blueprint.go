package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"salfetka/panel/internal/importer"
)

// Blueprint contains references and presentation/policy only, never credentials.
// Native settings remain owned by their frozen source or managed node.
type Blueprint struct {
	Version   int                     `json:"version"`
	Network   PolicyChoice            `json:"network"`
	Routing   map[string]PolicyChoice `json:"routing"`
	Locations []Location              `json:"locations"`
}
type PolicyChoice struct {
	Authority string          `json:"authority"`
	SourceID  string          `json:"source_id,omitempty"`
	Value     json.RawMessage `json:"value,omitempty"`
}
type Member struct {
	SourceID     string `json:"source_id,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
	NodeID       string `json:"node_id,omitempty"`
}
type Location struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Country   string   `json:"country,omitempty"`
	Icon      string   `json:"icon,omitempty"`
	Mode      string   `json:"mode"`
	Kind      string   `json:"kind"`
	Selection string   `json:"selection"`
	Members   []Member `json:"members"`
}

// Layout is a privileged preview projection. It never returns native settings.
type Layout struct {
	Version      int                `json:"version"`
	Network      json.RawMessage    `json:"network"`
	Routing      json.RawMessage    `json:"routing"`
	Locations    json.RawMessage    `json:"locations"`
	Profiles     []importer.Profile `json:"profiles"`
	PolicyDigest string             `json:"policy_digest"`
}

func Present(body []byte, now time.Time) (Layout, error) {
	r, e := importer.Parse(body, now)
	if e != nil {
		return Layout{}, e
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(r.Normalized, &m) != nil {
		return Layout{}, ErrInvalid
	}
	var version int
	json.Unmarshal(m["version"], &version)
	digest := Object{}
	for _, key := range []string{"version", "network", "routing", "locations", "connections"} {
		if v, ok := m[key]; ok {
			digest[key] = v
		}
	}
	sum := sha256.Sum256(raw(digest))
	routing := m["routing"]
	if len(routing) == 0 {
		routing = json.RawMessage(`{}`)
	}
	return Layout{version, m["network"], routing, m["locations"], r.Preview.Profiles, hex.EncodeToString(sum[:])}, nil
}
func QualifiedID(source, id string) string {
	sum := sha256.Sum256([]byte(source + "\x00" + id))
	return hex.EncodeToString(sum[:])
}

type SourceOutline struct {
	ID        string             `json:"id"`
	VersionID string             `json:"version_id"`
	Network   json.RawMessage    `json:"network,omitempty"`
	Routing   json.RawMessage    `json:"routing,omitempty"`
	Locations json.RawMessage    `json:"locations,omitempty"`
	Profiles  []importer.Profile `json:"profiles"`
}

// Outline is an explicit editor read, not an ordinary list or audit projection.
func Outline(s Source, now time.Time) (SourceOutline, error) {
	r, e := importer.Parse(s.Normalized, now)
	// URI normalization is a private record array, not a native JSON input.
	if s.Format == "uri" || s.Format == "base64" {
		r.Preview.Profiles = []importer.Profile{}
		v, err := importer.Decode(s.Normalized)
		if err != nil {
			return SourceOutline{}, err
		}
		records, ok := v.([]any)
		if !ok {
			return SourceOutline{}, ErrInvalid
		}
		for _, v := range records {
			c, ok := v.(map[string]any)
			if !ok {
				return SourceOutline{}, ErrInvalid
			}
			id, _ := c["id"].(string)
			r.Preview.Profiles = append(r.Preview.Profiles, importer.Profile{ID: id, Engine: "xray", Mode: "vpn"})
		}
		e = nil
	}
	if e != nil {
		return SourceOutline{}, e
	}
	out := SourceOutline{ID: s.ID, VersionID: s.VersionID, Profiles: r.Preview.Profiles}
	v, e := importer.Decode(s.Normalized)
	if e != nil {
		return out, e
	}
	if m, ok := v.(map[string]any); ok {
		if s.Format == "manifest" {
			out.Network = raw(m["network"])
			out.Locations = raw(m["locations"])
			if m["routing"] != nil {
				out.Routing = raw(m["routing"])
			}
		}
		if s.Format == "catalog" {
			out.Network = raw(Object{"dns_servers": m["dns_servers"], "probe": m["probe"]})
		}
	}
	return out, nil
}

func compose(in Input) (Input, error) {
	b := in.Blueprint
	if b.Version != 1 || len(b.Locations) == 0 || len(b.Locations) > 64 || len(b.Routing) > 2 || len(in.Network) > 0 || len(in.Locations) > 0 || in.Source != nil && len(in.Sources) > 0 {
		return in, ErrInvalid
	}
	sources := in.Sources
	if in.Source != nil {
		sources = []Source{*in.Source}
	}
	if len(sources) > 16 {
		return in, ErrInvalid
	}
	records := map[string]Object{}
	networks := map[string]any{}
	policies := map[string]map[string]any{}
	seen := map[string]bool{}
	var valid, expiry *time.Time
	version := 1
	for _, s := range sources {
		if s.ID == "" || seen[s.ID] {
			return in, ErrInvalid
		}
		seen[s.ID] = true
		v, e := importer.Decode(s.Normalized)
		if e != nil {
			return in, e
		}
		var cs []any
		switch s.Format {
		case "manifest":
			m, ok := v.(map[string]any)
			if !ok {
				return in, ErrInvalid
			}
			if n, ok := m["version"].(json.Number); ok && n.String() == "2" {
				version = 2
			}
			cs, _ = m["connections"].([]any)
			networks[s.ID] = m["network"]
			policies[s.ID], _ = m["routing"].(map[string]any)
		case "catalog":
			m, ok := v.(map[string]any)
			if !ok {
				return in, ErrInvalid
			}
			networks[s.ID] = Object{"dns_servers": m["dns_servers"], "probe": m["probe"]}
			ps, ok := m["profiles"].([]any)
			if !ok {
				return in, ErrInvalid
			}
			for _, v := range ps {
				c := v.(map[string]any)
				cs = append(cs, Object{"id": c["id"], "engine": c["engine"], "settings": c["settings"]})
			}
		case "uri", "base64", "xray":
			rs, ok := v.([]any)
			if !ok {
				return in, ErrInvalid
			}
			for i, v := range rs {
				if s.Format == "xray" {
					cs = append(cs, Object{"id": recordID(i), "engine": "xray", "settings": Object{"xray_config": v}})
				} else {
					c := v.(map[string]any)
					cs = append(cs, Object{"id": c["id"], "engine": "xray", "settings": c["settings"]})
				}
			}
		default:
			return in, ErrInvalid
		}
		for _, v := range cs {
			c := v.(map[string]any)
			id, ok := c["id"].(string)
			if !ok {
				return in, ErrInvalid
			}
			qid := QualifiedID(s.ID, id)
			c["id"] = qid
			records[qid] = c
		}
		if s.ValidUntil != nil && (valid == nil || s.ValidUntil.Before(*valid)) {
			valid = s.ValidUntil
		}
		if s.ExpiresAt != nil && (expiry == nil || s.ExpiresAt.Before(*expiry)) {
			expiry = s.ExpiresAt
		}
	}
	for _, n := range in.Nodes {
		v, e := importer.Decode(n.Config)
		if e != nil {
			return in, e
		}
		id := "node-" + n.ID
		if records[id] != nil {
			return in, ErrInvalid
		}
		engine, settings, _, err := nodeSettings(n.Engine, v)
		if err != nil {
			return in, err
		}
		records[id] = Object{"id": id, "engine": engine, "settings": settings}
	}
	choose := func(p PolicyChoice, kind string) (any, error) {
		switch p.Authority {
		case "source":
			if p.SourceID == "" || !seen[p.SourceID] || len(p.Value) > 0 {
				return nil, ErrInvalid
			}
			if kind == "network" {
				if networks[p.SourceID] == nil {
					return nil, ErrMapping
				}
				return networks[p.SourceID], nil
			}
			return policies[p.SourceID][kind], nil
		case "custom":
			if p.SourceID != "" || len(p.Value) == 0 {
				return nil, ErrInvalid
			}
			return importer.Decode(p.Value)
		case "personal":
			if kind == "network" || p.SourceID != "" || len(p.Value) > 0 {
				return nil, ErrInvalid
			}
			return nil, nil
		default:
			return nil, ErrInvalid
		}
	}
	network, e := choose(b.Network, "network")
	if e != nil {
		return in, e
	}
	routing := Object{}
	for mode, p := range b.Routing {
		if mode != "vpn" && mode != "bypass" {
			return in, ErrInvalid
		}
		v, e := choose(p, mode)
		if e != nil {
			return in, e
		}
		if v != nil {
			routing[mode] = v
		}
	}
	cs, ls := []any{}, []any{}
	used := map[string]bool{}
	usedNodes := map[string]bool{}
	usedSources := map[string]bool{}
	modes := map[string]bool{}
	for _, l := range b.Locations {
		if len(l.Members) == 0 || len(l.Members) > 32 {
			return in, ErrInvalid
		}
		modes[l.Mode] = true
		choice, ok := b.Routing[l.Mode]
		if !ok {
			return in, ErrInvalid
		}
		members := []any{}
		for _, ref := range l.Members {
			id := ""
			if ref.NodeID != "" {
				if ref.SourceID != "" || ref.ConnectionID != "" {
					return in, ErrInvalid
				}
				id = "node-" + ref.NodeID
				usedNodes[ref.NodeID] = true
			} else {
				if ref.SourceID == "" || ref.ConnectionID == "" {
					return in, ErrInvalid
				}
				id = QualifiedID(ref.SourceID, ref.ConnectionID)
				usedSources[ref.SourceID] = true
			}
			c := records[id]
			if c == nil {
				return in, ErrMapping
			}
			settings := c["settings"].(map[string]any)
			if config, ok := settings["xray_config"].(map[string]any); ok {
				if _, nativePolicy := config["routing"]; nativePolicy && c["routing_role"] == nil && choice.Authority != "source" {
					return in, ErrPolicyConflict
				}
			}
			// Personal authority cannot silently remove a portable source policy.
			if ref.SourceID != "" && choice.Authority == "personal" && policies[ref.SourceID][l.Mode] != nil {
				return in, ErrPolicyConflict
			}
			members = append(members, id)
			if !used[id] {
				used[id] = true
				cs = append(cs, c)
			}
		}
		loc := Object{"id": l.ID, "title": l.Title, "mode": l.Mode, "kind": l.Kind, "connection_ids": members, "selection": Object{"type": l.Selection}}
		if l.Country != "" {
			loc["country"] = l.Country
		}
		if l.Icon != "" {
			loc["icon"] = l.Icon
		}
		ls = append(ls, loc)
	}
	// Every selected source/node must contribute; no accidental readiness checks or leases for unused resources.
	for _, n := range in.Nodes {
		if !usedNodes[n.ID] {
			return in, ErrMapping
		}
	}
	for _, s := range sources {
		if !usedSources[s.ID] {
			return in, ErrMapping
		}
	}
	for mode, p := range routing {
		if !modes[mode] {
			return in, ErrInvalid
		}
		if !availableGeo(p) {
			return in, ErrCapability
		}
		if unreachable(p) {
			return in, ErrPolicyConflict
		}
	}
	m := Object{"format": "salfetka.subscription", "version": version, "network": network, "locations": ls, "connections": cs}
	if len(routing) > 0 {
		m["version"] = 2
		m["routing"] = routing
	}
	in.Source = &Source{Format: "manifest", Normalized: raw(m), ValidUntil: valid, ExpiresAt: expiry}
	in.Sources = nil
	in.Nodes = nil
	in.Blueprint = nil
	return in, nil
}

// Reject provably shadowed rules. Geo set intersections remain unknown.
func unreachable(policy any) bool {
	p, ok := policy.(map[string]any)
	if !ok {
		return false
	}
	rules, ok := p["rules"].([]any)
	if !ok {
		return false
	}
	prior := []map[string]any{}
	for _, v := range rules {
		r, ok := v.(map[string]any)
		if !ok {
			return false
		}
		m, ok := r["match"].(map[string]any)
		if !ok {
			return false
		}
		typ, _ := m["type"].(string)
		value, _ := m["value"].(string)
		for _, old := range prior {
			ot, _ := old["type"].(string)
			ov, _ := old["value"].(string)
			if ot == typ && ov == value {
				return true
			}
			if ot == "domain_suffix" && (typ == "domain_exact" || typ == "domain_suffix") && (value == ov || strings.HasSuffix(value, "."+ov)) {
				return true
			}
			if ot == "ip_cidr" && typ == "ip_cidr" {
				a, ea := netip.ParsePrefix(ov)
				b, eb := netip.ParsePrefix(value)
				if ea == nil && eb == nil && a.Bits() <= b.Bits() && a.Contains(b.Addr()) {
					return true
				}
			}
		}
		prior = append(prior, m)
	}
	return false
}
