package compiler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"salfetka/panel/internal/importer"
	"time"
)

// Namespacing touches only manifest references, never native DNS/routing tags.
// Conflicting network or mode policies must be resolved explicitly in B7.
func merged(in Input) (*Source, error) {
	if in.Source != nil || len(in.Sources) > 16 || len(in.Network) > 0 || len(in.Locations) > 0 {
		return nil, ErrInvalid
	}
	connections, locations := []any{}, []any{}
	var network any
	var networkBytes []byte
	routing := Object{}
	version := 1
	seen := map[string]bool{}
	var valid, expiry *time.Time
	for _, source := range in.Sources {
		if source.ID == "" || seen[source.ID] {
			return nil, ErrInvalid
		}
		seen[source.ID] = true
		one := in
		one.Source = &source
		one.Sources = nil
		one.Nodes = nil
		one.MaxVersion = 2
		artifact, e := Build(one)
		if e != nil {
			return nil, e
		}
		decoded, e := importer.Decode(artifact.Body)
		if e != nil {
			return nil, e
		}
		m := decoded.(map[string]any)
		b := raw(m["network"])
		if networkBytes != nil && !bytes.Equal(b, networkBytes) {
			return nil, ErrPolicyConflict
		}
		network, networkBytes = m["network"], b
		if m["version"].(json.Number).String() == "2" {
			version = 2
		}
		if policies, ok := m["routing"].(map[string]any); ok {
			for mode, p := range policies {
				if old, exists := routing[mode]; exists && !bytes.Equal(raw(old), raw(p)) {
					return nil, ErrPolicyConflict
				}
				routing[mode] = p
			}
		}
		name := func(id string) string {
			sum := sha256.Sum256([]byte(source.ID + "\x00" + id))
			return hex.EncodeToString(sum[:])
		}
		for _, v := range m["connections"].([]any) {
			c := v.(map[string]any)
			c["id"] = name(c["id"].(string))
			connections = append(connections, c)
		}
		for _, v := range m["locations"].([]any) {
			l := v.(map[string]any)
			l["id"] = name(l["id"].(string))
			members := l["connection_ids"].([]any)
			for i, id := range members {
				members[i] = name(id.(string))
			}
			locations = append(locations, l)
		}
		if source.ValidUntil != nil && (valid == nil || source.ValidUntil.Before(*valid)) {
			t := *source.ValidUntil
			valid = &t
		}
		if source.ExpiresAt != nil && (expiry == nil || source.ExpiresAt.Before(*expiry)) {
			t := *source.ExpiresAt
			expiry = &t
		}
	}
	m := Object{"format": "salfetka.subscription", "version": version, "id": in.ID, "revision": in.Revision, "network": network, "connections": connections, "locations": locations, "subscription": Object{"title": in.Title}}
	if len(routing) > 0 {
		m["routing"] = routing
	}
	return &Source{Format: "manifest", Normalized: raw(m), ValidUntil: valid, ExpiresAt: expiry}, nil
}
