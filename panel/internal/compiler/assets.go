package compiler

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
)

// Exact public index bundled in current mobile clients. No network lookup or
// arbitrary geodata file is accepted from a draft.
//
//go:embed assets/geodata-tags-v1.json
var geoIndex []byte

func GeoDigest() string { s := sha256.Sum256(geoIndex); return hex.EncodeToString(s[:]) }
func availableGeo(policy any) bool {
	var index struct {
		Files map[string]struct {
			Tags []string `json:"tags"`
		} `json:"files"`
	}
	if json.Unmarshal(geoIndex, &index) != nil {
		return false
	}
	p, ok := policy.(map[string]any)
	if !ok {
		return true
	}
	rs, _ := p["rules"].([]any)
	for _, v := range rs {
		r, ok := v.(map[string]any)
		if !ok {
			continue
		}
		m, _ := r["match"].(map[string]any)
		typ, _ := m["type"].(string)
		value, _ := m["value"].(string)
		if typ != "geoip" && typ != "geosite" {
			continue
		}
		found := false
		for _, tag := range index.Files[typ+".dat"].Tags {
			if tag == value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
