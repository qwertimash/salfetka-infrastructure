package importer

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/*.json
var schemas embed.FS
var schemaOnce sync.Once
var compiled [2]*jsonschema.Schema
var compileError error

type noLoader struct{}

func (noLoader) Load(string) (any, error) { return nil, Error("source_schema_unavailable") }
func schema(v any, version int) {
	schemaOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.UseLoader(noLoader{})
		// Trusted schemas use ECMA Unicode escapes; RE2 uses the equivalent x{...}.
		c.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) {
			pattern = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`).ReplaceAllString(pattern, `\x{$1}`)
			return regexp.Compile(pattern)
		})
		c.AssertFormat()
		for i := 1; i <= 2; i++ {
			b, e := schemas.ReadFile("schemas/v" + strconv.Itoa(i) + ".json")
			if e != nil {
				compileError = e
				return
			}
			v, e := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if e != nil {
				compileError = e
				return
			}
			name := "https://salfetka.invalid/import/v" + strconv.Itoa(i)
			if e = c.AddResource(name, v); e != nil {
				compileError = e
				return
			}
			compiled[i-1], e = c.Compile(name)
			if e != nil {
				compileError = e
				return
			}
		}
	})
	check(compileError == nil, "source_schema_unavailable")
	check(version == 1 || version == 2, "source_version")
	check(compiled[version-1].Validate(v) == nil, "source_manifest_schema")
}

// Only these fields are safe to return in lists/preview. Settings, source URLs,
// titles supplied by a URI, credentials and raw JSON never enter this projection.
type Profile struct {
	ContentDigest string `json:"content_digest"`
	ID            string `json:"id"`
	Engine        string `json:"engine"`
	Mode          string `json:"mode"`
	Native        bool   `json:"native"`
	Auto          bool   `json:"auto"`
	DNS           bool   `json:"source_dns"`
}
type Preview struct {
	Format                string     `json:"format"`
	Digest                string     `json:"digest"`
	Profiles              []Profile  `json:"profiles"`
	ValidUntil            *time.Time `json:"valid_until"`
	SubscriptionExpiresAt *time.Time `json:"subscription_expires_at"`
	PublicationReady      bool       `json:"publication_ready"`
}
type Result struct {
	Preview Preview
	// Original and Normalized are private. Callers must encrypt them and must not
	// serialize Result into an HTTP response, audit, or log.
	Original   []byte
	Normalized json.RawMessage
}

func date(v any, now time.Time) *time.Time {
	s := strings.ReplaceAll(strings.ReplaceAll(str(v), "t", "T"), "z", "Z")
	t, e := time.Parse(time.RFC3339Nano, s)
	check(e == nil, "source_date")
	check(t.After(now), "source_expired")
	return &t
}
func digest(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }

// Parse is all-or-nothing: an unsupported record invalidates the entire input.
// It does not infer locations, countries, source identity, expiry or entitlement.
func Parse(raw []byte, now time.Time) (result Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(Error); ok {
				result = Result{}
				err = e
			} else {
				panic(r)
			}
		}
	}()
	check(len(raw) > 0 && len(raw) <= MaxBytes, "source_size")
	text := bytes.TrimSpace(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}))
	check(len(text) > 0, "source_empty")
	p := Preview{Digest: digest(raw), Profiles: []Profile{}}
	var normalized any
	if text[0] == '{' || text[0] == '[' {
		v := strictJSON(text)
		if m, ok := v.(map[string]any); ok && m["format"] == "salfetka.subscription" {
			p.Format = "manifest"
			manifest(m, now, &p)
			normalized = m
		} else if m, ok := v.(map[string]any); ok && m["schema_version"] != nil {
			p.Format = "catalog"
			catalog(m, now, &p)
			normalized = m
		} else {
			p.Format = "xray"
			records, ok := v.([]any)
			if !ok {
				records = []any{v}
			}
			check(len(records) > 0 && len(records) <= 32, "source_count")
			normalizedRecords := []any{}
			for i, v := range records {
				config, auto := native(obj(v))
				_, dns := config["dns"]
				p.Profiles = append(p.Profiles, Profile{ContentDigest: digest(canonical(config)), ID: "record-" + strconv.Itoa(i+1), Engine: "xray", Mode: "vpn", Native: true, Auto: auto, DNS: dns})
				normalizedRecords = append(normalizedRecords, config)
			}
			normalized = normalizedRecords
		}
	} else {
		p.Format = "uri"
		if !bytes.Contains(text, []byte("://")) {
			decoded, e := base64.StdEncoding.Strict().DecodeString(string(text))
			if e != nil {
				decoded, e = base64.RawStdEncoding.Strict().DecodeString(string(text))
			}
			check(e == nil, "source_base64")
			text = bytes.TrimSpace(decoded)
			p.Format = "base64"
		}
		records := []any{}
		for _, line := range strings.Split(string(text), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			check(len(records) < 32, "source_count")
			settings, title := normalizedURI(line)
			id := "record-" + strconv.Itoa(len(records)+1)
			records = append(records, object{"id": id, "title": title, "settings": settings})
			p.Profiles = append(p.Profiles, Profile{ContentDigest: digest(canonical(settings)), ID: id, Engine: "xray", Mode: "vpn"})
		}
		check(len(records) > 0, "source_empty")
		normalized = records
	}
	return Result{Preview: p, Original: bytes.Clone(raw), Normalized: canonical(normalized)}, nil
}

func bypass(engine string, s object) {
	if engine == "openflux" {
		keys(s, "encryption_secret", "transport", "document_url", "codec", "max_token", "max_uid")
		for _, v := range s {
			check(validText(str(v), 16384), "source_bypass_field")
		}
		check(len(canonical(s)) <= 16384, "source_size")
		secret := str(s["encryption_secret"])
		check(validText(secret, 16384) && len(utf16.Encode([]rune(secret))) >= 16 && strings.TrimSpace(secret) == secret, "source_bypass_secret")
		check(member(str(optional(s, "codec", "")), "", "batched", "legacy"), "source_bypass_codec")
		carrier := str(s["transport"])
		ref := str(optional(s, "document_url", ""))
		token := str(optional(s, "max_token", ""))
		uid := str(optional(s, "max_uid", ""))
		switch carrier {
		case "yandex", "vyandex", "boards", "mailru":
			httpsReference(ref, false)
		case "cupsonline":
			check(strings.TrimSpace(ref) != "", "source_bypass_room")
		case "oneme":
			check(strings.TrimSpace(token) != "" && ref == "", "source_bypass_room")
			if uid != "" {
				v, e := strconv.ParseInt(uid, 10, 64)
				check(e == nil && v > 0 && len(uid) <= 20, "source_bypass_uid")
			}
		default:
			panic(Error("source_bypass_carrier"))
		}
		check(carrier == "oneme" || token == "" && uid == "", "source_bypass_fields")
		return
	}
	check(engine == "olcrtc", "source_engine")
	keys(s, "provider", "transport", "room", "key_hex", "bootstrap_dns", "channel_id", "provider_token", "device_id", "dtls_profile", "account_session")
	if v, exists := s["account_session"]; exists {
		enabled, ok := v.(bool)
		check(ok, "source_bypass_account_session")
		check(!enabled || s["provider"] == "jitsi" && s["transport"] == "vp8channel", "source_bypass_account_session")
	}
	check(member(str(s["provider"]), "jitsi", "telemost", "wbstream", "salutejazz", "vkcalls"), "source_bypass_provider")
	check(member(str(s["transport"]), "datachannel", "vp8channel", "seichannel"), "source_bypass_transport")
	check(regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(str(s["key_hex"])), "source_bypass_key")
	httpsReference(str(s["room"]), true)
	address, port, e := net.SplitHostPort(str(s["bootstrap_dns"]))
	check(e == nil, "source_bypass_dns")
	_, e = netip.ParseAddr(address)
	check(e == nil, "source_bypass_dns")
	n, e := strconv.Atoi(port)
	check(e == nil && n > 0 && n <= 65535, "source_bypass_dns")
	for k, v := range s {
		if k == "account_session" {
			continue // Validated as a boolean above; never coerce a string flag.
		}
		check(validText(str(v), 8192), "source_bypass_field")
	}
}
func httpsReference(s string, allowFragment bool) {
	u, e := url.Parse(s)
	check(e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && (allowFragment || u.Fragment == ""), "source_https")
	host(u.Hostname())
}
func profile(id, engine string, settings object) (p Profile) {
	p = Profile{ContentDigest: digest(canonical(settings)), ID: id, Engine: engine, Mode: "vpn"}
	if engine != "xray" {
		p.Mode = "bypass"
		bypass(engine, settings)
		return
	}
	if c, ok := settings["xray_config"]; ok {
		keys(settings, "xray_config")
		config, auto := native(obj(c))
		check(bytes.Equal(canonical(config), canonical(c)), "source_native_metadata")
		_, dns := config["dns"]
		p.Native, p.Auto, p.DNS = true, auto, dns
	} else {
		xray(settings)
	}
	return
}
func probe(n object) {
	dns := arr(n["dns_servers"])
	check(len(dns) > 0 && len(dns) <= 3, "source_dns")
	for _, v := range dns {
		a, e := netip.ParseAddr(str(v))
		check(e == nil && a.Is4(), "source_dns")
	}
	p := obj(n["probe"])
	keys(p, "url", "ipv4", "expected_status", "body_sha256")
	s := str(p["url"])
	httpsReference(s, false)
	u, _ := url.Parse(s)
	check(u.RawQuery == "" && !u.ForceQuery, "source_probe")
	ip, e := netip.ParseAddr(str(p["ipv4"]))
	check(e == nil && ip.Is4(), "source_probe")
	status := number(p["expected_status"])
	check(status >= 200 && status <= 299, "source_probe")
	check(regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(str(p["body_sha256"])), "source_probe")
}
func catalog(m object, now time.Time, p *Preview) {
	keys(m, "schema_version", "catalog_id", "revision", "expires_at", "profiles", "dns_servers", "probe")
	check(number(m["schema_version"]) == 1 && number(m["revision"]) > 0, "source_version")
	check(regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(str(m["catalog_id"])), "source_identity")
	p.ValidUntil = date(m["expires_at"], now)
	probe(m)
	profiles := arr(m["profiles"])
	check(len(profiles) > 0 && len(profiles) <= 32, "source_count")
	seen := map[string]bool{}
	for _, v := range profiles {
		c := obj(v)
		keys(c, "id", "name", "mode", "exit_country", "engine", "settings")
		id := str(c["id"])
		check(regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(id) && !seen[id], "source_identity")
		seen[id] = true
		check(validText(str(c["name"]), 64) && strings.TrimSpace(str(c["name"])) != "" && regexp.MustCompile(`^[A-Z]{2}$`).MatchString(str(c["exit_country"])), "source_metadata")
		item := profile(id, str(c["engine"]), obj(c["settings"]))
		check(c["mode"] == item.Mode && !item.Native, "source_mode")
		p.Profiles = append(p.Profiles, item)
	}
}

func manifest(m object, now time.Time, p *Preview) {
	version := number(m["version"])
	schema(m, int(version))
	number(m["revision"])
	sub := obj(m["subscription"])
	if v, ok := sub["expires_at"]; ok {
		p.SubscriptionExpiresAt = date(v, now)
	}
	if v, ok := m["valid_until"]; ok {
		p.ValidUntil = date(v, now)
	}
	scopes := map[string]bool{}
	for _, v := range arr(optional(sub, "traffic", []any{})) {
		r := obj(v)
		s := str(r["scope"])
		check(!scopes[s], "source_traffic_scope")
		scopes[s] = true
		for _, k := range []string{"upload_bytes", "download_bytes", "limit_bytes"} {
			if v, ok := r[k]; ok {
				_, e := strconv.ParseUint(string(v.(json.Number)), 10, 64)
				check(e == nil, "source_traffic_integer")
			}
		}
	}
	check(!scopes["subscription"] || len(scopes) == 1, "source_traffic_scope")
	probe(obj(m["network"]))
	records := map[string]Profile{}
	authorities := map[string]string{}
	portable := obj(optional(m, "routing", object{}))
	for _, v := range portable {
		routingPolicy(obj(v))
	}
	for _, v := range arr(m["connections"]) {
		c := obj(v)
		id := str(c["id"])
		_, exists := records[id]
		check(!exists, "source_connection_duplicate")
		s := obj(c["settings"])
		item := profile(id, str(c["engine"]), s)
		records[id] = item
		p.Profiles = append(p.Profiles, item)
		if version == 2 {
			authority := "user"
			if item.Native {
				config := obj(s["xray_config"])
				if _, ok := config["routing"]; ok {
					authority = "source"
				}
				if _, ok := c["routing_role"]; ok {
					transportOnly(config)
					authority = "user"
				}
			} else {
				_, role := c["routing_role"]
				check(!role, "source_routing_authority")
			}
			if _, ok := portable[item.Mode]; ok {
				check(authority == "user", "source_routing_authority")
				authority = "source"
			}
			check(authorities[item.Mode] == "" || authorities[item.Mode] == authority, "source_routing_authority")
			authorities[item.Mode] = authority
		}
	}
	for mode := range portable {
		check(authorities[mode] != "", "source_routing_authority")
	}
	seen := map[string]bool{}
	for _, v := range arr(m["locations"]) {
		l := obj(v)
		id := str(l["id"])
		check(!seen[id], "source_location_duplicate")
		seen[id] = true
		members := arr(l["connection_ids"])
		first := Profile{}
		for i, v := range members {
			item, ok := records[str(v)]
			check(ok, "source_location_member")
			check(item.Mode == l["mode"], "source_location_mode")
			if i == 0 {
				first = item
			} else {
				check(first.DNS == item.DNS, "source_location_dns")
			}
		}
		if obj(l["selection"])["type"] == "native" {
			check(l["mode"] == "vpn" && len(members) == 1 && first.Native, "source_native_location")
			check(l["kind"] != "auto" || first.Auto, "source_native_auto")
		}
	}
}
func routingPolicy(p object) {
	seen := map[string]bool{}
	for _, v := range arr(p["rules"]) {
		r := obj(v)
		id := str(r["id"])
		check(!seen[id], "source_routing_rule")
		seen[id] = true
		m := obj(r["match"])
		s := str(m["value"])
		switch str(m["type"]) {
		case "domain_exact", "domain_suffix":
			check(s == strings.ToLower(s) && !regexp.MustCompile(`^[0-9.]+$`).MatchString(s), "source_routing_match")
			host(s)
			check(!strings.HasSuffix(s, ".") && !strings.Contains(s, ":"), "source_routing_match")
		case "ip_cidr":
			prefix, e := netip.ParsePrefix(s)
			check(e == nil && prefix == prefix.Masked() && prefix.String() == s && !prefix.Addr().Is4In6(), "source_routing_match")
		case "geosite", "geoip":
			check(regexp.MustCompile(`^[a-z0-9_!-]{1,64}$`).MatchString(s), "source_routing_match")
		default:
			panic(Error("source_routing_match"))
		}
	}
}

// SchemaDigests records the exact trusted schemas used for a release validation.
// These are bundled public contracts, never fetched from imported documents.
func SchemaDigests() map[string]string {
	out := map[string]string{}
	for _, version := range []string{"1", "2"} {
		b, e := schemas.ReadFile("schemas/v" + version + ".json")
		if e == nil {
			out[version] = digest(b)
		}
	}
	return out
}
