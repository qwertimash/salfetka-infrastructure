package importer

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$`)
var labelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func host(s string) {
	check(s != "" && validText(s, 253) && !strings.ContainsAny(s, "/@?#%"), "source_host")
	if _, e := netip.ParseAddr(s); e == nil {
		return
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		check(labelPattern.MatchString(label), "source_host")
	}
}
func uriSettings(raw string) (object, string) {
	check(validText(raw, 16384), "source_uri")
	u, e := url.Parse(raw)
	check(e == nil, "source_uri")
	check(member(u.Scheme, "vless", "hysteria2", "hy2"), "source_protocol")
	check(u.User != nil && member(u.Path, "", "/"), "source_uri")
	host(u.Hostname())
	check(member(u.Scheme, "vless", "hysteria2", "hy2"), "source_protocol")
	q, e := url.ParseQuery(u.RawQuery)
	check(e == nil && len(q) <= 64, "source_uri")
	for k, vs := range q {
		check(len(vs) == 1 && validText(vs[0], 16384), "source_duplicate_parameter")
		check(strings.Contains(u.RawQuery, url.QueryEscape(k)+"=") || strings.Contains(u.RawQuery, k+"="), "source_uri")
	}
	value := func(k, d string) string {
		if v, ok := q[k]; ok {
			return v[0]
		}
		return d
	}
	port := 443
	if u.Scheme == "vless" || u.Port() != "" {
		port, e = strconv.Atoi(u.Port())
		check(e == nil && port > 0 && port <= 65535, "source_port")
	}
	name := u.Fragment
	check(validText(name, 128), "source_title")
	if strings.TrimSpace(name) == "" {
		name = "Импортированное подключение"
	}
	sni := value("sni", u.Hostname())
	host(sni)
	check(member(value("allowInsecure", "0"), "0", "false") && member(value("insecure", "0"), "0", "false"), "source_tls_required")
	if u.Scheme != "vless" {
		for k := range q {
			check(member(k, "sni", "insecure", "allowInsecure", "alpn", "fm"), "source_unknown_parameter")
		}
		auth, e := url.PathUnescape(u.User.String())
		check(e == nil && auth != "" && validText(auth, 8192), "source_auth")
		check(value("alpn", "h3") == "h3", "source_alpn")
		stream := object{"network": "hysteria", "security": "tls", "tlsSettings": object{"serverName": sni, "alpn": []any{"h3"}, "allowInsecure": false}, "hysteriaSettings": object{"version": 2, "auth": auth}}
		if fm, ok := q["fm"]; ok {
			mask := obj(strictJSON([]byte(fm[0])))
			hysteriaMask(mask)
			stream["finalmask"] = mask
		}
		return object{"outbound": object{"protocol": "hysteria", "settings": object{"version": 2, "address": u.Hostname(), "port": port}, "streamSettings": stream}}, name
	}
	_, password := u.User.Password()
	check(!password && uuidPattern.MatchString(u.User.Username()), "source_identity")
	for k := range q {
		check(member(k, "encryption", "flow", "security", "type", "sni", "fp", "pbk", "sid", "spx", "alpn", "allowInsecure", "headerType", "host", "path", "serviceName", "mode", "authority"), "source_unknown_parameter")
	}
	check(value("encryption", "none") == "none" && value("headerType", "none") == "none", "source_unsupported_parameter")
	security, network, flow := value("security", ""), value("type", "tcp"), value("flow", "")
	check(member(security, "tls", "reality"), "source_tls_required")
	check(member(network, "tcp", "raw", "grpc", "xhttp", "ws", "httpupgrade"), "source_transport")
	check(member(flow, "", "xtls-rprx-vision") && (flow == "" || member(network, "tcp", "raw")), "source_flow")
	user := object{"id": strings.ToLower(u.User.Username()), "encryption": "none"}
	if flow != "" {
		user["flow"] = flow
	}
	stream := object{"network": network, "security": security}
	fp := value("fp", "")
	if _, ok := q["fp"]; ok {
		check(regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(fp), "source_fingerprint")
	}
	if security == "reality" {
		check(fp != "" && regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(value("pbk", "")), "source_reality")
		sid := value("sid", "")
		check(regexp.MustCompile(`^(?:[0-9a-fA-F]{2}){0,8}$`).MatchString(sid), "source_reality")
		r := object{"serverName": sni, "fingerprint": fp, "publicKey": value("pbk", ""), "shortId": sid}
		if spx, ok := q["spx"]; ok {
			check(strings.HasPrefix(spx[0], "/"), "source_reality")
			r["spiderX"] = spx[0]
		}
		_, alpn := q["alpn"]
		check(!alpn, "source_alpn")
		stream["realitySettings"] = r
	} else {
		for _, k := range []string{"pbk", "sid", "spx"} {
			_, ok := q[k]
			check(!ok, "source_parameter_mismatch")
		}
		tls := object{"serverName": sni, "allowInsecure": false}
		if fp != "" {
			tls["fingerprint"] = fp
		}
		if a, ok := q["alpn"]; ok {
			values := strings.Split(a[0], ",")
			check(len(values) <= 2, "source_alpn")
			for _, x := range values {
				check(member(x, "h2", "http/1.1"), "source_alpn")
			}
			tls["alpn"] = values
		}
		stream["tlsSettings"] = tls
	}
	deny := func(names ...string) {
		for _, k := range names {
			_, ok := q[k]
			check(!ok, "source_parameter_mismatch")
		}
	}
	switch network {
	case "grpc":
		deny("path", "host")
		mode := value("mode", "gun")
		check(member(mode, "gun", "multi"), "source_transport")
		g := object{"serviceName": value("serviceName", ""), "multiMode": mode == "multi"}
		if v, ok := q["authority"]; ok {
			g["authority"] = v[0]
		}
		stream["grpcSettings"] = g
	case "xhttp", "ws", "httpupgrade":
		deny("serviceName", "authority")
		path := value("path", "/")
		check(strings.HasPrefix(path, "/"), "source_transport")
		s := object{"path": path}
		if network == "xhttp" {
			mode := value("mode", "auto")
			check(member(mode, "auto", "packet-up", "stream-up", "stream-one"), "source_transport")
			s["mode"] = mode
		} else {
			deny("mode")
		}
		if h, ok := q["host"]; ok {
			if network == "ws" {
				s["headers"] = object{"Host": h[0]}
			} else {
				s["host"] = h[0]
			}
		}
		stream[network+"Settings"] = s
	default:
		deny("path", "host", "serviceName", "authority", "mode")
	}
	return object{"outbound": object{"protocol": "vless", "settings": object{"vnext": []any{object{"address": u.Hostname(), "port": port, "users": []any{user}}}}, "streamSettings": stream}}, name
}

func hysteriaMask(m object) {
	keys(m, "quicParams")
	q := obj(m["quicParams"])
	keys(q, "debug", "congestion")
	check(optional(q, "debug", false) == false && member(str(optional(q, "congestion", "reno")), "reno", "bbr"), "source_hysteria_mask")
}

func xray(m object) {
	keys(m, "outbound")
	o := obj(m["outbound"])
	keys(o, "protocol", "settings", "streamSettings", "tag")
	safeOptions(o)
	p := str(o["protocol"])
	check(member(p, "vless", "hysteria"), "source_protocol")
	stream := obj(o["streamSettings"])
	network := str(stream["network"])
	sec := str(stream["security"])
	check(member(sec, "tls", "reality"), "source_tls_required")
	check(member(network, "tcp", "raw", "grpc", "xhttp", "ws", "httpupgrade", "hysteria"), "source_transport")
	s := obj(o["settings"])
	if p == "hysteria" {
		keys(s, "version", "address", "port")
		check(number(s["version"]) == 2 && sec == "tls" && network == "hysteria", "source_hysteria")
		host(str(s["address"]))
		check(number(s["port"]) > 0 && number(s["port"]) <= 65535, "source_port")
		keys(stream, "network", "security", "tlsSettings", "hysteriaSettings", "finalmask")
		h := obj(stream["hysteriaSettings"])
		keys(h, "version", "auth")
		check(number(h["version"]) == 2 && str(h["auth"]) != "" && validText(str(h["auth"]), 8192), "source_auth")
		check(obj(stream["tlsSettings"])["allowInsecure"] == false, "source_tls_required")
		if f, ok := stream["finalmask"]; ok {
			hysteriaMask(obj(f))
		}
		return
	}
	check(network != "hysteria", "source_transport")
	servers := arr(s["vnext"])
	check(len(servers) == 1, "source_vless_servers")
	server := obj(servers[0])
	host(str(server["address"]))
	check(number(server["port"]) > 0 && number(server["port"]) <= 65535, "source_port")
	users := arr(server["users"])
	check(len(users) == 1, "source_vless_users")
	u := obj(users[0])
	check(uuidPattern.MatchString(str(u["id"])) && u["encryption"] == "none", "source_identity")
}

// URI conversion uses typed numeric fields internally; normalize through the
// strict decoder before applying the same validator as imported JSON.
func normalizedURI(raw string) (object, string) {
	s, title := uriSettings(raw)
	b, _ := json.Marshal(s)
	s = obj(strictJSON(b))
	xray(s)
	return s, title
}
