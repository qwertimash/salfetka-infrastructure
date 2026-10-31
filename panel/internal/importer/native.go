package importer

import (
	"encoding/json"
	"reflect"
	"strings"
)

func safeOptions(v any) {
	switch m := v.(type) {
	case map[string]any:
		for k, v := range m {
			lower := strings.ToLower(k)
			check(!member(lower, "certificatefile", "keyfile", "cafile", "masterkeylog", "sockopt", "fakedns", "proxysettings", "dialerproxy"), "source_unsafe_option")
			if member(lower, "allowinsecure", "allowinsecureifpinnedpeercertificate") {
				check(v == false, "source_tls_required")
			}
			safeOptions(v)
		}
	case []any:
		for _, v := range m {
			safeOptions(v)
		}
	}
}
func native(m object) (object, bool) {
	keys(m, "outbounds", "routing", "dns", "policy", "stats", "observatory", "burstObservatory", "inbounds", "log", "remarks", "meta", "remnawave")
	n := object{}
	for k, v := range m {
		if member(k, "meta", "remnawave") {
			obj(v)
		}
		if !member(k, "remarks", "meta", "remnawave") {
			n[k] = v
		}
	}
	safeOptions(n)
	outs := arr(n["outbounds"])
	check(len(outs) > 0 && len(outs) <= 32, "source_outbounds")
	tags := map[string]bool{}
	for _, v := range outs {
		o := obj(v)
		check(member(str(o["protocol"]), "vless", "hysteria", "freedom", "blackhole", "dns"), "source_protocol")
		if t, ok := o["tag"]; ok {
			s := str(t)
			check(validText(s, 128) && (!tags[s] || s == ""), "source_tag")
			if s != "" {
				tags[s] = true
			}
		}
	}
	for _, k := range []string{"routing", "dns", "policy", "stats", "observatory", "burstObservatory", "log"} {
		if v, ok := n[k]; ok {
			obj(v)
		}
	}
	_, obs := n["observatory"]
	_, burst := n["burstObservatory"]
	check(!obs || !burst, "source_observatory_conflict")
	if v, ok := n["inbounds"]; ok {
		var prior any
		for _, v := range arr(v) {
			i := obj(v)
			check(member(str(i["protocol"]), "socks", "http", "mixed"), "source_inbound")
			sn := obj(optional(i, "sniffing", object{}))
			for _, x := range arr(optional(sn, "destOverride", []any{})) {
				check(member(str(x), "http", "tls"), "source_sniffing")
			}
			check(prior == nil || reflect.DeepEqual(prior, sn), "source_sniffing_conflict")
			prior = sn
		}
	}
	if v, ok := n["log"]; ok {
		for k, v := range obj(v) {
			if member(k, "access", "error") {
				check(member(str(v), "", "none"), "source_file_log")
			}
		}
	}
	routing := obj(optional(n, "routing", object{}))
	known := map[string]bool{}
	for _, v := range arr(optional(routing, "balancers", []any{})) {
		b := obj(v)
		tag := str(b["tag"])
		check(tag != "" && !known[tag], "source_balancer")
		sel := arr(b["selector"])
		check(len(sel) > 0, "source_selector")
		matched := false
		for _, x := range sel {
			prefix := str(x)
			check(prefix != "", "source_selector")
			for t := range tags {
				matched = matched || strings.HasPrefix(t, prefix)
			}
		}
		check(matched, "source_selector")
		strategy := str(obj(b["strategy"])["type"])
		check(member(strategy, "random", "roundRobin", "leastPing", "leastLoad"), "source_strategy")
		check(!member(strategy, "leastPing", "leastLoad") || obs || burst, "source_observatory_missing")
		if f, ok := b["fallbackTag"]; ok {
			check(tags[str(f)], "source_fallback")
		}
		known[tag] = true
	}
	auto := false
	for _, v := range arr(optional(routing, "rules", []any{})) {
		r := obj(v)
		if t, ok := r["balancerTag"]; ok {
			check(known[str(t)], "source_rule_balancer")
			auto = true
		}
		if t, ok := r["outboundTag"]; ok {
			check(tags[str(t)], "source_rule_outbound")
		}
	}
	return n, auto
}

func transportOnly(c object) {
	outs := arr(c["outbounds"])
	protocols := map[string]string{}
	for _, v := range outs {
		o := obj(v)
		t := str(o["tag"])
		check(t != "" && protocols[t] == "", "source_routing_authority")
		protocols[t] = str(o["protocol"])
	}
	remote := func(v any) bool { s, ok := v.(string); return ok && member(protocols[s], "vless", "hysteria") }
	check(remote(obj(outs[0])["tag"]), "source_routing_authority")
	r := obj(c["routing"])
	keys(r, "rules", "balancers", "domainStrategy", "domainMatcher")
	bs := arr(optional(r, "balancers", []any{}))
	check(len(bs) <= 32, "source_routing_authority")
	known := map[string]bool{}
	for _, v := range bs {
		b := obj(v)
		t := str(b["tag"])
		check(t != "" && !known[t], "source_routing_authority")
		selected := false
		for _, x := range arr(b["selector"]) {
			p := str(x)
			check(p != "", "source_routing_authority")
			for tag := range protocols {
				if strings.HasPrefix(tag, p) {
					check(remote(tag), "source_routing_authority")
					selected = true
				}
			}
		}
		check(selected, "source_routing_authority")
		if f, ok := b["fallbackTag"]; ok {
			check(remote(f), "source_routing_authority")
		}
		known[t] = true
	}
	dns := obj(optional(c, "dns", object{}))
	owners := []object{dns}
	for _, v := range arr(optional(dns, "servers", []any{})) {
		if m, ok := v.(map[string]any); ok {
			owners = append(owners, m)
		}
	}
	dnsTags := map[string]bool{}
	for _, m := range owners {
		if t, ok := m["tag"]; ok {
			check(str(t) != "", "source_routing_authority")
			dnsTags[str(t)] = true
		}
	}
	for _, v := range arr(optional(c, "inbounds", []any{})) {
		i := obj(v)
		if tag, ok := i["tag"]; ok {
			check(!dnsTags[str(tag)], "source_routing_authority")
		}
	}
	rules := arr(r["rules"])
	check(len(rules) > 0 && len(rules) <= 33, "source_routing_authority")
	for i, v := range rules {
		x := obj(v)
		technical := i < len(rules)-1
		if technical {
			keys(x, "inboundTag", "type", "outboundTag", "balancerTag")
			tags := arr(x["inboundTag"])
			check(len(tags) > 0 && len(tags) <= 16, "source_routing_authority")
			seen := map[string]bool{}
			for _, v := range tags {
				t := str(v)
				check(dnsTags[t] && !seen[t], "source_routing_authority")
				seen[t] = true
			}
		} else {
			keys(x, "type", "outboundTag", "balancerTag", "network")
			check(optional(x, "network", "tcp,udp") == "tcp,udp", "source_routing_authority")
		}
		check(optional(x, "type", "field") == "field", "source_routing_authority")
		o, hasO := x["outboundTag"]
		b, hasB := x["balancerTag"]
		check(hasO != hasB, "source_routing_authority")
		if hasO {
			check(remote(o) || technical && protocols[str(o)] == "freedom", "source_routing_authority")
		} else {
			check(known[str(b)], "source_routing_authority")
		}
	}
}

func canonical(v any) json.RawMessage {
	b, e := json.Marshal(v)
	check(e == nil, "source_json")
	return b
}
