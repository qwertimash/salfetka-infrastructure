"""Offline routing validation. No network, VPN lifecycle, or source mutation."""
import hashlib
import ipaddress
import json
import re
import unicodedata

from subscription_catalog import strict_json

MAX_BYTES = 512 * 1024
MAX_RULES = 256
MAX_PRESETS = 32
MAX_EXPANDED = 4096
ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
TAG = re.compile(r"[a-z0-9_!-]{1,64}\Z")
UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z")


class RoutingError(ValueError):
    def __init__(self):
        super().__init__("invalid_routing")


def require(value):
    if not value:
        raise RoutingError()


def exact(value, required, optional=()):
    require(isinstance(value, dict) and set(required) <= set(value) <= set(required) | set(optional))


def load(raw):
    try:
        require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BYTES)
        value = strict_json(raw)

        def bounds(item, depth=0):
            require(depth <= 32)
            if isinstance(item, dict):
                for key, child in item.items():
                    bounds(key, depth + 1)
                    bounds(child, depth + 1)
            elif isinstance(item, list):
                for child in item:
                    bounds(child, depth + 1)
            elif isinstance(item, str):
                item.encode("utf-8")
        bounds(value)
        return value
    except Exception:
        raise RoutingError() from None


def valid_id(value):
    return isinstance(value, str) and ID.fullmatch(value) is not None


def matcher(value, service=False):
    exact(value, {"type", "value"})
    kind, text = value["type"], value["value"]
    require(isinstance(text, str) and isinstance(kind, str))
    if kind in {"domain_exact", "domain_suffix"}:
        require(0 < len(text) <= 253 and text.isascii() and text.lower() == text)
        require(all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in text.split(".")))
        require(re.fullmatch(r"[0-9.]+", text) is None)
    elif kind == "ip_cidr":
        try:
            prefix = ipaddress.ip_network(text, strict=True)
            require(str(prefix) == text and not (prefix.version == 6 and prefix.network_address.ipv4_mapped))
        except ValueError:
            raise RoutingError() from None
    elif kind in {"geosite", "geoip"}:
        require(TAG.fullmatch(text) is not None)
    elif kind == "service" and service:
        require(valid_id(text))
    else:
        raise RoutingError()


def rules(value, service=False):
    require(isinstance(value, list) and len(value) <= MAX_RULES)
    seen = set()
    for rule in value:
        exact(rule, {"id", "action", "match"})
        require(valid_id(rule["id"]) and rule["id"] not in seen and isinstance(rule["action"], str) and rule["action"] in {"tunnel", "direct"})
        seen.add(rule["id"])
        matcher(rule["match"], service)


def policy(value):
    exact(value, {"id", "title", "default_action", "rules"})
    require(valid_id(value["id"]) and isinstance(value["title"], str) and 0 < len(value["title"]) <= 128)
    require(all(unicodedata.category(char) != "Cc" for char in value["title"]))
    require(value["default_action"] == "tunnel")
    rules(value["rules"])
    return value


def modes(value):
    exact(value, (), {"vpn", "bypass"})
    require(bool(value))
    for item in value.values():
        policy(item)
    return value


def preferences(value):
    if "source_mode" in value:
        require(isinstance(value["source_mode"], str) and value["source_mode"] in {"subscription", "overlay", "personal"})
    exact(value, {"format", "version", "subscription_id", "mode", "revision", "default_action", "presets", "overrides"}, {"android_apps", "source_mode"})
    require(value["format"] == "salfetka.routing_preferences" and type(value["version"]) is int and value["version"] == 1)
    require(isinstance(value["subscription_id"], str) and UUID.fullmatch(value["subscription_id"]))
    require(isinstance(value["mode"], str) and value["mode"] in {"vpn", "bypass"} and type(value["revision"]) is int and 1 <= value["revision"] <= 2**63 - 1)
    require(value["default_action"] == "tunnel" and isinstance(value["presets"], list) and len(value["presets"]) <= MAX_PRESETS)
    seen = set()
    for ref in value["presets"]:
        exact(ref, {"id", "revision"})
        require(valid_id(ref["id"]) and ref["id"] not in seen and type(ref["revision"]) is int and 1 <= ref["revision"] <= 2**63 - 1)
        seen.add(ref["id"])
    rules(value["overrides"], service=True)
    if "android_apps" in value:
        apps = value["android_apps"]
        exact(apps, {"mode", "packages"})
        require(apps["mode"] == "exclude" and isinstance(apps["packages"], list) and len(apps["packages"]) <= MAX_RULES)
        require(all(isinstance(pkg, str) and len(pkg) <= 255 and PACKAGE.fullmatch(pkg) for pkg in apps["packages"]))
        require(len(set(apps["packages"])) == len(apps["packages"]))
    return value


def fingerprint(value):
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return hashlib.sha256(canonical.encode()).hexdigest()


def manifest_authorities(manifest):
    portable = modes(manifest["routing"]) if "routing" in manifest else {}
    authorities = {}
    for connection in manifest["connections"]:
        mode = "vpn" if connection["engine"] == "xray" else "bypass"
        authority = native_authority(connection["settings"], connection.get("routing_role"))
        if mode in portable:
            require(authority == "user")
            authority = "source"
        require(mode not in authorities or authorities[mode] == authority)
        authorities[mode] = authority
    require(set(portable) <= set(authorities))
    return authorities


def native_authority(settings, role=None):
    require(isinstance(settings, dict) and (role is None or role == "transport_only"))
    if "xray_config" not in settings:
        require(role is None)
        return "user"
    config = settings["xray_config"]
    require(isinstance(config, dict))
    if role is not None:
        transport_only(config)
        return "user"
    return "source" if "routing" in config else "user"


def transport_only(config):
    require(isinstance(config, dict) and isinstance(config.get("outbounds"), list) and bool(config["outbounds"]))
    protocols = {}
    for out in config["outbounds"]:
        require(isinstance(out, dict) and isinstance(out.get("tag"), str) and out["tag"] and out["tag"] not in protocols)
        require(isinstance(out.get("protocol"), str))
        protocols[out["tag"]] = out.get("protocol")

    def remote(tag):
        return isinstance(tag, str) and protocols.get(tag) in {"vless", "hysteria"}
    require(remote(config["outbounds"][0]["tag"]))
    routing = config.get("routing")
    exact(routing, {"rules"}, {"balancers", "domainStrategy", "domainMatcher"})
    balancers = routing.get("balancers", [])
    require(isinstance(balancers, list) and len(balancers) <= 32)
    known = set()
    for balancer in balancers:
        require(isinstance(balancer, dict) and isinstance(balancer.get("tag"), str) and balancer["tag"] and balancer["tag"] not in known)
        selectors = balancer.get("selector")
        require(isinstance(selectors, list) and bool(selectors) and all(isinstance(s, str) and s for s in selectors))
        selected = [tag for tag in protocols if any(tag.startswith(prefix) for prefix in selectors)]
        require(bool(selected) and all(remote(tag) for tag in selected))
        if "fallbackTag" in balancer:
            require(remote(balancer["fallbackTag"]))
        known.add(balancer["tag"])
    dns = config.get("dns", {})
    require(isinstance(dns, dict))
    require(isinstance(dns.get("servers", []), list))
    dns_tags = set()
    for owner in [dns] + [server for server in dns.get("servers", []) if isinstance(server, dict)]:
        if "tag" in owner:
            require(isinstance(owner["tag"], str) and owner["tag"])
            dns_tags.add(owner["tag"])
    inbounds = config.get("inbounds", [])
    require(isinstance(inbounds, list) and all(isinstance(item, dict) and ("tag" not in item or isinstance(item["tag"], str)) and item.get("tag") not in dns_tags for item in inbounds))
    require(isinstance(routing["rules"], list) and 1 <= len(routing["rules"]) <= 33)
    for index, rule in enumerate(routing["rules"]):
        technical = index < len(routing["rules"]) - 1
        exact(rule, {"inboundTag"} if technical else (), {"type", "outboundTag", "balancerTag"} | (set() if technical else {"network"}))
        if "network" in rule:
            require(not technical and rule["network"] == "tcp,udp")
        if technical:
            tags = rule["inboundTag"]
            require(isinstance(tags, list) and 1 <= len(tags) <= 16 and all(isinstance(tag, str) and tag in dns_tags for tag in tags))
            require(len(set(tags)) == len(tags))
        require(rule.get("type", "field") == "field")
        require(("outboundTag" in rule) != ("balancerTag" in rule))
        if "outboundTag" in rule:
            tag = rule["outboundTag"]
            require(remote(tag) or technical and isinstance(tag, str) and protocols.get(tag) == "freedom")
        else:
            require(isinstance(rule["balancerTag"], str) and rule["balancerTag"] in known)
