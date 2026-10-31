#!/usr/bin/env python3
"""Offline candidate builder: lab-v1 + explicit sidecar + exact native records.

No HTTP, device registration or production publication occurs here. JSON Schema
and cross-reference checks are not a substitute for the pinned engine validators.
"""
import argparse
import collections
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import stat
import sys
from urllib.parse import urlsplit

from subscription_catalog import MAX_BYTES, ID, strict_json, validate_catalog

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = ROOT / "mobile/private"
SCHEMA = ROOT / "mobile/contracts/subscription-manifest.schema.json"
SCHEMA_V2 = ROOT / "mobile/contracts/subscription-manifest-v2.schema.json"
MAX_DEPTH = 32
NATIVE_FIELDS = {"outbounds", "routing", "dns", "policy", "stats", "observatory",
                 "burstObservatory", "inbounds", "log"}
PRESENTATION_FIELDS = {"remarks", "meta", "remnawave"}
UNSAFE_OPTIONS = {"certificatefile", "keyfile", "cafile", "masterkeylog", "sockopt",
                  "fakedns", "proxysettings", "dialerproxy"}
ABSENT_ROUTING = object()


class ManifestError(ValueError):
    """Fixed categories only; source values must never enter the exception."""


def require(condition, code):
    if not condition:
        raise ManifestError(code)


def bounds(value, depth=0):
    require(depth <= MAX_DEPTH, "json_depth")
    if isinstance(value, dict):
        for key, item in value.items():
            require(isinstance(key, str), "json_key")
            bounds(key, depth + 1)
            bounds(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            bounds(item, depth + 1)
    elif isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise ManifestError("json_unicode") from None
    elif isinstance(value, float):
        require(math.isfinite(value), "json_number")


def canonical(value):
    bounds(value)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ManifestError("json_encoding") from None


def load_json(raw):
    try:
        value = strict_json(raw)
        bounds(value)
        return value
    except ManifestError:
        raise
    except Exception:
        raise ManifestError("invalid_json") from None


def checked_schema(value, schema_path=None):
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError:
        raise ManifestError("jsonschema_dependency_missing") from None
    # Only the offline caller/service configuration chooses this trusted file;
    # requests, tokens and source documents never select a schema.
    selected = SCHEMA_V2 if isinstance(value, dict) and type(value.get("version")) is int and value["version"] == 2 else SCHEMA
    schema = json.loads(Path(schema_path or selected).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    # Do not format ValidationError: it can include credentials/settings.
    require(next(validator.iter_errors(value), None) is None, "manifest_schema")


def identifier(value):
    return isinstance(value, str) and ID.fullmatch(value) is not None


def date(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
        require(result.tzinfo is not None, "date_timezone")
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        raise ManifestError("invalid_date") from None


def native_options(value):
    if isinstance(value, dict):
        for key, child in value.items():
            require(key.lower() not in UNSAFE_OPTIONS, "unsafe_native_option")
            if key.lower() in {"allowinsecure", "allowinsecureifpinnedpeercertificate"}:
                require(child is False, "unsafe_native_tls")
            native_options(child)
    elif isinstance(value, list):
        for child in value:
            native_options(child)


def native_config(source):
    """Keep transport/routing policy verbatim; remove only display metadata."""
    require(isinstance(source, dict) and set(source) <= NATIVE_FIELDS | PRESENTATION_FIELDS,
            "native_top_level")
    for key in {"meta", "remnawave"} & set(source):
        require(isinstance(source[key], dict), "native_metadata")
    config = {key: copy.deepcopy(value) for key, value in source.items() if key not in PRESENTATION_FIELDS}
    bounds(config)
    native_options(config)
    outbounds = config.get("outbounds")
    require(isinstance(outbounds, list) and 1 <= len(outbounds) <= 32, "native_outbounds")
    tags = set()
    for outbound in outbounds:
        require(isinstance(outbound, dict) and isinstance(outbound.get("protocol"), str) and outbound["protocol"] in
                {"vless", "hysteria", "freedom", "blackhole", "dns"}, "native_protocol")
        if "tag" in outbound:
            tag = outbound["tag"]
            require(isinstance(tag, str) and len(tag) <= 128 and
                    all(ord(c) >= 32 and not 127 <= ord(c) <= 159 for c in tag), "native_tag")
            require(not tag or tag not in tags, "native_tag_duplicate")
            if tag:
                tags.add(tag)
    for key in NATIVE_FIELDS - {"outbounds", "inbounds"}:
        if key in config:
            require(isinstance(config[key], dict), "native_field_shape")
    require(not ({"observatory", "burstObservatory"} <= set(config)), "native_observatory_conflict")
    if "inbounds" in config:
        require(isinstance(config["inbounds"], list), "native_ingress")
        sniffing = None
        for entry in config["inbounds"]:
            require(isinstance(entry, dict) and isinstance(entry.get("protocol"), str) and
                    entry["protocol"] in {"socks", "http", "mixed"}, "native_ingress")
            raw = entry.get("sniffing", {})
            require(isinstance(raw, dict), "native_sniffing")
            overrides = raw.get("destOverride", [])
            require(isinstance(overrides, list) and all(isinstance(item, str) and item in {"http", "tls"} for item in overrides), "native_sniffing")
            require(sniffing is None or sniffing == raw, "native_ingress_conflict")
            sniffing = raw
    if "log" in config:
        for key in {"access", "error"} & set(config["log"]):
            require(isinstance(config["log"][key], str) and config["log"][key] in {"", "none"}, "native_file_log")
    routing = config.get("routing", {})
    rules, balancers = routing.get("rules", []), routing.get("balancers", [])
    require(isinstance(rules, list) and isinstance(balancers, list), "native_routing")
    known = set()
    for balancer in balancers:
        require(isinstance(balancer, dict), "native_balancer")
        tag, selectors = balancer.get("tag"), balancer.get("selector")
        strategy = balancer.get("strategy")
        require(isinstance(tag, str) and tag and tag not in known and
                isinstance(selectors, list) and selectors and
                all(isinstance(item, str) and item for item in selectors), "native_balancer")
        require(any(outbound.startswith(selector) for outbound in tags for selector in selectors), "native_selector")
        require(isinstance(strategy, dict) and isinstance(strategy.get("type"), str) and strategy["type"] in
                {"random", "roundRobin", "leastPing", "leastLoad"}, "native_strategy")
        if strategy["type"] in {"leastPing", "leastLoad"}:
            require("observatory" in config or "burstObservatory" in config, "native_observatory_missing")
        if "fallbackTag" in balancer:
            require(isinstance(balancer["fallbackTag"], str) and balancer["fallbackTag"] in tags, "native_fallback")
        known.add(tag)
    has_auto = False
    for rule in rules:
        require(isinstance(rule, dict), "native_rule")
        if "balancerTag" in rule:
            require(isinstance(rule["balancerTag"], str) and rule["balancerTag"] in known, "native_rule_balancer")
            has_auto = True
        if "outboundTag" in rule:
            require(isinstance(rule["outboundTag"], str) and rule["outboundTag"] in tags, "native_rule_outbound")
    return config, has_auto


def validate_manifest(manifest, now, modes, schema_path=None, routing_candidate=False):
    bounds(manifest)
    checked_schema(manifest, schema_path=schema_path)
    require(type(manifest["version"]) is int and type(manifest["revision"]) is int, "manifest_integer")
    require(manifest["version"] == 1 or routing_candidate and manifest["version"] == 2, "manifest_version")
    if manifest["version"] == 2:
        from routing_contract import manifest_authorities, RoutingError
        try:
            manifest_authorities(manifest)
        except (RoutingError, TypeError, KeyError, ValueError):
            raise ManifestError("manifest_routing") from None
    for key, value in manifest["subscription"].items():
        if key == "expires_at":
            require(date(value) > now, "subscription_expired")
    if "valid_until" in manifest:
        require(date(manifest["valid_until"]) > now, "lease_expired")
    traffic = manifest["subscription"].get("traffic", [])
    scopes = [record["scope"] for record in traffic]
    require(len(set(scopes)) == len(scopes) and
            not ("subscription" in scopes and len(scopes) > 1), "traffic_scopes")
    for record in traffic:
        for key in {"upload_bytes", "download_bytes", "limit_bytes"} & set(record):
            require(type(record[key]) is int, "traffic_integer")
    probe = urlsplit(manifest["network"]["probe"]["url"])
    require(probe.scheme == "https" and probe.hostname and not probe.username and
            not probe.password and not probe.query and not probe.fragment, "probe_url")
    require(type(manifest["network"]["probe"]["expected_status"]) is int, "probe_integer")
    records = {}
    auto = {}
    for connection in manifest["connections"]:
        key = connection["id"]
        require(key not in records, "connection_duplicate")
        records[key] = connection
        if "xray_config" in connection["settings"]:
            require(connection["engine"] == "xray" and set(connection["settings"]) == {"xray_config"}, "native_wrapper")
            checked, auto[key] = native_config(connection["settings"]["xray_config"])
            require(checked == connection["settings"]["xray_config"], "native_metadata_in_runtime")
    seen = set()
    for location in manifest["locations"]:
        require(location["id"] not in seen, "location_duplicate")
        seen.add(location["id"])
        members = location["connection_ids"]
        require(all(member in records for member in members), "location_member_missing")
        require(all(modes[member] == location["mode"] for member in members), "location_mode")
        source_dns = {"dns" in records[member]["settings"].get("xray_config", {}) for member in members}
        require(len(source_dns) == 1, "location_dns_mixed")
        if location["selection"]["type"] == "native":
            require(location["mode"] == "vpn" and len(members) == 1 and members[0] in auto, "native_location")
            if location["kind"] == "auto":
                require(auto[members[0]], "native_auto_missing")


def build_manifest(lab, sidecar, native_source=None, now=None):
    now = now or datetime.now(timezone.utc)
    try:
        bounds(lab)
        validate_catalog(lab, now)
    except Exception:
        raise ManifestError("invalid_lab_catalog") from None
    require(isinstance(sidecar, dict) and set(sidecar) <=
            {"mapping_version", "id", "revision", "subscription", "locations", "native_connection_ids"} and
            {"mapping_version", "id", "revision", "subscription", "locations"} <= set(sidecar), "sidecar_fields")
    require(type(sidecar["mapping_version"]) is int and sidecar["mapping_version"] == 1, "sidecar_version")
    native_ids = sidecar.get("native_connection_ids", [])
    require(isinstance(native_ids, list) and all(identifier(key) for key in native_ids) and
            len(native_ids) == len(set(native_ids)), "native_record_ids")
    require(not native_ids or isinstance(native_source, dict), "native_source_missing")
    if native_source is not None:
        require(isinstance(native_source, dict) and all(identifier(key) for key in native_source), "native_source_ids")
    connections = [{"id": profile["id"], "engine": profile["engine"], "settings": copy.deepcopy(profile["settings"])}
                   for profile in lab["profiles"]]
    modes = {profile["id"]: profile["mode"] for profile in lab["profiles"]}
    removed_display_fields = 0
    for key in native_ids:
        require(key in native_source and key not in modes, "native_record_missing_or_collision")
        config, _ = native_config(native_source[key])
        removed_display_fields += len(set(native_source[key]) & PRESENTATION_FIELDS)
        connections.append({"id": key, "engine": "xray", "settings": {"xray_config": config}})
        modes[key] = "vpn"
    manifest = {"format": "salfetka.subscription", "version": 1, "id": sidecar["id"],
                "revision": sidecar["revision"], "subscription": copy.deepcopy(sidecar["subscription"]),
                "valid_until": lab["expires_at"],
                "network": {"dns_servers": copy.deepcopy(lab["dns_servers"]), "probe": copy.deepcopy(lab["probe"])},
                "connections": connections, "locations": copy.deepcopy(sidecar["locations"])}
    validate_manifest(manifest, now, modes)
    payload = canonical(manifest)
    require(len(payload) <= MAX_BYTES, "output_size")
    receipt = {"status": "LOCAL_CANDIDATE_ONLY", "runtime_validation": "NOT_PERFORMED",
               "counts": {"lab_connections": len(lab["profiles"]), "native_connections": len(native_ids),
                          "connections": len(connections), "locations": len(manifest["locations"]),
                          "modes": dict(collections.Counter(location["mode"] for location in manifest["locations"])),
                          "engines": dict(collections.Counter(record["engine"] for record in connections)),
                          "removed_native_presentation_fields": removed_display_fields},
               "provenance": {"connections": "lab_v1_preserved_plus_explicit_native_ids", "locations": "explicit_sidecar",
                              "metadata": "explicit_sidecar", "lease": "lab_v1_expires_at",
                              "subscription_expiry": "explicit" if "expires_at" in manifest["subscription"] else "unknown"},
               "hashes": {"lab": hashlib.sha256(canonical(lab)).hexdigest(),
                          "sidecar": hashlib.sha256(canonical(sidecar)).hexdigest(),
                          "native_source": hashlib.sha256(canonical(native_source)).hexdigest() if native_source is not None else None,
                          "payload": hashlib.sha256(payload).hexdigest()}, "output_bytes": len(payload)}
    return payload, receipt


def build_routing_candidate(manifest_v1, *, routing=ABSENT_ROUTING,
                            transport_only_ids=(), now=None):
    """Explicit offline v2 copy; native settings and the v1 input stay intact."""
    now = now or datetime.now(timezone.utc)
    require(isinstance(manifest_v1, dict), "routing_input")
    bounds(manifest_v1)
    checked_schema(manifest_v1)
    require(type(manifest_v1["version"]) is int and manifest_v1["version"] == 1, "manifest_version")
    modes = {record["id"]: "vpn" if record["engine"] == "xray" else "bypass"
             for record in manifest_v1.get("connections", [])}
    validate_manifest(manifest_v1, now, modes)
    require(isinstance(transport_only_ids, (list, tuple)) and
            all(identifier(key) for key in transport_only_ids) and
            len(set(transport_only_ids)) == len(transport_only_ids), "transport_only_ids")
    candidate = copy.deepcopy(manifest_v1)
    records = {record["id"]: record for record in candidate["connections"]}
    for key in transport_only_ids:
        record = records.get(key)
        require(record is not None and record["engine"] == "xray" and
                "xray_config" in record["settings"], "transport_only_record")
        record["routing_role"] = "transport_only"
    candidate["version"] = 2
    if routing is not ABSENT_ROUTING:
        require(isinstance(routing, dict), "manifest_routing")
        candidate["routing"] = copy.deepcopy(routing)
    # This rejects destination/direct-fallback policies marked transport_only,
    # mixed authority, explicit null and collisions with source-native rules.
    validate_manifest(candidate, now, modes, routing_candidate=True)
    payload = canonical(candidate)
    require(len(payload) <= MAX_BYTES, "output_size")
    receipt = {"status": "LOCAL_ROUTING_CANDIDATE_ONLY", "runtime_validation": "NOT_PERFORMED",
               "source_version": 1, "candidate_version": 2,
               "explicit_transport_only_count": len(transport_only_ids),
               "portable_routing_modes": sorted(candidate.get("routing", {})),
               "hashes": {"source_v1_payload": hashlib.sha256(canonical(manifest_v1)).hexdigest(),
                          "payload": hashlib.sha256(payload).hexdigest()}, "output_bytes": len(payload)}
    return payload, receipt


def private_parent(path, create=False):
    """Directory-descriptor walk refuses symlinks, including intermediate dirs."""
    root = Path(os.path.abspath(PRIVATE))
    path = Path(os.path.abspath(path))
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        raise ManifestError("path_outside_private") from None
    require(bool(parts), "path_not_file")
    if create:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        for component in parts[:-1]:
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd); fd = child
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def private_read(path):
    parent, name = private_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
                    info.st_uid == os.getuid(), "input_permissions")
            require(0 < info.st_size <= MAX_BYTES, "input_size")
            raw = stream.read(MAX_BYTES + 1)
            require(0 < len(raw) <= MAX_BYTES, "input_size")
            return raw
    finally:
        os.close(parent)


def private_pair(output, payload, receipt_path, receipt):
    require(os.path.abspath(output) != os.path.abspath(receipt_path), "output_collision")
    staged, published = [], []
    try:
        for path, data in [(output, payload), (receipt_path, canonical(receipt))]:
            parent, name = private_parent(path, create=True)
            temporary = ".source-manifest-" + secrets.token_hex(12)
            staged.append((parent, temporary, name))
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
        for parent, temporary, name in staged:
            os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            published.append((parent, temporary, name))
            os.fsync(parent)
    except BaseException:
        # Roll back only names still pointing at this invocation's own inode.
        for parent, temporary, name in published:
            if os.stat(name, dir_fd=parent, follow_symlinks=False).st_ino == os.stat(temporary, dir_fd=parent, follow_symlinks=False).st_ino:
                os.unlink(name, dir_fd=parent)
        raise
    finally:
        for parent, temporary, _ in staged:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ManifestError("cli_arguments")


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--lab-catalog", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--native-source", type=Path)
    parser.add_argument("--routing-candidate", action="store_true")
    parser.add_argument("--routing-policy", type=Path)
    parser.add_argument("--transport-only", action="append", default=[], metavar="CONNECTION_ID")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        require(args.routing_candidate or not args.routing_policy and not args.transport_only,
                "routing_candidate_required")
        lab = load_json(private_read(args.lab_catalog))
        mapping = load_json(private_read(args.mapping))
        native = load_json(private_read(args.native_source)) if args.native_source else None
        payload, receipt = build_manifest(lab, mapping, native)
        if args.routing_candidate:
            policy = load_json(private_read(args.routing_policy)) if args.routing_policy else ABSENT_ROUTING
            payload, routing_receipt = build_routing_candidate(load_json(payload), routing=policy,
                                                               transport_only_ids=args.transport_only)
            receipt["routing_candidate"] = routing_receipt
            receipt["hashes"]["source_v1_payload"] = receipt["hashes"]["payload"]
            receipt["hashes"]["payload"] = routing_receipt["hashes"]["payload"]
            receipt["output_bytes"] = len(payload)
            receipt["status"] = routing_receipt["status"]
        private_pair(args.output, payload, args.receipt, receipt)
        print(canonical(receipt).decode("utf-8").strip())
        return 0
    except ManifestError as error:
        print(json.dumps({"status": "SOURCE_MANIFEST_FAILED", "category": str(error)}))
        return 1
    except Exception:
        # Neither OS paths nor library exceptions are safe source diagnostics.
        print('{"status":"SOURCE_MANIFEST_FAILED","category":"private_io_or_validation"}')
        return 1


if __name__ == "__main__":
    sys.exit(main())
