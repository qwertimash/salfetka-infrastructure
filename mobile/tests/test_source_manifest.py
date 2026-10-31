"""Offline, synthetic builder/semantic/privacy/filesystem regression tests."""
import contextlib
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

MOBILE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MOBILE / "scripts"))
import source_manifest as builder

NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)


def sources():
    sample = json.loads((MOBILE / "tests/fixtures/subscription-manifest.json").read_text())
    native = {}
    profiles = []
    for connection in sample["connections"]:
        if "xray_config" in connection["settings"]:
            native[connection["id"]] = copy.deepcopy(connection["settings"]["xray_config"])
        else:
            engine = connection["engine"]
            profiles.append({"id": connection["id"], "name": "Synthetic source profile",
                             "mode": "vpn" if engine == "xray" else "bypass",
                             "exit_country": "FI" if engine == "xray" else "DE", "engine": engine,
                             "settings": copy.deepcopy(connection["settings"])})
    lab = {"schema_version": 1, "catalog_id": "synthetic-lab", "revision": 1,
           "expires_at": sample["valid_until"], "profiles": profiles,
           "dns_servers": sample["network"]["dns_servers"], "probe": sample["network"]["probe"]}
    mapping = {"mapping_version": 1, "id": sample["id"], "revision": sample["revision"],
               "subscription": sample["subscription"], "locations": sample["locations"],
               "native_connection_ids": list(native)}
    return lab, mapping, native, sample


class SourceManifestTests(unittest.TestCase):
    def test_account_session_survives_builder_without_coercion(self):
        lab, mapping, native, _ = sources()
        settings = next(p['settings'] for p in lab['profiles'] if p['engine'] == 'olcrtc')
        settings.update(transport='vp8channel', account_session=True)
        raw, _ = builder.build_manifest(lab, mapping, native, NOW)
        parsed = json.loads(raw)
        actual = next(p['settings'] for p in parsed['connections'] if p['engine'] == 'olcrtc')
        self.assertIs(actual['account_session'], True)
        for invalid in ['true', 1, None]:
            settings['account_session'] = invalid
            with self.assertRaises(ValueError): builder.build_manifest(lab, mapping, native, NOW)
        settings.update(account_session=True, transport='datachannel')
        with self.assertRaises(ValueError): builder.build_manifest(lab, mapping, native, NOW)

    def setUp(self):
        self.lab, self.mapping, self.native, self.sample = sources()

    def build(self, lab=None, mapping=None, native=None):
        return builder.build_manifest(lab or self.lab, mapping or self.mapping,
                                      self.native if native is None else native, NOW)

    def no_native(self):
        self.mapping.pop("native_connection_ids")
        self.mapping["locations"] = self.mapping["locations"][1:]

    def test_roundtrip_preserves_all_profiles_explicit_groups_and_exact_native_policy(self):
        payload, receipt = self.build()
        manifest = builder.load_json(payload)
        self.assertEqual(manifest["locations"], self.mapping["locations"])
        self.assertEqual(manifest["network"], self.sample["network"])
        records = {record["id"]: record for record in manifest["connections"]}
        for profile in self.lab["profiles"]:
            self.assertEqual(records[profile["id"]]["settings"], profile["settings"])
        native_id = self.mapping["native_connection_ids"][0]
        self.assertEqual(records[native_id]["settings"]["xray_config"], self.native[native_id])
        self.assertEqual(receipt["hashes"]["payload"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(receipt["runtime_validation"], "NOT_PERFORMED")

    def test_no_auto_country_title_or_flag_is_inferred_from_lab_profiles(self):
        self.no_native()
        for profile in self.lab["profiles"]:
            profile["name"] = "Авто Германия 🇩🇪"
            profile["exit_country"] = "DE"
        raw, _ = self.build(native={})
        self.assertEqual(builder.load_json(raw)["locations"], self.mapping["locations"])
        self.assertFalse(any(location["kind"] == "auto" for location in builder.load_json(raw)["locations"]))
        self.assertEqual(len(builder.load_json(raw)["locations"]), 3)

    def test_four_variants_only_grouped_by_explicit_members_in_source_order(self):
        self.no_native()
        location = self.mapping["locations"][0]
        for suffix in ["hy2", "xhttp"]:
            profile = copy.deepcopy(self.lab["profiles"][0])
            profile["id"] = "synthetic-extra-" + suffix
            self.lab["profiles"].append(profile)
            location["connection_ids"].insert(0, profile["id"])
        raw, _ = self.build(native={})
        self.assertEqual(builder.load_json(raw)["locations"][0]["connection_ids"], location["connection_ids"])
        self.assertEqual(len(builder.load_json(raw)["connections"]), 6)

    def test_lease_is_preserved_but_never_becomes_unknown_paid_expiry_or_traffic(self):
        self.mapping["subscription"] = {"title": "Synthetic subscription"}
        raw, receipt = self.build()
        value = builder.load_json(raw)
        self.assertEqual(value["valid_until"], self.lab["expires_at"])
        self.assertNotIn("expires_at", value["subscription"])
        self.assertNotIn("traffic", value["subscription"])
        self.assertEqual(receipt["provenance"]["subscription_expiry"], "unknown")

    def test_duplicate_missing_cross_mode_members_and_duplicate_locations_fail_atomically(self):
        for failure in ["duplicate-member", "missing-member", "wrong-mode", "duplicate-location"]:
            mapping = copy.deepcopy(self.mapping)
            location = mapping["locations"][1]
            if failure == "duplicate-member":
                location["connection_ids"].append(location["connection_ids"][0])
            elif failure == "missing-member":
                location["connection_ids"] = ["private-not-present"]
            elif failure == "wrong-mode":
                location["mode"] = "bypass"
            else:
                mapping["locations"].append(copy.deepcopy(location))
            with self.subTest(failure=failure), self.assertRaises(builder.ManifestError):
                self.build(mapping=mapping)

    def test_native_source_is_explicit_and_record_collisions_never_replace_lab_settings(self):
        with self.assertRaises(builder.ManifestError):
            builder.build_manifest(self.lab, self.mapping, None, NOW)
        for ids in [["missing"], [self.lab["profiles"][0]["id"]], ["same", "same"]]:
            mapping = copy.deepcopy(self.mapping); mapping["native_connection_ids"] = ids
            with self.subTest(count=len(ids)), self.assertRaises(builder.ManifestError):
                self.build(mapping=mapping)
        self.native["unselected-exact-record"] = copy.deepcopy(next(iter(self.native.values())))
        raw, _ = self.build()
        self.assertNotIn("unselected-exact-record", {record["id"] for record in builder.load_json(raw)["connections"]})

    def test_native_selection_requires_one_full_config_and_source_auto_routing(self):
        for members in [[self.lab["profiles"][0]["id"]], list(self.native) + [self.lab["profiles"][0]["id"]]]:
            mapping = copy.deepcopy(self.mapping); mapping["locations"][0]["connection_ids"] = members
            with self.assertRaises(builder.ManifestError):
                self.build(mapping=mapping)
        native = copy.deepcopy(self.native); next(iter(native.values()))["routing"].pop("balancers")
        with self.assertRaises(builder.ManifestError):
            self.build(native=native)
        native = copy.deepcopy(self.native); next(iter(native.values()))["routing"]["rules"] = []
        with self.assertRaises(builder.ManifestError):
            self.build(native=native)

    def test_least_ping_and_least_load_selectors_tags_fallback_dns_are_preserved(self):
        for strategy in ["leastPing", "leastLoad"]:
            native = copy.deepcopy(self.native)
            config = next(iter(native.values()))
            config["routing"]["balancers"][0]["strategy"]["type"] = strategy
            raw, _ = self.build(native=native)
            record = next(record for record in builder.load_json(raw)["connections"] if "xray_config" in record["settings"])
            self.assertEqual(record["settings"]["xray_config"], config)

    def test_invalid_native_selectors_fallback_strategies_and_observer_fail(self):
        for failure in ["selector", "fallback", "strategy", "observer", "rule", "duplicate-tag"]:
            native = copy.deepcopy(self.native); config = next(iter(native.values()))
            balancer = config["routing"]["balancers"][0]
            if failure == "selector": balancer["selector"] = ["not-a-host-tag"]
            elif failure == "fallback": balancer["fallbackTag"] = "not-a-host-tag"
            elif failure == "strategy": balancer["strategy"]["type"] = "leastoad"
            elif failure == "observer": config.pop("observatory")
            elif failure == "rule": config["routing"]["rules"][0]["balancerTag"] = "not-a-balancer"
            else: config["outbounds"][1]["tag"] = config["outbounds"][0]["tag"]
            with self.subTest(failure=failure), self.assertRaises(builder.ManifestError):
                self.build(native=native)

    def test_native_display_fields_are_removed_but_runtime_fields_are_never_rewritten(self):
        config = next(iter(self.native.values()))
        config.update({"remarks": "Private display name", "meta": {"title": "Private"}, "remnawave": {}})
        raw, receipt = self.build()
        value = next(record["settings"]["xray_config"] for record in builder.load_json(raw)["connections"] if "xray_config" in record["settings"])
        self.assertEqual(value, {key: value for key, value in config.items() if key not in builder.PRESENTATION_FIELDS})
        self.assertEqual(receipt["counts"]["removed_native_presentation_fields"], 3)

    def test_unsafe_native_fields_tls_files_logging_and_inconsistent_ingress_rejected(self):
        for failure in ["unknown", "tls", "file", "log", "ingress"]:
            native = copy.deepcopy(self.native); config = next(iter(native.values()))
            if failure == "unknown": config["api"] = {"tag": "private"}
            elif failure == "tls": config["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"] = True
            elif failure == "file": config["outbounds"][0]["streamSettings"]["tlsSettings"]["certificateFile"] = "/private/key"
            elif failure == "log": config["log"] = {"access": "/private/log"}
            else: config["inbounds"] = [{"protocol": "socks", "sniffing": {"destOverride": ["http"]}}, {"protocol": "http", "sniffing": {"destOverride": ["tls"]}}]
            with self.subTest(failure=failure), self.assertRaises(builder.ManifestError):
                self.build(native=native)

    def test_group_cannot_mix_native_source_dns_and_legacy_dns_members(self):
        mapping = copy.deepcopy(self.mapping)
        mapping["locations"][1]["connection_ids"].append(next(iter(self.native)))
        with self.assertRaisesRegex(builder.ManifestError, "location_dns_mixed"):
            self.build(mapping=mapping)
        # Two exact native configs sharing source DNS capabilities are valid;
        # source first_working order is kept instead of inventing a new policy.
        native_id = "synthetic-second-native"
        self.native[native_id] = copy.deepcopy(next(iter(self.native.values())))
        mapping = copy.deepcopy(self.mapping)
        mapping["native_connection_ids"].append(native_id)
        mapping["locations"][0]["selection"] = {"type": "first_working"}
        mapping["locations"][0]["connection_ids"].append(native_id)
        self.build(mapping=mapping)

    def test_schema_unknown_fields_float_integer_limits_and_traffic_ambiguity_rejected(self):
        for failure in ["unknown", "float-revision", "float-counter", "overflow", "scopes", "duplicate-scope", "unlimited-limit", "unknown-selection"]:
            mapping = copy.deepcopy(self.mapping)
            metadata = mapping["subscription"]
            if failure == "unknown": metadata["unrecognized"] = "private value"
            elif failure == "float-revision": mapping["revision"] = 1.0
            elif failure == "float-counter": metadata["traffic"][0]["upload_bytes"] = 1.0
            elif failure == "overflow": metadata["traffic"][0]["upload_bytes"] = 2**64
            elif failure == "scopes": metadata["traffic"].append({"scope": "vpn"})
            elif failure == "duplicate-scope": metadata["traffic"].append({"scope": "subscription"})
            elif failure == "unlimited-limit": metadata["traffic"][0]["unlimited"] = True
            else: mapping["locations"][0]["selection"]["type"] = "guess_best"
            with self.subTest(failure=failure), self.assertRaises(builder.ManifestError):
                self.build(mapping=mapping)

    def test_schema_formats_dates_expired_access_and_probe_constraints_rejected(self):
        for failure in ["no-timezone", "bad-calendar", "expired-paid", "expired-lease", "probe-query", "probe-ip"]:
            lab, mapping = copy.deepcopy(self.lab), copy.deepcopy(self.mapping)
            if failure == "no-timezone": mapping["subscription"]["expires_at"] = "2030-12-01T00:00:00"
            elif failure == "bad-calendar": mapping["subscription"]["expires_at"] = "2030-02-31T00:00:00Z"
            elif failure == "expired-paid": mapping["subscription"]["expires_at"] = "2020-01-01T00:00:00Z"
            elif failure == "expired-lease": lab["expires_at"] = "2020-01-01T00:00:00Z"
            elif failure == "probe-query": lab["probe"]["url"] += "?private=token"
            else: lab["probe"]["ipv4"] = "not-an-ip"
            with self.subTest(failure=failure), self.assertRaises(builder.ManifestError):
                self.build(lab=lab, mapping=mapping)

    def test_json_duplicates_unicode_nonfinite_depth_and_bytes_are_bounded(self):
        for raw in [b'{"private":1,"private":2}', b'{"value":NaN}', b'{"value":1e999}', b'{"value":"\\ud800"}',
                    b'[' * 34 + b'0' + b']' * 34, b' ' * (builder.MAX_BYTES + 1)]:
            with self.subTest(length=len(raw)), self.assertRaises(builder.ManifestError):
                builder.load_json(raw)
        native = copy.deepcopy(self.native); next(iter(native.values()))["dns"]["hosts"] = {"large.example.invalid": "x" * builder.MAX_BYTES}
        with self.assertRaisesRegex(builder.ManifestError, "output_size"):
            self.build(native=native)

    def test_receipt_and_rejections_never_include_private_names_accesses_paths_or_exception_values(self):
        raw, receipt = self.build()
        text = builder.canonical(receipt).decode()
        for secret in [self.sample["subscription"]["title"], "tcp.example.invalid", "synthetic-test-secret-do-not-use", "00000000-0000-4000-8000-000000000001"]:
            self.assertNotIn(secret, text)
        self.assertEqual(raw, self.build()[0])
        self.assertEqual(receipt, self.build()[1])
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            status = builder.main(["--unknown-private-argument", "DO_NOT_LOG_THIS"])
        self.assertEqual(status, 1)
        self.assertNotIn("DO_NOT_LOG_THIS", capture.getvalue())
        self.assertNotIn("Traceback", capture.getvalue())


class PrivateManifestIOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.private = Path(self.temp.name)
        self.scope = patch.object(builder, "PRIVATE", self.private)
        self.scope.start()
        self.lab, self.mapping, self.native, _ = sources()

    def tearDown(self):
        self.scope.stop(); self.temp.cleanup()

    def write(self, name, value):
        path = self.private / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(builder.canonical(value)); path.chmod(0o600)
        return path

    def args(self, output="candidate.json", receipt="receipt.json"):
        return ["--lab-catalog", str(self.write("lab.json", self.lab)), "--mapping", str(self.write("mapping.json", self.mapping)),
                "--native-source", str(self.write("native.json", self.native)), "--output", str(self.private / output),
                "--receipt", str(self.private / receipt)]

    def test_cli_private_candidate_and_receipt_have_0600_permissions_exact_hash_and_safe_stdout(self):
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture): status = builder.main(self.args())
        self.assertEqual(status, 0)
        for name in ["candidate.json", "receipt.json"]:
            self.assertEqual(stat.S_IMODE((self.private / name).stat().st_mode), 0o600)
        receipt = builder.load_json((self.private / "receipt.json").read_bytes())
        self.assertEqual(receipt["hashes"]["payload"], hashlib.sha256((self.private / "candidate.json").read_bytes()).hexdigest())
        self.assertEqual(json.loads(capture.getvalue()), receipt)
        self.assertNotIn(str(self.private), capture.getvalue())

    def test_input_permissions_outside_paths_and_symlink_components_are_refused(self):
        path = self.write("lab.json", self.lab); path.chmod(0o644)
        with self.assertRaisesRegex(builder.ManifestError, "input_permissions"): builder.private_read(path)
        with self.assertRaisesRegex(builder.ManifestError, "path_outside_private"): builder.private_read(self.private.parent / "outside.json")
        path.chmod(0o600)
        (self.private / "link.json").symlink_to(path)
        with self.assertRaises(OSError): builder.private_read(self.private / "link.json")
        (self.private / "linked-parent").symlink_to(self.private, target_is_directory=True)
        with self.assertRaises(OSError): builder.private_read(self.private / "linked-parent/lab.json")

    def test_existing_output_or_receipt_is_not_overwritten_and_partial_candidate_rolls_back(self):
        payload, receipt = builder.build_manifest(self.lab, self.mapping, self.native, NOW)
        output, receipt_path = self.private / "candidate.json", self.private / "receipt.json"
        output.write_bytes(b"owner previous candidate")
        with self.assertRaises(FileExistsError): builder.private_pair(output, payload, receipt_path, receipt)
        self.assertEqual(output.read_bytes(), b"owner previous candidate")
        self.assertFalse(receipt_path.exists())
        output.unlink(); receipt_path.write_bytes(b"owner previous receipt")
        with self.assertRaises(FileExistsError): builder.private_pair(output, payload, receipt_path, receipt)
        self.assertFalse(output.exists())
        self.assertEqual(receipt_path.read_bytes(), b"owner previous receipt")
        self.assertFalse(any(path.name.startswith(".source-manifest-") for path in self.private.iterdir()))

    def test_invalid_cli_source_writes_neither_candidate_nor_receipt_and_logs_no_values(self):
        args = self.args()
        self.mapping["locations"][0]["title"] = "PRIVATE\u0000TITLE"
        self.write("mapping.json", self.mapping)
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture): status = builder.main(args)
        self.assertEqual(status, 1)
        self.assertFalse((self.private / "candidate.json").exists())
        self.assertFalse((self.private / "receipt.json").exists())
        self.assertNotIn("PRIVATE", capture.getvalue())
        self.assertNotIn(str(self.private), capture.getvalue())

    def test_output_scope_collision_symlink_and_nonregular_input_are_refused(self):
        payload, receipt = builder.build_manifest(self.lab, self.mapping, self.native, NOW)
        with self.assertRaisesRegex(builder.ManifestError, "output_collision"):
            builder.private_pair(self.private / "same", payload, self.private / "same", receipt)
        with self.assertRaisesRegex(builder.ManifestError, "path_outside_private"):
            builder.private_pair(self.private.parent / "outside.json", payload, self.private / "receipt", receipt)
        target = self.write("protected.json", {"owner": True})
        (self.private / "linked-output.json").symlink_to(target)
        with self.assertRaises(FileExistsError):
            builder.private_pair(self.private / "linked-output.json", payload, self.private / "receipt", receipt)
        self.assertEqual(builder.load_json(target.read_bytes()), {"owner": True})
        fifo = self.private / "fifo"; os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(builder.ManifestError, "input_permissions"): builder.private_read(fifo)


if __name__ == "__main__":
    unittest.main()
