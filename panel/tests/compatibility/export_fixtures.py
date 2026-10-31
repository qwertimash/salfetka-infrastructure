"""Regenerate/check the B0 synthetic oracle. Never reads private catalog files."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from mobile.tests.test_source_manifest import sources, builder, NOW


def build():
    cases = []
    for name in ("full_v1", "native_display", "least_load", "unknown_paid_expiry",
                 "explicit_order", "v2_transport_only", "v2_source_empty_rules"):
        lab, mapping, native, _ = sources()
        first = next(iter(native.values()))
        if name == "native_display":
            first.update(remarks="Синтетика <>&", meta={"display": "synthetic"})
        if name == "least_load":
            first["routing"]["balancers"][0]["strategy"]["type"] = "leastLoad"
        if name == "unknown_paid_expiry":
            mapping["subscription"] = {"title": "Unknown paid expiry and traffic"}
        if name == "explicit_order":
            lab["profiles"].reverse()
            mapping["locations"].reverse()
            for location in mapping["locations"]:
                location["connection_ids"].reverse()
        raw, _ = builder.build_manifest(lab, mapping, native, NOW)
        request = {"lab": lab, "mapping": mapping, "native": native, "version": 1,
                   "transport_only_ids": []}
        if name.startswith("v2_"):
            request["version"] = 2
            request["transport_only_ids"] = mapping["native_connection_ids"]
            options = {"transport_only_ids": request["transport_only_ids"], "now": NOW}
            if name == "v2_source_empty_rules":
                request["routing"] = {"vpn": {"id": "empty", "title": "Правила подписки",
                                    "default_action": "tunnel", "rules": []}}
                options["routing"] = request["routing"]
            raw, _ = builder.build_routing_candidate(builder.load_json(raw), **options)
        cases.append({"name": name, "input": request, "expected": builder.load_json(raw)})
    files = ["panel/tests/compatibility/export_fixtures.py", "mobile/tests/test_source_manifest.py",
             "mobile/scripts/source_manifest.py", "mobile/scripts/subscription_catalog.py",
             "mobile/scripts/routing_contract.py", "mobile/tests/fixtures/subscription-manifest.json",
             "mobile/contracts/subscription-manifest.schema.json",
             "mobile/contracts/subscription-manifest-v2.schema.json",
             "mobile/contracts/routing-policy.schema.json"]
    return {"scope": "B0 semantic-preservation spike; not a production validator/compiler",
            "source_hashes": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files},
            "cases": cases}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Explicitly refresh the checked-in synthetic oracle")
    args = parser.parse_args()
    path = Path(__file__).with_name("fixtures.json")
    data = (json.dumps(build(), ensure_ascii=False, indent=2) + "\n").encode()
    if args.write:
        path.write_bytes(data)
    elif not path.is_file() or path.read_bytes() != data:
        sys.exit("B0 golden/source drift: inspect before explicitly regenerating")
    print("B0 golden: 7 complete synthetic cases match current Python oracle")
