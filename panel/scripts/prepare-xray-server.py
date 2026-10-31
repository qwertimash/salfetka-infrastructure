#!/usr/bin/env python3
"""Reproduce a server-only dependency from verified cached sources and pinned patches.
Never downloads, changes the mobile dependency, or replaces a divergent cache.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'panel/third_party/xray-server.lock.json'
BASE = ROOT / 'mobile/artifacts/upstream/xray-core/source'
TARGET = ROOT / 'panel/artifacts/server-sources/xray-core'


def main():
    module = ROOT / 'mobile/scripts/fetch-core-sources.py'
    spec = importlib.util.spec_from_file_location('source_verifier', module)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    lock = json.loads(LOCK.read_text())
    verifier.verify_digest(ROOT / lock['base_contract'], lock['base_contract_sha256'])
    contract = json.loads((ROOT / lock['base_contract']).read_text())
    baseline = verifier.local_path(ROOT, contract['source_lock'])
    verifier.verify_digest(baseline, contract['source_lock_sha256'])
    dependencies = {d['id']: d for d in json.loads(baseline.read_text())['dependencies']}
    verifier.prepare(dependencies['xray-core'], ROOT / 'mobile', True, True)
    verifier.prepare(dependencies['gvisor'], ROOT / 'mobile', True, True)
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    if TARGET.parent.is_symlink() or TARGET.is_symlink():
        raise RuntimeError('server source symlink rejected')
    with tempfile.TemporaryDirectory(prefix='.xray-server-', dir=TARGET.parent) as tmp:
        source = Path(tmp) / 'source'
        shutil.copytree(BASE, source)
        env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(source.parent))
        for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'):
            env.pop(key, None)
        for item in lock['patches']:
            patch = verifier.local_path(ROOT, item['path'])
            if not item['path'].startswith('panel/third_party/patches/xray-server/'):
                raise RuntimeError('patch outside server namespace')
            verifier.verify_digest(patch, item['sha256'])
            for check in (['--check'], []):
                subprocess.run(['git', 'apply', *check, '--whitespace=error-all', str(patch)], cwd=source, env=env, check=True, capture_output=True)
        wanted = verifier.tree(source)
        digest = hashlib.sha256(json.dumps(wanted, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if digest != lock['server_tree_sha256']:
            raise RuntimeError('server tree pin mismatch')
        if TARGET.exists():
            if verifier.tree(TARGET) != wanted:
                raise RuntimeError('existing server cache diverged; not replaced')
        else:
            source.rename(TARGET)
    print(json.dumps({'status': 'PASS', 'server_tree_sha256': digest, 'mobile_unchanged': True}))


if __name__ == '__main__':
    main()
