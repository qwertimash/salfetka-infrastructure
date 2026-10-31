#!/usr/bin/env python3
"""Export only standalone product sources. Never copy the bot or private state."""
import argparse
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[2]


def files():
    chosen = set()
    for prefix in ('panel/internal', 'panel/cmd', 'panel/migrations', 'panel/engine/xray', 'panel/deploy/licenses',
                   'panel/internal/importer/schemas', 'panel/web/src', 'panel/web/public', 'panel/third_party/patches/xray-server'):
        for path in (ROOT / prefix).rglob('*'):
            if path.is_file() and not path.is_symlink() and not any(part in ('artifacts', '__pycache__', 'node_modules') for part in path.parts): chosen.add(path.relative_to(ROOT).as_posix())
    for pattern in ('panel/web/*.json', 'panel/web/*.ts', 'panel/web/*.html', 'panel/scripts/installer/*.py',
                    'panel/tests/test_installer*.py', 'panel/tests/test_node*.py', 'panel/tests/test_prepare*.py',
                    'mobile/contracts/*.json'):
        for path in ROOT.glob(pattern): chosen.add(path.relative_to(ROOT).as_posix())
    chosen.update(['panel/go.mod', 'panel/go.sum', 'panel/contracts/backend-pins.json',
        'panel/third_party/mobile-baseline.lock.json', 'panel/third_party/xray-server.lock.json',
        'panel/deploy/pilot/compose.json', 'panel/deploy/pilot/Dockerfile', 'panel/deploy/release/public-key.pem',
        'panel/deploy/systemd/salfetka-server-node.service', 'panel/deploy/systemd/salfetka-vpn-node.service', 'panel/deploy/systemd/vpn.env.example',
        'panel/docs/operator/pilot.md', 'panel/docs/operator/b4-vpn-node.md', 'panel/docs/operator/node-installer.md',
        'panel/docs/operator/installer-lifecycle.md',
        'panel/scripts/install.py', 'panel/scripts/install-node.py', 'panel/scripts/node-wizard.py', 'panel/scripts/salfetka.py',
        'panel/scripts/build-release.py', 'panel/scripts/export-release-source.py', 'panel/scripts/prepare-pilot.py',
        'panel/scripts/package-pilot.sh', 'panel/scripts/package-vpn-node.sh', 'panel/scripts/prepare-xray-server.py',
        'panel/scripts/collect-node-licenses.py', 'panel/scripts/ci-release.sh',
        'mobile/scripts/fetch-core-sources.py', 'mobile/scripts/subscription_catalog.py',
        'mobile/core/routing/assets/geodata-tags-v1.json', 'mobile/core/routing/assets/registry-v1.json',
        'panel/tests/compatibility/fixtures.json', 'panel/tests/compatibility/manifest_test.go',
        'services/traffic_observation.py', 'services/traffic_observation_sources.py',
        'panel/tests/acceptance_installer_linux.py'])
    baseline = json.loads((ROOT / 'panel/third_party/mobile-baseline.lock.json').read_text())
    for dep in baseline['dependencies']:
        if dep['id'] in ('xray-core', 'gvisor'):
            chosen.update('mobile/' + item['path'] for item in dep['source_archive'].get('patches', []))
    return sorted(chosen)


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('output')
    target = Path(parser.parse_args().output).absolute()
    if target.exists(): raise ValueError('new_export_directory_required')
    target.mkdir(mode=0o700)
    for relative in files():
        source = ROOT / relative
        if source.is_symlink() or not source.is_file(): raise ValueError('export_source_missing:' + relative)
        destination = target / relative; destination.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(source, destination)
    # The source fetcher uses this conventional path. Preserve the frozen server baseline.
    shutil.copy2(ROOT / 'panel/third_party/mobile-baseline.lock.json', target / 'mobile/third_party/DEPENDENCIES.lock.json')
    workflow = target / '.github/workflows/release.yml'; workflow.parent.mkdir(parents=True)
    shutil.copy2(ROOT / 'panel/deploy/release/workflow.yml', workflow)
    shutil.copy2(ROOT / 'panel/docs/operator/installer-lifecycle.md', target / 'README.md')
    print('allowlisted_source_exported')

if __name__ == '__main__': main()
