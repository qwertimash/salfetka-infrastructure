#!/usr/bin/env python3
"""Package already-built Linux components and sign an immutable release manifest.
Signing material is supplied in a private file; it never enters any package.
"""
import argparse
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile

from installer.common import Failure, atomic, regular, require, run, save, sha256, version
from installer.releases import REPOSITORY, verify_manifest

ROOT = Path(__file__).resolve().parents[1]


def archive(source, target):
    source, target = Path(source), Path(target)
    with target.open('xb') as stream, gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0, compresslevel=6) as zipped:
        with tarfile.open(fileobj=zipped, mode='w', format=tarfile.USTAR_FORMAT) as out:
            for path in sorted(source.rglob('*')):
                require(not path.is_symlink(), 'package_symlink_refused')
                if path.is_dir() or '__pycache__' in path.parts or path.suffix == '.pyc': continue
                require(path.is_file(), 'package_special_file_refused')
                info = tarfile.TarInfo(path.relative_to(source).as_posix())
                info.size = path.stat().st_size; info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                info.uid = info.gid = info.mtime = 0
                with path.open('rb') as content: out.addfile(info, content)


def bootstrap(public_key):
    sources = {name: (ROOT / 'scripts/installer' / name).read_text() for name in ('__init__.py', 'common.py', 'releases.py')}
    return ('''#!/usr/bin/env python3
# Initial trust: this file is obtained from the official GitHub repository over HTTPS.
# After bootstrap, immutable releases require the pinned Ed25519 signing key.
import argparse, os, pathlib, platform, subprocess, sys, tempfile
SOURCES = ''' + repr(sources) + '\nPUBLIC_KEY = ' + repr(public_key) + '''
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--version')
    parser.add_argument('--github-token-file',help='Temporary private development repository only; file mode 0600')
    args=parser.parse_args()
    if platform.system()!='Linux' or os.geteuid()!=0: raise RuntimeError('linux_root_required')
    arch={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
    if not arch: raise RuntimeError('unsupported_architecture')
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='salfetka-bootstrap-') as temporary:
        root=pathlib.Path(temporary); (root/'installer').mkdir()
        for name,source in SOURCES.items(): (root/'installer'/name).write_text(source)
        sys.path.insert(0,str(root))
        from installer.releases import Catalog,Github
        catalog=Catalog(Github(token_file=args.github_token_file),PUBLIC_KEY)
        manifest,assets=catalog.fetch(root,args.version)
        # Extract into a different directory from the bootstrap support module.
        (root/'payload').mkdir()
        package=catalog.component(manifest,assets,'installer','linux/'+arch,root/'payload')
        command=[sys.executable,str(package/'salfetka.py'),'--version',manifest['version']]
        if args.github_token_file: command+=['--github-token-file',str(pathlib.Path(args.github_token_file).absolute())]
        return subprocess.call(command)
if __name__=='__main__':
    try: sys.exit(main())
    except Exception:
        print('bootstrap_failed; no unverified package executed',file=sys.stderr); sys.exit(1)
''').encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--signing-key', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--panel', action='append', default=[], help='amd64_or_arm64=prepared package containing image.tar and image.json')
    parser.add_argument('--node', action='append', default=[], help='amd64_or_arm64=prepared node package')
    args = parser.parse_args(); version(args.version)
    key = Path(args.signing_key).absolute(); regular(key, 4096, private=True)
    output = Path(args.output).absolute(); require(not output.exists(), 'new_release_directory_required'); output.mkdir(mode=0o700)
    public_key = run(['openssl', 'pkey', '-in', key, '-pubout'])
    require(public_key == regular(ROOT / 'deploy/release/public-key.pem'), 'signer_does_not_match_distribution_key')
    sources = {}
    for component, inputs in [('panel', args.panel), ('node', args.node)]:
        for value in inputs:
            arch, path = value.split('=', 1)
            require(arch in ('amd64', 'arm64') and (component, arch) not in sources, 'duplicate_or_invalid_platform')
            sources[component, arch] = Path(path)
    require(sources and set(sources) == {(component, arch) for arch in {a for _, a in sources} for component in ('panel', 'node')}, 'paired_panel_node_packages_required')
    with tempfile.TemporaryDirectory(prefix='salfetka-release-') as temporary:
        installer = Path(temporary).resolve() / 'installer'; installer.mkdir()
        shutil.copytree(ROOT / 'scripts/installer', installer / 'installer', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        shutil.copy2(ROOT / 'scripts/salfetka.py', installer / 'salfetka.py')
        atomic(installer / 'release-public-key.pem', public_key, 0o644)
        path = installer / 'installer/manager.py'
        text = path.read_text().replace("VERSION = '0.6.0'", 'VERSION = ' + repr(args.version))
        path.write_text(text)
        for arch in {a for _, a in sources}: sources['installer', arch] = installer
        artifacts = []
        for (component, arch), source in sorted(sources.items()):
            name = f'salfetka-{component}-{args.version}-linux-{arch}.tar.gz'
            archive(source, output / name)
            artifacts.append({'component': component, 'platform': 'linux/' + arch, 'name': name,
                              'sha256': sha256(output / name), 'bytes': (output / name).stat().st_size})
    now = datetime.now(timezone.utc)
    value = {'schema': 2, 'repository': REPOSITORY, 'version': args.version,
             'published_at': now.isoformat(), 'expires_at': (now + timedelta(days=365)).isoformat(),
             'protocol_min': 1, 'protocol_max': 1, 'database_min': 1, 'database_max': 24, 'database_target': 24,
             'artifacts': artifacts}
    save(output / 'release.json', value)
    run(['openssl', 'pkeyutl', '-sign', '-inkey', key, '-rawin', '-in', output / 'release.json', '-out', output / 'release.sig'])
    verify_manifest(regular(output / 'release.json'), regular(output / 'release.sig'), public_key)
    atomic(output / 'install.py', bootstrap(public_key), 0o755)
    print('signed_release_packages_created:' + args.version)

if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(str(error) if isinstance(error, Failure) else 'release_build_failed', file=sys.stderr); sys.exit(1)
