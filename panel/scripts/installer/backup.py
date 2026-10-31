"""Private, checksummed backups; restore into a separate inactive database."""
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import uuid
from urllib.parse import urlsplit, urlunsplit

from . import panel
from .common import atomic, decode, regular, require, run, save, sha256

PANEL_FILES = {'owner.json', 'compose.json', 'compose.env', 'edge.conf', 'secrets', 'public-tls', 'owner-created', 'combined.json'}


def copy_private(source, destination):
    source, destination = Path(source), Path(destination)
    require(not source.is_symlink(), 'backup_symlink_refused')
    if source.is_dir():
        destination.mkdir(mode=0o700)
        for path in sorted(source.iterdir()): copy_private(path, destination / path.name)
    else:
        require(source.is_file(), 'backup_special_file_refused')
        with source.open('rb') as src, destination.open('xb') as dst:
            os.fchmod(dst.fileno(), 0o600)
            shutil.copyfileobj(src, dst, 1 << 20); dst.flush(); os.fsync(dst.fileno())


def create(root, state):
    root = Path(root)
    destination = root / 'backups' / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:8])
    destination.parent.mkdir(mode=0o700, exist_ok=True); destination.mkdir(mode=0o700)
    if 'panel' in state['components']:
        home = root / 'panel'; panel.owned(home)
        # pg_dump is a consistent transaction even while administrators use UI.
        with (destination / 'database.dump').open('xb') as output:
            os.fchmod(output.fileno(), 0o600)
            panel.compose(home, 'exec', '-T', 'postgres', 'pg_dump', '-U', 'panel_migrator', '-Fc', database_name(home), output=output)
            output.flush(); os.fsync(output.fileno())
        target = destination / 'panel'; target.mkdir(mode=0o700)
        for name in PANEL_FILES:
            if (home / name).exists(): copy_private(home / name, target / name)
    # Keep exact signed packages with the backup; restoration never trusts main.
    (destination / 'packages').mkdir(mode=0o700)
    versions = sorted(set(item['version'] for item in state['components'].values()))
    for version in versions:
        cache = root / 'releases' / version
        target = destination / 'packages' / version; target.mkdir(mode=0o700)
        for path in sorted(cache.iterdir()):
            if path.name.endswith('.tar.gz') or path.name in ('release.json', 'release.sig'):
                copy_private(path, target / path.name)
    save(destination / 'state.json', state)
    files = {path.relative_to(destination).as_posix(): {'sha256': sha256(path), 'bytes': path.stat().st_size}
             for path in sorted(destination.rglob('*')) if path.is_file()}
    save(destination / 'backup.json', {'schema': 1, 'created_at': datetime.now(timezone.utc).isoformat(), 'files': files})
    return destination


def verify(directory):
    directory = Path(directory).absolute()
    manifest = decode(regular(directory / 'backup.json', 4 * 1024 * 1024, private=True))
    require(manifest.get('schema') == 1 and isinstance(manifest.get('files'), dict), 'backup_manifest_invalid')
    require(len(manifest['files']) <= 20000, 'backup_too_many_files')
    for name, value in manifest['files'].items():
        path = Path(name)
        require(not path.is_absolute() and '..' not in path.parts and str(path) == name
                and re.fullmatch(r'[A-Za-z0-9_./-]+', name), 'backup_path_invalid')
        file = directory / path
        require(not any(p.is_symlink() for p in (file, *file.parents)) and file.is_file(), 'backup_file_invalid')
        require(file.stat().st_size == value['bytes'] and sha256(file) == value['sha256'], 'backup_corrupt')
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file() and p.name != 'backup.json'}
    require(actual == set(manifest['files']), 'backup_extra_files')
    return decode(regular(directory / 'state.json', private=True))


def database_name(home):
    value = urlsplit(regular(Path(home) / 'secrets/database-migrator-url', private=True).decode().strip()).path[1:]
    require(re.fullmatch(r'panel(?:_restore_[a-f0-9]{12})?', value), 'database_name_invalid')
    return value


def restore(root, directory, expected_state):
    root, directory = Path(root), Path(directory).absolute()
    source_state = verify(directory)
    require('panel' in source_state['components'] and 'panel' in expected_state['components'], 'installed_panel_required_for_restore')
    require(source_state['config'] == expected_state['config'], 'backup_belongs_to_different_installation')
    home = root / 'panel'; owner = panel.owned(home)
    # Preserve live identity/configuration. A DB snapshot from a different master
    # key/authority cannot be safely combined with this installation.
    for name in ('master-key', 'node-authority', 'node-signer', 'tls.crt', 'tls.key', 'postgres-password'):
        require(sha256(home / 'secrets' / name) == sha256(directory / 'panel/secrets' / name), 'backup_identity_mismatch')
    target_db = 'panel_restore_' + uuid.uuid4().hex[:12]
    panel.compose(home, 'exec', '-T', 'postgres', 'createdb', '-U', 'panel_migrator', target_db)
    # Feed through stdin: no world-readable copy of the dump in the container.
    with (directory / 'database.dump').open('rb') as source:
        import subprocess
        argv = ['docker', 'compose', '--project-name', panel.PROJECT, '--env-file', 'compose.env', '-f', 'compose.json',
                'exec', '-T', 'postgres', 'pg_restore', '--exit-on-error', '--no-owner', '-U', 'panel_migrator', '-d', target_db]
        result = subprocess.run(argv, cwd=home, stdin=source, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
        require(result.returncode == 0, 'restore_failed_live_database_unchanged')
    # Sessions and unused invitations are never resurrected. Runtime leases expire
    # and the panel remains stopped until the operator explicitly starts it.
    panel.compose(home, 'exec', '-T', 'postgres', 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'panel_migrator', '-d', target_db,
                  '-c', "BEGIN; DELETE FROM admin_sessions; UPDATE nodes_enrollments SET revoked=true WHERE used_at IS NULL; DELETE FROM bypass_leases; COMMIT;")
    panel.compose(home, 'stop', 'edge', 'admin', 'delivery', 'worker')
    for name in ('database-migrator-url', 'database-runtime-url'):
        path = home / 'secrets' / name
        u = urlsplit(regular(path, private=True).decode().strip())
        atomic(path, (urlunsplit((u.scheme, u.netloc, '/' + target_db, u.query, '')) + '\n').encode())
    # Migrate the restored snapshot using the currently installed version. Old
    # database remains intact; a failure leaves services stopped with the journal.
    panel.compose(home, 'run', '--rm', 'setup', 'migrate')
    panel.compose(home, 'run', '--rm', 'setup', 'provision-runtime', '--password-file', '/run/panel/runtime-password')
    return target_db
