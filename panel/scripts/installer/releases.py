"""Signed GitHub Releases; archives are never executed before verification."""
import base64
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from .common import Failure, decode, regular, require, run, sha256, version

REPOSITORY = 'qwertimash/salfetka-infrastructure'
PROTOCOL = 1
COMPONENTS = {'installer', 'panel', 'node'}
PLATFORMS = {'linux/amd64', 'linux/arm64'}
GITHUB_HOSTS = {'api.github.com', 'github.com', 'objects.githubusercontent.com',
                'release-assets.githubusercontent.com'}
MAX_ARCHIVE = 1024 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Github:
    def __init__(self, repository=REPOSITORY, token_file=None):
        require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'invalid_repository')
        self.repository = repository
        self.token = regular(token_file, 4096, private=True).decode().strip() if token_file else None
        require(not self.token or re.fullmatch(r'[A-Za-z0-9_]+', self.token), 'invalid_github_credential')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                    urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect())

    def download(self, url, target, limit, *, api_asset=False):
        """Only GitHub HTTPS; credentials never follow a cross-origin redirect."""
        target = Path(target)
        require(not target.exists() and not target.is_symlink(), 'download_target_exists')
        deadline = time.monotonic() + 900
        try:
            for hop in range(5):
                parsed = urllib.parse.urlsplit(url)
                require(parsed.scheme == 'https' and parsed.hostname in GITHUB_HOSTS
                        and parsed.port in (None, 443) and not parsed.username
                        and not parsed.password and not parsed.fragment, 'download_origin_refused')
                headers = {'User-Agent': 'Salfetka-Installer',
                           'Accept': 'application/octet-stream' if api_asset else 'application/vnd.github+json'}
                if self.token and parsed.hostname == 'api.github.com':
                    require(parsed.path.startswith('/repos/' + self.repository + '/'), 'credential_scope_refused')
                    headers['Authorization'] = 'Bearer ' + self.token
                request = urllib.request.Request(url, headers=headers)
                try:
                    response = self.opener.open(request, timeout=30)
                except urllib.error.HTTPError as error:
                    status, location = error.code, error.headers.get('Location')
                    error.close()
                    if status in (301, 302, 303, 307, 308) and location:
                        url = urllib.parse.urljoin(url, location)
                        continue
                    raise Failure('github_download_failed:' + str(status)) from None
                with response:
                    require(response.status == 200, 'download_status_invalid')
                    length = response.headers.get('Content-Length')
                    require(length is None or length.isdigit() and int(length) <= limit, 'download_too_large')
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    total = 0
                    with os.fdopen(fd, 'wb') as stream:
                        while block := response.read(min(1 << 20, limit - total + 1)):
                            require(time.monotonic() < deadline, 'download_deadline_exceeded')
                            total += len(block)
                            require(total <= limit, 'download_too_large')
                            stream.write(block)
                        stream.flush()
                        os.fsync(stream.fileno())
                return target
            raise Failure('too_many_download_redirects')
        except (OSError, ValueError, urllib.error.URLError):
            if target.exists():
                target.unlink()
            raise Failure('github_transport_failed') from None
        except Failure:
            if target.exists():
                target.unlink()
            raise

    def release(self, tag=None):
        if tag:
            version(tag.removeprefix('v'))
        suffix = 'tags/v' + tag.removeprefix('v') if tag else 'latest'
        with tempfile.TemporaryDirectory(prefix='salfetka-github-') as temporary:
            raw = self.download('https://api.github.com/repos/' + self.repository + '/releases/' + suffix,
                                Path(temporary) / 'release.json', 1 << 20)
            value = decode(regular(raw))
        require(isinstance(value, dict) and isinstance(value.get('tag_name'), str)
                and value['tag_name'].startswith('v') and not value.get('draft'), 'release_metadata_invalid')
        version(value['tag_name'][1:])
        require(tag is None or value['tag_name'] == 'v' + tag.removeprefix('v'), 'release_tag_mismatch')
        assets = {}
        for item in value.get('assets', []):
            name = item.get('name', '')
            require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,120}', name)
                    and name not in assets and type(item.get('id')) is int, 'release_assets_invalid')
            assets[name] = 'https://api.github.com/repos/' + self.repository + '/releases/assets/' + str(item['id'])
        return value['tag_name'][1:], assets


def verify_manifest(raw, signature, public_key, *, now=None, openssl='openssl'):
    require(len(raw) <= 262144 and len(signature) == 64 and len(public_key) <= 1024, 'release_signature_invalid')
    try:
        match = re.fullmatch(rb'-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)\n-----END PUBLIC KEY-----\n?', public_key)
        require(match is not None, 'release_key_invalid')
        der = base64.b64decode(match[1].replace(b'\n', b''), validate=True)
        require(len(der) == 44 and der[:12] == bytes.fromhex('302a300506032b6570032100'), 'release_key_invalid')
    except ValueError:
        raise Failure('release_key_invalid') from None
    with tempfile.TemporaryDirectory(prefix='salfetka-signature-') as temporary:
        files = [Path(temporary) / name for name in ('manifest', 'signature', 'key')]
        for path, data in zip(files, (raw, signature, public_key)):
            path.write_bytes(data)
            path.chmod(0o600)
        try:
            run([openssl, 'pkeyutl', '-verify', '-pubin', '-inkey', files[2], '-rawin',
                 '-in', files[0], '-sigfile', files[1]], timeout=15)
        except Failure:
            raise Failure('release_signature_invalid') from None
    value = decode(raw)
    require(isinstance(value, dict) and set(value) == {'schema', 'repository', 'version',
            'published_at', 'expires_at', 'protocol_min', 'protocol_max', 'database_min',
            'database_max', 'database_target', 'artifacts'}, 'release_manifest_invalid')
    require(type(value['schema']) is int and value['schema'] == 2 and value['repository'] == REPOSITORY,
            'release_manifest_invalid')
    version(value['version'])
    try:
        published = datetime.fromisoformat(value['published_at'].replace('Z', '+00:00'))
        expires = datetime.fromisoformat(value['expires_at'].replace('Z', '+00:00'))
        require(published <= (now or datetime.now(timezone.utc)) < expires, 'release_manifest_expired_or_future')
    except (ValueError, TypeError, AttributeError):
        raise Failure('release_manifest_invalid') from None
    require(all(type(value[k]) is int for k in ('protocol_min', 'protocol_max', 'database_min', 'database_max', 'database_target')),
            'release_compatibility_invalid')
    require(0 < value['protocol_min'] <= PROTOCOL <= value['protocol_max'], 'release_protocol_incompatible')
    require(0 <= value['database_min'] <= value['database_target'] <= value['database_max'], 'release_database_invalid')
    require(isinstance(value['artifacts'], list) and 1 <= len(value['artifacts']) <= 6, 'release_artifacts_invalid')
    seen, names = set(), set()
    for artifact in value['artifacts']:
        require(isinstance(artifact, dict) and set(artifact) == {'component', 'platform', 'name', 'sha256', 'bytes'}, 'release_artifact_invalid')
        require(isinstance(artifact['component'], str) and isinstance(artifact['platform'], str)
                and artifact['component'] in COMPONENTS and artifact['platform'] in PLATFORMS, 'release_artifact_invalid')
        pair = artifact['component'], artifact['platform']
        expected = 'salfetka-' + artifact['component'] + '-' + value['version'] + '-' + artifact['platform'].replace('/', '-') + '.tar.gz'
        require(artifact['name'] == expected and pair not in seen and expected not in names, 'release_artifact_invalid')
        seen.add(pair); names.add(expected)
        require(isinstance(artifact['sha256'], str) and re.fullmatch('[0-9a-f]{64}', artifact['sha256'])
                and type(artifact['bytes']) is int and 0 < artifact['bytes'] <= MAX_ARCHIVE, 'release_artifact_invalid')
    return value


def compatible(manifest, installed='0.0.0', database=None):
    require(version(manifest['version']) >= version(installed), 'release_downgrade_refused')
    if database is not None:
        require(manifest['database_min'] <= database <= manifest['database_max']
                and database <= manifest['database_target'], 'release_database_incompatible')


class BoundedTarInfo(tarfile.TarInfo):
    def _proc_pax(self, tarfile):
        require(self.size <= 65536, 'archive_metadata_too_large')
        return super()._proc_pax(tarfile)

    def _proc_gnulong(self, tarfile):
        require(self.size <= 65536, 'archive_metadata_too_large')
        return super()._proc_gnulong(tarfile)


def unpack(archive, destination, maximum=2 * 1024 * 1024 * 1024):
    destination = Path(destination)
    require(not destination.exists() and not destination.is_symlink(), 'extract_target_exists')
    require(not any(p.is_symlink() for p in destination.parents), 'extract_parent_unsafe')
    # Preflight the entire archive before creating any destination files.
    with tarfile.open(archive, 'r:gz', tarinfo=BoundedTarInfo) as bundle:
        entries, seen, total = [], set(), 0
        for member in bundle:
            name = member.name.removeprefix('./').rstrip('/')
            if name in ('', '.') and member.isdir():
                continue
            path = PurePosixPath(name)
            require(len(entries) < 20000 and len(name) <= 512 and re.fullmatch(r'[A-Za-z0-9_./-]+', name)
                    and not path.is_absolute() and '..' not in path.parts
                    and name == str(path) and name not in seen, 'unsafe_archive_path')
            require(member.isfile() or member.isdir(), 'unsafe_archive_entry')
            require(0 <= member.size <= maximum, 'archive_too_large')
            total += member.size
            require(total <= maximum, 'archive_too_large')
            seen.add(name); entries.append((member, path))
        files = {str(path) for member, path in entries if member.isfile()}
        require(not any(str(parent) in files for _, path in entries for parent in path.parents), 'archive_path_collision')
        destination.mkdir(mode=0o700)
        for member, relative in entries:
            path = destination / str(relative)
            if member.isdir():
                path.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            with source, path.open('xb') as out:
                remaining = member.size
                while remaining:
                    block = source.read(min(1 << 20, remaining))
                    require(bool(block), 'archive_truncated')
                    out.write(block); remaining -= len(block)
            path.chmod(0o755 if member.mode & 0o111 else 0o644)
    return destination


class Catalog:
    def __init__(self, github, public_key):
        self.github, self.public_key = github, public_key

    def fetch(self, directory, tag=None):
        directory = Path(directory)
        release_version, assets = self.github.release(tag)
        require('release.json' in assets and 'release.sig' in assets, 'signed_release_missing')
        raw = self.github.download(assets['release.json'], directory / 'release.json', 262144, api_asset=True)
        signature = self.github.download(assets['release.sig'], directory / 'release.sig', 64, api_asset=True)
        manifest = verify_manifest(regular(raw, 262144), regular(signature, 64), self.public_key)
        require(manifest['version'] == release_version, 'signed_release_version_mismatch')
        return manifest, assets

    def component(self, manifest, assets, component, platform, directory):
        matches = [a for a in manifest['artifacts'] if a['component'] == component and a['platform'] == platform]
        require(len(matches) == 1, 'release_component_unavailable')
        artifact = matches[0]
        require(artifact['name'] in assets, 'release_asset_missing')
        directory = Path(directory)
        archive = self.github.download(assets[artifact['name']], directory / artifact['name'], artifact['bytes'], api_asset=True)
        require(archive.stat().st_size == artifact['bytes'] and sha256(archive) == artifact['sha256'], 'release_checksum_mismatch')
        return unpack(archive, directory / component)
