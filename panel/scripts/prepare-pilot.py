#!/usr/bin/env python3
"""Prepare a fresh private pilot bundle; never starts services or contacts a host."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


class Invalid(ValueError):
    pass


def origin(value):
    try:
        u = urlsplit(value)
        port = 443 if u.port is None else u.port
    except ValueError:
        raise Invalid('invalid_subscription_origin') from None
    if (u.scheme != 'https' or not u.hostname or u.username is not None or
            u.password is not None or u.path or u.query or u.fragment or
            '?' in value or '#' in value or not value.isascii() or
            not re.fullmatch(r'https://[A-Za-z0-9.\-]+(?::[0-9]+)?', value) or
            not 1 <= port <= 65535):
        raise Invalid('invalid_subscription_origin')
    if any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?', label)
           for label in u.hostname.split('.')):
        raise Invalid('invalid_subscription_hostname')
    return u.hostname, port


def private_read(path, key=False):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 65536:
            raise Invalid('invalid_tls_file')
        if key and info.st_mode & 0o077:
            raise Invalid('tls_key_must_be_private')
        return f.read()


def write(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def quiet(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=40, check=False)
    if result.returncode:
        raise Invalid('prepare_command_failed')


def prepare(args):
    host, port = origin(args.origin)
    try:
        bind = ipaddress.IPv4Address(args.bind)
    except ValueError:
        raise Invalid('bind_must_be_literal_ipv4') from None
    if args.lab and (host != 'localhost' or not bind.is_loopback):
        raise Invalid('lab_requires_localhost_and_loopback')
    if not args.lab and (host == 'localhost' or host.endswith(('.test', '.invalid', '.localhost'))):
        raise Invalid('public_domain_required')
    if not 1024 <= args.admin_port <= 65535 or port == args.admin_port:
        raise Invalid('admin_port_invalid_or_conflicts')
    if not re.fullmatch(r'[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_.-]+', args.image):
        raise Invalid('explicit_image_tag_required')
    if not args.lab and (not args.cert or not args.key):
        raise Invalid('public_certificate_and_private_key_required')
    if bool(args.cert) != bool(args.key):
        raise Invalid('both_tls_files_required')
    target = Path(args.dir).absolute()
    if target.exists() or target.is_symlink() or not target.parent.is_dir():
        raise Invalid('new_directory_with_existing_parent_required')
    if target.parent.resolve() != target.parent:
        raise Invalid('symlink_parent_rejected')
    cert = private_read(args.cert) if args.cert else None
    key = private_read(args.key, key=True) if args.key else None
    ctl = Path(args.panelctl).resolve(strict=True)
    if not ctl.is_file() or not os.access(ctl, os.X_OK):
        raise Invalid('panelctl_executable_required')
    target.mkdir(mode=0o700)
    # On failure keep only this new partial installation for diagnosis. Never
    # overwrite it on retry and never remove an existing installation.
    quiet([str(ctl), 'prepare', '--dir', str(target / 'secrets')])
    secret = target / 'secrets'
    write(secret / 'delivery.crt', cert or private_read(secret / 'tls.crt'))
    write(secret / 'delivery.key', key or private_read(secret / 'tls.key', key=True))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(secret / 'delivery.crt', secret / 'delivery.key')
    except ssl.SSLError:
        raise Invalid('tls_pair_invalid') from None
    quiet(['openssl', 'x509', '-in', str(secret / 'delivery.crt'), '-noout', '-checkhost', host])
    quiet(['openssl', 'x509', '-in', str(secret / 'delivery.crt'), '-noout', '-checkend', '86400'])
    # Pair/name/expiry verification does not claim public CA trust or DNS reachability.
    template = ROOT / 'deploy/pilot/compose.json'
    write(target / 'compose.json', template.read_bytes())
    values = {'PANEL_IMAGE': args.image, 'PANEL_UID': str(os.getuid()), 'PANEL_GID': str(os.getgid()),
              'PANEL_ADMIN_PORT': str(args.admin_port), 'PANEL_SUBSCRIPTION_ORIGIN': args.origin,
              'PANEL_DELIVERY_BIND': str(bind), 'PANEL_DELIVERY_PORT': str(port)}
    write(target / 'compose.env', ''.join(f'{k}={v}\n' for k, v in values.items()).encode())
    write(target / 'installation.json', (json.dumps({
        'schema': 1, 'kind': 'isolated_panel_pilot', 'lab_only': args.lab,
        'services_started': False, 'public_tls_trust_verified': False,
        'compose_sha256': hashlib.sha256(template.read_bytes()).hexdigest(),
        'admin_origin': f'https://localhost:{args.admin_port}',
        'subscription_origin': args.origin,
    }, indent=2) + '\n').encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dir', required=True)
    parser.add_argument('--origin', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--panelctl', default=str(ROOT / 'artifacts/bin/panelctl'))
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--admin-port', type=int, default=18463)
    parser.add_argument('--cert')
    parser.add_argument('--key')
    parser.add_argument('--lab', action='store_true')
    try:
        prepare(parser.parse_args())
    except (Invalid, OSError, ssl.SSLError, subprocess.SubprocessError) as exc:
        # No exception text from TLS/OS/subprocess: it could contain private paths.
        parser.exit(1, (str(exc) if isinstance(exc, Invalid) else 'pilot_prepare_failed') + '\n')
    print('pilot_bundle_prepared_no_services_started')


if __name__ == '__main__':
    main()
