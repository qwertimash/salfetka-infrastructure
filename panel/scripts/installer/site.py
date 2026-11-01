"""Owned node website/HTTP-01 and atomic local TLS, independent of node identity."""
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.request

from . import node, system
from .common import Failure, atomic, decode, regular, require, run, save
from .releases import NoRedirect

SERVICE = 'salfetka-node-site.service'
UNIT = Path('/etc/systemd/system') / SERVICE


def home():
    return node.HOME / 'site'


def definition():
    return (f'''[Unit]
Description=Salfetka node website and ACME HTTP-01
Wants=network-online.target
After=network-online.target
[Service]
Type=exec
DynamicUser=yes
User=salfetka-node-site
Group=salfetka-main
ExecStart={node.HOME}/bin/panel-server-node site {home()}
UMask=0077
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectProc=invisible
InaccessiblePaths=-{node.HOME}/state -{node.HOME}/config
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryMax=128M
TasksMax=64
LimitNOFILE=2048
[Install]
WantedBy=multi-user.target
''').encode()


def owned():
    marker = decode(regular(home() / 'owner.json', private=True))
    require(marker == {'kind': 'salfetka-node-site-v1', 'unit_sha256': hashlib.sha256(definition()).hexdigest()}, 'foreign_node_site_preserved')
    require(regular(UNIT) == definition(), 'foreign_site_unit_preserved')
    require(home().stat().st_uid == 0 and home().stat().st_mode & 0o022 == 0, 'site_directory_not_owned')
    return decode(regular(home() / 'config.json'))


def metadata():
    # Read one atomic identity snapshot. Do not open or alter the agent's lock,
    # private state, renewal sequence, invitation or replay watermarks.
    identity = decode(regular(node.HOME / 'state/identity/state.json', 16 << 20, private=True))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    context.load_verify_locations(cadata=regular(node.HOME / 'config/ca.crt').decode())
    environment = dict(line.split('=', 1) for line in regular(node.HOME / 'config/agent.env').decode().splitlines())
    origin = environment['PANEL_NODE_PANEL_URL']
    require(identity['panel_url'] == origin and identity['node_id'] == environment['PANEL_NODE_EXPECTED_ID'], 'site_identity_mismatch')
    with tempfile.TemporaryDirectory(prefix='salfetka-site-mtls-') as temporary:
        pair = Path(temporary) / 'identity.pem'
        atomic(pair, (identity['enrollment']['certificate_pem'] + '\n' + identity['private_key_pem']).encode())
        context.load_cert_chain(pair)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
    request = urllib.request.Request(origin + '/api/v1/node/site-info',
        data=json.dumps({'schema_version': 1, 'node_id': identity['node_id']}).encode(), headers={'Content-Type': 'application/json'})
    try:
        with opener.open(request, timeout=15) as response:
            raw = response.read(8193)
            require(len(raw) <= 8192, 'site_metadata_too_large')
            value = decode(raw)
    except (OSError, urllib.error.URLError):
        raise Failure('node_site_metadata_unavailable_upgrade_panel_first') from None
    require(set(value) == {'schema_version', 'node_id', 'domain', 'address'} and value['schema_version'] == 1
            and value['node_id'] == identity['node_id'], 'site_metadata_invalid')
    system.domain(value['domain']); ipaddress.ip_address(value['address'])
    return value


def dns(domain, address):
    addresses = set(system.dns(domain, address))
    # Permit dual stack only if each additional A/AAAA belongs to this machine.
    # The explicitly registered public address also supports ordinary NAT VPSes.
    local = {str(ipaddress.ip_address(address))}
    interfaces = decode(run(['ip', '-j', 'address', 'show']))
    for interface in interfaces:
        for entry in interface.get('addr_info', []):
            if 'local' in entry: local.add(str(ipaddress.ip_address(entry['local'])))
    require(addresses <= local, 'node_dns_has_foreign_A_or_AAAA')


def install_bundle(cert, key, domain):
    directory = home()
    # Stage the pair, verify key match, hostname, expiry AND public chain before
    # replacing the single active PEM. No partially updated cert/key window.
    with tempfile.TemporaryDirectory(dir=directory, prefix='.tls-') as temporary:
        stage = Path(temporary)
        system.install_public_pair(stage, cert, key, [domain])
        run(['openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', domain,
             '-untrusted', stage / 'fullchain.pem', stage / 'fullchain.pem'])
        pair = cert.rstrip() + b'\n' + key.rstrip() + b'\n'
        staged = stage / 'bundle.pem'; atomic(staged, pair, 0o640)
        gid = pwd.getpwnam('salfetka-main').pw_gid
        os.chown(staged, 0, gid)
        target = directory / 'bundle.pem'
        if target.exists() and regular(target) == pair: return
        # Keep one last-known-good pair, inaccessible to the network service's writes.
        if target.exists():
            atomic(directory / 'previous.pem', regular(target), 0o600)
        os.replace(staged, target)
        fd = os.open(directory, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)


def _health(domain):
    run(['systemctl', 'is-active', '--quiet', SERVICE])
    context = ssl.create_default_context(); context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2'])
    with socket.create_connection(('127.0.0.1', 8445), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as connection:
            require(connection.selected_alpn_protocol() == 'h2', 'node_site_h2_unavailable')
            served = connection.getpeercert(binary_form=True)
    active = ssl.PEM_cert_to_DER_cert(regular(home() / 'bundle.pem').decode().split('-----END CERTIFICATE-----')[0] + '-----END CERTIFICATE-----')
    require(served == active, 'node_site_certificate_not_activated')
    connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=5)
    try:
        connection.request('GET', '/', headers={'Host': domain})
        response = connection.getresponse()
        require(response.status == 200 and b'Field notes' in response.read(8192), 'node_site_http_unavailable')
    finally: connection.close()


def health(domain):
    deadline = time.monotonic() + 20
    while True:
        try: return _health(domain)
        except (Failure, OSError):
            if time.monotonic() >= deadline: raise
            time.sleep(0.5)


def http_ready(domain):
    deadline = time.monotonic() + 15
    while True:
        connection = http.client.HTTPConnection('127.0.0.1', 80, timeout=2)
        try:
            connection.request('GET', '/', headers={'Host': domain})
            response = connection.getresponse()
            require(response.status == 200 and b'Field notes' in response.read(8192), 'node_site_http_unavailable')
            return
        except (Failure, OSError):
            if time.monotonic() >= deadline: raise
            time.sleep(0.5)
        finally: connection.close()


def acme(root, domain, email):
    require(re.fullmatch(r'[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+', email), 'invalid_acme_email')
    acme_home = Path(root) / 'node-acme'; acme_home.mkdir(mode=0o700, exist_ok=True)
    run(['certbot', 'certonly', '--webroot', '--webroot-path', home() / 'webroot',
         '--non-interactive', '--agree-tos', '--email', email, '--cert-name', 'salfetka',
         '--config-dir', acme_home / 'config', '--work-dir', acme_home / 'work', '--logs-dir', acme_home / 'logs',
         '--key-type', 'ecdsa', '-d', system.domain(domain)], timeout=600)
    return system.public_pair(acme_home)


def setup(root, config, pair=None):
    info = metadata()
    if config.get('node_domain'): require(config['node_domain'] == info['domain'], 'node_site_domain_changed')
    dns(info['domain'], info['address'])
    directory = home(); account = pwd.getpwnam('salfetka-main')
    # Never run the public website as a pre-existing account, especially the
    # node identity's UID. systemd creates and removes its separate dynamic UID.
    require(not any(line.split(':', 1)[0] == 'salfetka-node-site'
                    for line in Path('/etc/passwd').read_text().splitlines()), 'foreign_site_user_preserved')
    require(not directory.is_symlink(), 'unsafe_site_directory')
    if directory.exists():
        require(regular(directory / 'config.json') == (json.dumps({'domain': info['domain']}, ensure_ascii=False, indent=2)+'\n').encode(), 'node_site_domain_changed')
        marker = decode(regular(directory / 'owner.json', private=True))
        require(marker == {'kind': 'salfetka-node-site-v1', 'unit_sha256': hashlib.sha256(definition()).hexdigest()}, 'foreign_node_site_preserved')
    else:
        require(not os.path.lexists(UNIT), 'foreign_site_unit_preserved')
        system.free_ports([80, 8445])
        # A single staged directory commits our ownership before enabling a unit.
        with tempfile.TemporaryDirectory(dir=node.HOME, prefix='.site-') as temporary:
            stage = Path(temporary) / 'site'; stage.mkdir(mode=0o750)
            save(stage / 'config.json', {'domain': info['domain']})
            save(stage / 'owner.json', {'kind': 'salfetka-node-site-v1', 'unit_sha256': hashlib.sha256(definition()).hexdigest()})
            os.rename(stage, directory)
    os.chown(directory, 0, account.pw_gid); directory.chmod(0o750)
    os.chown(directory / 'config.json', 0, account.pw_gid); (directory / 'config.json').chmod(0o640)
    for relative in ('webroot', 'webroot/.well-known', 'webroot/.well-known/acme-challenge'):
        path = directory / relative
        require(not path.is_symlink(), 'unsafe_challenge_directory')
        path.mkdir(mode=0o750, exist_ok=True); os.chown(path, 0, account.pw_gid); path.chmod(0o750)
    if UNIT.exists(): require(regular(UNIT) == definition(), 'foreign_site_unit_preserved')
    else: atomic(UNIT, definition(), 0o644)
    run(['systemctl', 'daemon-reload']); run(['systemctl', 'enable', '--now', SERVICE])
    http_ready(info['domain'])
    # Initial issuance is HTTP-only; no placeholder or insecure/self-signed TLS.
    cert, key = pair or acme(root, info['domain'], config['email'])
    install_bundle(cert, key, info['domain'])
    health(info['domain'])
    return info


def renew(root):
    config = owned(); acme_home = Path(root) / 'node-acme'
    run(['certbot', 'renew', '--non-interactive', '--no-random-sleep-on-renew', '--config-dir', acme_home / 'config',
         '--work-dir', acme_home / 'work', '--logs-dir', acme_home / 'logs'], timeout=600)
    cert, key = system.public_pair(acme_home)
    install_bundle(cert, key, config['domain'])
    health(config['domain'])
