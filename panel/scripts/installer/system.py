"""Owned Linux dependencies and independent public/browser TLS lifecycle."""
import ipaddress
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import ssl

from .common import atomic, decode, regular, require, run


def platform_id():
    require(platform.system() == 'Linux' and os.geteuid() == 0, 'linux_root_required')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    require(arch is not None, 'unsupported_architecture')
    require(Path('/run/systemd/system').is_dir(), 'systemd_required')
    return 'linux/' + arch


def dependencies(panel=False):
    release = Path('/etc/os-release').resolve()
    require(release in (Path('/etc/os-release'), Path('/usr/lib/os-release'))
            and release.stat().st_uid == 0 and release.stat().st_mode & 0o022 == 0, 'os_release_untrusted')
    data = dict(line.split('=', 1) for line in regular(release).decode().splitlines() if '=' in line)
    require(data.get('ID', '').strip('"') == 'ubuntu' and data.get('VERSION_ID', '').strip('"') == '24.04', 'supported_os_ubuntu_24_04_required')
    packages = ['ca-certificates', 'openssl', 'python3']
    if panel: packages += ['docker.io', 'docker-compose-v2', 'certbot']
    run(['apt-get', 'update', '-qq'], timeout=600)
    run(['apt-get', 'install', '-y', '--no-install-recommends', *packages],
        env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'), timeout=900)
    if panel:
        run(['systemctl', 'enable', '--now', 'docker'])
        run(['docker', 'compose', 'version'])


def domain(value):
    require(isinstance(value, str) and len(value) <= 253 and '.' in value
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in value.split('.')),
            'invalid_domain')
    try: ipaddress.ip_address(value)
    except ValueError: return value
    raise ValueError('domain_required')


def dns(host, address):
    domain(host)
    address = str(ipaddress.ip_address(address))
    try: addresses = {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    except OSError: raise ValueError('dns_not_resolved') from None
    require(address in addresses, 'dns_does_not_match_server_address')
    # ACME itself verifies external reachability, including all published AAAA.
    return sorted(addresses)


def free_ports(ports):
    for port in ports:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            try: sock.bind(('::', port))
            except OSError: raise ValueError('required_port_busy:' + str(port)) from None


def private_tls(directory, hosts):
    """Stable pinned machine ingress; never overwritten on update/ACME renewal."""
    directory = Path(directory)
    require(not (directory / 'tls.crt').exists() and not (directory / 'tls.key').exists(), 'machine_trust_already_exists')
    run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
         '-nodes', '-days', '3650', '-subj', '/CN=Salfetka machine ingress',
         '-addext', 'subjectAltName=' + ','.join('DNS:' + domain(host) for host in hosts),
         '-addext', 'extendedKeyUsage=serverAuth', '-addext', 'keyUsage=digitalSignature,keyCertSign',
         '-out', directory / 'tls.crt', '-keyout', directory / 'tls.key'])
    (directory / 'tls.key').chmod(0o600)


def acme(home, hosts, email):
    require(re.fullmatch(r'[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+', email), 'invalid_acme_email')
    home = Path(home)
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    argv = ['certbot', 'certonly', '--standalone', '--non-interactive', '--agree-tos',
            '--email', email, '--cert-name', 'salfetka', '--config-dir', home / 'config',
            '--work-dir', home / 'work', '--logs-dir', home / 'logs']
    for host in hosts: argv += ['-d', domain(host)]
    run(argv, timeout=600)
    return public_pair(home)


def public_pair(home):
    root = (Path(home) / 'config').resolve()
    paths = [(root / 'live/salfetka' / name).resolve() for name in ('fullchain.pem', 'privkey.pem')]
    require(all(path.is_relative_to(root / 'archive/salfetka') for path in paths), 'acme_file_outside_owned_archive')
    return regular(paths[0], 65536), regular(paths[1], 65536, private=True)


def install_public_pair(directory, cert, key, hosts):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Verify before touching active files. Atomic directory-level switch is not
    # needed: nginx reload reads after both replacements, current workers retain TLS.
    import tempfile
    with tempfile.TemporaryDirectory(dir=directory) as temporary:
        c, k = Path(temporary) / 'cert', Path(temporary) / 'key'
        atomic(c, cert); atomic(k, key)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(c, k)
        for host in hosts: run(['openssl', 'x509', '-in', c, '-noout', '-checkhost', domain(host)])
        run(['openssl', 'x509', '-in', c, '-noout', '-checkend', '86400'])
    atomic(directory / 'fullchain.pem', cert)
    atomic(directory / 'privkey.pem', key)
