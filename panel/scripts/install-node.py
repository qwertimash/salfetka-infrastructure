#!/usr/bin/env python3
"""Install a separately owned Linux agent. Default is read-only plan; no SSH/firewall.
All sources must come from a verified local package, never curl|sh.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import uuid
from urllib.parse import urlsplit


class InstallError(Exception):
    pass


def fail(code):
    raise InstallError(code)


def file_bytes(path, maximum=64 * 1024 * 1024):
    path = Path(path)
    # No symlinks in any input component: avoid installing a moving target.
    if any(p.is_symlink() for p in [path, *path.parents]):
        fail('source_symlink')
    if not path.is_file() or path.stat().st_size > maximum:
        fail('source_invalid')
    return path.read_bytes()


def canonical_id(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        fail('identity_invalid')
    return value


def build_plan(package, spec_path):
    package = Path(package).absolute()
    spec = json.loads(file_bytes(spec_path, 65536))
    expected = {'instance', 'node_id', 'installation_id', 'panel_url', 'backend',
                'ca_file', 'signer_file', 'enrollment_file', 'listen_ip', 'port',
                'certificate_file', 'key_file', 'endpoint_file'}
    if not isinstance(spec, dict) or set(spec) - expected:
        fail('spec_fields_invalid')
    name = spec.get('instance', '')
    if not re.fullmatch('[a-z][a-z0-9-]{0,15}', name):
        fail('instance_invalid')
    node = canonical_id(spec['node_id'])
    installation = '' if spec.get('backend') == 'managed' else canonical_id(spec['installation_id'])
    backend = spec.get('backend')
    if backend not in ('vless', 'hysteria2', 'olcrtc', 'managed'):
        fail('backend_invalid')
    url = urlsplit(spec['panel_url'])
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.path not in ('', '/') or url.query or url.fragment
            or not re.fullmatch(r'https://[A-Za-z0-9.\-:\[\]]+/?', spec['panel_url'])):
        fail('panel_origin_invalid')
    _ = url.port
    service = 'salfetka-' + name
    home = '/opt/salfetka-nodes/' + name
    binary = 'panel-server-node' if backend == 'managed' else ('panel-bypass-node' if backend == 'olcrtc' else 'panel-vpn-node')
    unit_source = 'salfetka-server-node' if backend == 'managed' else ('salfetka-bypass-node' if backend == 'olcrtc' else 'salfetka-vpn-node')
    # Require checksums for every executable and the service template we use.
    sums = {}
    for line in file_bytes(package / 'SHA256SUMS', 262144).decode().splitlines():
        digest, relative = line.split(None, 1); relative = relative.lstrip('*')
        if not re.fullmatch('[0-9a-f]{64}', digest) or relative in sums:
            fail('package_manifest_invalid')
        sums[relative] = digest
    payload = {}
    for relative in ['bin/panel-node', 'bin/' + binary, 'systemd/' + unit_source + '.service']:
        raw = file_bytes(package / relative)
        if hashlib.sha256(raw).hexdigest() != sums.get(relative):
            fail('package_checksum_failed')
        payload[relative] = raw
    # Never execute a package built for the wrong OS/CPU.
    machine = {'x86_64': 62, 'aarch64': 183, 'arm64': 183}.get(platform.machine())
    for key in ['bin/panel-node', 'bin/' + binary]:
        raw = payload[key]
        if len(raw) < 20 or raw[:5] != b'\x7fELF\x02' or raw[5] != 1 or int.from_bytes(raw[18:20], 'little') != machine:
            fail('package_architecture_mismatch')
    env = {'PANEL_NODE_EXPECTED_ID': node, 'PANEL_NODE_PANEL_URL': spec['panel_url'].rstrip('/'),
           'PANEL_NODE_STATE_DIR': home + '/state/identity', 'PANEL_VPN_STATE_DIR': home + '/state/engine',
           'PANEL_VPN_INSTALLATION_ID': installation, 'PANEL_NODE_CA_FILE': home + '/config/ca.crt',
           'PANEL_NODE_SIGNER_PUBLIC_FILE': home + '/config/signer.pub'}
    files = {'bin/panel-node': (payload['bin/panel-node'], 0o755),
             'bin/' + binary: (payload['bin/' + binary], 0o755)}
    for field, target in [('ca_file', 'ca.crt'), ('signer_file', 'signer.pub'), ('enrollment_file', 'enrollment.json')]:
        files['config/' + target] = (file_bytes(spec[field], 65536), 0o600)
    enrollment = json.loads(files['config/enrollment.json'][0])
    if enrollment.get('node_id') != node:
        fail('enrollment_identity_mismatch')
    port = None
    if backend == 'managed':
        env.pop('PANEL_VPN_INSTALLATION_ID'); env.pop('PANEL_VPN_STATE_DIR')
        env['PANEL_FLEET_STATE_DIR'] = home + '/state/fleet'
    elif backend == 'olcrtc':
        raw = file_bytes(spec['endpoint_file'], 20000)
        endpoint = json.loads(raw)
        if endpoint.get('backend') != 'olcrtc':
            fail('endpoint_backend_mismatch')
        files['config/endpoint.json'] = (raw, 0o600)
        env.update(PANEL_OLCRTC_CONFIG_FILE=home + '/config/endpoint.json', PION_LOG_DISABLE='all')
    else:
        listen = str(ipaddress.ip_address(spec['listen_ip']))
        port = spec['port']
        if type(port) is not int or not 1024 <= port <= 65535:
            fail('unprivileged_port_required')
        files['config/vpn.crt'] = (file_bytes(spec['certificate_file'], 65536), 0o600)
        files['config/vpn.key'] = (file_bytes(spec['key_file'], 65536), 0o600)
        env.update(PANEL_VPN_BACKEND='' if backend == 'vless' else backend,
                   PANEL_VPN_LISTEN_IP=listen, PANEL_VPN_PORT=str(port),
                   PANEL_VPN_CERT_FILE=home + '/config/vpn.crt', PANEL_VPN_KEY_FILE=home + '/config/vpn.key')
    files['config/agent.env'] = (''.join(k + '=' + v + '\n' for k, v in sorted(env.items())).encode(), 0o600)
    unit = payload['systemd/' + unit_source + '.service'].decode()
    unit = unit.replace('/usr/local/libexec/' + unit_source, home + '/bin').replace('/etc/' + unit_source, home + '/config')
    unit = unit.replace('/var/lib/' + unit_source, home + '/state').replace('agent.env', 'agent.env')
    unit = unit.replace('User=' + unit_source, 'User=' + service).replace('Group=' + unit_source, 'Group=' + service)
    unit = unit.replace('StateDirectory=' + unit_source + '\nStateDirectoryMode=0700', 'ReadWritePaths=' + home + '/state')
    # No command injection via spec; paths and service names come from the validated instance.
    return {'schema': 1, 'instance': name, 'service': service, 'home': home, 'node_id': node,
            'installation_id': installation, 'backend': backend, 'port': port,
            'listen_ip': env.get('PANEL_VPN_LISTEN_IP'), 'binary': binary,
            'files': files, 'unit': unit.encode(), 'env': env}


def receipt(plan):
    return {k: plan[k] for k in ('schema', 'instance', 'service', 'home', 'node_id', 'installation_id', 'backend', 'port')}


def run(args, **kwargs):
    # Do not leak enrollment tokens, endpoint secrets or tool output on errors.
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, **kwargs)
    if result.returncode:
        fail('command_failed:' + Path(args[0]).name)
    return result.stdout


def preflight(plan, root=Path('/'), check_port=True):
    home = root / plan['home'].lstrip('/')
    unit = root / ('etc/systemd/system/' + plan['service'] + '.service')
    if any(p.is_symlink() for p in [home, *home.parents, unit, *unit.parents]):
        fail('destination_symlink')
    if plan['backend'] == 'managed':
        owned_root = root / 'opt/salfetka-nodes'
        if owned_root.exists():
            for marker in owned_root.glob('*/owner.json'):
                existing = json.loads(file_bytes(marker, 65536))
                if existing.get('backend') == 'managed':
                    fail('single_managed_node_already_installed')
    if home.exists() or unit.exists():
        fail('installation_exists_preserved')
    if check_port and plan['port']:
        family = socket.AF_INET6 if ':' in plan['listen_ip'] else socket.AF_INET
        kind = socket.SOCK_DGRAM if plan['backend'] == 'hysteria2' else socket.SOCK_STREAM
        with socket.socket(family, kind) as sock:
            try: sock.bind((plan['listen_ip'], plan['port']))
            except OSError: fail('listener_unavailable')
    return home, unit


def stage(plan, root=Path('/')):
    # Preflight is repeated immediately before writing. Existing installations are never upgraded.
    home, unit = preflight(plan, root, check_port=False)
    home.mkdir(parents=True, mode=0o700)
    # Save ownership before partial work, for diagnosis/explicit recovery. Never recursively delete.
    (home / 'owner.json').write_text(json.dumps(receipt(plan), sort_keys=True) + '\n')
    os.chmod(home / 'owner.json', 0o600)
    for relative, (raw, mode) in plan['files'].items():
        target = home / relative; target.parent.mkdir(mode=0o700, exist_ok=True)
        with target.open('xb') as stream: stream.write(raw)
        target.chmod(mode)
    (home / 'state').mkdir(mode=0o700)
    # Unit is staged, not made visible to systemd until enrollment and init succeed.
    (home / (plan['service'] + '.service')).write_bytes(plan['unit'])
    return home, unit


def secure_ownership(plan, home, uid, gid):
    # Root protects directories, binaries and public configuration. The strict
    # node loaders require private enrollment/TLS files owned by the service UID.
    # The manager uses umask 077. Its namespace must remain traversable by
    # service UIDs, while each installation remains protected by its group.
    os.chmod(home.parent, 0o711)
    os.chmod(home, 0o750); os.chown(home, 0, gid)
    for directory in ['bin', 'config']:
        os.chmod(home / directory, 0o750); os.chown(home / directory, 0, gid)
    for relative in plan['files']:
        path = home / relative
        private = relative in ('config/enrollment.json', 'config/vpn.key')
        os.chown(path, uid if private else 0, gid)
        if relative.startswith('config/'):
            os.chmod(path, 0o600 if private else 0o640)
    os.chown(home / 'state', uid, gid)


def install(plan):
    if platform.system() != 'Linux' or os.geteuid() != 0: fail('linux_root_required')
    import fcntl, stat
    fd = os.open('/run/salfetka-install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1: fail('installer_lock_unsafe')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return install_locked(plan)
    finally: os.close(fd)

def install_locked(plan):
    if platform.system() != 'Linux' or os.geteuid() != 0:
        fail('linux_root_required')
    preflight(plan)
    namespace = Path(plan['home']).parent
    if namespace.exists() and namespace.stat().st_uid != 0: fail('node_namespace_not_root_owned')
    for tool in ['systemctl', 'systemd-analyze', 'useradd', 'runuser', 'getent']:
        if not shutil.which(tool): fail('required_tool_missing:' + tool)
    state = run(['systemctl', 'show', plan['service'] + '.service', '--property=LoadState', '--value']).decode().strip()
    if state != 'not-found': fail('service_already_exists')
    if subprocess.run(['getent', 'passwd', plan['service']], stdout=subprocess.DEVNULL).returncode == 0:
        fail('service_user_already_exists')
    home, unit = stage(plan)
    run(['systemd-analyze', 'verify', str(home / (plan['service'] + '.service'))])
    run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', str(home / 'state'), '--shell', '/usr/sbin/nologin', plan['service']])
    import pwd
    account = pwd.getpwnam(plan['service'])
    secure_ownership(plan, home, account.pw_uid, account.pw_gid)
    env = dict(plan['env'], PATH='/usr/sbin:/usr/bin:/sbin:/bin', PANEL_NODE_TOKEN_FILE=str(home / 'config/enrollment.json'))
    # Expected identity is enforced by the managed runtime after enrollment.
    # The enrollment command starts without local state; build_plan already
    # binds the invitation node_id to this installation.
    enroll_env = dict(env); enroll_env.pop('PANEL_NODE_EXPECTED_ID', None)
    run(['runuser', '-u', plan['service'], '--', str(home / 'bin/panel-node'), 'enroll'], env=enroll_env)
    (home / 'config/enrollment.json').unlink()
    env.pop('PANEL_NODE_TOKEN_FILE')
    run(['runuser', '-u', plan['service'], '--', str(home / ('bin/' + plan['binary'])), 'initialize'], env=env)
    # O_EXCL prevents overwriting a unit created while enrollment was in flight.
    with unit.open('xb') as stream: stream.write(plan['unit'])
    unit.chmod(0o644)
    run(['systemctl', 'daemon-reload'])
    # Explicit separate activate command; installing never starts traffic by itself.


def owned(instance):
    if not re.fullmatch('[a-z][a-z0-9-]{0,15}', instance): fail('instance_invalid')
    home = Path('/opt/salfetka-nodes') / instance
    data = json.loads(file_bytes(home / 'owner.json', 65536))
    if data.get('instance') != instance or data.get('home') != str(home) or data.get('service') != 'salfetka-' + instance:
        fail('ownership_mismatch')
    expected = file_bytes(home / (data['service'] + '.service'), 65536)
    actual = file_bytes(Path('/etc/systemd/system') / (data['service'] + '.service'), 65536)
    if actual != expected: fail('service_changed_preserved')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['plan', 'install', 'activate', 'disable'])
    parser.add_argument('--package'); parser.add_argument('--spec'); parser.add_argument('--instance')
    args = parser.parse_args()
    if args.operation in ('plan', 'install'):
        if not args.package or not args.spec: fail('package_and_spec_required')
        plan = build_plan(args.package, args.spec); preflight(plan)
        if args.operation == 'install': install(plan)
        print(json.dumps(receipt(plan), indent=2))
    else:
        if platform.system() != 'Linux' or os.geteuid() != 0: fail('linux_root_required')
        data = owned(args.instance or '')
        run(['systemctl', 'enable' if args.operation == 'activate' else 'disable', '--now', data['service'] + '.service'])
        print('service_activated' if args.operation == 'activate' else 'service_disabled_data_preserved')


if __name__ == '__main__':
    try: main()
    except (InstallError, ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, InstallError) else 'installation_failed_no_automatic_cleanup', file=sys.stderr)
        sys.exit(1)
