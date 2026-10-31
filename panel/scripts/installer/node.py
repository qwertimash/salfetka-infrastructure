"""Single physical node lifecycle. Never reset enrollment or fleet watermarks."""
import importlib.util
import os
from pathlib import Path
import tempfile
import time

from .common import Failure, atomic, decode, lock, regular, require, run, save, sha256

HOME = Path('/opt/salfetka-nodes/main')
SERVICE = 'salfetka-main.service'


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def wizard(package):
    return module(Path(package) / 'node-wizard.py', 'salfetka_node_wizard')


def install(package, invitation, version):
    helper = wizard(package)
    helper.verify_panel(invitation)
    with tempfile.TemporaryDirectory(prefix='salfetka-invite-') as temporary:
        legacy, plan = helper.prepare(package, invitation, 'main', temporary)
        legacy.install(plan)
        legacy.owned('main')
    save(HOME / 'release.json', {'version': version, 'binary_sha256': sha256(HOME / 'bin/panel-server-node'),
                               'enroller_sha256': sha256(HOME / 'bin/panel-node')})
    run(['systemctl', 'enable', '--now', SERVICE])
    health()


def owned(package):
    legacy = wizard(package).load_installer(package)
    value = legacy.owned('main')
    require(value['backend'] == 'managed', 'managed_node_required')
    return value


def health():
    # A running process alone is not successful enrollment: require a fresh
    # authenticated heartbeat persisted by this actual agent.
    start = time.time()
    for _ in range(60):
        run(['systemctl', 'is-active', '--quiet', SERVICE])
        path = HOME / 'state/identity/state.json'
        if path.exists():
            state = decode(regular(path, 16 * 1024 * 1024))
            beat = state.get('last_heartbeat')
            if beat and beat.get('status') == 'recorded':
                from datetime import datetime
                at = datetime.fromisoformat(beat['received_at'].replace('Z', '+00:00')).timestamp()
                if at >= start - 5: return
        time.sleep(2)
    raise Failure('node_authenticated_heartbeat_timeout')


def update(package, version):
    owned(package)
    with lock('/run/salfetka-install.lock'):
        # All inputs verified against the signed outer archive before this call.
        # Keep service identity, CA, signer, private keys and replay watermarks.
        run(['systemctl', 'stop', SERVICE])
        import pwd
        gid = pwd.getpwnam('salfetka-main').pw_gid
        for name in ('panel-node', 'panel-server-node'):
            target = HOME / 'bin' / name
            atomic(target, regular(Path(package) / 'bin' / name, 256 * 1024 * 1024), 0o755)
            os.chown(target, 0, gid)
        run(['systemctl', 'start', SERVICE])
        health()
        save(HOME / 'release.json', {'version': version, 'binary_sha256': sha256(HOME / 'bin/panel-server-node'),
                                   'enroller_sha256': sha256(HOME / 'bin/panel-node')})


def resume(package, version):
    """Finish our interrupted installation without replacing any private identity."""
    helper = wizard(package); legacy = helper.load_installer(package)
    require(HOME.parent.stat().st_uid == 0, 'node_namespace_not_root_owned')
    owner = decode(regular(HOME / 'owner.json', private=True))
    require(owner.get('instance') == 'main' and owner.get('home') == str(HOME)
            and owner.get('service') == 'salfetka-main' and owner.get('backend') == 'managed', 'node_ownership_mismatch')
    environment = dict(line.split('=', 1) for line in regular(HOME / 'config/agent.env').decode().splitlines())
    with lock('/run/salfetka-install.lock'), tempfile.TemporaryDirectory(prefix='salfetka-resume-') as temporary:
        # build_plan revalidates node ID, origin, binaries, architecture and unit.
        # Dummy metadata is used only to reconstruct the plan, never for enrollment.
        token = Path(temporary) / 'identity.json'; save(token, {'node_id': owner['node_id']})
        spec = Path(temporary) / 'spec.json'
        save(spec, {'instance': 'main', 'backend': 'managed', 'node_id': owner['node_id'],
                    'panel_url': environment['PANEL_NODE_PANEL_URL'], 'ca_file': str(HOME / 'config/ca.crt'),
                    'signer_file': str(HOME / 'config/signer.pub'), 'enrollment_file': str(token)})
        plan = legacy.build_plan(package, spec)
        for relative, (raw, _) in plan['files'].items():
            if relative == 'config/enrollment.json': continue
            require(regular(HOME / relative, 256 * 1024 * 1024) == raw, 'partial_node_files_changed')
        require(regular(HOME / SERVICE) == plan['unit'], 'partial_node_unit_changed')
        unit = Path('/etc/systemd/system') / SERVICE
        if unit.exists(): require(regular(unit) == plan['unit'], 'foreign_node_unit_preserved')
        import pwd
        try: account = pwd.getpwnam('salfetka-main')
        except KeyError:
            run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', HOME / 'state', '--shell', '/usr/sbin/nologin', 'salfetka-main'])
            account = pwd.getpwnam('salfetka-main')
        require(account.pw_uid != 0 and account.pw_dir == str(HOME / 'state') and account.pw_shell == '/usr/sbin/nologin', 'foreign_service_user_preserved')
        if not (HOME / 'config/enrollment.json').exists(): plan['files'].pop('config/enrollment.json')
        legacy.secure_ownership(plan, HOME, account.pw_uid, account.pw_gid)
        env = dict(plan['env'], PATH='/usr/sbin:/usr/bin:/sbin:/bin')
        if (HOME / 'config/enrollment.json').exists():
            invite = decode(regular(HOME / 'config/enrollment.json', private=True))
            require(invite['node_id'] == owner['node_id'], 'partial_enrollment_identity_mismatch')
            enroll_env = dict(env, PANEL_NODE_TOKEN_FILE=str(HOME / 'config/enrollment.json'))
            enroll_env.pop('PANEL_NODE_EXPECTED_ID', None)
            run(['runuser', '-u', 'salfetka-main', '--', HOME / 'bin/panel-node', 'enroll'], env=enroll_env)
            (HOME / 'config/enrollment.json').unlink()
        run(['runuser', '-u', 'salfetka-main', '--', HOME / 'bin/panel-server-node', 'initialize'], env=env)
        if not unit.exists(): atomic(unit, plan['unit'], 0o644)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', SERVICE])
    health()
    save(HOME / 'release.json', {'version': version, 'binary_sha256': sha256(HOME / 'bin/panel-server-node'),
                               'enroller_sha256': sha256(HOME / 'bin/panel-node')})
