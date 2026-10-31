"""Interactive three-role installer and explicit signed release updates."""
import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import warnings

from . import backup, node, panel, system
from .common import Failure, atomic, decode, lock, regular, require, save, sha256, version
from .releases import Catalog, Github, compatible, unpack, verify_manifest

ROOT = Path('/opt/salfetka-manager')
VERSION = '0.6.0'


def private_prompt(label):
    require(sys.stdin.isatty(), 'interactive_terminal_required')
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        try: return getpass.getpass(label)
        except (getpass.GetPassWarning, EOFError): raise Failure('hidden_terminal_input_required') from None


def confirm(message):
    require(sys.stdin.isatty(), 'interactive_terminal_required')
    return input(message + ' [yes/no]: ').strip() == 'yes'


def initial_config(role):
    value = {'role': role}
    if role in ('panel', 'both'):
        value['admin_domain'] = system.domain(input('Домен панели: ').strip().lower())
        value['subscription_domain'] = system.domain(input('Домен подписок: ').strip().lower())
        require(value['admin_domain'] != value['subscription_domain'], 'separate_domains_required')
        import ipaddress
        value['address'] = str(ipaddress.ip_address(input('Публичный IP этого сервера (для проверки DNS): ').strip()))
        value['email'] = input('Email для сертификатов Let’s Encrypt: ').strip()
        require(re.fullmatch(r'[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+', value['email']), 'invalid_acme_email')
        value['username'] = input('Логин владельца панели: ').strip()
        require(re.fullmatch(r'[a-z0-9][a-z0-9_.-]{2,63}', value['username']), 'invalid_owner_username')
        value['public_port'] = 9443 if role == 'both' else 443
        for host in (value['admin_domain'], value['subscription_domain']): system.dns(host, value['address'])
        if role == 'both':
            value['node_name'] = input('Название этого сервера в панели: ').strip()
            require(2 <= len(value['node_name']) <= 80 and all(ord(c) >= 32 for c in value['node_name']), 'invalid_node_name')
            value['node_domain'] = system.domain(input('Отдельный домен ноды: ').strip().lower())
            system.dns(value['node_domain'], value['address'])
        print('Панель: https://' + value['admin_domain'] + (':9443' if role == 'both' else ''))
        print('Подписки: https://' + value['subscription_domain'] + (':9443' if role == 'both' else ''))
        print('Защищённая связь нод: TCP 18443. Выпуск/продление HTTPS: входящий TCP 80.')
        if role == 'both': print('TCP/UDP 443 оставлены ноде; панель и подписки используют HTTPS 9443.')
    return value


class Manager:
    def __init__(self, root=ROOT, token_file=None, key=None):
        self.root = Path(root)
        self.key = key or regular(Path(__file__).resolve().parents[1] / 'release-public-key.pem', 1024)
        self.catalog = Catalog(Github(token_file=token_file), self.key)
        self.platform = system.platform_id()

    def state(self):
        return decode(regular(self.root / 'state.json', private=True))

    def commit(self, state):
        save(self.root / 'state.json', state)

    def journal(self, operation, phase, **values):
        save(self.root / 'transaction.json', {'operation': operation, 'phase': phase,
             'at': datetime.now(timezone.utc).isoformat(), **values})

    def fetch(self, tag, components, installed=None):
        releases = self.root / 'releases'; releases.mkdir(mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.fetch-', dir=releases) as temporary:
            manifest, assets = self.catalog.fetch(temporary, tag)
            for current in (installed or {}).values(): compatible(manifest, current['version'])
            destination = releases / manifest['version']
            if destination.exists():
                require(sha256(destination / 'release.json') == sha256(Path(temporary) / 'release.json'), 'release_version_republished_refused')
            else:
                destination.mkdir(mode=0o700)
                for name in ('release.json', 'release.sig'): atomic(destination / name, regular(Path(temporary) / name))
            for component in components:
                artifact = next((a for a in manifest['artifacts'] if a['component'] == component and a['platform'] == self.platform), None)
                require(artifact is not None, 'release_component_missing')
                archive = destination / artifact['name']
                if archive.exists():
                    require(archive.stat().st_size == artifact['bytes'] and sha256(archive) == artifact['sha256'], 'cached_package_corrupt')
                    # Verify the persistent extraction without replacing code that
                    # may be executing this very command.
                    extracted = destination / component
                    if not extracted.exists():
                        unpack(archive, extracted)
                    else:
                        fresh = Path(temporary) / component
                        unpack(archive, fresh)
                        for source in fresh.rglob('*'):
                            target = extracted / source.relative_to(fresh)
                            require(not target.is_symlink(), 'cache_symlink_refused')
                            if source.is_file():
                                require(target.is_file() and sha256(source) == sha256(target), 'cached_extraction_modified')
                else:
                    self.catalog.component(manifest, assets, component, self.platform, destination)
            return manifest, destination

    def install_launcher(self, directory, target):
        package = directory / 'installer'
        require(regular(package / 'release-public-key.pem') == self.key, 'installer_trust_change_refused')
        launcher = Path('/usr/local/sbin/salfetka')
        if launcher.exists():
            old = regular(launcher, 4096)
            require(old.startswith(b'#!/bin/sh\n# Salfetka managed installer\n'), 'foreign_command_preserved')
        launcher.parent.mkdir(parents=True, exist_ok=True)
        atomic(launcher, ('#!/bin/sh\n# Salfetka managed installer\nexec /usr/bin/python3 '
                         + str(package / 'salfetka.py') + ' "$@"\n').encode(), 0o755)
        self.renew_timer()

    def renew_timer(self):
        # This timer only renews owned public certificates. It never updates code.
        definitions = {
            'salfetka-certificate.service': '[Unit]\nDescription=Salfetka public TLS renewal\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/salfetka renew\nUMask=0077\n',
            'salfetka-certificate.timer': '[Unit]\nDescription=Salfetka public TLS renewal schedule\n[Timer]\nOnCalendar=*-*-* 03,15:17:00\nRandomizedDelaySec=3600\nPersistent=true\n[Install]\nWantedBy=timers.target\n'}
        from .common import run
        for name, value in definitions.items():
            path = Path('/etc/systemd/system') / name
            if path.exists(): require(regular(path) == value.encode(), 'foreign_renewal_unit_preserved')
            atomic(path, value.encode(), 0o644)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', 'salfetka-certificate.timer'])

    def install(self, role, tag, config=None, password=None, invitation=None, public_pair=None):
        # Injected configuration/TLS is used by isolated Linux acceptance; the
        # public CLI always goes through DNS, terminal confirmation and ACME.
        if (self.root / 'state.json').exists():
            state = self.state(); require(state.get('phase') == 'installing', 'already_installed_use_menu')
            require(state['config']['role'] == role, 'resume_role_mismatch')
            config = state['config']; tag = state['target']
        else:
            config = config or initial_config(role)
            require(config['role'] == role, 'role_mismatch')
            state = {'schema': 1, 'phase': 'installing', 'config': config, 'components': {}}
        components = ['installer'] + (['panel'] if role in ('panel', 'both') else []) + (['node'] if role in ('node', 'both') else [])
        manifest, directory = self.fetch(tag, components)
        state['target'] = manifest['version']
        # Only verified code is persisted; no services are touched before confirmation.
        self.commit(state)
        self.journal('install', 'dependencies', target=manifest['version'])
        system.dependencies(panel=role in ('panel', 'both'))
        self.install_launcher(directory, manifest['version'])
        state['components']['installer'] = {'version': manifest['version']}; self.commit(state)
        home = self.root / 'panel'
        if role in ('panel', 'both'):
            password = password or private_prompt('Пароль владельца (не менее 12 символов): ')
            require(len(password) >= 12 and len(password.encode('utf-8')) <= 128, 'owner_password_length_invalid')
            if not home.exists():
                system.free_ports([80, 18443, config['public_port']])
                self.journal('install', 'certificate', target=manifest['version'])
                cert, key = public_pair or system.acme(self.root / 'acme', [config['admin_domain'], config['subscription_domain']], config['email'])
                image = panel.load_image(directory / 'panel')
                require(image['version'] == manifest['version'] and image['platform'] == self.platform, 'panel_image_release_mismatch')
                self.journal('install', 'panel_stage', target=manifest['version'])
                panel.stage(home, directory / 'panel', config, image, cert, key)
            panel.owned(home)
            self.journal('install', 'panel_initialize', target=manifest['version'])
            panel.initialize(home)
            api = panel.setup_owner(home, config['username'], password)
            state['components']['panel'] = {'version': manifest['version']}; self.commit(state)
            try:
                if role == 'both' and not node.HOME.exists():
                    path = home / 'combined.json'
                    journal = decode(regular(path, private=True)) if path.exists() else {}
                    invitation = panel.combined_invitation(home, api, config, journal)
            finally: api.logout()
            panel.health(home)
        if role in ('node', 'both'):
            self.journal('install', 'node_install', target=manifest['version'])
            if not node.HOME.exists():
                helper = node.wizard(directory / 'node')
                if invitation is None:
                    print('Скопируйте единый код из своей авторизованной панели → Сервер → Установить ноду.')
                    code = helper.read_code(); invitation = helper.decode_code(code)
                    info = helper.verify_panel(invitation)
                    print(json.dumps(info, ensure_ascii=False, indent=2))
                    require(confirm('Адрес панели верен? Зарегистрировать ноду?'), 'installation_cancelled')
                    helper.decode_code(code); helper.verify_panel(invitation)
                node.install(directory / 'node', invitation, manifest['version'])
            else:
                # A completed enrollment can be resumed without consuming a new code.
                node.resume(directory / 'node', manifest['version'])
            state['components']['node'] = {'version': manifest['version']}; self.commit(state)
        state['phase'] = 'ready'; self.commit(state); self.journal('install', 'complete')
        print('Установка завершена. Управление: sudo salfetka')
        if 'panel' in state['components']: print('Панель: ' + panel.owned(home)['admin_origin'])

    def check(self, tag=None):
        state = self.state()
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            manifest, _ = self.catalog.fetch(temporary, tag)
        for component, value in state['components'].items():
            compatible(manifest, value['version'])
            print(component + ': ' + value['version'] + ' → ' + manifest['version'])
        if 'panel' in state['components']: compatible(manifest, state['components']['panel']['version'], panel.database_version(self.root / 'panel'))
        return manifest

    def update(self, tag=None, selected='all'):
        state = self.state()
        require(state['phase'] in ('ready', 'updating'), 'finish_install_or_restore_first')
        if state['phase'] == 'updating':
            pending = decode(regular(self.root / 'transaction.json', private=True))
            tag, selected = pending['target'], pending['selected']
        wanted = list(state['components']) if selected == 'all' else [selected]
        require(all(c in state['components'] for c in wanted), 'component_not_installed')
        manifest, directory = self.fetch(tag, wanted, {c: state['components'][c] for c in wanted})
        if 'panel' in wanted: compatible(manifest, state['components']['panel']['version'], panel.database_version(self.root / 'panel'))
        if state['phase'] != 'updating' and all(state['components'][c]['version'] == manifest['version'] for c in wanted):
            print('Уже установлена эта версия.'); return
        # Download/verify/load before any outage; journal survives process death.
        if 'panel' in wanted: panel.load_image(directory / 'panel')
        if state['phase'] == 'updating':
            point = Path(pending['backup'])
            backup.verify(point)
        else:
            point = backup.create(self.root, state)
        print('Резервная копия: ' + str(point))
        self.journal('update', 'prepared', target=manifest['version'], selected=selected, backup=str(point))
        state['phase'] = 'updating'; self.commit(state)
        for component in wanted:
            self.journal('update', component, target=manifest['version'], selected=selected, backup=str(point))
            if component == 'panel': panel.update(self.root / 'panel', directory / 'panel', manifest['version'])
            elif component == 'node': node.update(directory / 'node', manifest['version'])
            else: self.install_launcher(directory, manifest['version'])
            state['components'][component] = {'version': manifest['version']}; self.commit(state)
        state['phase'] = 'ready'; self.commit(state); self.journal('update', 'complete')
        print('Обновление завершено; данные и идентичности сохранены.')

    def renew(self):
        state = self.state()
        if 'panel' not in state['components']: return
        require(state['phase'] in ('ready', 'stopped', 'restored_stopped'), 'installation_operation_in_progress')
        from .common import run
        home = self.root / 'acme'
        run(['certbot', 'renew', '--non-interactive', '--config-dir', home / 'config',
             '--work-dir', home / 'work', '--logs-dir', home / 'logs'], timeout=600)
        cert, key = system.public_pair(home)
        config = state['config']; target = self.root / 'panel/public-tls'
        if regular(target / 'fullchain.pem') == cert and regular(target / 'privkey.pem') == key: return
        panel.owned(self.root / 'panel')
        system.install_public_pair(target, cert, key, [config['admin_domain'], config['subscription_domain']])
        for path in target.iterdir(): os.chown(path, 0, 65532); path.chmod(0o640)
        if state['phase'] == 'ready':
            panel.compose(self.root / 'panel', 'exec', '-T', 'edge', 'nginx', '-t')
            panel.compose(self.root / 'panel', 'exec', '-T', 'edge', 'nginx', '-s', 'reload')

    def status(self):
        state = self.state()
        print(json.dumps({'phase': state['phase'], 'components': state['components']}, ensure_ascii=False, indent=2))
        if state['phase'] != 'ready':
            print('Установка не отмечена работающей; этап операции: /opt/salfetka-manager/transaction.json')
            return
        if 'panel' in state['components']: panel.health(self.root / 'panel')
        if 'node' in state['components']: node.health()
        print('Проверка работающих служб и защищённой связи: OK')


def main():
    parser = argparse.ArgumentParser(description='САЛФЕТКА: установка, обновления и управление')
    parser.add_argument('operation', nargs='?', choices=['install', 'check', 'update', 'status', 'backup', 'restore', 'start', 'stop', 'renew'])
    parser.add_argument('--role', choices=['panel', 'node', 'both'])
    parser.add_argument('--version'); parser.add_argument('--component', choices=['all', 'installer', 'panel', 'node'], default='all')
    parser.add_argument('--github-token-file', help='Только для временного PRIVATE-репозитория; файл 0600')
    parser.add_argument('--backup-dir')
    args = parser.parse_args()
    os.umask(0o077); system.platform_id()
    require(not ROOT.is_symlink() and not any(p.is_symlink() for p in ROOT.parents), 'manager_path_unsafe')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(ROOT.stat().st_uid == 0 and ROOT.stat().st_mode & 0o077 == 0, 'manager_directory_not_private')
    with lock('/run/salfetka-manager.lock'):
        manager = Manager(token_file=args.github_token_file)
        if not args.operation:
            if (ROOT / 'state.json').exists():
                current = manager.state()
                if current['phase'] == 'installing':
                    print('Есть незавершённая установка. Продолжение сохранит созданные ключи и данные.')
                    args.operation, args.role = 'install', current['config']['role']
                else:
                    print('1 — состояние; 2 — проверить обновления; 3 — обновить; 4 — резервная копия; 5 — восстановить; 6 — запустить; 7 — остановить')
                    args.operation = {'1': 'status', '2': 'check', '3': 'update', '4': 'backup', '5': 'restore', '6': 'start', '7': 'stop'}.get(input('Выбор: ').strip())
            else:
                print('1 — панель и нода; 2 — только нода; 3 — только панель')
                args.role = {'1': 'both', '2': 'node', '3': 'panel'}.get(input('Выбор: ').strip()); args.operation = 'install'
        require(args.operation is not None, 'operation_required')
        if args.operation == 'install':
            require(args.role is not None, 'role_required')
            require(confirm('Установить выбранные компоненты на этом сервере?'), 'installation_cancelled')
            manager.install(args.role, args.version)
        elif args.operation == 'check': manager.check(args.version)
        elif args.operation == 'update':
            manager.check(args.version)
            require(confirm('Установить обновление? Работа компонентов кратковременно прервётся.'), 'update_cancelled')
            manager.update(args.version, args.component)
        elif args.operation == 'renew': manager.renew()
        elif args.operation == 'status': manager.status()
        elif args.operation == 'backup': print('Резервная копия: ' + str(backup.create(ROOT, manager.state())))
        elif args.operation == 'restore':
            directory = args.backup_dir or input('Путь к резервной копии: ').strip()
            backup.verify(directory)
            print('Восстановление возвращает данные к дате копии, включая права доступа. Более поздние изменения будут потеряны. Ноды и их локальные ключи не заменяются. Панель останется остановленной до отдельного запуска.')
            require(confirm('Восстановить данные из этой копии?'), 'restore_cancelled')
            state = manager.state(); point = backup.create(ROOT, state)
            manager.journal('restore', 'database', backup=str(point))
            state['phase'] = 'restoring'; manager.commit(state)
            db = backup.restore(ROOT, directory, state)
            state['phase'] = 'restored_stopped'; manager.commit(state); manager.journal('restore', 'complete', database=db)
            print('Данные восстановлены в отдельной БД. Проверьте дату копии; запуск: sudo salfetka start')
        else:
            from .common import run
            state = manager.state()
            require(state['phase'] in ('ready', 'stopped', 'restored_stopped'), 'finish_pending_operation_first')
            require(confirm('Запустить службы?' if args.operation == 'start' else 'Остановить службы?'), 'operation_cancelled')
            if 'panel' in state['components']:
                panel.owned(ROOT / 'panel')
                if args.operation == 'start': panel.compose(ROOT / 'panel', 'up', '-d', 'postgres', 'admin', 'delivery', 'worker', 'edge')
                else: panel.compose(ROOT / 'panel', 'stop', 'edge', 'admin', 'delivery', 'worker')
            if 'node' in state['components']:
                package = ROOT / 'releases' / state['components']['node']['version'] / 'node'
                node.owned(package); run(['systemctl', args.operation, node.SERVICE])
            if args.operation == 'start':
                if 'panel' in state['components']: panel.health(ROOT / 'panel')
                if 'node' in state['components']: node.health()
                state['phase'] = 'ready'; manager.commit(state)
            else:
                state['phase'] = 'stopped'; manager.commit(state)
