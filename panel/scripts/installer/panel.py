"""Owned Compose runtime; public ACME TLS never changes machine trust."""
import hashlib
import json
from pathlib import Path
import re
import time
import uuid

from .api import API
from .common import Failure, atomic, decode, regular, require, run, save, sha256
from .system import domain, install_public_pair, private_tls

NGINX = 'nginx:stable-bookworm@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609'
PROJECT = 'salfetka-managed'


def compose(home, *args, output=None, input=None):
    return run(['docker', 'compose', '--project-name', PROJECT, '--env-file', 'compose.env',
                '-f', 'compose.json', *args], cwd=home, timeout=600, output=output, input=input)


def owned(home):
    home = Path(home)
    owner = decode(regular(home / 'owner.json', private=True))
    require(owner.get('schema') == 2 and owner.get('project') == PROJECT
            and owner.get('home') == str(home) and owner.get('compose_sha256') == sha256(home / 'compose.json'),
            'panel_ownership_mismatch')
    return owner


def record(home, doc, owner):
    raw = (json.dumps(doc, indent=2) + '\n').encode()
    # Caller writes its transaction journal first; interrupted pair is explicit.
    atomic(Path(home) / 'compose.json', raw)
    owner['compose_sha256'] = hashlib.sha256(raw).hexdigest()
    save(Path(home) / 'owner.json', owner)


def load_image(package):
    package = Path(package)
    data = decode(regular(package / 'image.json'))
    require(set(data) == {'image_id', 'version', 'platform'}
            and re.fullmatch(r'sha256:[0-9a-f]{64}', data['image_id']), 'image_metadata_invalid')
    run(['docker', 'load', '-i', package / 'image.tar'], timeout=600)
    value = run(['docker', 'image', 'inspect', '--format={{.Id}}', data['image_id']]).decode().strip()
    require(value == data['image_id'], 'image_id_mismatch')
    arch = run(['docker', 'image', 'inspect', '--format={{.Os}}/{{.Architecture}}', value]).decode().strip()
    require(arch == data['platform'], 'image_architecture_mismatch')
    return data


def edge_config(config):
    admin, subscription = domain(config['admin_domain']), domain(config['subscription_domain'])
    port = config['public_port']
    require(port in (443, 9443), 'public_port_invalid')
    servers = []
    for host, upstream, target in [(admin, 'admin:18443', admin), (subscription, 'delivery:18483', subscription)]:
        servers.append(f'''server {{
 listen 8443 ssl; server_name {host};
 ssl_certificate /tls/fullchain.pem; ssl_certificate_key /tls/privkey.pem;
 ssl_protocols TLSv1.2 TLSv1.3;
 client_max_body_size 5m;
 location / {{
  proxy_pass https://{upstream}; proxy_ssl_server_name on; proxy_ssl_name {target};
  proxy_ssl_trusted_certificate /machine/tls.crt; proxy_ssl_verify on;
  proxy_set_header Host $http_host; proxy_set_header X-Forwarded-For "";
  proxy_http_version 1.1; proxy_read_timeout 30s;
 }}
}}''')
    return ('pid /tmp/nginx.pid; events { worker_connections 1024; }\nhttp {\n'
            'access_log off; error_log /dev/stderr warn; server_tokens off;\n'
            'client_body_temp_path /tmp/client; proxy_temp_path /tmp/proxy;\n'
            'fastcgi_temp_path /tmp/fastcgi; uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi;\n'
            'server { listen 8443 ssl default_server; ssl_reject_handshake on; }\n'
            + '\n'.join(servers) + '\n}\n').encode()


def stage(home, package, config, image, public_cert, public_key):
    home, package = Path(home), Path(package)
    require(not home.exists(), 'panel_home_exists_preserved')
    existing = run(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + PROJECT]).strip()
    volumes = run(['docker', 'volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + PROJECT]).strip()
    require(not existing and not volumes, 'foreign_compose_project_preserved')
    home.mkdir(mode=0o700)
    # Staging has no external effects; a partial home is retained for diagnosis.
    run([package / 'artifacts/bin/panelctl', 'prepare', '--dir', home / 'secrets'])
    secret = home / 'secrets'
    (secret / 'tls.crt').unlink(); (secret / 'tls.key').unlink()
    private_tls(secret, [config['admin_domain'], config['subscription_domain']])
    (secret / 'tls.crt').chmod(0o644)
    atomic(secret / 'delivery.crt', regular(secret / 'tls.crt'))
    atomic(secret / 'delivery.key', regular(secret / 'tls.key'))
    install_public_pair(home / 'public-tls', public_cert, public_key,
                        [config['admin_domain'], config['subscription_domain']])
    doc = decode(regular(package / 'deploy/pilot/compose.json'))
    doc['name'] = PROJECT
    services = doc['services']
    admin_origin = 'https://' + config['admin_domain'] + (':9443' if config['public_port'] == 9443 else '')
    sub_origin = 'https://' + config['subscription_domain'] + (':9443' if config['public_port'] == 9443 else '')
    machine_origin = 'https://' + config['admin_domain'] + ':18443'
    services['admin']['environment'].update(PANEL_PUBLIC_ORIGIN=admin_origin, PANEL_NODE_INSTALL_ORIGIN=machine_origin)
    services['admin']['ports'] = ['0.0.0.0:18443:18443']
    # Delivery is reachable only via its separate nginx vhost and Compose network.
    services['delivery'].pop('ports', None)
    services['edge'] = {'image': NGINX, 'entrypoint': ['nginx', '-g', 'daemon off;'],
        'user': '65532:65532', 'read_only': True, 'cap_drop': ['ALL'],
        'security_opt': ['no-new-privileges:true'], 'tmpfs': ['/tmp:size=32m,mode=1777'],
        'restart': 'unless-stopped', 'pids_limit': 128, 'mem_limit': '128m',
        'logging': {'driver': 'local', 'options': {'max-size': '5m', 'max-file': '3'}},
        'ports': [f"0.0.0.0:{config['public_port']}:8443"],
        'volumes': ['./edge.conf:/etc/nginx/nginx.conf:ro', './public-tls:/tls:ro', './secrets/tls.crt:/machine/tls.crt:ro']}
    # The edge UID has read-only access to its own public TLS; machine secrets stay private.
    (home / 'public-tls').chmod(0o750)
    import os
    os.chown(home / 'public-tls', 0, 65532)
    for path in (home / 'public-tls').iterdir(): os.chown(path, 0, 65532); path.chmod(0o640)
    atomic(home / 'edge.conf', edge_config(config), 0o644)
    atomic(home / 'compose.env', (f"PANEL_IMAGE={image['image_id']}\nPANEL_UID=0\nPANEL_GID=0\nPANEL_ADMIN_PORT=18443\n"
           f"PANEL_SUBSCRIPTION_ORIGIN={sub_origin}\n").encode())
    owner = {'schema': 2, 'home': str(home), 'project': PROJECT, 'version': image['version'],
             'image_id': image['image_id'], 'admin_origin': admin_origin, 'subscription_origin': sub_origin,
             'machine_origin': machine_origin}
    record(home, doc, owner)
    compose(home, 'config', '--quiet')
    return owner


def client(home):
    owner = owned(home)
    return API(owner['machine_origin'], Path(home) / 'secrets/tls.crt', owner['admin_origin'])


def wait_ready(home):
    api = client(home)
    for _ in range(60):
        try: api.call('/readyz'); return api
        except Failure: time.sleep(2)
    raise Failure('panel_readiness_timeout')


def initialize(home):
    owned(home)
    compose(home, 'up', '-d', 'postgres')
    for args in [('migrate',), ('provision-runtime', '--password-file', '/run/panel/runtime-password')]:
        compose(home, 'run', '--rm', 'setup', *args)
    # Bootstrap is durable and replayable until used; never regenerate identities.
    if not (Path(home) / 'owner-created').exists():
        compose(home, 'run', '--rm', 'setup', 'bootstrap', '--token-file', '/run/panel/bootstrap.json')
    compose(home, 'up', '-d', 'admin', 'delivery', 'worker', 'edge')
    return wait_ready(home)


def setup_owner(home, username, password):
    api = wait_ready(home)
    if api.call('/api/v1/setup/status')['setup_required']:
        token = decode(regular(Path(home) / 'secrets/bootstrap.json', private=True))['token']
        api.call('/api/v1/setup', {'token': token, 'username': username, 'password': password})
    api.login(username, password)
    atomic(Path(home) / 'owner-created', b'1\n')
    path = Path(home) / 'secrets/bootstrap.json'
    if path.exists(): path.unlink()
    return api


def combined_invitation(home, api, config, journal):
    # Stable operation keys survive a lost HTTP response; no duplicate server/node.
    journal.setdefault('server_key', str(uuid.uuid4()))
    journal.setdefault('node_key', str(uuid.uuid4()))
    journal.setdefault('enrollment_key', str(uuid.uuid4()))
    save(Path(home) / 'combined.json', journal)
    server = api.call('/api/v1/servers', {'name': config['node_name'], 'address': config['address'],
                      'domain': config['node_domain']}, key=journal['server_key'])
    node = api.call('/api/v1/managed/servers/' + server['id'] + '/node', {}, key=journal['node_key'])
    current = api.call('/api/v1/nodes/' + node['id'])
    journal.setdefault('enrollment_revision', current['revision'])
    save(Path(home) / 'combined.json', journal)
    invitation = api.call('/api/v1/nodes/' + node['id'] + '/enrollment', {},
                          key=journal['enrollment_key'], revision=journal['enrollment_revision'])['enrollment']
    info = api.call('/api/v1/managed/install-info')
    info.update({key: invitation[key] for key in ('node_id', 'token', 'expires_at')})
    return info


def database_version(home):
    owned(home)
    from .backup import database_name
    return int(compose(home, 'exec', '-T', 'postgres', 'psql', '-U', 'panel_migrator', '-d', database_name(home),
                       '-Atc', 'SELECT COALESCE(max(version),0) FROM schema_migrations').decode().strip())


def health(home):
    wait_ready(home)
    for service in ('postgres', 'admin', 'delivery', 'worker', 'edge'):
        ids = compose(home, 'ps', '-q', service).decode().split()
        require(len(ids) == 1, 'panel_service_missing:' + service)
        require(run(['docker', 'inspect', '--format={{.State.Running}}', ids[0]]).strip() == b'true', 'panel_service_not_running:' + service)
    compose(home, 'exec', '-T', 'edge', 'nginx', '-t')
    owner = owned(home)
    for origin in (owner['admin_origin'], owner['subscription_origin']):
        API(origin, Path(home) / 'public-tls/fullchain.pem').call('/readyz')


def update(home, package, target):
    owner = owned(home)
    image = load_image(package)
    require(image['version'] == target, 'image_version_mismatch')
    compose(home, 'stop', 'edge', 'admin', 'delivery', 'worker')
    # Persisted journal in manager records target before changing the image.
    env = regular(Path(home) / 'compose.env').decode().splitlines()
    env = [f"PANEL_IMAGE={image['image_id']}" if line.startswith('PANEL_IMAGE=') else line for line in env]
    atomic(Path(home) / 'compose.env', ('\n'.join(env) + '\n').encode())
    compose(home, 'run', '--rm', 'setup', 'migrate')
    compose(home, 'up', '-d', 'admin', 'delivery', 'worker', 'edge')
    health(home)
    owner.update(version=target, image_id=image['image_id'])
    save(Path(home) / 'owner.json', owner)
