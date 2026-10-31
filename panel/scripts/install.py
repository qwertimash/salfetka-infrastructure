#!/usr/bin/env python3
"""One local installer entry point: panel, one server node, or both.
Plan is read-only. No SSH, firewall, DNS, package manager or remote shell scripts.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
from types import SimpleNamespace
from urllib.parse import urlsplit

class InstallError(Exception):
    pass

def fail(code):
    raise InstallError(code)

def read(path, maximum=64*1024*1024):
    p=Path(path).absolute()
    if any(q.is_symlink() for q in [p,*p.parents]) or not p.is_file() or p.stat().st_size>maximum:
        fail('unsafe_source_file')
    return p.read_bytes()

def command(argv, cwd=None, timeout=90, output=None):
    result=subprocess.run(argv,cwd=cwd,stdout=output or subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if result.returncode: fail('command_failed:'+Path(argv[0]).name)
    return result.stdout

def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def verify_panel(package):
    p=Path(package).absolute();manifest=json.loads(read(p/'SHA256.json',4*1024*1024))
    arch={'x86_64':'amd64','arm64':'arm64','aarch64':'arm64'}.get(platform.machine())
    if manifest.get('schema')!=1 or manifest.get('platform')!='linux/'+str(arch) or not isinstance(manifest.get('files'),dict):fail('panel_package_invalid')
    required=['artifacts/bin/panelctl','artifacts/bin/panel-api','artifacts/bin/panel-worker','scripts/prepare-pilot.py','deploy/pilot/compose.json','web/dist/index.html']
    for relative,digest in manifest['files'].items():
        path=Path(relative)
        if path.is_absolute() or '..' in path.parts or not re.fullmatch('[0-9a-f]{64}',digest):fail('package_manifest_invalid')
        if hashlib.sha256(read(p/path)).hexdigest()!=digest:fail('package_checksum_failed')
    if any(f not in manifest['files'] for f in required):fail('package_incomplete')
    for name in ['panelctl','panel-api','panel-worker']:
        raw=read(p/'artifacts/bin'/name)
        machine=62 if arch=='amd64' else 183
        if len(raw)<20 or raw[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(raw[18:20],'little')!=machine:fail('package_architecture_mismatch')
    return p

def panel_plan(package,spec):
    allowed={'instance','admin_origin','subscription_origin','bind','certificate_file','key_file','image','image_id'}
    if set(spec)-allowed:fail('panel_spec_fields_invalid')
    name=spec.get('instance','')
    if not re.fullmatch('[a-z][a-z0-9-]{0,15}',name):fail('instance_invalid')
    package=verify_panel(package)
    prepare=module(package/'scripts/prepare-pilot.py','salfetka_prepare')
    ah,ap=prepare.origin(spec['admin_origin']);sh,sp=prepare.origin(spec['subscription_origin'])
    if ap==sp or ap<1024:fail('panel_ports_conflict')
    import ipaddress
    bind=str(ipaddress.IPv4Address(spec['bind']))
    if not re.fullmatch(r'[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_.-]+',spec['image']):fail('image_tag_required')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',spec['image_id']):fail('verified_image_id_required')
    cert=read(spec['certificate_file'],65536);key=read(spec['key_file'],65536)
    if Path(spec['key_file']).stat().st_mode&0o077:fail('tls_key_must_be_private')
    import ssl
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(spec['certificate_file'],spec['key_file'])
    for host in [ah,sh]:command(['openssl','x509','-in',spec['certificate_file'],'-noout','-checkhost',host])
    command(['openssl','x509','-in',spec['certificate_file'],'-noout','-checkend','86400'])
    # No private material is returned in the reviewable plan.
    return {'kind':'panel','instance':name,'home':'/opt/salfetka-stack/'+name+'/panel','project':'salfetka-'+name,
            'package':str(package),'bind':bind,'admin_port':ap,'delivery_port':sp,'image':spec['image'],'image_id':spec['image_id']}

def preflight_panel(plan,root=Path('/'),ports=True):
    home=root/plan['home'].lstrip('/')
    if home.exists() or any(p.is_symlink() for p in [home,*home.parents]):fail('existing_installation_preserved')
    if ports:
        for port in [plan['admin_port'],plan['delivery_port']]:
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
                try:sock.bind((plan['bind'],port))
                except OSError:fail('panel_listener_unavailable')
    return home

def compose(home,project,*args,output=None):
    return command(['docker','compose','--project-name',project,'--env-file','compose.env','-f','compose.json',*args],cwd=home,timeout=180,output=output)

def install_panel(plan,spec):
    if platform.system()!='Linux' or os.geteuid()!=0:fail('linux_root_required')
    home=preflight_panel(plan)
    if not shutil.which('docker'):fail('docker_compose_required')
    image=command(['docker','image','inspect','--format={{.Id}}',plan['image']]).decode().strip()
    if image!=plan['image_id']:fail('image_digest_mismatch')
    # Refuse adopting an existing Compose project, including a stopped one.
    existing=command(['docker','ps','-aq','--filter','label=com.docker.compose.project='+plan['project']]).strip()
    volumes=command(['docker','volume','ls','-q','--filter','label=com.docker.compose.project='+plan['project']]).strip()
    if existing or volumes:fail('compose_project_already_exists')
    home.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    prepare=module(Path(plan['package'])/'scripts/prepare-pilot.py','salfetka_prepare_install')
    prepare.prepare(SimpleNamespace(dir=str(home),origin=spec['subscription_origin'],bind=plan['bind'],admin_port=plan['admin_port'],image=spec['image'],panelctl=str(Path(plan['package'])/'artifacts/bin/panelctl'),cert=spec['certificate_file'],key=spec['key_file'],lab=False))
    doc=json.loads((home/'compose.json').read_text());doc['name']=plan['project']
    doc['services']['admin']['environment']['PANEL_PUBLIC_ORIGIN']=spec['admin_origin']
    doc['services']['admin']['ports']=[f"{plan['bind']}:{plan['admin_port']}:18443"]
    # A new installation only: replace generated loopback admin TLS before any node enrollment.
    for name,source in [('tls.crt','certificate_file'),('tls.key','key_file')]:
        dest=home/'secrets'/name;dest.write_bytes(read(spec[source],65536));dest.chmod(0o600)
    encoded=(json.dumps(doc,indent=2)+'\n').encode();(home/'compose.json').write_bytes(encoded)
    owner=dict(plan,compose_sha256=hashlib.sha256(encoded).hexdigest(),schema=1)
    (home/'owner.json').write_text(json.dumps(owner,indent=2)+'\n');(home/'owner.json').chmod(0o600)
    compose(home,plan['project'],'config','--quiet')
    compose(home,plan['project'],'up','-d','postgres')
    for args in [('migrate',),('provision-runtime','--password-file','/run/panel/runtime-password'),('bootstrap','--token-file','/run/panel/bootstrap.json')]:
        compose(home,plan['project'],'run','--rm','setup',*args)
    compose(home,plan['project'],'up','-d','admin','delivery','worker')
    print('panel_started; bootstrap file: '+str(home/'secrets/bootstrap.json'))

def panel_owned(instance):
    if not re.fullmatch('[a-z][a-z0-9-]{0,15}',instance):fail('instance_invalid')
    home=Path('/opt/salfetka-stack')/instance/'panel';owner=json.loads(read(home/'owner.json',65536))
    if owner.get('kind')!='panel' or owner.get('home')!=str(home) or owner.get('project')!='salfetka-'+instance or owner.get('compose_sha256')!=hashlib.sha256(read(home/'compose.json',1024*1024)).hexdigest():fail('ownership_mismatch')
    return home,owner

def manage_panel(instance,operation):
    home,owner=panel_owned(instance);project=owner['project']
    if operation=='status':
        print(compose(home,project,'ps','--format','json').decode())
    elif operation=='start':compose(home,project,'up','-d','postgres','admin','delivery','worker')
    elif operation=='stop':compose(home,project,'stop','admin','delivery','worker','postgres')
    elif operation=='backup':
        from datetime import datetime,timezone
        import tarfile
        directory=home.parent/('backup-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));directory.mkdir(mode=0o700)
        path=directory/'database.dump'
        with path.open('xb') as stream:
            path.chmod(0o600);compose(home,project,'exec','-T','postgres','pg_dump','-U','panel_migrator','-Fc','panel',output=stream)
        archive=directory/'configuration.tar'
        with archive.open('xb') as stream:
            archive.chmod(0o600)
            with tarfile.open(fileobj=stream,mode='w') as out:
                for name in ['owner.json','compose.json','compose.env','secrets']:out.add(home/name,arcname=name,recursive=True)
        print('private_backup: '+str(directory))

def main():
    if len(sys.argv) == 1:
        from installer.manager import main as managed_main
        return managed_main()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',nargs='?',choices=['plan','install','status','start','stop','backup'])
    parser.add_argument('--role',choices=['panel','node','both']);parser.add_argument('--package',default=str(Path(__file__).resolve().parent))
    parser.add_argument('--spec');parser.add_argument('--instance')
    args=parser.parse_args()
    interactive=args.operation is None
    if not args.operation:
        print('САЛФЕТКА: 1 — панель; 2 — нода сервера; 3 — панель и нода')
        args.role={'1':'panel','2':'node','3':'both'}.get(input('Что установить: ').strip())
        if not args.role:fail('role_required')
        args.operation='plan';args.spec=input('Путь к файлу настроек установки: ').strip()
    if not args.role:fail('role_required')
    package=Path(args.package).absolute()
    node_module=None
    if args.role in ('node','both'):
        manifest = read(package/'node/SHA256SUMS',262144).decode().splitlines()
        checks = {line.split(None,1)[1].lstrip('*'):line.split(None,1)[0] for line in manifest}
        if hashlib.sha256(read(package/'node/install-node.py')).hexdigest()!=checks.get('install-node.py'):fail('installer_checksum_failed')
        node_module=module(package/'node/install-node.py','salfetka_node_install')
    if args.operation in ('status','start','stop','backup'):
        if args.role!='panel':fail('select_panel_for_this_operation')
        return manage_panel(args.instance or '',args.operation)
    if not args.spec:fail('spec_required')
    spec=json.loads(read(args.spec,262144));plans={}
    if set(spec)-{'panel','node_spec_file'}:fail('installer_spec_fields_invalid')
    if args.role=='both' and spec.get('node_spec_file'):fail('fresh_panel_requires_new_invitation_after_bootstrap')
    if args.role in ('panel','both'):
        plans['panel']=panel_plan(package/'panel',spec['panel']);preflight_panel(plans['panel'])
    if node_module and spec.get('node_spec_file'):
        plans['node']=node_module.build_plan(package/'node',spec['node_spec_file'])
        if plans['node']['backend']!='managed':fail('unified_installer_requires_managed_node')
        node_module.preflight(plans['node'])
    print(json.dumps({k:(node_module.receipt(v) if k=='node' else v) for k,v in plans.items()},indent=2))
    if node_module and 'node' not in plans and args.role=='node':fail('node_spec_required')
    if node_module and 'node' not in plans:print('After panel setup, create its node invitation and run the node stage with a fresh node_spec_file.')
    if args.operation=='plan':
        if not interactive or input('Установить показанные компоненты? Введите install: ').strip()!='install':return
        args.operation='install'
    if platform.system()!='Linux' or os.geteuid()!=0:fail('linux_root_required')
    if 'panel' in plans:install_panel(plans['panel'],spec['panel'])
    if args.role=='both' and 'node' not in plans:
        if not sys.stdin.isatty():fail('panel_installed_node_stage_requires_fresh_invitation')
        print('Создайте владельца в панели, затем сервер и приглашение ноды.')
        node_spec=input('Путь к node.json с новым приглашением этой панели: ').strip()
        plans['node']=node_module.build_plan(package/'node',node_spec)
        if plans['node']['backend']!='managed':fail('unified_installer_requires_managed_node')
        if plans['node']['env']['PANEL_NODE_PANEL_URL']!=spec['panel']['admin_origin']:fail('combined_node_panel_origin_mismatch')
    if 'node' in plans:
        node_module.install(plans['node'])
        print('node_installed; activate with: python3 node/install-node.py activate --instance '+plans['node']['instance'])

if __name__=='__main__':
    try:main()
    except Exception as error:
        print(str(error) if isinstance(error,InstallError) else 'installation_failed_existing_services_preserved',file=sys.stderr);sys.exit(1)
