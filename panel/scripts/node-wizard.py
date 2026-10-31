#!/usr/bin/env python3
"""Install a verified local node package using one code from your own panel.
The code is read from a terminal without echo, never a command-line argument.
"""
import argparse
import base64
from datetime import datetime, timezone, timedelta
import getpass
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import uuid
import warnings

class WizardError(Exception):
    pass

def unique_fields(pairs):
    value={}
    for key,item in pairs:
        if key in value: raise ValueError('duplicate_field')
        value[key]=item
    return value

def panel_origin(value):
    # Reject invisible characters, URL-parser normalization and terminal escapes.
    if not isinstance(value,str) or not re.fullmatch(r'https://[A-Za-z0-9.\-:\[\]]+',value):
        raise ValueError()
    u=urlsplit(value)
    if not u.hostname or u.username or u.password or u.path or u.query or u.fragment:
        raise ValueError()
    port=u.port if u.port is not None else 443
    if not 1<=port<=65535 or u.netloc.endswith(':'): raise ValueError()
    try: ipaddress.ip_address(u.hostname)
    except ValueError:
        if len(u.hostname)>253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label) for label in u.hostname.split('.')):
            raise ValueError()
    return u.hostname,port

def signer_der(value):
    match=re.fullmatch(r'-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)\n-----END PUBLIC KEY-----\n?',value)
    if not match: raise ValueError()
    der=base64.b64decode(match[1].replace('\n',''),validate=True)
    if len(der)!=44 or der[:12]!=bytes.fromhex('302a300506032b6570032100'): raise ValueError()
    return der

def certificate_der(value):
    # Existing invitations may contain a fullchain. Only its first certificate
    # pins the panel; extra certificates must never add independent trust roots.
    pattern=r'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END CERTIFICATE-----'
    blocks=re.findall(pattern,value)
    if not blocks or len(blocks)>8 or re.sub(pattern,'',value).strip(): raise ValueError()
    certificates=[ssl.PEM_cert_to_DER_cert(block) for block in blocks]
    if len(set(certificates))!=len(certificates): raise ValueError()
    return certificates[0]

def tls_context(value):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    # The invitation pins the panel's certificate, which may be a public leaf.
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(certificate_der(value['ca_pem'])))
    return ctx

def decode_code(code, now=None):
    if not isinstance(code,str) or not code.startswith('SN1.') or len(code)>65536:
        raise WizardError('invalid_install_code')
    try:
        if not re.fullmatch(r'[A-Za-z0-9_-]+',code[4:]): raise ValueError()
        raw=base64.b64decode(code[4:]+'='*(-len(code[4:])%4),altchars=b'-_',validate=True)
        value=json.loads(raw,object_pairs_hook=unique_fields)
        if not isinstance(value,dict) or set(value)!={'schema','panel_url','ca_pem','signer_pem','node_id','token','expires_at'} or type(value['schema']) is not int or value['schema']!=1:
            raise ValueError()
        for k in ('panel_url','ca_pem','signer_pem','node_id','token','expires_at'):
            if not isinstance(value[k],str): raise ValueError()
        panel_origin(value['panel_url'])
        if str(uuid.UUID(value['node_id']))!=value['node_id'] or not re.fullmatch(r'[A-Za-z0-9_-]{43}',value['token']): raise ValueError()
        token=base64.urlsafe_b64decode(value['token']+'=')
        if base64.urlsafe_b64encode(token).decode().rstrip('=')!=value['token']: raise ValueError()
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})',value['expires_at']): raise ValueError()
        expires=datetime.fromisoformat(value['expires_at'].replace('Z','+00:00'))
        current=now or datetime.now(timezone.utc)
        if not current<expires<=current+timedelta(minutes=15): raise WizardError('install_code_expired_or_clock_incorrect')
        if len(value['ca_pem'])>32768 or len(value['signer_pem'])>1024: raise ValueError()
        certificate_der(value['ca_pem']);signer_der(value['signer_pem']);tls_context(value)
        return value
    except WizardError:raise
    except (ValueError,TypeError,KeyError,ssl.SSLError,OverflowError,RecursionError):raise WizardError('invalid_install_code') from None

def read_code():
    if not sys.stdin.isatty(): raise WizardError('interactive_terminal_required')
    # getpass otherwise falls back to echoed input when terminal control fails.
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error',getpass.GetPassWarning)
            return getpass.getpass('Код установки (ввод скрыт): ')
    except (getpass.GetPassWarning,EOFError):
        raise WizardError('hidden_terminal_input_required') from None

def verify_panel(value):
    """TLS-only preflight: no enrollment token, HTTP request or redirect."""
    try:
        host,port=panel_origin(value['panel_url'])
        with socket.create_connection((host,port),timeout=5) as connection:
            with tls_context(value).wrap_socket(connection,server_hostname=host) as secure:
                peer=secure.getpeercert(binary_form=True)
                if peer!=certificate_der(value['ca_pem']): raise ValueError()
        return {'panel_url':value['panel_url'],'node_id':value['node_id'],
                'expires_at':value['expires_at'],
                'certificate_sha256':hashlib.sha256(peer).hexdigest(),
                'signer_sha256':hashlib.sha256(signer_der(value['signer_pem'])).hexdigest()}
    except (OSError,ValueError):
        raise WizardError('panel_tls_verification_failed') from None

def load_installer(package):
    package=Path(package).resolve();source=package/'install-node.py'
    lines=(package/'SHA256SUMS').read_text().splitlines()
    hashes={}
    for line in lines:
        digest,name=line.split(None,1);name=name.lstrip('*')
        if name in hashes or not re.fullmatch('[0-9a-f]{64}',digest):raise WizardError('package_manifest_invalid')
        hashes[name]=digest
    if source.is_symlink() or hashlib.sha256(source.read_bytes()).hexdigest()!=hashes.get('install-node.py'):
        raise WizardError('installer_checksum_failed')
    spec=importlib.util.spec_from_file_location('verified_node_installer',source)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

def prepare(package,value,instance,directory):
    directory=Path(directory)
    spec={'instance':instance,'backend':'managed','node_id':value['node_id'],'panel_url':value['panel_url']}
    for field,name,data in [('ca_file','ca.pem',ssl.DER_cert_to_PEM_cert(certificate_der(value['ca_pem']))),('signer_file','signer.pem',value['signer_pem']),('enrollment_file','enrollment.json',json.dumps({k:value[k] for k in ('node_id','token','expires_at')}))]:
        target=directory/name
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:f.write(data)
        spec[field]=str(target)
    path=directory/'spec.json';path.write_text(json.dumps(spec));path.chmod(0o600)
    installer=load_installer(package)
    return installer,installer.build_plan(package,path)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',default=str(Path(__file__).resolve().parent))
    parser.add_argument('--instance',default='main')
    parser.add_argument('--plan',action='store_true',help='Validate and show the plan without installing')
    args=parser.parse_args()
    if not sys.stdin.isatty():raise WizardError('interactive_terminal_required')
    os.umask(0o077)
    print('В панели откройте сервер → Установить ноду → Скопировать код установки.')
    code=read_code();value=decode_code(code)
    print('Панель из приглашения: '+value['panel_url'])
    print('Берите приглашение только из своей авторизованной панели. Проверьте адрес перед подтверждением.')
    verified=verify_panel(value)
    print('TLS проверен; токен регистрации ещё не отправлен.')
    print('ID ноды: '+verified['node_id'])
    print('Приглашение действует до: '+verified['expires_at'])
    print('SHA256 сертификата панели: '+verified['certificate_sha256'])
    print('SHA256 ключа подписания команд: '+verified['signer_sha256'])
    with tempfile.TemporaryDirectory(prefix='salfetka-enroll-') as tmp:
        installer,plan=prepare(args.package,value,args.instance,Path(tmp).resolve())
        installer.preflight(plan)
        print(json.dumps(installer.receipt(plan),indent=2))
        if args.plan:return
        if input('Установить и запустить эту ноду? [yes/no]: ').strip()!='yes':return
        # Expiry is rechecked after operator review, before any service mutation.
        decode_code(code)
        verify_panel(value)
        installer.install(plan)
        installer.owned(args.instance)
        installer.run(['systemctl','enable','--now',plan['service']+'.service'])
        installer.run(['systemctl','is-active','--quiet',plan['service']+'.service'])
        print('Служба запущена. Дождитесь статуса «На связи» в панели; это отдельное подтверждение связи.')

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt) as e:
        print(str(e) if isinstance(e,WizardError) else 'node_installation_failed_existing_state_preserved',file=sys.stderr)
        sys.exit(1)
