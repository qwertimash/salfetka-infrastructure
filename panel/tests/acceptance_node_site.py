#!/usr/bin/env python3
"""Real Certbot/HTTP-01 acceptance. Only in an explicitly disposable Linux VM.
Uses Pebble 2.10.1, a test CA, never the public Let's Encrypt service.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.request
from unittest.mock import patch

sys.path.insert(0, '/tmp/salfetka-qa-code')
from installer import manager, node, panel, site, system
from installer.common import atomic, decode, regular, run, save, sha256, Failure

assert os.geteuid() == 0
assert Path('/run/salfetka-isolated-installer-qa').read_text().strip() == 'disposable-lima-salfetka-qa'
os.umask(0o077)
root=Path('/opt/salfetka-qa-runtime');home=root/'panel'
qa=root/'site-acceptance';qa.mkdir(mode=0o700,exist_ok=True)
report={}
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
hashes={'amd64':'4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed','arm64':'b53fd072a69eb7692451de4e8b0667e0bdf5cccd7e36fc51b8eaf2fcc135ed9f'}
archive=qa/'pebble.tar.gz'
if not archive.exists():
 with urllib.request.urlopen('https://github.com/letsencrypt/pebble/releases/download/v2.10.1/pebble-linux-'+arch+'.tar.gz',timeout=30) as response:
  atomic(archive,response.read(32<<20))
assert sha256(archive)==hashes[arch]
with tarfile.open(archive,'r:gz') as tar:
 member=tar.getmember('pebble-linux-'+arch+'/linux/'+arch+'/pebble')
 assert member.isfile() and member.size<64<<20
 atomic(qa/'pebble',tar.extractfile(member).read(),0o700)

# Root trust applies only to this disposable test process and its Certbot children.
# No trust-store modifications and no --no-verify-ssl/allowInsecure anywhere.
server_tls=qa/'server';server_tls.mkdir(mode=0o700,exist_ok=True)
if not (server_tls/'tls.crt').exists():system.private_tls(server_tls,['localhost.test'])
# Use localhost.test for HTTPS and its explicitly generated trust anchor.
hosts=Path('/etc/hosts')
if 'localhost.test' not in hosts.read_text():
 with hosts.open('a') as f:f.write('\n127.0.0.1 localhost.test\n')
save(qa/'pebble.json',{'pebble':{'listenAddress':'127.0.0.1:14000','managementListenAddress':'127.0.0.1:15000',
 'certificate':str(server_tls/'tls.crt'),'privateKey':str(server_tls/'tls.key'),'httpPort':80,'tlsPort':5001,
 'externalAccountBindingRequired':False,'keyAlgorithm':'ecdsa','profiles':{'default':{'description':'QA only','validityPeriod':7776000}}}})
log=(qa/'pebble.log').open('w')
process=subprocess.Popen([str(qa/'pebble'),'-config',str(qa/'pebble.json')],env=dict(os.environ,PEBBLE_VA_NOSLEEP='1',PEBBLE_AUTHZREUSE='0',PEBBLE_WFE_NONCEREJECT='0'),stdout=log,stderr=subprocess.STDOUT)
force=False
original_run=run

def acme_run(argv,**kwargs):
 if str(argv[0])=='certbot':
  argv=[*argv,'--server','https://localhost.test:14000/dir']
  if force:argv+=['--force-renewal']
 return original_run(argv,**kwargs)

def wait(fn,seconds=60):
 deadline=time.monotonic()+seconds
 while True:
  try:return fn()
  except Exception:
   if time.monotonic()>deadline:raise
   time.sleep(1)

def peer(port):
 context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_3
 with socket.create_connection(('127.0.0.1',port),timeout=3) as raw:
  with context.wrap_socket(raw,server_hostname='node.qa.test') as connection:
   return hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()

def until_new(port,old):
 value=peer(port);assert value!=old;return value

api=None
try:
 context=ssl.create_default_context(cafile=str(server_tls/'tls.crt'))
 def getroot():
  with urllib.request.urlopen('https://localhost.test:15000/roots/0',context=context,timeout=3) as response:return response.read(32768)
 issuing=wait(getroot)
 atomic(qa/'trust.pem',regular(server_tls/'tls.crt')+issuing,0o600)
 os.environ['SSL_CERT_FILE']=str(qa/'trust.pem');os.environ['REQUESTS_CA_BUNDLE']=str(qa/'trust.pem')
 info=site.metadata();assert info['domain']=='node.qa.test' and info['address']=='127.0.0.1'
 identity=decode(regular(node.HOME/'state/identity/state.json',16<<20))
 identity_key=hashlib.sha256(identity['private_key_pem'].encode()).hexdigest()
 pid=run(['systemctl','show',node.SERVICE,'--property=MainPID','--value']).strip()
 config={'role':'both','node_domain':'node.qa.test','email':'qa@example.invalid'}
 if not site.home().exists():
  with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as busy:
   busy.bind(('::',80));busy.listen()
   try:site.setup(root,config)
   except ValueError as error:assert str(error)=='required_port_busy:80'
   else:raise AssertionError('foreign HTTP listener adopted')
  report['foreign_http_port_preserved']=True; print('PASS: foreign_http_port_preserved',flush=True)
 with patch.object(site,'run',side_effect=acme_run):
  site.setup(root,config)
  before=peer(8445)
  site.setup(root,config)
  assert peer(8445)==before
  report['real_http01_issue_and_repeat']=True; print('PASS: real_http01_issue_and_repeat',flush=True)

 # Authenticate using only the synthetic owner created by native acceptance.
 api=panel.setup_owner(home,'qa_owner',regular(root/'password').decode())
 servers=api.call('/api/v1/servers')['items'];server=next(v for v in servers if v['domain']=='node.qa.test')
 def ready():
  detail=api.call('/api/v1/managed/servers/'+server['id']);n=detail['node']
  assert n['inventory']['site']['state']=='ready';assert n['inventory']['site']['domain']=='node.qa.test'
  assert 'PRIVATE' not in json.dumps(n['inventory']['site']);return n
 n=wait(ready)
 group='00000000-0000-4000-8000-000000000001'
 connections=[]
 for template,port in [('vless-tcp-reality',443),('hysteria2',443),('vless-grpc-tls',8443),('vless-xhttp-tls',8444)]:
  spec={'certificate_source':'node','template':template,'version':1,'host':'127.0.0.1','listen_ip':'0.0.0.0','port':port,'server_name':'node.qa.test'}
  if template=='vless-tcp-reality':spec['reality_target']='127.0.0.1:8445'
  if template=='vless-grpc-tls':spec['service_name']='vpn'
  if template=='vless-xhttp-tls':spec['path']='/vpn'
  connections.append({'name':template,'group_id':group,'enabled':True,'configuration':{'public':spec,'private':{}}})
 detail=api.call('/api/v1/managed/servers/'+server['id'])
 if not detail['connections']:api.call('/api/v1/managed/nodes/'+n['id']+'/connections',{'connections':connections},revision=n['revision'])
 def listening():
  detail=api.call('/api/v1/managed/servers/'+server['id']);assert len(detail['connections'])==4
  assert all(c['runtime_state']=='listening' for c in detail['connections']);return detail
 wait(listening)
 for port in (443,8443,8444):assert wait(lambda:peer(port))==before
 report['four_connections_without_pem_and_verified_tls']=True; print('PASS: four_connections_without_pem_and_verified_tls',flush=True)
 # A genuine ACME renewal must perform HTTP-01 again (AUTHZREUSE=0).
 force=True
 with patch.object(site,'run',side_effect=acme_run):site.renew(root)
 after=peer(8445);assert after!=before
 for port in (443,8443,8444):assert wait(lambda:until_new(port,before))==after
 wait(listening)
 assert run(['systemctl','show',node.SERVICE,'--property=MainPID','--value']).strip()==pid
 report['renewal_live_site_and_tls_connections_without_agent_restart']=True; print('PASS: renewal_live_site_and_tls_connections_without_agent_restart',flush=True)
 # Test panel renewal on the same HTTP-01 listener; it must accept both panel names.
 acme_home=root/'acme';acme_home.mkdir(mode=0o700,exist_ok=True)
 command=['certbot','certonly','--webroot','--webroot-path',site.home()/'webroot','--non-interactive','--agree-tos','--email','qa@example.invalid','--cert-name','salfetka','--config-dir',acme_home/'config','--work-dir',acme_home/'work','--logs-dir',acme_home/'logs','-d','panel.qa.test','-d','sub.qa.test']
 force=False;acme_run(command,timeout=120)
 m=object.__new__(manager.Manager);m.root=root
 m.commit({'phase':'ready','components':{'panel':{'version':'0.7.0'},'node':{'version':'0.7.0'}},'config':{'node_site':True,'admin_domain':'panel.qa.test','subscription_domain':'sub.qa.test'}})
 with patch.object(site,'run',side_effect=acme_run),patch('installer.common.run',side_effect=acme_run):m.renew()
 report['combined_panel_webroot_renewal']=True; print('PASS: combined_panel_webroot_renewal',flush=True)
 api.logout();api=None
 run(['systemctl','restart',site.SERVICE]);wait(lambda:site.health('node.qa.test'))
 assert peer(8445)==after
 process.terminate();process.wait(timeout=15)
 active=sha256(site.home()/'bundle.pem')
 force=True
 try:
  with patch.object(site,'run',side_effect=acme_run):site.renew(root)
 except Failure:pass
 else:raise AssertionError('offline ACME falsely succeeded')
 assert sha256(site.home()/'bundle.pem')==active;site.health('node.qa.test')
 report['failed_acme_preserves_working_site_and_certificate']=True; print('PASS: failed_acme_preserves_working_site_and_certificate',flush=True)
 current=decode(regular(node.HOME/'state/identity/state.json',16<<20))
 assert current['node_id']==identity['node_id'] and hashlib.sha256(current['private_key_pem'].encode()).hexdigest()==identity_key
 report['node_identity_preserved']=True; print('PASS: node_identity_preserved',flush=True)
 save(qa/'receipt.json',report);print(json.dumps(report))
finally:
 if api:
  try:api.logout()
  except Exception:pass
 if process.poll() is None:process.terminate();process.wait(timeout=15)
 log.close()
