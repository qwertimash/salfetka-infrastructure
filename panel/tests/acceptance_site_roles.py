#!/usr/bin/env python3
"""Three Manager.install roles + interrupted site activation on owned QA Linux.
Package download/signature checks have separate tests; here prebuilt packages
are injected so the full service/enrollment/site lifecycle runs deterministically.
"""
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import sys
from unittest.mock import patch

sys.path.insert(0,'/tmp/salfetka-qa-code')
from installer import manager,node,panel,site,system
from installer.common import atomic,decode,regular,run,save
assert os.geteuid()==0 and Path('/run/salfetka-isolated-installer-qa').read_text().strip()=='disposable-lima-salfetka-qa'
os.umask(0o077)
release=Path(sys.argv[1]).resolve();version=decode(regular(release/'panel/image.json'))['version']
key=regular(release/'installer/release-public-key.pem')
root=Path('/opt/salfetka-manager');node_root=Path('/opt/salfetka-qa-node-manager')
report={}

def cleanup(root):
 if site.home().exists():
  site.owned();run(['systemctl','disable','--now',site.SERVICE]);site.UNIT.unlink()
 if node.HOME.exists():
  owner=decode(regular(node.HOME/'owner.json'));assert owner['service']=='salfetka-main' and owner['home']==str(node.HOME)
  unit=Path('/etc/systemd/system')/node.SERVICE;assert regular(unit)==regular(node.HOME/node.SERVICE)
  run(['systemctl','disable','--now',node.SERVICE]);unit.unlink();run(['systemctl','daemon-reload']);run(['userdel','salfetka-main']);shutil.rmtree(node.HOME)
 if (root/'panel').exists():panel.owned(root/'panel');panel.compose(root/'panel','down','-v')
 if root.exists():shutil.rmtree(root)

def instance(root):
 root.mkdir(mode=0o700,exist_ok=True)
 value=manager.Manager(root=root,key=key)
 value.fetch=lambda *args,**kwargs:({'version':version},release)
 return value

cleanup(Path('/opt/salfetka-qa-runtime'));cleanup(root)
if node_root.exists():shutil.rmtree(node_root)
qa=Path('/tmp/salfetka-site-role-fixture');qa.mkdir(mode=0o700,exist_ok=True)
if not (qa/'tls.crt').exists():system.private_tls(qa,['panel.qa.test','sub.qa.test','node.qa.test'])
os.environ['SSL_CERT_FILE']=str(qa/'tls.crt')
pair=(regular(qa/'tls.crt'),regular(qa/'tls.key'))
config={'role':'panel','admin_domain':'panel.qa.test','subscription_domain':'sub.qa.test','address':'127.0.0.1','email':'qa@example.invalid','username':'qa_owner','public_port':443}
password=secrets.token_urlsafe(32)
m=instance(root);m.install('panel',version,config=config,password=password,public_pair=pair)
assert not site.home().exists() and set(m.state()['components'])=={'installer','panel'}
report['panel_only_no_node_services']=True
api=panel.setup_owner(root/'panel',config['username'],password)
try:invite=panel.combined_invitation(root/'panel',api,dict(config,node_name='Separate QA',node_domain='node.qa.test'),{})
finally:api.logout()
n=instance(node_root)
with patch.object(site,'install_bundle',side_effect=RuntimeError('QA interrupted certificate activation')):
 try:n.install('node',version,config={'role':'node','email':config['email']},invitation=invite,node_pair=pair)
 except RuntimeError:pass
 else:raise AssertionError('site interruption was not observed')
assert n.state()['phase']=='installing'
identity=decode(regular(node.HOME/'state/identity/state.json',16<<20))
# The second run must reuse enrollment, without a code or another invitation.
n.install('node',version,node_pair=pair)
current=decode(regular(node.HOME/'state/identity/state.json',16<<20))
assert current['node_id']==identity['node_id'] and current['private_key_pem']==identity['private_key_pem']
assert n.state()['config']['node_site'] and set(n.state()['components'])=={'installer','node'}
report['node_only_and_interrupted_site_resume_same_identity']=True
cleanup(node_root);cleanup(root)
config=dict(config,role='both',public_port=9443,node_name='Combined QA',node_domain='node.qa.test')
m=instance(root);m.install('both',version,config=config,password=password,public_pair=pair,node_pair=pair)
assert set(m.state()['components'])=={'installer','panel','node'} and m.state()['config']['node_site']
site.health('node.qa.test');node.health();panel.health(root/'panel')
report['combined_automatic_enrollment_and_site']=True
save('/tmp/salfetka-site-roles-receipt.json',report);print(report)
