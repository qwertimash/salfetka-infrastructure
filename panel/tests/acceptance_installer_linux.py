#!/usr/bin/env python3
"""Destructive only inside the explicitly marked disposable installer QA VM.
Arguments: prepared panel package, node package. No production credentials.
"""
import json
import os
from pathlib import Path
import secrets
import sys
import time

sys.path.insert(0, '/tmp/salfetka-qa-code')
from installer import panel, node, system
from installer.common import atomic, decode, regular, run, save

assert os.geteuid() == 0
assert Path('/run/salfetka-isolated-installer-qa').read_text().strip() == 'disposable-lima-salfetka-qa'
root = Path('/opt/salfetka-qa-runtime')
root.mkdir(mode=0o700, exist_ok=True)
package, node_package = map(Path, sys.argv[1:3])
image = decode(regular(package/'image.json'))
release_version = image['version']
config = {'role': 'both', 'admin_domain': 'panel.qa.test', 'subscription_domain': 'sub.qa.test',
          'address': '127.0.0.1', 'email': 'qa@example.invalid', 'username': 'qa_owner', 'public_port': 9443,
          'node_name': 'Installer QA', 'node_domain': 'node.qa.test'}
certs=root/'certificate';certs.mkdir(mode=0o700, exist_ok=True)
if not (certs/'tls.crt').exists(): system.private_tls(certs, [config['admin_domain'], config['subscription_domain']])
home=root/'panel'
if not home.exists():
    panel.stage(home, package, config, panel.load_image(package), regular(certs/'tls.crt'), regular(certs/'tls.key'))
password_file=root/'password'
if not password_file.exists(): atomic(password_file, secrets.token_urlsafe(32).encode())
panel.initialize(home)
api=panel.setup_owner(home, config['username'], regular(password_file).decode())
try:
    journal=decode(regular(home/'combined.json')) if (home/'combined.json').exists() else {}
    invitation=panel.combined_invitation(home,api,config,journal)
    if not node.HOME.exists(): node.install(node_package, invitation, release_version)
    else: node.resume(node_package, release_version)
    panel.health(home)
    report={'panel_ready':True,'database_schema':panel.database_version(home), 'node_authenticated_heartbeat':True}
    state=decode(regular(node.HOME/'state/identity/state.json'))
    report['identity_node_id']=state['node_id']
    save(root/'receipt.json',report)
    print(json.dumps(report))
finally: api.logout()
