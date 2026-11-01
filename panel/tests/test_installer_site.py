import hashlib
import os
from pathlib import Path
import pwd
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from installer import site, system, manager, node
from installer.common import Failure, atomic, regular, run, save

class SiteTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name).resolve();self.home=self.root/'node';self.home.mkdir()
  self.site=self.home/'site';self.site.mkdir()
  self.addCleanup(patch.stopall)
  patch.object(node,'HOME',self.home).start()
  patch.object(site,'UNIT',self.root/'site.service').start()

 def cert(self,name='node.example.test',serial=1):
  cert,key=self.root/f'cert{serial}.pem',self.root/f'key{serial}.pem'
  run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','3','-subj','/CN=fixture','-set_serial',str(serial),'-addext','subjectAltName=DNS:'+name,'-addext','extendedKeyUsage=serverAuth','-out',cert,'-keyout',key])
  key.chmod(0o600);return cert,key

 def install(self,cert,key):
  # The test's isolated CA is explicit, never available in the public CLI.
  with patch.dict(os.environ,{'SSL_CERT_FILE':str(cert),'SSL_CERT_DIR':str(self.root/'empty-roots')}),patch.object(site.pwd,'getpwnam',return_value=SimpleNamespace(pw_gid=os.getgid())),patch.object(site.os,'chown'):
   site.install_bundle(regular(cert),regular(key),'node.example.test')

 def test_atomic_pair_rotation_and_last_known_good(self):
  cert,key=self.cert();self.install(cert,key);old=regular(self.site/'bundle.pem')
  cert,key=self.cert(serial=2);self.install(cert,key)
  self.assertEqual(regular(self.site/'previous.pem'),old)
  self.assertNotEqual(regular(self.site/'bundle.pem'),old)
  self.assertEqual((self.site/'bundle.pem').stat().st_mode&0o777,0o640)
  self.assertEqual((self.site/'previous.pem').stat().st_mode&0o777,0o600)
  self.install(cert,key);self.assertEqual(regular(self.site/'previous.pem'),old)

 def test_bad_key_wrong_san_and_untrusted_chain_preserve_pair(self):
  cert,key=self.cert();self.install(cert,key);old=regular(self.site/'bundle.pem')
  other,otherkey=self.cert(name='foreign.example.test',serial=2)
  for c,k in [(cert,otherkey),(other,otherkey)]:
   with self.subTest(cert=c),self.assertRaises(Exception):self.install(c,k)
   self.assertEqual(regular(self.site/'bundle.pem'),old)
  with patch.object(site.pwd,'getpwnam',return_value=SimpleNamespace(pw_gid=os.getgid())),patch.object(site.os,'chown'),self.assertRaises(Failure):
   site.install_bundle(regular(cert),regular(key),'node.example.test')
  self.assertEqual(regular(self.site/'bundle.pem'),old)

 def test_all_dns_addresses_must_be_owned(self):
  with patch.object(system,'dns',return_value=['192.0.2.1','2001:db8::1']),patch.object(site,'run',return_value=b'[{"addr_info":[{"local":"2001:db8::1"}]}]'):
   site.dns('node.example.test','192.0.2.1')
  with patch.object(system,'dns',return_value=['192.0.2.1','2001:db8::2']),patch.object(site,'run',return_value=b'[]'),self.assertRaisesRegex(Failure,'foreign_A_or_AAAA'):
   site.dns('node.example.test','192.0.2.1')

 def test_foreign_unit_is_not_adopted_or_stopped(self):
  self.site.rmdir();atomic(site.UNIT,b'foreign')
  with patch.object(site,'metadata',return_value={'domain':'node.example.test','address':'192.0.2.1'}),patch.object(site,'dns'),patch.object(site.pwd,'getpwnam',return_value=SimpleNamespace(pw_gid=os.getgid())),patch.object(site,'run') as command,self.assertRaisesRegex(Failure,'foreign_site_unit'):
   site.setup(self.root,{'email':'owner@example.test'})
  command.assert_not_called();self.assertEqual(regular(site.UNIT),b'foreign')

 def test_renew_failure_does_not_replace_certificate(self):
  atomic(self.site/'bundle.pem',b'last-known-good')
  with patch.object(site,'owned',return_value={'domain':'node.example.test'}),patch.object(site,'run',side_effect=Failure('acme_unavailable')),patch.object(site,'install_bundle') as install,self.assertRaises(Failure):site.renew(self.root)
  install.assert_not_called();self.assertEqual(regular(self.site/'bundle.pem'),b'last-known-good')

 def test_node_renew_failure_does_not_skip_panel_renewal(self):
  m=object.__new__(manager.Manager);m.root=self.root
  m.commit({'phase':'ready','config':{'node_site':True,'admin_domain':'panel.example.test','subscription_domain':'sub.example.test'},'components':{'panel':{'version':'0.7.0'},'node':{'version':'0.7.0'}}})
  target=self.root/'panel/public-tls';target.mkdir(parents=True)
  atomic(target/'fullchain.pem',b'cert');atomic(target/'privkey.pem',b'key')
  with patch.object(site,'renew',side_effect=Failure('acme_failed')),patch.object(site,'owned'),patch('installer.common.run') as command,patch.object(system,'public_pair',return_value=(b'cert',b'key')),patch.object(manager.panel,'owned'),patch.object(manager.panel,'compose') as compose,patch.object(manager.os,'chown'),self.assertRaisesRegex(Failure,'node_certificate_renewal'):
   m.renew()
  args=command.call_args.args[0];self.assertIn('--webroot',args);self.assertIn(site.home()/'webroot',args);self.assertEqual(compose.call_count,2)

 def test_site_unit_has_no_write_access_to_certificates(self):
  text=site.definition().decode()
  self.assertIn('User=salfetka-main',text);self.assertIn('ProtectSystem=strict',text)
  self.assertNotIn('ReadWritePaths=',text);self.assertNotIn('CAP_NET_ADMIN',text)
