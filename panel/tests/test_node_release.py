from datetime import datetime,timezone,timedelta
import importlib.util,json,os
from pathlib import Path
import shutil,subprocess,tempfile,unittest
s=importlib.util.spec_from_file_location('release_check',Path(__file__).resolve().parents[1]/'scripts/check-node-release.py');r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
class ReleaseTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.p=Path(self.tmp.name).resolve()
  self.openssl='/opt/homebrew/opt/openssl@3/bin/openssl' if Path('/opt/homebrew/opt/openssl@3/bin/openssl').exists() else shutil.which('openssl')
  self.key=self.p/'key';self.pub=self.p/'pub';self.manifest=self.p/'manifest';self.sig=self.p/'sig'
  self.runopenssl('genpkey','-algorithm','ED25519','-out',str(self.key));self.runopenssl('pkey','-in',str(self.key),'-pubout','-out',str(self.pub))
  now=datetime.now(timezone.utc);self.data={'schema':1,'version':'0.6.0','published_at':(now-timedelta(minutes=1)).isoformat(),'expires_at':(now+timedelta(days=1)).isoformat(),'protocol_min':1,'protocol_max':1,'artifacts':[{'platform':'linux/amd64','url':'https://example.com/node.tgz','sha256':'a'*64,'bytes':500}]}
 def runopenssl(self,*args):subprocess.run([self.openssl,*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 def sign(self):
  self.manifest.write_text(json.dumps(self.data));self.runopenssl('pkeyutl','-sign','-inkey',str(self.key),'-rawin','-in',str(self.manifest),'-out',str(self.sig))
 def check(self,current='0.5.0',platform='linux/amd64',protocol=1):return r.check(self.manifest,self.sig,self.pub,current,platform,protocol,self.openssl)
 def test_signature_tamper_and_wrong_key(self):
  self.sign();self.assertEqual(self.check()['status'],'update_available')
  self.manifest.write_bytes(self.manifest.read_bytes()+b' ')
  with self.assertRaisesRegex(r.ReleaseError,'signature'):self.check()
  self.sign();self.runopenssl('genpkey','-algorithm','ED25519','-out',str(self.key));self.runopenssl('pkey','-in',str(self.key),'-pubout','-out',str(self.pub))
  with self.assertRaisesRegex(r.ReleaseError,'signature'):self.check()
 def test_compatibility_downgrade_expiry_and_platform(self):
  self.sign();self.assertEqual(self.check('0.6.0')['status'],'up_to_date')
  for args in [('0.7.0',),('0.5.0','linux/arm64'),('0.5.0','linux/amd64',2)]:
   with self.assertRaises(r.ReleaseError):self.check(*args)
  self.data['expires_at']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat();self.sign()
  with self.assertRaisesRegex(r.ReleaseError,'not_current'):self.check()
 def test_duplicate_platform_http_and_symlink(self):
  self.data['artifacts'].append(self.data['artifacts'][0].copy());self.sign()
  with self.assertRaises(r.ReleaseError):self.check()
  self.data['artifacts'].pop();self.data['artifacts'][0]['url']='http://example.com/node.tgz';self.sign()
  with self.assertRaises(r.ReleaseError):self.check()
  linked=self.p/'link';linked.symlink_to(self.pub)
  with self.assertRaisesRegex(r.ReleaseError,'unsafe_release_file'):r.check(self.manifest,self.sig,linked,'0.5.0','linux/amd64',1,self.openssl)
 def test_other_signing_algorithm_refused(self):
  self.sign()
  self.runopenssl('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out',str(self.key))
  self.runopenssl('pkey','-in',str(self.key),'-pubout','-out',str(self.pub))
  with self.assertRaisesRegex(r.ReleaseError,'invalid_release_signature'):self.check()
