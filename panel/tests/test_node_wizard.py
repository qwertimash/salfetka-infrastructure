import base64
from datetime import datetime,timezone,timedelta
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch, Mock
spec=importlib.util.spec_from_file_location('node_wizard',Path(__file__).resolve().parents[1]/'scripts/node-wizard.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
class WizardTests(unittest.TestCase):
 def setUp(self):
  self.now=datetime.now(timezone.utc)
  self.data=dict(schema=1,panel_url='https://panel.example.com:18463',node_id='11111111-1111-4111-8111-111111111111',token='A'*43,expires_at=(self.now+timedelta(minutes=10)).isoformat(),ca_pem='-----BEGIN CERTIFICATE-----\nZml4dHVyZQ==\n-----END CERTIFICATE-----\n',signer_pem='-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(bytes.fromhex('302a300506032b6570032100')+bytes(32)).decode()+'\n-----END PUBLIC KEY-----\n')
 def code(self):return 'SN1.'+base64.urlsafe_b64encode(json.dumps(self.data).encode()).decode().rstrip('=')
 def test_auth_code_fields_and_no_plain_http(self):
  with patch.object(w.ssl,'SSLContext'):
   self.assertEqual(w.decode_code(self.code(),self.now),self.data)
   credentials_url = 'https://' + 'user' + ':' + 'pass' + '@panel.example.com'
   for url in ['http://panel.example.com',credentials_url,'https://panel.example.com/path','https://panel.example.com?token=x']:
    self.data['panel_url']=url
    with self.assertRaises(w.WizardError):w.decode_code(self.code(),self.now)
 def test_expiry_unknown_fields_and_tokens_rejected_without_leak(self):
  for field,value in [('expires_at',(self.now-timedelta(seconds=1)).isoformat()),('token','secret-with-bad-format'),('node_id','invalid'),('extra','secret')]:
   old=self.data.copy();self.data[field]=value
   with self.assertRaises(w.WizardError) as e:w.decode_code(self.code(),self.now)
   self.assertNotIn(self.data['token'],str(e.exception));self.data=old
 def test_invalid_certificate_is_not_trusted(self):
  with self.assertRaises(w.WizardError):w.decode_code(self.code(),self.now)
 def test_bad_encoding_is_bounded(self):
  for code in ['SN1.%%%%','SN1.'+'x'*65536,'bad']:
   with self.assertRaises(w.WizardError):w.decode_code(code,self.now)
 def test_duplicate_fields_and_boolean_schema_rejected(self):
  raw=json.dumps(self.data)[:-1]+',"schema":1}'
  code='SN1.'+base64.urlsafe_b64encode(raw.encode()).decode().rstrip('=')
  with patch.object(w.ssl,'SSLContext'):
   with self.assertRaises(w.WizardError):w.decode_code(code,self.now)
   self.data['schema']=True
   with self.assertRaises(w.WizardError):w.decode_code(self.code(),self.now)
 def test_ambiguous_origins_terminal_controls_and_noncanonical_tokens_rejected(self):
  with patch.object(w.ssl,'SSLContext'):
   for url in ['https://panel.example.com:0','https://panel.example.com:',
               'https://panel.example.com\n','https://pan\tel.example.com',
               'https://panel.example.com\x1b[2J','https://panel.example.com/%2f',
               'https://раnel.example.com','https://panel..example.com',
               'https://panel.example.com#fragment','https://panel.example.com:65536']:
    self.data['panel_url']=url
    with self.subTest(url=repr(url)),self.assertRaises(w.WizardError):w.decode_code(self.code(),self.now)
   self.data['panel_url']='https://panel.example.com'
   self.data['token']='x'*43
   with self.assertRaises(w.WizardError):w.decode_code(self.code(),self.now)
   self.data['token']='A'*43
   self.data['expires_at']=self.data['expires_at'].replace('T','\x1b')
   with self.assertRaises(w.WizardError):w.decode_code(self.code(),self.now)
 def test_duplicate_certificates_and_other_signer_algorithms_rejected(self):
  with patch.object(w.ssl,'SSLContext'):
   self.data['ca_pem']*=2
   with self.assertRaises(w.WizardError):w.decode_code(self.code(),self.now)
   self.setUp()
   self.data['signer_pem']='-----BEGIN PUBLIC KEY-----\nZml4dHVyZQ==\n-----END PUBLIC KEY-----\n'
   with self.assertRaises(w.WizardError):w.decode_code(self.code(),self.now)
 def test_hidden_input_fails_closed_when_terminal_echo_cannot_be_disabled(self):
  with patch.object(w.sys.stdin,'isatty',return_value=False),patch.object(w.getpass,'getpass') as read:
   with self.assertRaisesRegex(w.WizardError,'terminal'):w.read_code()
   read.assert_not_called()
  def fallback(*args):w.warnings.warn('echo fallback',w.getpass.GetPassWarning)
  with patch.object(w.sys.stdin,'isatty',return_value=True),patch.object(w.getpass,'getpass',side_effect=fallback):
   with self.assertRaisesRegex(w.WizardError,'hidden_terminal'):w.read_code()
 def run_main(self,answer='no',failure=None,expired=False):
  installer=Mock();installer.receipt.return_value={'node_id':self.data['node_id']}
  verified=dict(self.data,certificate_sha256='c'*64,signer_sha256='d'*64)
  out=io.StringIO();old_umask=os.umask(0o077);os.umask(old_umask)
  try:
   with contextlib.ExitStack() as stack:
    stack.enter_context(patch.object(w.sys,'argv',['node-wizard.py']))
    stack.enter_context(patch.object(w.sys.stdin,'isatty',return_value=True))
    stack.enter_context(patch.object(w,'read_code',return_value=self.code()))
    decode=stack.enter_context(patch.object(w,'decode_code',side_effect=[self.data,w.WizardError('install_code_expired_or_clock_incorrect')] if expired else None,return_value=self.data))
    verify=stack.enter_context(patch.object(w,'verify_panel',side_effect=failure,return_value=verified))
    prepare=stack.enter_context(patch.object(w,'prepare',return_value=(installer,{'service':'salfetka-main'})))
    stack.enter_context(patch('builtins.input',return_value=answer))
    stack.enter_context(contextlib.redirect_stdout(out))
    if failure or expired:
     with self.assertRaises(w.WizardError):w.main()
    else:w.main()
   return installer,verify,prepare,decode,out.getvalue()
  finally:os.umask(old_umask)
 def test_review_displays_panel_identity_without_secrets_and_cancel_does_not_install(self):
  installer,verify,_,_,output=self.run_main()
  self.assertIn(self.data['panel_url'],output);self.assertIn(self.data['node_id'],output)
  for secret in [self.code(),self.data['token'],self.data['ca_pem'],self.data['signer_pem']]:self.assertNotIn(secret,output)
  self.assertEqual(verify.call_count,1);installer.install.assert_not_called();installer.run.assert_not_called()
 def test_tls_failure_stops_before_package_preparation(self):
  installer,_,prepare,_,_=self.run_main(failure=w.WizardError('panel_tls_verification_failed'))
  prepare.assert_not_called();installer.install.assert_not_called()
 def test_expiry_after_confirmation_prevents_installation(self):
  installer,_,_,decode,_=self.run_main(answer='yes',expired=True)
  self.assertEqual(decode.call_count,2);installer.install.assert_not_called()
 def test_tls_change_during_operator_review_prevents_installation(self):
  verified=dict(self.data,certificate_sha256='c'*64,signer_sha256='d'*64)
  installer,verify,_,_,_=self.run_main(answer='yes',failure=[verified,w.WizardError('panel_tls_verification_failed')])
  self.assertEqual(verify.call_count,2);installer.install.assert_not_called()
 def test_confirmation_rechecks_expiry_and_tls_before_install(self):
  installer,verify,_,decode,_=self.run_main(answer='yes')
  self.assertEqual(decode.call_count,2);self.assertEqual(verify.call_count,2)
  installer.install.assert_called_once();installer.run.assert_any_call(['systemctl','is-active','--quiet','salfetka-main.service'])

class WizardTLSTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name)
  openssl='/opt/homebrew/opt/openssl@3/bin/openssl' if Path('/opt/homebrew/opt/openssl@3/bin/openssl').exists() else shutil.which('openssl')
  for name in ['panel','other']:
   subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(cls.directory/(name+'.key')),'-out',str(cls.directory/(name+'.crt'))],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  subprocess.run([openssl,'req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout',str(cls.directory/'leaf.key'),'-out',str(cls.directory/'leaf.csr')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  (cls.directory/'extensions').write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
  subprocess.run([openssl,'x509','-req','-in',str(cls.directory/'leaf.csr'),'-CA',str(cls.directory/'panel.crt'),'-CAkey',str(cls.directory/'panel.key'),'-CAcreateserial','-days','1','-extfile',str(cls.directory/'extensions'),'-out',str(cls.directory/'leaf.crt')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  (cls.directory/'fullchain.crt').write_text((cls.directory/'leaf.crt').read_text()+(cls.directory/'panel.crt').read_text())
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 @contextlib.contextmanager
 def server(self,cert='panel',key='panel'):
  ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(self.directory/(cert+'.crt'),self.directory/(key+'.key'))
  ctx.num_tickets=0
  listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(5)
  received=[]
  def serve():
   try:
    connection,_=listener.accept();connection.settimeout(5)
    with connection:
     with ctx.wrap_socket(connection,server_side=True) as secure:
      try:received.append(secure.recv(4096))
      except (ConnectionResetError,ssl.SSLEOFError):received.append(b'')
   except (OSError,ssl.SSLError):pass
  thread=threading.Thread(target=serve);thread.start()
  try:yield listener.getsockname()[1],received
  finally:listener.close();thread.join(6);self.assertFalse(thread.is_alive())
 def invitation(self,port,cert='panel'):
  return dict(schema=1,panel_url=f'https://localhost:{port}',node_id='11111111-1111-4111-8111-111111111111',token='A'*43,expires_at=(datetime.now(timezone.utc)+timedelta(minutes=10)).isoformat(),ca_pem=(self.directory/(cert+'.crt')).read_text(),signer_pem='-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(bytes.fromhex('302a300506032b6570032100')+bytes(32)).decode()+'\n-----END PUBLIC KEY-----\n')
 def test_real_pinned_tls_sends_no_token_or_http_request(self):
  with self.server() as (port,received):
   value=self.invitation(port);code='SN1.'+base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
   verified=w.verify_panel(w.decode_code(code));self.assertEqual(verified['panel_url'],value['panel_url'])
   self.assertEqual(verified['certificate_sha256'],w.hashlib.sha256(w.certificate_der(value['ca_pem'])).hexdigest())
  self.assertEqual(received,[b''])
 def test_wrong_certificate_or_hostname_rejected_without_sending_token(self):
  for mismatch in ['certificate','hostname']:
   with self.subTest(mismatch=mismatch),self.server() as (port,received):
    value=self.invitation(port,'other' if mismatch=='certificate' else 'panel')
    if mismatch=='hostname':value['panel_url']=f'https://127.0.0.1:{port}'
    with self.assertRaisesRegex(w.WizardError,'panel_tls_verification_failed'):w.verify_panel(value)
   self.assertEqual(received,[])
 def test_fullchain_preserves_first_certificate_pin_without_trusting_extra_root(self):
  with self.server() as (port,received):
   value=self.invitation(port);value['ca_pem']+=(self.directory/'other.crt').read_text()
   verified=w.verify_panel(value)
   self.assertEqual(verified['certificate_sha256'],w.hashlib.sha256(w.certificate_der(value['ca_pem'])).hexdigest())
  self.assertEqual(received,[b''])
  with self.server() as (port,received):
   value=self.invitation(port,'other');value['ca_pem']+=(self.directory/'panel.crt').read_text()
   with self.assertRaises(w.WizardError):w.verify_panel(value)
  self.assertEqual(received,[])
 def test_prepared_agent_keeps_only_the_pinned_leaf_and_private_token_files(self):
  value=self.invitation(443);leaf=value['ca_pem'];value['ca_pem']+=(self.directory/'other.crt').read_text()
  installer=Mock()
  with tempfile.TemporaryDirectory() as tmp,patch.object(w,'load_installer',return_value=installer):
   w.prepare('/synthetic/package',value,'main',tmp)
   self.assertEqual((Path(tmp)/'ca.pem').read_text(),leaf)
   for file in Path(tmp).iterdir():self.assertEqual(file.stat().st_mode&0o777,0o600)
   self.assertEqual(json.loads((Path(tmp)/'enrollment.json').read_text())['token'],value['token'])
 def test_ca_signed_leaf_fullchain_works_with_only_leaf_trusted(self):
  with self.server(cert='fullchain',key='leaf') as (port,received):
   value=self.invitation(port,'leaf');value['ca_pem']='\n'+value['ca_pem']+'\n'+(self.directory/'panel.crt').read_text()
   verified=w.verify_panel(value)
   self.assertEqual(verified['certificate_sha256'],w.hashlib.sha256(w.certificate_der((self.directory/'leaf.crt').read_text())).hexdigest())
  self.assertEqual(received,[b''])
 def test_network_error_does_not_echo_untrusted_exception(self):
  with patch.object(w.socket,'create_connection',side_effect=OSError('synthetic secret detail')):
   with self.assertRaises(w.WizardError) as error:w.verify_panel(self.invitation(443))
  self.assertEqual(str(error.exception),'panel_tls_verification_failed')
