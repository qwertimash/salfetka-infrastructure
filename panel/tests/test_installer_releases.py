import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from installer.common import Failure, atomic, decode, lock, regular
from installer.releases import Github, Catalog, compatible, unpack, verify_manifest


class ReleasesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.openssl = '/opt/homebrew/opt/openssl@3/bin/openssl' if Path('/opt/homebrew/opt/openssl@3/bin/openssl').exists() else shutil.which('openssl')
        self.key, self.pub = self.root / 'private', self.root / 'public'
        self.command('genpkey', '-algorithm', 'ED25519', '-out', self.key)
        self.command('pkey', '-in', self.key, '-pubout', '-out', self.pub)
        now = datetime.now(timezone.utc)
        self.manifest = dict(schema=2, repository='qwertimash/salfetka-infrastructure', version='0.6.0',
            published_at=(now-timedelta(minutes=1)).isoformat(), expires_at=(now+timedelta(days=30)).isoformat(),
            protocol_min=1, protocol_max=1, database_min=24, database_max=24, database_target=24,
            artifacts=[dict(component='node', platform='linux/arm64',
                            name='salfetka-node-0.6.0-linux-arm64.tar.gz', sha256='a'*64, bytes=123)])

    def command(self, *args):
        subprocess.run([self.openssl, *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def signed(self, raw=None):
        raw = raw or json.dumps(self.manifest).encode()
        (self.root / 'manifest').write_bytes(raw)
        self.command('pkeyutl', '-sign', '-inkey', self.key, '-rawin', '-in', self.root/'manifest', '-out', self.root/'signature')
        return raw, (self.root/'signature').read_bytes(), self.pub.read_bytes()

    def verify(self):
        return verify_manifest(*self.signed(), openssl=self.openssl)

    def test_signature_expiry_downgrade_and_database_gate(self):
        value = self.verify()
        compatible(value, '0.5.0', 24)
        for installed, database in [('0.7.0',24),('0.5.0',23),('0.5.0',25)]:
            with self.assertRaises(Failure): compatible(value, installed, database)
        raw, signature, public = self.signed()
        with self.assertRaisesRegex(Failure, 'signature'):
            verify_manifest(raw+b' ', signature, public, openssl=self.openssl)
        self.manifest['expires_at'] = (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        with self.assertRaisesRegex(Failure, 'expired'): self.verify()

    def test_wrong_key_duplicates_protocol_and_asset_names(self):
        raw, signature, public = self.signed()
        self.command('genpkey','-algorithm','ED25519','-out',self.key)
        self.command('pkey','-in',self.key,'-pubout','-out',self.pub)
        with self.assertRaisesRegex(Failure,'signature'):
            verify_manifest(raw,signature,self.pub.read_bytes(),openssl=self.openssl)
        duplicate=json.dumps(self.manifest)[:-1]+',"version":"0.6.0"}'
        with self.assertRaisesRegex(Failure,'duplicate'):
            verify_manifest(*self.signed(duplicate.encode()),openssl=self.openssl)
        self.manifest['protocol_min']=2
        with self.assertRaisesRegex(Failure,'protocol'):self.verify()
        self.manifest['protocol_min']=1
        self.manifest['artifacts'][0]['name']='../payload.sh'
        with self.assertRaisesRegex(Failure,'artifact'):self.verify()

    def archive(self, entries):
        file = self.root/'archive.tar.gz'
        with tarfile.open(file,'w:gz') as tar:
            for name, kind, body in entries:
                info=tarfile.TarInfo(name);info.type=kind;info.mode=0o777
                if kind==tarfile.REGTYPE:
                    info.size=len(body);tar.addfile(info,io.BytesIO(body))
                else:
                    info.linkname=body.decode();tar.addfile(info)
        return file

    def test_archive_rejects_traversal_links_duplicates_and_size_before_writes(self):
        cases=[('../escape',tarfile.REGTYPE,b'bad'),('/absolute',tarfile.REGTYPE,b'bad'),
               ('link',tarfile.SYMTYPE,b'/etc'),('hard',tarfile.LNKTYPE,b'file'),
               ('device',tarfile.CHRTYPE,b''),('many',tarfile.REGTYPE,b'x'*20)]
        for entry in cases:
            with self.subTest(entry=entry[0]):
                file=self.archive([entry])
                with self.assertRaises(Failure):unpack(file,self.root/'out',maximum=10)
                self.assertFalse((self.root/'out').exists())
        for entries in [[('same',tarfile.REGTYPE,b'a'),('same',tarfile.REGTYPE,b'b')],
                        [('a',tarfile.REGTYPE,b'x'),('a/b',tarfile.REGTYPE,b'x')]]:
            with self.assertRaises(Failure):unpack(self.archive(entries),self.root/'out')
        self.assertFalse((self.root/'out').exists())

    def test_valid_archive_preserves_executable_but_not_write_permissions(self):
        file=self.archive([('./bin/run',tarfile.REGTYPE,b'#!/bin/sh\n')])
        out=unpack(file,self.root/'out')
        self.assertEqual((out/'bin/run').read_bytes(),b'#!/bin/sh\n')
        self.assertEqual((out/'bin/run').stat().st_mode&0o777,0o755)

    def github(self):
        token=self.root/'github-token';token.write_text('synthetic_read_token');token.chmod(0o600)
        return Github(token_file=token)

    def response(self, body):
        response=io.BytesIO(body);response.status=200;response.headers={'Content-Length':str(len(body))}
        return response

    def test_download_strips_auth_on_asset_redirect_and_never_uses_proxy(self):
        gh=self.github();seen=[]
        def opened(request,timeout):
            seen.append(request)
            if len(seen)==1:
                raise urllib.error.HTTPError(request.full_url,302,'redirect',{'Location':'https://release-assets.githubusercontent.com/file?signature=fixture'},None)
            return self.response(b'payload')
        gh.opener.open=opened
        file=gh.download('https://api.github.com/repos/qwertimash/salfetka-infrastructure/releases/assets/1',self.root/'out',10,api_asset=True)
        self.assertEqual(file.read_bytes(),b'payload')
        self.assertIsNotNone(seen[0].get_header('Authorization'))
        self.assertIsNone(seen[1].get_header('Authorization'))

    def test_untrusted_redirect_and_partial_download_leave_no_payload(self):
        gh=self.github()
        gh.opener.open=Mock(side_effect=urllib.error.HTTPError('https://github.com/',302,'redirect',{'Location':'http://evil.invalid/'},None))
        with self.assertRaises(Failure):gh.download('https://github.com/file',self.root/'out',10)
        self.assertFalse((self.root/'out').exists())
        response=self.response(b'abcdefgh');response.headers={}
        gh.opener.open=Mock(return_value=response)
        with self.assertRaisesRegex(Failure,'large'):gh.download('https://github.com/file',self.root/'out',3)
        self.assertFalse((self.root/'out').exists())

    def test_auth_cannot_leave_repository_and_private_files_reject_permissions(self):
        gh=self.github()
        with self.assertRaisesRegex(Failure,'scope'):
            gh.download('https://api.github.com/repos/someone/else/releases/assets/1',self.root/'out',10)
        (self.root/'github-token').chmod(0o644)
        with self.assertRaisesRegex(Failure,'private'):Github(token_file=self.root/'github-token')

    def test_lock_and_atomic_state_preserve_existing_on_failure(self):
        file=self.root/'state';atomic(file,b'old')
        with lock(self.root/'lock'):
            with self.assertRaisesRegex(Failure,'another'): 
                with lock(self.root/'lock'):pass
        link=self.root/'linked';link.symlink_to(file)
        with self.assertRaises(Failure):atomic(link,b'bad')
        self.assertEqual(file.read_bytes(),b'old')
