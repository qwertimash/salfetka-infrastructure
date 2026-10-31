import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from installer import backup, manager, panel, system
from installer.common import Failure, atomic, decode, regular, save, sha256


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def test_public_edge_keeps_machine_tls_verified_and_delivery_separate(self):
        config = panel.edge_config({'admin_domain': 'panel.example.com', 'subscription_domain': 'sub.example.com', 'public_port': 9443}).decode()
        self.assertIn('proxy_ssl_verify on;', config)
        self.assertIn('proxy_pass https://admin:18443', config)
        self.assertIn('proxy_pass https://delivery:18483', config)
        self.assertIn('ssl_reject_handshake on', config)
        self.assertNotIn('access_log /', config)
        for invalid in ['bad; return 200;', 'https://example.com', '127.0.0.1', 'EXAMPLE.com', 'a..example.com']:
            with self.subTest(invalid=invalid), self.assertRaises((Failure, ValueError)):
                system.domain(invalid)

    def test_machine_identity_never_overwritten_by_setup(self):
        atomic(self.root/'tls.crt', b'original')
        with self.assertRaisesRegex(Failure, 'already_exists'):
            system.private_tls(self.root, ['panel.example.com'])
        self.assertEqual(regular(self.root/'tls.crt'), b'original')

    def test_public_certificate_validation_happens_before_replacement(self):
        atomic(self.root/'fullchain.pem', b'old cert'); atomic(self.root/'privkey.pem', b'old key')
        with self.assertRaises(Exception):
            system.install_public_pair(self.root, b'invalid', b'invalid', ['panel.example.com'])
        self.assertEqual(regular(self.root/'fullchain.pem'), b'old cert')
        self.assertEqual(regular(self.root/'privkey.pem'), b'old key')

    def test_combined_invitation_retry_keeps_original_revision_and_operation_keys(self):
        api=Mock(); config={'node_name':'QA','address':'203.0.113.8','node_domain':'node.example.com'}
        def call(path, body=None, **kwargs):
            if path=='/api/v1/servers': return {'id':'server'}
            if path.startswith('/api/v1/managed/servers/'): return {'id':'node'}
            if path=='/api/v1/nodes/node': return {'revision':4}
            if path.endswith('/enrollment'):
                self.assertEqual(kwargs['revision'],1)
                self.assertEqual(kwargs['key'],'original-enrollment-key')
                return {'enrollment':{'node_id':'node','token':'synthetic','expires_at':'expiry'}}
            return {'schema':1,'panel_url':'https://panel.example.com:18443','ca_pem':'certificate','signer_pem':'signer'}
        api.call.side_effect=call
        journal={'server_key':'original-server-key','node_key':'original-node-key','enrollment_key':'original-enrollment-key','enrollment_revision':1}
        value=panel.combined_invitation(self.root,api,config,journal)
        self.assertEqual(value['node_id'],'node')
        self.assertEqual(value['panel_url'],'https://panel.example.com:18443')
        self.assertEqual(decode(regular(self.root/'combined.json'))['enrollment_revision'],1)

    def test_foreign_compose_configuration_is_preserved(self):
        home=self.root/'panel';home.mkdir()
        atomic(home/'compose.json',b'original')
        save(home/'owner.json',{'schema':2,'project':panel.PROJECT,'home':str(home),'compose_sha256':sha256(home/'compose.json')})
        panel.owned(home)
        atomic(home/'compose.json',b'external change')
        with self.assertRaisesRegex(Failure,'ownership'):panel.owned(home)

    def manager(self):
        with patch.object(system,'platform_id',return_value='linux/arm64'):
            return manager.Manager(self.root,key=b'public-key')

    def test_failed_update_keeps_resumable_journal_and_never_reports_ready(self):
        m=self.manager()
        state={'phase':'ready','components':{'panel':{'version':'0.6.0'}},'config':{}}
        m.commit(state)
        release={'version':'0.6.1','database_min':1,'database_max':24,'database_target':24}
        m.fetch=Mock(return_value=(release,self.root/'release'))
        with patch.object(panel,'database_version',return_value=24), patch.object(panel,'load_image'), \
             patch.object(backup,'create',return_value=self.root/'backup') as saved, \
             patch.object(panel,'update',side_effect=Failure('migration_failed')) as update:
            with self.assertRaisesRegex(Failure,'migration_failed'):m.update()
        saved.assert_called_once();update.assert_called_once()
        self.assertEqual(m.state()['phase'],'updating')
        self.assertEqual(m.state()['components']['panel']['version'],'0.6.0')
        journal=decode(regular(self.root/'transaction.json'))
        self.assertEqual(journal['target'],'0.6.1')
        self.assertEqual(journal['phase'],'panel')

    def test_incompatible_database_never_backs_up_or_stops_runtime(self):
        m=self.manager();m.commit({'phase':'ready','components':{'panel':{'version':'0.6.0'}},'config':{}})
        m.fetch=Mock(return_value=({'version':'0.6.1','database_min':1,'database_max':24,'database_target':24},self.root/'release'))
        with patch.object(panel,'database_version',return_value=25), patch.object(backup,'create') as saved, patch.object(panel,'update') as update:
            with self.assertRaisesRegex(Failure,'incompatible'):m.update()
        saved.assert_not_called();update.assert_not_called()
        self.assertEqual(m.state()['phase'],'ready')

    def test_backup_verification_rejects_tampering_and_traversal(self):
        save(self.root/'state.json',{'components':{}})
        save(self.root/'backup.json',{'schema':1,'files':{'state.json':{'sha256':sha256(self.root/'state.json'),'bytes':(self.root/'state.json').stat().st_size}}})
        self.assertEqual(backup.verify(self.root),{'components':{}})
        atomic(self.root/'state.json',b'{}')
        with self.assertRaisesRegex(Failure,'corrupt'):backup.verify(self.root)
        save(self.root/'backup.json',{'schema':1,'files':{'../elsewhere':{'sha256':'0'*64,'bytes':0}}})
        with self.assertRaisesRegex(Failure,'path'):backup.verify(self.root)

    def test_backup_rejects_symlinks_and_preserves_private_mode(self):
        source=self.root/'source';source.mkdir();atomic(source/'secret',b'fixture-secret')
        backup.copy_private(source,self.root/'copy')
        self.assertEqual((self.root/'copy/secret').stat().st_mode&0o777,0o600)
        (source/'link').symlink_to(source/'secret')
        with self.assertRaisesRegex(Failure,'symlink'):backup.copy_private(source,self.root/'another')

    def test_restore_foreign_identity_fails_before_database_creation(self):
        current=self.root/'panel';current.mkdir();(current/'secrets').mkdir()
        atomic(current/'secrets/master-key',b'current')
        archive=self.root/'backup';(archive/'panel/secrets').mkdir(parents=True)
        atomic(archive/'panel/secrets/master-key',b'foreign')
        state={'components':{'panel':{}},'config':{'role':'panel'}}
        with patch.object(backup,'verify',return_value=state), patch.object(panel,'owned',return_value={}), patch.object(panel,'compose') as compose:
            with self.assertRaisesRegex(Failure,'identity_mismatch'):backup.restore(self.root,archive,state)
        compose.assert_not_called()
