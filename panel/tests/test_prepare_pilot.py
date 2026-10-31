import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare_pilot', ROOT / 'scripts/prepare-pilot.py')
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


class PilotBundleTests(unittest.TestCase):
    def test_origin_rejects_secrets_paths_and_env_injection(self):
        # Construct the synthetic credential URL without a literal secret-scanner match.
        credential_url = 'https://' + 'example:placeholder@host.test'
        for value in ('http://host.test', credential_url, 'https://host.test/',
                      'https://host.test?', 'https://host.test#', 'https://host.test:99999', 'https://host.test:0',
                      'https://host.test\nPANEL_IMAGE=other', 'https://$(bad)',
                      'https://.test', 'https://host.test/$VAR'):
            with self.subTest(value=value), self.assertRaises(pilot.Invalid):
                pilot.origin(value)
        self.assertEqual(pilot.origin('https://subscriptions.example.com:18483'),
                         ('subscriptions.example.com', 18483))

    def test_public_bundle_keeps_admin_and_authority_private(self):
        doc = json.loads((ROOT / 'deploy/pilot/compose.json').read_text())
        services = doc['services']
        self.assertNotIn('ports', services['postgres'])
        self.assertTrue(all(p.startswith('127.0.0.1:') for p in services['admin']['ports']))
        delivery = services['delivery']
        self.assertEqual(delivery['environment']['PANEL_API_MODE'], 'delivery')
        self.assertNotIn('PANEL_WEB_DIR', delivery['environment'])
        for value in delivery['volumes']:
            self.assertNotIn('node-signer', value)
            self.assertNotIn('node-authority', value)
            self.assertNotIn('database-migrator', value)
        for name in ('admin', 'delivery', 'worker'):
            self.assertTrue(services[name]['read_only'])
            self.assertEqual(services[name]['cap_drop'], ['ALL'])
            self.assertEqual(services[name]['restart'], 'unless-stopped')
            self.assertLessEqual(services[name]['cpus'], 0.25)
            self.assertIn('GOMEMLIMIT', services[name]['environment'])
        # Four bounded Argon2 checks need 4 * 64 MiB plus process/heap headroom.
        self.assertEqual(services['admin']['mem_limit'], '384m')
        self.assertEqual(services['admin']['environment']['GOMEMLIMIT'], '320MiB')

    def test_private_tls_files_reject_symlink_and_world_readable_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / 'key'
            key.write_bytes(b'synthetic')
            key.chmod(0o644)
            with self.assertRaises(pilot.Invalid):
                pilot.private_read(key, key=True)
            key.chmod(0o600)
            (root / 'link').symlink_to(key)
            with self.assertRaises(OSError):
                pilot.private_read(root / 'link', key=True)
            self.assertEqual(pilot.private_read(key, key=True), b'synthetic')

    def args(self, path, **changes):
        values = dict(dir=str(path), origin='https://localhost:18483', image='salfetka-panel:pilot-test',
                      panelctl=str(ROOT / 'artifacts/bin/panelctl'), bind='127.0.0.1',
                      admin_port=18463, lab=True, cert=None, key=None)
        values.update(changes)
        return types.SimpleNamespace(**values)

    def test_new_bundle_real_cli_tls_and_no_overwrite(self):
        ctl = ROOT / 'artifacts/bin/panelctl'
        self.assertTrue(ctl.is_file(), 'build panel binaries before running pilot acceptance')
        with tempfile.TemporaryDirectory(dir=ROOT / 'artifacts') as temp:
            path = Path(temp) / 'installation'
            args = self.args(path)
            pilot.prepare(args)
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
            for child in path.rglob('*'):
                if child.is_file():
                    self.assertEqual(child.stat().st_mode & 0o777, 0o600)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(path / 'secrets/delivery.crt', path / 'secrets/delivery.key')
            self.assertFalse(json.loads((path / 'installation.json').read_text())['services_started'])
            before = (path / 'secrets/master-key').read_bytes()
            with self.assertRaises(pilot.Invalid):
                pilot.prepare(args)
            self.assertEqual((path / 'secrets/master-key').read_bytes(), before)
            # The certificate hostname check must fail, not just print a warning.
            with self.assertRaises(pilot.Invalid):
                pilot.quiet(['openssl', 'x509', '-in', str(path / 'secrets/delivery.crt'),
                             '-noout', '-checkhost', 'wrong.example.com'])

    def test_bad_inputs_do_not_create_partial_installation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'new'
            for changes in ({'lab': False}, {'bind': '0.0.0.0'}, {'image': 'latest'},
                            {'origin': 'https://localhost:18463'}, {'admin_port': 0}):
                with self.subTest(changes=changes), self.assertRaises(pilot.Invalid):
                    pilot.prepare(self.args(path, **changes))
                self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
