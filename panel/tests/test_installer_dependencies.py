import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from installer import common, system
from installer.common import Failure


class DependencyTests(unittest.TestCase):
    def dependencies(self, docker, service=False, failed=False, panel=True):
        calls=[]
        def run(argv, **kwargs):
            calls.append(argv)
            if argv[0]=='docker' and failed: raise Failure('existing_docker_unavailable')
            return b'linux\n' if argv[:2]==['docker','info'] else b''
        with patch.object(system.Path,'resolve',return_value=Path('/usr/lib/os-release')), \
             patch.object(system.Path,'stat',return_value=SimpleNamespace(st_uid=0,st_mode=0o100644)), \
             patch.object(system,'regular',return_value=b'ID=ubuntu\nVERSION_ID="24.04"\n'), \
             patch.object(system.shutil,'which',return_value='/usr/bin/docker' if docker else None), \
             patch.object(system.os.path,'lexists',return_value=service), patch.object(system,'run',side_effect=run):
            try: system.dependencies(panel=panel)
            except Failure:
                self.calls=calls
                raise
        return calls

    def test_reuses_existing_docker_without_replacement_or_restart(self):
        calls=self.dependencies(True)
        install=next(c for c in calls if c[:2]==['apt-get','install'])
        self.assertNotIn('docker.io',install); self.assertNotIn('docker-compose-v2',install)
        self.assertIn('--no-remove',install); self.assertIn('--no-upgrade',install)
        self.assertFalse(any(c[0]=='systemctl' for c in calls))

    def test_fresh_host_installs_and_starts_docker(self):
        calls=self.dependencies(False)
        install=next(c for c in calls if c[:2]==['apt-get','install'])
        self.assertIn('docker.io',install); self.assertIn('docker-compose-v2',install)
        self.assertIn(['systemctl','enable','--now','docker'],calls)

    def test_broken_or_foreign_docker_fails_before_package_changes(self):
        for options in ({'docker':True,'failed':True},{'docker':False,'service':True}):
            with self.subTest(options=options), self.assertRaises(Failure): self.dependencies(**options)
            self.assertFalse(any(c[0]=='apt-get' for c in self.calls))

    def test_node_only_does_not_touch_docker(self):
        calls=self.dependencies(False,panel=False)
        self.assertFalse(any(c[0] in ('docker','systemctl') for c in calls))
        self.assertFalse(any('docker.io' in c for c in calls))

    def test_docker_cannot_use_inherited_remote_context(self):
        inherited={'DOCKER_HOST':'tcp://example.invalid:2375','DOCKER_CONTEXT':'remote',
                   'DOCKER_TLS_VERIFY':'1','DOCKER_CERT_PATH':'/private/remote','PATH':'/usr/bin'}
        with patch.object(common.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'OK')) as call:
            common.run(['docker','info'],env=inherited)
        env=call.call_args.kwargs['env']
        self.assertEqual(env['DOCKER_HOST'],'unix:///var/run/docker.sock')
        self.assertFalse(any(k in env for k in ('DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH')))
        self.assertEqual(inherited['DOCKER_CONTEXT'],'remote')
