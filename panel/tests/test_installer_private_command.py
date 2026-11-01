"""Exercise the pasted command with a real terminal and synthetic HTTP/installer."""
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import sys
import tempfile
import time
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))


class PrivateCommandTests(unittest.TestCase):
    def exercise(self, mode='success', credential='synthetic_test_credential'):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            # The credential is sent only after the child's read has disabled echo.
            curl = root / 'curl'
            curl.write_text('#!' + sys.executable + '''
import json,os,sys
from pathlib import Path
args=sys.argv[1:];header=sys.stdin.read();token=header.removeprefix('Authorization: Bearer ').strip()
target=Path(args[args.index('-o')+1]);secret=target.parent/'token'
assert token and token not in repr(args) and token not in repr(dict(os.environ))
assert args[0]=='-q' and args[args.index('--max-redirs')+1]=='0'
assert args[args.index('--proto')+1]=='=https' and '@-' in args
assert '-k' not in args and '--insecure' not in args
assert secret.read_text()==token and secret.stat().st_mode&0o777==0o600
assert target.parent.stat().st_mode&0o777==0o700
Path(os.environ['QA_REPORT']).write_text(json.dumps({'temporary':str(target.parent),'credential_private':True}))
if os.environ['QA_MODE']=='download_failure':sys.exit(22)
if os.environ['QA_MODE']=='interrupt':
 import time
 os.kill(os.getppid(),15);time.sleep(0.1);sys.exit(0)
target.write_text("import os,sys;from pathlib import Path;p=Path(sys.argv[sys.argv.index('--github-token-file')+1]);assert p.exists();assert p.read_text() not in repr(dict(os.environ));print('SYNTHETIC_INSTALLER_STARTED');sys.exit("+('7' if os.environ['QA_MODE']=='installer_failure' else '0')+")\\n")
''')
            curl.chmod(0o700)
            command = shlex.split((SCRIPTS / 'private-install-command.sh').read_text())
            self.assertEqual(command[:3], ['sudo', 'bash', '-c'])
            pid, fd = pty.fork()
            if pid == 0:
                os.environ.update(PATH=str(root)+os.pathsep+os.environ['PATH'], QA_REPORT=str(root/'report.json'), QA_MODE=mode)
                os.execl('/bin/bash', 'bash', '-c', command[3])
            output = b''; sent = False; status = None; deadline = time.monotonic()+15
            try:
                while time.monotonic() < deadline:
                    if select.select([fd], [], [], 0.1)[0]:
                        try: chunk = os.read(fd, 65536)
                        except OSError: break
                        if not chunk: break
                        output += chunk
                        if not sent and b'Contents: read): ' in output:
                            os.write(fd, credential.encode()+b'\n'); sent=True
                    found, value = os.waitpid(pid, os.WNOHANG)
                    if found: status=value;break
                if status is None:
                    found,value=os.waitpid(pid,os.WNOHANG)
                    if not found:
                        # Allow the process that closed its PTY to finish exiting.
                        time.sleep(0.1);found,value=os.waitpid(pid,os.WNOHANG)
                    if not found:os.kill(pid,signal.SIGKILL);os.waitpid(pid,0);self.fail('command_timeout')
                    status=value
            finally: os.close(fd)
            self.assertTrue(sent)
            self.assertNotIn(credential.encode(), output)
            report=root/'report.json'
            if mode == 'invalid':
                self.assertFalse(report.exists());self.assertNotEqual(os.waitstatus_to_exitcode(status),0)
            else:
                value=json.loads(report.read_text());self.assertTrue(value['credential_private'])
                self.assertFalse(Path(value['temporary']).exists(), 'temporary credential survived command')
                self.assertEqual(os.waitstatus_to_exitcode(status), {'success':0,'download_failure':22,'installer_failure':7,'interrupt':143}[mode])
                self.assertEqual(b'SYNTHETIC_INSTALLER_STARTED' in output, mode not in ('download_failure','interrupt'))

    def test_success_hidden_input_and_cleanup(self): self.exercise()
    def test_download_failure_never_runs_partial_file(self): self.exercise('download_failure')
    def test_installer_failure_cleans_up(self): self.exercise('installer_failure')
    def test_invalid_token_never_reaches_network(self): self.exercise('invalid','invalid credential')
    def test_termination_cleans_up(self): self.exercise('interrupt')

    def test_repository_bootstrap_uses_release_generator(self):
        spec=importlib.util.spec_from_file_location('exporter',SCRIPTS/'export-release-source.py')
        exporter=importlib.util.module_from_spec(spec);spec.loader.exec_module(exporter)
        spec=importlib.util.spec_from_file_location('builder',SCRIPTS/'build-release.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as temporary:
            exporter.write_bootstrap(temporary)
            raw=(Path(temporary)/'install.py').read_bytes()
            self.assertEqual(raw,builder.bootstrap((SCRIPTS.parent/'deploy/release/public-key.pem').read_bytes()))
            compile(raw,'install.py','exec')
