import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/public-install.sh'


class PublicCommandTests(unittest.TestCase):
    def exercise(self, fail=False):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();fake=root/'curl'
            fake.write_text('#!'+sys.executable+'''\nimport json,os,sys
from pathlib import Path
a=sys.argv[1:];target=Path(a[a.index('-o')+1])
assert a[0]=='-q' and a[a.index('--proto')+1]=='=https' and a[a.index('--proto-redir')+1]=='=https'
assert 'https://github.com/qwertimash/salfetka-infrastructure/releases/latest/download/install.py' in a
assert not any(x in a for x in ('-k','--insecure','--header','-H','--location-trusted'))
assert target.parent.stat().st_mode&0o777==0o700
Path(os.environ['QA_REPORT']).write_text(json.dumps({'directory':str(target.parent)}))
target.write_text("import sys;assert sys.argv[1:]==['--version','0.7.0'];assert sys.stdin.readline().strip()=='synthetic-menu-input';print('MENU_FIXTURE')\\n")
if os.environ['QA_FAIL']=='1':sys.exit(22)
''');fake.chmod(0o700)
            # Test the exact network/cleanup body without installing OS packages
            # or requiring root. The complete entry point is also smoke-tested on Ubuntu.
            before,body=SCRIPT.read_text().split('\numask 077\n',1)
            self.assertIn('$EUID -ne 0',before);self.assertIn('VERSION_ID',before)
            result=subprocess.run(['/bin/bash','-c','set -euo pipefail\numask 077\n'+body,'install.sh','--version','0.7.0'],
                input='synthetic-menu-input\n',text=True,capture_output=True,
                env=dict(os.environ,PATH=str(root)+os.pathsep+os.environ['PATH'],QA_REPORT=str(root/'report.json'),QA_FAIL='1' if fail else '0'),timeout=15)
            self.assertEqual(result.returncode,22 if fail else 0,result.stderr)
            self.assertEqual('MENU_FIXTURE' in result.stdout,not fail)
            self.assertFalse(Path(json.loads((root/'report.json').read_text())['directory']).exists())

    def test_anonymous_download_preserves_interactive_stdin_and_cleans_up(self): self.exercise()
    def test_download_failure_never_executes_partial_script(self): self.exercise(True)
    def test_shell_syntax(self): subprocess.run(['/bin/bash','-n',str(SCRIPT)],check=True)
