#!/bin/sh
# Run on a clean native Ubuntu 24.04 runner. No target-server compilation.
set -eu
version=${1:?version required}
arch=${2:?amd64 or arm64 required}
export SALFETKA_VERSION="$version" PANEL_GO=go GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
python3 - <<'PY'
import importlib.util,json
from pathlib import Path
s=importlib.util.spec_from_file_location('fetch','mobile/scripts/fetch-core-sources.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
for dep in json.loads(Path('panel/third_party/mobile-baseline.lock.json').read_text())['dependencies']:
 if dep['id'] in ('xray-core','gvisor'):m.prepare(dep,Path('mobile').resolve(),False,False)
PY
(cd panel/web && npm ci && npm run test -- --run && npm run build)
(cd panel && go mod download && go test -race ./...)
python3 panel/scripts/prepare-xray-server.py
(cd panel/engine/xray && go mod download && go test -race ./...)
python3 -m unittest discover -s panel/tests -p 'test_installer*.py'
sh panel/scripts/package-pilot.sh "$arch" "$PWD/dist/panel"
sh panel/scripts/package-vpn-node.sh "$arch"
cp -R "panel/artifacts/packages/vpn-node-linux-$arch" dist/node
docker build --platform "linux/$arch" -t "salfetka-panel:$version" -f dist/panel/deploy/pilot/Dockerfile dist/panel
docker save -o dist/panel/image.tar "salfetka-panel:$version"
python3 - "$version" "$arch" <<'PY'
import json,subprocess,sys
from pathlib import Path
value={'version':sys.argv[1],'platform':'linux/'+sys.argv[2],'image_id':subprocess.check_output(['docker','image','inspect','--format={{.Id}}','salfetka-panel:'+sys.argv[1]],text=True).strip()}
Path('dist/panel/image.json').write_text(json.dumps(value)+'\n')
PY

# Native systemd/Docker acceptance on the disposable runner, with fixture TLS.
sudo mkdir -p /tmp/salfetka-qa-code
sudo cp -R panel/scripts/installer /tmp/salfetka-qa-code/
sudo sh -c 'printf "%s\n" disposable-lima-salfetka-qa > /run/salfetka-isolated-installer-qa'
printf '%s\n' '127.0.0.1 panel.qa.test sub.qa.test node.qa.test' | sudo tee -a /etc/hosts >/dev/null
sudo python3 panel/tests/acceptance_installer_linux.py "$PWD/dist/panel" "$PWD/dist/node"
