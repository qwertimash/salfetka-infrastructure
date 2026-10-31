#!/bin/sh
# Create an allowlisted, secret-free Linux build context in a NEW directory.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
arch=${1:?usage: package-pilot.sh amd64_or_arm64 NEW_OUTPUT_DIRECTORY}
target=${2:?new output directory required}
case "$arch" in amd64|arm64) ;; *) exit 2 ;; esac
test ! -e "$target" && test ! -L "$target"
test -f "$root/web/dist/index.html"
mkdir -m 700 "$target"
target=$(CDPATH= cd -- "$target" && pwd)
mkdir -p "$target/artifacts/bin" "$target/web" "$target/deploy/pilot" "$target/scripts" "$target/docs/operator"
cd "$root"
export GOWORK=off GOTOOLCHAIN=local GOOS=linux GOARCH="$arch" CGO_ENABLED=0
export GOMAXPROCS=2
export GOPROXY="${GOPROXY:-off}" GOSUMDB="${GOSUMDB:-off}"
for command in panel-api panel-worker panelctl panel-node; do
  "${PANEL_GO:-$root/../mobile/scripts/go.sh}" build -mod=readonly -trimpath -ldflags "-X main.version=${SALFETKA_VERSION:-0.6.0-dev}" -o "$target/artifacts/bin/$command" "./cmd/$command"
done
cp -R web/dist "$target/web/"
cp -R deploy/licenses "$target/deploy/"
cp deploy/pilot/compose.json deploy/pilot/Dockerfile "$target/deploy/pilot/"
cp scripts/prepare-pilot.py "$target/scripts/"
cp docs/operator/pilot.md "$target/docs/operator/"
chmod -R a+rX "$target/web" "$target/deploy/licenses"
python3 - "$target" "$arch" <<'PY'
import hashlib, json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
files = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
         for p in sorted(root.rglob('*')) if p.is_file()}
value = {'schema': 1, 'platform': 'linux/' + sys.argv[2], 'files': files,
         'git_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
         'working_tree_changes': bool(subprocess.check_output(['git', 'status', '--porcelain'])),
         'contains_secrets': False, 'runtime_acceptance': 'not_implied_by_packaging'}
(root / 'SHA256.json').write_text(json.dumps(value, indent=2) + '\n')
print('Linux package prepared; verify SHA256.json before image build')
PY
