#!/bin/sh
# Offline, pinned Linux package for a separate owned VPN service.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
arch=${1:-arm64}
case "$arch" in arm64|amd64) ;; *) printf '%s\n' 'supported: arm64 or amd64' >&2; exit 2 ;; esac
python3 "$root/scripts/prepare-xray-server.py"
out="$root/artifacts/packages/vpn-node-linux-$arch"
mkdir -p "$out/bin" "$out/systemd" "$out/source" "$out/licenses"
cd "$root/engine/xray"
export GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$arch"
export GOPROXY="${GOPROXY:-off}" GOSUMDB="${GOSUMDB:-off}"
"${PANEL_GO:-$root/../mobile/scripts/go.sh}" build -mod=readonly -trimpath -ldflags "-X main.version=${SALFETKA_VERSION:-0.6.0-dev}" -o "$out/bin/panel-vpn-node" ./cmd/panel-vpn-node
"${PANEL_GO:-$root/../mobile/scripts/go.sh}" build -mod=readonly -trimpath -ldflags "-X main.version=${SALFETKA_VERSION:-0.6.0-dev}" -o "$out/bin/panel-server-node" ./cmd/panel-server-node
cd "$root"
"${PANEL_GO:-$root/../mobile/scripts/go.sh}" build -mod=readonly -trimpath -ldflags "-X main.version=${SALFETKA_VERSION:-0.6.0-dev}" -o "$out/bin/panel-node" ./cmd/panel-node
cp deploy/systemd/salfetka-vpn-node.service deploy/systemd/salfetka-server-node.service deploy/systemd/vpn.env.example "$out/systemd/"
cp third_party/xray-server.lock.json third_party/patches/xray-server/*.patch "$out/source/"
cp artifacts/server-sources/xray-core/LICENSE "$out/licenses/Xray-MPL-2.0.txt"
python3 "$root/scripts/collect-node-licenses.py" "$out/licenses"
cp docs/operator/b4-vpn-node.md "$out/README.md"
cp scripts/install-node.py "$out/install-node.py"
cp scripts/node-wizard.py "$out/node-wizard.py"
cat docs/operator/node-installer.md >> "$out/README.md"
(cd "$out" && shasum -a 256 bin/* systemd/* source/* licenses/* README.md install-node.py node-wizard.py > SHA256SUMS)
COPYFILE_DISABLE=1 tar -czf "$root/artifacts/packages/vpn-node-linux-$arch.tar.gz" -C "$out" .
