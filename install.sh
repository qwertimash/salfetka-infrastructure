#!/usr/bin/env bash
# Public entry point. The downloaded bootstrap verifies signed Release packages.
set -euo pipefail
if [[ $(uname -s) != Linux || $EUID -ne 0 ]]; then
    printf '%s\n' 'Запустите установку на Ubuntu 24.04 от root (sudo -i).' >&2
    exit 1
fi
. /etc/os-release
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 24.04 ]]; then
    printf '%s\n' 'Поддерживается Ubuntu 24.04.' >&2
    exit 1
fi
if ! command -v curl >/dev/null || ! command -v python3 >/dev/null || ! command -v openssl >/dev/null || [[ ! -s /etc/ssl/certs/ca-certificates.crt ]]; then
    apt-get update
    apt-get install -y --no-install-recommends --no-remove --no-upgrade curl python3 openssl ca-certificates
fi
umask 077
directory=$(mktemp -d /tmp/salfetka-start.XXXXXXXX)
cleanup() { rm -rf -- "$directory"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
curl -q -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --max-redirs 5 --connect-timeout 15 --max-time 120 --max-filesize 262144 \
    https://github.com/qwertimash/salfetka-infrastructure/releases/latest/download/install.py \
    -o "$directory/install.py"
python3 "$directory/install.py" "$@"
