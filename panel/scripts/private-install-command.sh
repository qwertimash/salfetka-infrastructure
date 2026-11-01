sudo bash -c 'set +x; set -euo pipefail; umask 077
d=$(mktemp -d /tmp/salfetka-start.XXXXXXXX)
cleanup() { rm -rf -- "$d"; }; trap cleanup EXIT; trap "exit 130" INT; trap "exit 143" TERM
read -rsp "GitHub token (Contents: read): " salfetka_token </dev/tty; printf "\n"
[[ "$salfetka_token" =~ ^[A-Za-z0-9_]+$ && ${#salfetka_token} -le 4096 ]] || exit 1
printf "%s" "$salfetka_token" > "$d/token"
printf "Authorization: Bearer %s\n" "$salfetka_token" | curl -q -fsS --proto =https --tlsv1.2 --location --max-redirs 0 --connect-timeout 15 --max-time 60 --max-filesize 262144 -H @- -H "Accept: application/vnd.github.raw+json" "https://api.github.com/repos/qwertimash/salfetka-infrastructure/contents/install.py?ref=main" -o "$d/install.py"
unset salfetka_token
python3 "$d/install.py" --github-token-file "$d/token"'
