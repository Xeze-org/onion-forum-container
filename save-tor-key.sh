#!/bin/sh
set -eu

key_file=${1:-/data/tor/hs/hs_ed25519_secret_key}
env_file=${2:-/data/.env}

[ -z "${TOR_PRIVATE_KEY_B64:-}" ] || exit 0
[ -s "$key_file" ] || exit 0
[ -f "$env_file" ] || exit 0

encoded_key=$(base64 < "$key_file" | tr -d '\r\n')
temp_env=$(mktemp)
trap 'rm -f "$temp_env"' EXIT INT TERM

if grep -q '^TOR_PRIVATE_KEY_B64=' "$env_file"; then
  sed "s|^TOR_PRIVATE_KEY_B64=.*$|TOR_PRIVATE_KEY_B64=$encoded_key|" "$env_file" > "$temp_env"
else
  cp "$env_file" "$temp_env"
  printf '\nTOR_PRIVATE_KEY_B64=%s\n' "$encoded_key" >> "$temp_env"
fi

cat "$temp_env" > "$env_file"
chmod 600 "$env_file" 2>/dev/null || true
echo "[+] Tor identity saved to .env."
