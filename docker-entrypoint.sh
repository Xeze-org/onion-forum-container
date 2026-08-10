#!/bin/sh
set -e

# Keep the forum database, Tor state, and identity under one data directory.
tor_dir=/data/tor
hs_dir=$tor_dir/hs
mkdir -p "$hs_dir"
chmod 700 "$tor_dir" "$hs_dir"

# Inject private key if provided via environment variable
if [ -n "${TOR_PRIVATE_KEY_B64:-}" ]; then
  printf '%s' "$TOR_PRIVATE_KEY_B64" | base64 -d > "$hs_dir/hs_ed25519_secret_key"
  chmod 600 "$hs_dir/hs_ed25519_secret_key"
fi

chown -R onion-tor:onion-tor "$tor_dir"

# Launch Tor as dedicated user in background
su-exec onion-tor tor \
  --SocksPort 0 \
  --DataDirectory "$tor_dir" \
  --HiddenServiceDir "$hs_dir" \
  --HiddenServicePort "80 127.0.0.1:${PORT:-8080}" \
  --Log "notice stdout" &

# Wait for hostname generation
i=0
while [ ! -f "$hs_dir/hostname" ] && [ $i -lt 300 ]; do
  sleep 0.2
  i=$((i+1))
done

/usr/local/bin/save-tor-key.sh

if [ -f "$hs_dir/hostname" ]; then
  echo "======================================================="
  echo " SUCCESS! Onion Forum is live on the Tor Network!"
  echo " -> Onion Link: http://$(cat "$hs_dir/hostname")"
  echo "======================================================="
fi

# Execute main forum application
exec onion-forum
