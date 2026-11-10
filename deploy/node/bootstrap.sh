#!/usr/bin/env bash
#
# Prepare a small Debian or Ubuntu VPS to run a HoneySentinel sensor.
#
#   sudo bash bootstrap.sh
#
# Expects the repository at /opt/honeysentinel and deploy/node/.env filled in
# (README.md). Safe to re-run; re-run it after changing INGEST_ADDR or
# INGEST_PORT.
#
# What it does, in order:
#   1. checks the settings and the tools it needs
#   2. moves the real SSH daemon to port 22022, and makes you confirm you can
#      still log in, BEFORE port 22 is given to the decoy
#   3. loads the egress firewall with this sensor's one permitted destination
#      and installs the units that keep it loaded (Docker will not start
#      without it; a timer re-checks it every five minutes)
#   4. generates the HTTPS decoy's certificate and a local control token
#
# It does NOT create or configure anything at a cloud provider, does not
# install Docker or the overlay network for you, and does NOT start the
# engine: the last step is yours, after the checklist in README.md.

set -euo pipefail

REAL_SSH_PORT="${REAL_SSH_PORT:-22022}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SERVER="$HERE/../server"
ENV_FILE="$HERE/.env"

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
[[ "$HERE" == /opt/honeysentinel/deploy/node ]] || {
  echo "Expected the repository at /opt/honeysentinel (the systemd units point there)." >&2
  exit 1
}

echo "==> 1/4  Settings and tools"
missing=()
for bin in docker nft python3 openssl curl; do
  command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
done
docker compose version >/dev/null 2>&1 || missing+=("docker-compose-plugin")
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "Missing: ${missing[*]}" >&2
  echo "On Debian or Ubuntu: apt install docker.io docker-compose-plugin nftables python3 openssl curl" >&2
  exit 1
fi
[[ -f "$ENV_FILE" ]] || { echo "No $ENV_FILE: cp .env.example .env and fill it in first." >&2; exit 1; }
chmod 0600 "$ENV_FILE"
value() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1 | tr -d '[:space:]'; }
for key in HONEYPOT_NODE_NAME HONEYPOT_NODE_TOKEN INGEST_ADDR SENSOR_BIND_IPV4; do
  [[ -n "$(value "$key")" ]] || { echo "$key is empty in $ENV_FILE" >&2; exit 1; }
done
ingest_addr=$(value INGEST_ADDR)
ingest_port=$(value INGEST_PORT); ingest_port=${ingest_port:-8001}
bind_addr=$(value SENSOR_BIND_IPV4)
ip -4 -o addr show | grep -qw "$bind_addr" \
  || { echo "SENSOR_BIND_IPV4=$bind_addr is not an address of this machine (see: ip -4 addr)" >&2; exit 1; }
# The ingest endpoint must be on a private overlay, not across the internet.
python3 - "$ingest_addr" <<'PY' || { echo "INGEST_ADDR must be a private overlay address (WireGuard, Tailscale), not a public one." >&2; exit 1; }
import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
overlay = address.is_private or address in ipaddress.ip_network("100.64.0.0/10")
sys.exit(0 if address.version == 4 and overlay else 1)
PY
echo "    sensor $(value HONEYPOT_NODE_NAME) -> ${ingest_addr}:${ingest_port}, decoys on ${bind_addr}"

echo "==> 2/4  Moving the real SSH daemon to port ${REAL_SSH_PORT}"
if ! grep -qE "^Port ${REAL_SSH_PORT}\b" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
  install -d -m 0755 /etc/ssh/sshd_config.d
  # Port 22 keeps listening until the decoy is started, so the session this
  # is typed in is never cut off.
  printf '# HoneySentinel: real administrative SSH\nPort %s\nPort 22\n' "${REAL_SSH_PORT}" \
    > /etc/ssh/sshd_config.d/10-honeysentinel.conf
  systemctl restart ssh 2>/dev/null || systemctl restart sshd
fi
cat <<EOF

  *** OPEN A SECOND TERMINAL NOW AND CONFIRM THIS WORKS: ***

      ssh -p ${REAL_SSH_PORT} <user>@<this-host>

  Better still, reach this machine for administration over the overlay only.
  Once the engine is started, port 22 belongs to the decoy.

EOF
read -r -p "Confirmed you can log in on ${REAL_SSH_PORT}? [yes/NO] " ok
[[ "${ok}" == "yes" ]] || { echo "Aborted; nothing else was changed."; exit 1; }
# Only now is 22 released, so the decoy can bind it.
printf '# HoneySentinel: real administrative SSH (port 22 is the decoy)\nPort %s\n' "${REAL_SSH_PORT}" \
  > /etc/ssh/sshd_config.d/10-honeysentinel.conf
systemctl restart ssh 2>/dev/null || systemctl restart sshd

echo "==> 3/4  Egress firewall"
# The server's script and units, with this sensor's profile: everything the
# engine opens is dropped except connections to the ingest endpoint.
umask 077
cat > "$SERVER/egress.conf" <<EOF
# Written by deploy/node/bootstrap.sh. Read by honeysentinel-egress.sh.
PROFILE=sensor
ALLOW_OUT="hs-sensor:${ingest_addr}:${ingest_port}"
EOF
install -m 0644 "$SERVER/systemd/honeysentinel-egress.service" \
  "$SERVER/systemd/honeysentinel-egress-check.service" \
  "$SERVER/systemd/honeysentinel-egress-check.timer" /etc/systemd/system/
# Docker refuses to start without the egress rules (fail closed).
install -d -m 0755 /etc/systemd/system/docker.service.d
install -m 0644 "$SERVER/systemd/docker.service.d-honeysentinel.conf" /etc/systemd/system/docker.service.d/honeysentinel.conf
systemctl daemon-reload
systemctl enable honeysentinel-egress.service >/dev/null 2>&1
if systemctl is-active --quiet honeysentinel-egress.service; then
  systemctl reload honeysentinel-egress.service
else
  systemctl start honeysentinel-egress.service
fi
bash "$SERVER/honeysentinel-egress.sh" check >/dev/null \
  || { echo "    egress rules not in place; do not start the engine" >&2; exit 1; }
systemctl enable --now honeysentinel-egress-check.timer >/dev/null 2>&1
echo "    loaded and verified; re-checked every 5 minutes (journalctl -t honeysentinel-egress)"

echo "==> 4/4  Decoy certificate and control token"
tls="$HERE/state/decoy-tls"
if [[ ! -f "$tls/server.key" ]]; then
  install -d -m 0700 "$HERE/state"
  install -d -m 0755 "$tls"
  # A different plausible name per install, as on the server.
  cn=$(printf '%s\n' web01 web-prod-02 app-node-1 srv-web-03 edge-01 www2 portal-01 | shuf -n1)
  openssl req -x509 -newkey rsa:2048 -nodes -days 1095 -sha256 \
    -subj "/CN=${cn}" -addext "subjectAltName=DNS:${cn}" \
    -keyout "$tls/server.key" -out "$tls/server.crt" 2>/dev/null
  # uid 10001 is the engine's user in honeypot/Dockerfile.
  chown 10001:10001 "$tls/server.key" "$tls/server.crt"
  chmod 0600 "$tls/server.key"
  echo "    issued the HTTPS decoy's certificate"
fi
if ! grep -q '^HONEYPOT_CONTROL_TOKEN=' "$ENV_FILE"; then
  printf 'HONEYPOT_CONTROL_TOKEN=%s\n' "$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" >> "$ENV_FILE"
  echo "    generated a control token"
fi

cat <<EOF

Prepared. The engine is not running. Before you start it, go through the
pre-exposure checklist in deploy/node/README.md. Then:

  cd /opt/honeysentinel/deploy/node
  GIT_REVISION=\$(git -C /opt/honeysentinel rev-parse HEAD) docker compose up -d --build
  sudo bash ../server/honeysentinel-egress.sh probe     # must end with "Probe passed"

EOF
