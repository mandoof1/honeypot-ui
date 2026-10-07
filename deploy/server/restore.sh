#!/usr/bin/env bash
#
# Restore a backup made by backup.sh, on this machine or a fresh one.
#
#   sudo bash restore.sh /var/backups/honeysentinel/20261007-033307 [--yes]
#
# On a fresh machine: clone the repository to /opt/honeysentinel first, copy
# the backup directory over, then run this BEFORE install.sh — it puts .env
# and state/ back so install.sh keeps them instead of generating new secrets
# (a new ENCRYPTION_KEY would make every stored transcript unreadable).
#
# On a running deployment it stops the services that write to the database,
# restores the dump with errors treated as fatal, and starts them again.

set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
src=${1:-}
[[ -d "$src" ]] || { echo "usage: $0 <backup directory> [--yes]" >&2; exit 1; }
yes=${2:-}
cd "$(dirname "$0")"

echo "Backup manifest:"
sed 's/^/  /' "$src/MANIFEST" 2>/dev/null || echo "  (no MANIFEST; older backup)"
for f in db.sql.gz config.tar.gz engine-data.tar.gz; do
  [[ -f "$src/$f" ]] || continue
  want=$(grep "^$f " "$src/MANIFEST" 2>/dev/null | sed -n 's/.*sha256=\([0-9a-f]*\).*/\1/p')
  if [[ -n "$want" ]] && [[ "$(sha256sum "$src/$f" | cut -d' ' -f1)" != "$want" ]]; then
    echo "checksum mismatch on $f; refusing" >&2; exit 1
  fi
done

if [[ "$yes" != "--yes" ]]; then
  read -r -p "Restore over the current deployment? [y/N] " answer
  [[ "$answer" == y || "$answer" == Y ]] || exit 1
fi

if [[ -f "$src/config.tar.gz" ]]; then
  if [[ -f .env ]]; then
    cp -a .env ".env.before-restore-$(date +%s)"
    echo "kept a copy of the current .env"
  fi
  tar -xzf "$src/config.tar.gz" -C .
  chmod 0600 .env
  echo "restored .env, state/ and the compose override"
fi

running=0
docker compose ps -q postgres 2>/dev/null | grep -q . && running=1
if [[ $running -eq 0 ]]; then
  echo "starting the database"
  docker compose up -d postgres
  for _ in $(seq 1 30); do
    docker compose exec -T postgres pg_isready -U honeypot -d honeysentinel >/dev/null 2>&1 && break
    sleep 2
  done
fi

if [[ -f "$src/db.sql.gz" ]]; then
  echo "stopping writers"
  docker compose stop honeypot ingest backend web >/dev/null 2>&1 || true
  echo "restoring the database"
  gunzip -c "$src/db.sql.gz" \
    | docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -q -U honeypot -d honeysentinel >/dev/null
  echo "database restored"
fi

if [[ -f "$src/engine-data.tar.gz" ]]; then
  volume="$(docker compose config --format json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["volumes"]["honeypot_data"]["name"])' 2>/dev/null || echo honeysentinel_honeypot_data)"
  docker volume create "$volume" >/dev/null
  docker run --rm -v "$volume":/data -v "$src":/in:ro alpine:3.20 \
    sh -c 'rm -rf /data/* && tar -xzf /in/engine-data.tar.gz -C /data'
  echo "engine data (host keys, identity, captures) restored"
fi

if [[ $running -eq 1 ]]; then
  docker compose up -d
  echo "services started"
else
  echo "Now run: sudo bash install.sh"
fi
