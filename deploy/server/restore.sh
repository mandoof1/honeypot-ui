#!/usr/bin/env bash
#
# Restore a backup made by backup.sh, on this machine or a fresh one.
#
#   sudo bash restore.sh /var/backups/honeysentinel/20261007-033307 [--yes]
#        [--identity <age identity file>] [--passphrase-file <file>]
#
# On a fresh machine: clone the repository to /opt/honeysentinel first, copy
# the backup directory over, then run this BEFORE install.sh. It puts .env
# and state/ back so install.sh keeps them instead of generating new secrets
# (a new ENCRYPTION_KEY would make every stored transcript unreadable), puts
# the shop's source back where the override builds it from, and fills the
# database, the models volume and the engines' volumes. Then run install.sh.
#
# On a running deployment it stops the services that write to the database,
# restores, and starts them again.
#
# The database is restored in a single transaction: either the whole dump is
# applied or none of it. Before, an error half-way left a database that was
# neither the old one nor the backup.
#
# An encrypted set needs the key it was encrypted to: --identity for age,
# root's keyring for a GnuPG recipient, --passphrase-file for a passphrase
# (.env, where that path is normally set, is itself inside the set).
# Rehearse on a scratch database first: restore-drill.sh.

set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
src=""
yes=""
AGE_IDENTITY=""
PASSPHRASE_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) yes=1; shift ;;
    --identity) AGE_IDENTITY=$2; shift 2 ;;
    --passphrase-file) PASSPHRASE_FILE=$2; shift 2 ;;
    *) src=$1; shift ;;
  esac
done
[[ -d "$src" ]] || { echo "usage: $0 <backup directory> [--yes] [--identity FILE] [--passphrase-file FILE]" >&2; exit 1; }
src=$(cd "$src" && pwd)
cd "$(dirname "$0")"
# shellcheck source=deploy/server/backup-lib.sh
. ./backup-lib.sh
export AGE_IDENTITY PASSPHRASE_FILE

echo "Backup manifest:"
grep -vE '^(plain|stored) ' "$src/MANIFEST" 2>/dev/null | sed 's/^/  /' || true
verify_manifest "$src" || { echo "The set does not match its manifest; refusing." >&2; exit 1; }
# Prove the key works before anything is stopped or overwritten.
if has "$src" config.tar.gz; then
  plain "$src" config.tar.gz | tar -tzf - >/dev/null \
    || { echo "config.tar.gz could not be read (wrong or missing key?); nothing was changed." >&2; exit 1; }
fi

if [[ -z "$yes" ]]; then
  read -r -p "Restore over the current deployment? [y/N] " answer
  [[ "$answer" == y || "$answer" == Y ]] || exit 1
fi

if has "$src" config.tar.gz; then
  if [[ -f .env ]]; then
    # Inside state/, which git ignores and only root can read. It used to be
    # left beside .env, where `git status` offered it for commit.
    install -d -m 0700 state
    install -m 0600 .env "state/env.before-restore-$(date +%s)"
    echo "kept a copy of the current .env in state/"
  fi
  plain "$src" config.tar.gz | tar -xzf - -C .
  chmod 0600 .env
  echo "restored .env, state/ and the compose override"
fi

if has "$src" shop-source.tar.gz; then
  shop_source=$(setting SHOP_SOURCE); shop_source=${shop_source:-/opt/bolt-and-batten}
  if [[ -d "$shop_source" ]]; then
    echo "shop source already at $shop_source; left as is"
  else
    install -d "$(dirname "$shop_source")"
    plain "$src" shop-source.tar.gz | tar -xzf - -C "$(dirname "$shop_source")"
    echo "restored the shop's source to $shop_source"
  fi
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
image=$(helper_image)

if has "$src" db.sql.gz; then
  echo "stopping writers"
  docker compose stop honeypot honeypot-web ingest backend web >/dev/null 2>&1 || true
  echo "restoring the database"
  plain "$src" db.sql.gz | gunzip -c \
    | docker compose exec -T postgres psql -v ON_ERROR_STOP=1 --single-transaction -q \
        -U honeypot -d honeysentinel >/dev/null
  echo "database restored"
fi

for pair in models:models honeypot_data:engine-data honeypot_web_data:engine-web-data; do
  key=${pair%%:*} archive=${pair##*:}.tar.gz
  has "$src" "$archive" || continue
  volume=$(volume_name "$key")
  docker volume create "$volume" >/dev/null
  # Emptied and refilled in a container with no network; tar restores the
  # owners recorded in the archive (uid 10001, the services' user).
  plain "$src" "$archive" | docker run --rm -i --network none --user 0 --entrypoint sh \
    -v "$volume":/data "$image" -c 'find /data -mindepth 1 -delete && tar -xzf - -C /data'
  echo "$key restored"
done
has "$src" models.tar.gz || echo "NOTE: this set has no models archive; train-model.sh must be run again, or verdicts come from the synthetic bootstrap model."

if [[ $running -eq 1 ]]; then
  docker compose up -d
  echo "services started"
else
  echo "Now run: sudo bash install.sh"
fi
