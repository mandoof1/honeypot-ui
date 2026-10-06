#!/usr/bin/env bash
#
# Nightly care of the website behind the HTTP decoys.
#
# With a decoy copy (the shop-decoy service), the decoy copy goes back to
# freshly generated data, so nothing an attacker changed survives the night,
# and the live copy is backed up without being touched: it is the one real
# visitors use. With a single shop, that shop is reset. Either way each
# database is kept first (14 days), for working out what an attacker altered
# and for restoring the live copy.
# Run nightly by honeysentinel-shop-reset.timer; safe to run by hand.

set -euo pipefail

DEST=/var/backups/honeysentinel/shop
KEEP_DAYS=14
cd "$(dirname "$0")"

services=$(docker compose config --services)
has() { grep -x "$1" >/dev/null <<<"$services"; }

if ! has shop; then
  echo "No shop service (docker-compose.override.yml absent); nothing to reset"
  exit 0
fi

install -d -m 0700 "$DEST"
stamp=$(date +%Y%m%d-%H%M%S)

keep() {  # keep <name>: store the tar stream on stdin as <name>-<stamp>.tar.gz
  local tmp="$DEST/.$1-$stamp.tar.gz.part"
  gzip -9 > "$tmp"
  chmod 0600 "$tmp"
  mv "$tmp" "$DEST/$1-$stamp.tar.gz"
  echo "Kept: $DEST/$1-$stamp.tar.gz"
}

backup_running() {  # backup_running <service> <name>: a consistent copy, no downtime
  docker compose exec -T "$1" node --no-warnings -e "
    require('node:fs').rmSync('/app/data/.backup.db', { force: true });
    new (require('node:sqlite').DatabaseSync)('/app/data/shop.db').exec(\"VACUUM INTO '/app/data/.backup.db'\");
  " < /dev/null
  docker cp "$(docker compose ps -q "$1")":/app/data/.backup.db - | keep "$2"
  docker compose exec -T "$1" rm -f /app/data/.backup.db < /dev/null
}

reset() {  # reset <service> <name>: keep the data, regenerate it, restart
  docker compose stop "$1"
  # Whatever happens below, the shop comes back up. If the generator failed
  # part-way, the shop seeds an empty database itself on start.
  trap "docker compose start $1 >/dev/null" EXIT
  docker cp "$(docker compose ps -aq "$1")":/app/data - | keep "$2"
  docker compose run --rm --no-deps -T "$1" node server/seed.js
  trap - EXIT
  docker compose start "$1"
  for _ in $(seq 1 30); do
    status=$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q "$1")" 2>/dev/null || true)
    [[ "$status" == healthy ]] && { echo "$1 reset and healthy"; return 0; }
    sleep 2
  done
  echo "$1 did not become healthy after the reset" >&2
  docker compose logs --tail 30 "$1" >&2
  return 1
}

if has shop-decoy; then
  backup_running shop live
  reset shop-decoy decoy
else
  reset shop shop
fi

find "$DEST" -name '*-*.tar.gz' -mtime +"$KEEP_DAYS" -delete
