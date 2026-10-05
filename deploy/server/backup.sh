#!/usr/bin/env bash
#
# Nightly logical backup of the HoneySentinel database. Keeps 14 days.
# Restore: gunzip -c FILE | docker compose exec -T postgres psql -U honeypot -d honeysentinel

set -euo pipefail

DEST=/var/backups/honeysentinel
KEEP_DAYS=14
cd "$(dirname "$0")"

install -d -m 0700 "$DEST"
stamp=$(date +%Y%m%d-%H%M%S)
tmp="$DEST/.honeysentinel-$stamp.sql.gz.part"
docker compose exec -T postgres pg_dump -U honeypot -d honeysentinel --clean --if-exists \
  | gzip -9 > "$tmp"
chmod 0600 "$tmp"
mv "$tmp" "$DEST/honeysentinel-$stamp.sql.gz"
find "$DEST" -name 'honeysentinel-*.sql.gz' -mtime +"$KEEP_DAYS" -delete
echo "Backup written: $DEST/honeysentinel-$stamp.sql.gz"
