#!/usr/bin/env bash
#
# Nightly backup of everything needed to rebuild this deployment elsewhere.
# Keeps 14 days. Restore with restore.sh.
#
# Each run writes a directory /var/backups/honeysentinel/<stamp>/ holding:
#   db.sql.gz          logical dump of Postgres (sessions, alerts, samples;
#                      transcripts and payload bytes are encrypted inside it)
#   config.tar.gz      deploy/server/.env, docker-compose.override.yml and
#                      state/ (TLS keys, admin credentials, GeoIP; not the
#                      model file) — WITHOUT these, and ENCRYPTION_KEY in
#                      particular, the dump is unreadable
#   engine-data.tar.gz the engine's volume: SSH host keys and identity (so a
#                      rebuilt box looks like the same box), local captures,
#                      uploads, spool
#   MANIFEST           sizes and SHA-256 of each file, plus the git revision
#
# The directory is root-only. It is still on the same disk as the data: copy
# it somewhere else (rclone, scp, a USB disk) — that part is yours.

set -euo pipefail

DEST=${BACKUP_DEST:-/var/backups/honeysentinel}
KEEP_DAYS=${BACKUP_KEEP_DAYS:-14}
cd "$(dirname "$0")"

install -d -m 0700 "$DEST"
stamp=$(date +%Y%m%d-%H%M%S)
work="$DEST/.$stamp.part"
install -d -m 0700 "$work"
trap 'rm -rf "$work"' ERR

docker compose exec -T postgres pg_dump -U honeypot -d honeysentinel --clean --if-exists \
  | gzip -9 > "$work/db.sql.gz"
# A dump that ends early still gzips cleanly; make sure the dump completed.
gunzip -c "$work/db.sql.gz" | tail -n 5 | grep -q 'PostgreSQL database dump complete' \
  || { echo "pg_dump did not complete" >&2; exit 1; }

# state/models holds the multi-gigabyte analysis model, which is not
# configuration and is kept elsewhere; copy it back by hand on a rebuild.
tar -czf "$work/config.tar.gz" \
  --exclude='state/geoip/*.part' --exclude='state/models' \
  .env state $(ls docker-compose.override.yml 2>/dev/null)

volume="$(docker compose config --format json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["volumes"]["honeypot_data"]["name"])' 2>/dev/null || echo honeysentinel_honeypot_data)"
docker run --rm -v "$volume":/data:ro -v "$work":/out alpine:3.20 \
  tar -czf /out/engine-data.tar.gz -C /data . 2>/dev/null \
  || echo "engine volume not backed up (is the stack running?)" >&2

(
  cd "$work"
  {
    echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "host=$(hostname)"
    echo "git=$(git -C /opt/honeysentinel rev-parse HEAD 2>/dev/null || echo unknown)"
    for f in db.sql.gz config.tar.gz engine-data.tar.gz; do
      [[ -f $f ]] && printf '%s size=%s sha256=%s\n' "$f" "$(stat -c %s "$f")" "$(sha256sum "$f" | cut -d' ' -f1)"
    done
  } > MANIFEST
)
chmod -R go-rwx "$work"
mv "$work" "$DEST/$stamp"

# Old layout (single .sql.gz files) and old directories.
find "$DEST" -maxdepth 1 -name 'honeysentinel-*.sql.gz' -mtime +"$KEEP_DAYS" -delete
find "$DEST" -maxdepth 1 -type d -name '20*' -mtime +"$KEEP_DAYS" -exec rm -rf {} +
find "$DEST" -maxdepth 1 -type d -name '.*.part' -mmin +180 -exec rm -rf {} +

echo "Backup written: $DEST/$stamp ($(du -sh "$DEST/$stamp" | cut -f1))"
