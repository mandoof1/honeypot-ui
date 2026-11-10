#!/usr/bin/env bash
#
# Nightly backup of everything needed to rebuild this deployment elsewhere.
# Keeps 14 days. Restore with restore.sh; rehearse with restore-drill.sh.
#
# Each run writes a directory /var/backups/honeysentinel/<stamp>/ holding:
#   db.sql.gz              logical dump of Postgres (sessions, alerts, samples;
#                          transcripts and payload bytes are encrypted inside it)
#   config.tar.gz          deploy/server/.env, docker-compose.override.yml and
#                          state/ (TLS keys, sensor tokens, GeoIP; not the
#                          language-model files). WITHOUT these, and
#                          ENCRYPTION_KEY in particular, the dump is unreadable
#   models.tar.gz          the models volume: the trained classifier and the
#                          fitted cluster and anomaly models. It used to be
#                          left out, and a restored deployment then classified
#                          with the synthetic bootstrap model without saying so
#   engine-data.tar.gz     each engine's volume: SSH host keys and identity (so
#   engine-web-data.tar.gz a rebuilt box looks like the same box), the spool
#                          and dead-letter directories, local captures, uploads
#   shop-source.tar.gz     the shop's source, when an override builds one from
#                          outside this repository
#   MANIFEST               what is in the set: sizes and SHA-256 of each file,
#                          row counts at dump time, the git revision
#
# What the set contains, in the clear unless it is encrypted: the encryption
# key beside the data it protects, every other secret in .env, sessions the
# engines have not delivered yet, and files attackers uploaded (live malware).
# Set one of BACKUP_AGE_RECIPIENT, BACKUP_GPG_RECIPIENT or
# BACKUP_PASSPHRASE_FILE (see backup-lib.sh) and every file except MANIFEST
# is encrypted before the set is finished. Without one the uploaded files are
# left out (the database holds them, encrypted), the script says so on every
# run, and the set still holds the engines' local copies of the last days'
# sessions in plain text.
#
# The set is written to the same disk as the data. BACKUP_OFFSITE_RSYNC
# (user@host:/path) or BACKUP_OFFSITE_RCLONE (remote:path) copies each
# finished set somewhere else; an unencrypted set is not sent unless
# BACKUP_OFFSITE_ALLOW_PLAINTEXT=1.

set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=deploy/server/backup-lib.sh
. ./backup-lib.sh

DEST=$(setting BACKUP_DEST); DEST=${DEST:-/var/backups/honeysentinel}
KEEP_DAYS=$(setting BACKUP_KEEP_DAYS); KEEP_DAYS=${KEEP_DAYS:-14}
encryption_method

install -d -m 0700 "$DEST"
stamp=$(date +%Y%m%d-%H%M%S)
work="$DEST/.$stamp.part"
install -d -m 0700 "$work"
# Any failure removes the unfinished set and nothing else. Once the set has
# been moved into place this does nothing.
trap 'rm -rf "$work"' EXIT

psql() { docker compose exec -T postgres psql -U honeypot -d honeysentinel -v ON_ERROR_STOP=1 "$@"; }

rows_before=$(row_counts psql)
docker compose exec -T postgres pg_dump -U honeypot -d honeysentinel --clean --if-exists \
  | gzip -9 > "$work/db.sql.gz"
# A dump that ends early still gzips cleanly; make sure the dump completed.
gunzip -c "$work/db.sql.gz" | tail -n 5 | grep -q 'PostgreSQL database dump complete' \
  || { echo "pg_dump did not complete" >&2; exit 1; }
rows_after=$(row_counts psql)

# state/models holds the multi-gigabyte language-model files, which are
# fetched again on a rebuild (fetch-decider.sh). state/out is tool output.
# state/admin-credentials is the first administrator password in plain text,
# written by earlier versions; it has no place in a backup.
config_files=(.env state)
[[ -f docker-compose.override.yml ]] && config_files+=(docker-compose.override.yml)
tar -czf "$work/config.tar.gz" \
  --exclude='state/geoip/*.part' --exclude='state/models' --exclude='state/out' \
  --exclude='state/admin-credentials' --exclude='state/env.before-restore-*' \
  "${config_files[@]}"

image=$(helper_image)
skipped=()
# archive_volume <compose volume key> <archive name> [tar --exclude patterns]
# A volume that does not exist is noted and skipped; a volume that exists and
# cannot be archived fails the whole backup. That failure used to be printed
# and ignored, and a later step then deleted the set, good dump included.
archive_volume() {
  local key=$1 out=$2 volume
  shift 2
  volume=$(volume_name "$key")
  if ! docker volume inspect "$volume" >/dev/null 2>&1; then
    skipped+=("$out (no volume $volume)")
    return 0
  fi
  docker run --rm --network none --user 0 --entrypoint tar -v "$volume":/data:ro "$image" \
    -czf - -C /data "$@" . > "$work/$out.tar.gz"
}

capture_excludes=()
if [[ "$ENC_METHOD" == none && "$(setting BACKUP_ENGINE_CAPTURES)" != 1 ]]; then
  # Raw uploads only: one directory, named exactly. The session directory
  # also holds the host keys, the identity and the sessions not delivered
  # yet, and a pattern that risked dropping those is not worth it.
  capture_excludes=(--exclude='./uploads')
fi
archive_volume models models
archive_volume honeypot_data engine-data "${capture_excludes[@]}"
archive_volume honeypot_web_data engine-web-data "${capture_excludes[@]}"

shop_source=$(setting SHOP_SOURCE); shop_source=${shop_source:-/opt/bolt-and-batten}
if [[ -f docker-compose.override.yml && -d "$shop_source" ]] && grep -q 'SHOP_SOURCE' docker-compose.override.yml; then
  tar -czf "$work/shop-source.tar.gz" --exclude=node_modules --exclude=.git --exclude=data \
    -C "$(dirname "$shop_source")" "$(basename "$shop_source")"
fi

{
  echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host=$(hostname)"
  echo "git=$(git -C /opt/honeysentinel rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "encryption=$ENC_METHOD"
  [[ ${#capture_excludes[@]} -eq 0 ]] || echo "engine_uploads=excluded (set is not encrypted)"
  for item in "${skipped[@]:-}"; do [[ -z "$item" ]] || echo "skipped=$item"; done
  while read -r table count; do echo "rows_before.$table=$count"; done <<<"$rows_before"
  while read -r table count; do echo "rows_after.$table=$count"; done <<<"$rows_after"
  for f in "$work"/*.gz; do
    printf 'plain %s size=%s sha256=%s\n' "$(basename "$f")" "$(stat -c %s "$f")" "$(sha256sum "$f" | cut -d' ' -f1)"
  done
} > "$work/MANIFEST"

if [[ "$ENC_METHOD" != none ]]; then
  for f in "$work"/*.gz; do encrypt_file "$f"; done
fi
# What restore.sh verifies before it touches anything: the files as stored.
for f in "$work"/*.gz*; do
  printf 'stored %s size=%s sha256=%s\n' "$(basename "$f")" "$(stat -c %s "$f")" "$(sha256sum "$f" | cut -d' ' -f1)"
done >> "$work/MANIFEST"

chmod -R go-rwx "$work"
mv "$work" "$DEST/$stamp"
# Read by host-heartbeat.sh to tell whether backups are still being made.
echo "$stamp" > "$DEST/LATEST"

# Old layout (single .sql.gz files) and old directories.
find "$DEST" -maxdepth 1 -name 'honeysentinel-*.sql.gz' -mtime +"$KEEP_DAYS" -delete
find "$DEST" -maxdepth 1 -type d -name '20*' -mtime +"$KEEP_DAYS" -exec rm -rf {} +
find "$DEST" -maxdepth 1 -type d -name '.*.part' -mmin +180 -exec rm -rf {} +

echo "Backup written: $DEST/$stamp ($(du -sh "$DEST/$stamp" | cut -f1), encryption: $ENC_METHOD)"
for item in "${skipped[@]:-}"; do [[ -z "$item" ]] || echo "  not included: $item"; done
if [[ "$ENC_METHOD" == none ]]; then
  echo "WARNING: this set is not encrypted. It holds ENCRYPTION_KEY and every other secret in" >&2
  echo "  .env in plain text. Set BACKUP_AGE_RECIPIENT or BACKUP_PASSPHRASE_FILE in .env." >&2
fi

# Off the machine. The local set is complete either way; a failed copy makes
# the run fail (and so raises the alert) without discarding it.
rsync_target=$(setting BACKUP_OFFSITE_RSYNC)
rclone_target=$(setting BACKUP_OFFSITE_RCLONE)
if [[ -n "$rsync_target$rclone_target" ]]; then
  if [[ "$ENC_METHOD" == none && "$(setting BACKUP_OFFSITE_ALLOW_PLAINTEXT)" != 1 ]]; then
    echo "Not copied off this machine: the set is not encrypted (BACKUP_OFFSITE_ALLOW_PLAINTEXT=1 overrides)." >&2
    exit 1
  fi
  if [[ -n "$rsync_target" ]]; then
    rsync -a --chmod=go-rwx "$DEST/$stamp" "$rsync_target/"
    echo "Copied to $rsync_target/$stamp"
  fi
  if [[ -n "$rclone_target" ]]; then
    rclone copy "$DEST/$stamp" "$rclone_target/$stamp"
    echo "Copied to $rclone_target/$stamp"
  fi
elif [[ "$ENC_METHOD" != none ]]; then
  echo "Note: still on the same disk as the data (BACKUP_OFFSITE_RSYNC or BACKUP_OFFSITE_RCLONE)."
fi
