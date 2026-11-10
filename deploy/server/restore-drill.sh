#!/usr/bin/env bash
#
# Rehearse a restore without touching the deployment.
#
#   sudo bash restore-drill.sh                      # the newest backup
#   sudo bash restore-drill.sh /var/backups/honeysentinel/20261107-033012
#        [--identity <age identity file>] [--passphrase-file <file>]
#
# A backup that has never been restored is a hope. This restores one into a
# throwaway Postgres and checks the three things that have gone wrong, or
# would go wrong silently:
#
#   1. Row counts. The dump loads in a single transaction, and each main
#      table has as many rows as the backup recorded when it was taken.
#   2. A decryptable sample. One stored transcript is decrypted with the
#      ENCRYPTION_KEY from the same set, using the application's own code.
#      A dump restored beside the wrong key looks complete and is unreadable.
#   3. The models. The set holds the trained classifier; without it a
#      restored deployment answers from the synthetic bootstrap model.
#
# The scratch database and the container that reads it live on the test
# bridge (hs-test), with no route anywhere, and are removed at the end. The
# live database, volumes and .env are not written to. The result is printed
# and saved as state/restore-drill-<time>.json.
#
# Run it after the first backup, after changing the backup's encryption
# settings, and before relying on a set (docs/EXPOSURE_RUNBOOK.md).

set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
src=""
AGE_IDENTITY=""
PASSPHRASE_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --identity) AGE_IDENTITY=$2; shift 2 ;;
    --passphrase-file) PASSPHRASE_FILE=$2; shift 2 ;;
    *) src=$1; shift ;;
  esac
done
cd "$(dirname "$0")"
# shellcheck source=deploy/server/backup-lib.sh
. ./backup-lib.sh
export AGE_IDENTITY PASSPHRASE_FILE

if [[ -z "$src" ]]; then
  dest=$(setting BACKUP_DEST); dest=${dest:-/var/backups/honeysentinel}
  src="$dest/$(cat "$dest/LATEST" 2>/dev/null || true)"
fi
[[ -f "$src/MANIFEST" ]] || { echo "no backup set at '$src'" >&2; exit 1; }
src=$(cd "$src" && pwd)

DB=hs-drill-db
NET=honeysentinel_test
image=$(helper_image)
password=$(python3 -c "import secrets; print(secrets.token_hex(16))")
results=()
failed=0
record() {  # record <check> <pass|fail|skipped> <detail>
  results+=("$1|$2|$3")
  printf '  %-8s %-12s %s\n' "$2" "$1" "$3"
  [[ "$2" != fail ]] || failed=1
}

cleanup() { docker rm -fv "$DB" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "==> Drill on $src"
if verify_manifest "$src"; then
  record manifest pass "every stored file matches its recorded SHA-256"
else
  record manifest fail "a stored file is missing or does not match the manifest"
fi

echo "==> Restoring the dump into a scratch database"
docker network inspect "$NET" >/dev/null 2>&1 \
  || docker network create --internal --subnet 172.30.75.0/24 \
       -o com.docker.network.bridge.name=hs-test \
       --label com.docker.compose.project=honeysentinel-test "$NET" >/dev/null
docker run -d --name "$DB" --network "$NET" \
  -e POSTGRES_USER=honeypot -e POSTGRES_PASSWORD="$password" -e POSTGRES_DB=honeysentinel \
  --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETGID --cap-add SETUID \
  --security-opt no-new-privileges:true "$image" >/dev/null
for _ in $(seq 1 60); do
  docker exec "$DB" pg_isready -U honeypot -d honeysentinel >/dev/null 2>&1 && break
  sleep 1
done
scratch() { docker exec -i "$DB" psql -U honeypot -d honeysentinel -v ON_ERROR_STOP=1 "$@"; }

if plain "$src" db.sql.gz | gunzip -c | scratch --single-transaction -q >/dev/null; then
  record dump pass "loaded in a single transaction"
  mismatch=""
  while read -r table count; do
    lo=$(sed -n "s/^rows_before\.$table=//p" "$src/MANIFEST")
    hi=$(sed -n "s/^rows_after\.$table=//p" "$src/MANIFEST")
    [[ -n "$lo" && -n "$hi" ]] || { mismatch+=" $table(no count recorded)"; continue; }
    (( lo > hi )) && { tmp=$lo; lo=$hi; hi=$tmp; }
    # The dump is one snapshot taken between the two counts.
    (( count >= lo && count <= hi )) || mismatch+=" $table(restored $count, backup recorded $lo..$hi)"
  done < <(row_counts scratch)
  if [[ -z "$mismatch" ]]; then
    record rows pass "$(row_counts scratch | tr '\n' ' ')"
  else
    record rows fail "$mismatch"
  fi
else
  record dump fail "psql stopped on an error; see above"
fi

echo "==> Decrypting a stored transcript with the key in the same set"
# The key is read into this process and handed to the container through its
# environment; it is not written anywhere.
ENCRYPTION_KEY=$(plain "$src" config.tar.gz | tar -xzf - -O .env 2>/dev/null | sed -n 's/^ENCRYPTION_KEY=//p' | tail -n 1 || true)
ENCRYPTION_KEY_PREVIOUS=$(plain "$src" config.tar.gz | tar -xzf - -O .env 2>/dev/null | sed -n 's/^ENCRYPTION_KEY_PREVIOUS=//p' | tail -n 1 || true)
export ENCRYPTION_KEY ENCRYPTION_KEY_PREVIOUS
if [[ -z "$ENCRYPTION_KEY" ]]; then
  record decrypt fail "no ENCRYPTION_KEY in the set's config archive (or the archive could not be read)"
elif [[ $failed -ne 0 ]]; then
  record decrypt skipped "the dump did not load"
else
  # Development mode only so the container starts without the deployment's
  # other secrets and without TLS to a database that has no certificate.
  out=$(docker run --rm -i --network "$NET" --cap-drop ALL --security-opt no-new-privileges:true \
    -e ENVIRONMENT=development -e DATABASE_SSL=false \
    -e DATABASE_URL="postgresql+asyncpg://honeypot:$password@$DB:5432/honeysentinel" \
    -e ENCRYPTION_KEY -e ENCRYPTION_KEY_PREVIOUS \
    honeysentinel-backend python - 2>&1 <<'PY' || true
import asyncio

from sqlalchemy import text

from app.core.database import async_session_factory
from app.core.encryption import decrypt_data

COLUMNS = ("transcript_encrypted", "raw_commands_encrypted", "credentials_encrypted")


async def main():
    async with async_session_factory() as db:
        for column in COLUMNS:
            row = (await db.execute(text(
                f"select id, {column} from honeypot_sessions where {column} is not null order by id desc limit 1"
            ))).first()
            if row:
                # Never printed: only that it decrypts, and how long it is.
                clear = decrypt_data(row[1])
                print(f"RESULT=pass session {row[0]}, {column}: {len(clear)} characters")
                return
    print("RESULT=skipped no session with encrypted content in this backup")


asyncio.run(main())
PY
  )
  line=$(sed -n 's/^RESULT=//p' <<<"$out" | tail -n 1)
  case "$line" in
    pass*) record decrypt pass "${line#pass }" ;;
    skipped*) record decrypt skipped "${line#skipped }" ;;
    *) record decrypt fail "$(tail -n 2 <<<"$out" | tr '\n' ' ')" ;;
  esac
fi

echo "==> Models in the set"
if has "$src" models.tar.gz; then
  listing=$(plain "$src" models.tar.gz | tar -tzf - | sed 's|^\./||' | grep -v '^$' | tr '\n' ' ')
  if grep -q 'random_forest_model.pkl' <<<"$listing"; then
    record models pass "$listing"
  else
    record models fail "no random_forest_model.pkl (found: ${listing:-nothing}); verdicts would be synthetic"
  fi
else
  record models fail "no models archive in this set"
fi

report="state/restore-drill-$(date -u +%Y%m%dT%H%M%SZ).json"
install -d -m 0700 state
python3 - "$report" "$src" "$(git -C /opt/honeysentinel rev-parse HEAD 2>/dev/null || echo unknown)" "${results[@]}" <<'PY'
import json, sys, datetime
path, backup, revision, *rows = sys.argv[1:]
checks = [dict(zip(("check", "result", "detail"), row.split("|", 2))) for row in rows]
report = {
    "test": "restore drill",
    "run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "backup": backup,
    "git_revision": revision,
    "passed": all(c["result"] != "fail" for c in checks),
    "checks": checks,
}
json.dump(report, open(path, "w"), indent=2)
PY
echo
echo "Report: $(pwd)/$report"
if [[ $failed -ne 0 ]]; then
  echo "DRILL FAILED: this backup would not restore a working deployment." >&2
  exit 1
fi
echo "Drill passed."
