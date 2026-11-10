#!/usr/bin/env bash
#
# Fetch or refresh the geolocation database (DB-IP City Lite, CC BY 4.0, no
# account needed) into state/geoip/city.mmdb.
#
#   sudo bash fetch-geoip.sh              # fetch if this month's is not installed
#   sudo bash fetch-geoip.sh --restart    # ...and restart the API if it changed
#
# install.sh runs the first form. honeysentinel-geoip.timer runs the second
# every week: DB-IP publishes monthly, and before the timer the database was
# only refreshed when someone happened to re-run install.sh.
#
# Runs on the host: the containers have no internet access, by design.
#
# What is and is not verified. DB-IP publishes an MD5 and a SHA-1 of the
# current month's file on its download page, as HTML, and nothing machine-
# readable. This script reads the SHA-1 from that page and compares it with
# the download. That catches a truncated or corrupted file. It is weaker than
# the checks on the two model files: the checksum and the file come from the
# same organisation over TLS (so it does not prove who produced the file),
# SHA-1 is no defence against a deliberate collision, and when the page
# layout changes the checksum cannot be read at all. In that case the file is
# still installed, after the structural check below, with "sha1_verified=no"
# recorded beside it; set GEOIP_REQUIRE_CHECKSUM=1 to refuse instead. No
# checksum exists for the previous month's file, which is the fallback when
# the current one is not out yet.
#
# Whatever the checksum says, the file must look like a DB-IP City Lite
# database before it replaces the installed one, and the swap is a rename.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
GEO="$HERE/state/geoip"
DB="$GEO/city.mmdb"
SOURCE="$DB.source"
PAGE=https://db-ip.com/db/download/ip-to-city-lite
RESTART=0
[[ "${1:-}" == --restart ]] && RESTART=1

install -d -m 0755 "$GEO"
this_month=$(date +%Y-%m)
last_month=$(date -d "$(date +%Y-%m-15) -1 month" +%Y-%m)
installed=$(sed -n 's/^release=//p' "$SOURCE" 2>/dev/null || true)

# A MaxMind GeoLite2 file put there by hand reads through the same API; it is
# the operator's to maintain, and is never overwritten.
if [[ -f "$DB" && ! -f "$SOURCE" ]] && tail -c 131072 "$DB" | grep -qa 'GeoLite2'; then
  echo "city.mmdb is a GeoLite2 database installed by hand; left alone"
  exit 0
fi
if [[ -f "$DB" && "$installed" == "$this_month" ]]; then
  echo "DB-IP City Lite $installed is current; kept"
  exit 0
fi

cleanup() { rm -f "$GEO"/city.mmdb.gz.part "$GEO"/city.mmdb.part; }
trap cleanup EXIT

published_sha1() {  # SHA-1 the download page shows for <file name>, or nothing
  curl -fsSL -m 30 -A "honeysentinel-fetch-geoip" "$PAGE" 2>/dev/null | python3 -c '
import re, sys
name = sys.argv[1]
page = sys.stdin.read()
link = page.find(name)
# The checksum sits in the card above the download link for the same file.
found = re.findall(r"SHA1SUM</dt>\s*<dd[^>]*>\s*([0-9a-f]{40})\s*</dd>", page[:link]) if link > 0 else []
print(found[-1] if found else "")
' "$1" || true
}

looks_like_dbip() {  # the MaxMind DB metadata block must name the product
  python3 - "$1" <<'PY'
import os, sys
path = sys.argv[1]
size = os.path.getsize(path)
with open(path, "rb") as handle:
    handle.seek(max(0, size - 131072))
    tail = handle.read()
marker = tail.rfind(b"\xab\xcd\xefMaxMind.com")
ok = size > 10 * 1024 * 1024 and marker >= 0 and b"DBIP-City-Lite" in tail[marker:]
sys.exit(0 if ok else 1)
PY
}

for month in "$this_month" "$last_month"; do
  # Never go backwards: the fallback is only for a first install, or for a
  # database older than last month's.
  if [[ "$month" == "$last_month" && -f "$DB" && -n "$installed" && ! "$installed" < "$last_month" ]]; then
    break
  fi
  name="dbip-city-lite-${month}.mmdb.gz"
  url="https://download.db-ip.com/free/$name"
  if ! curl -fsSL -m 600 --retry 2 -o "$GEO/city.mmdb.gz.part" "$url"; then
    echo "    $name: not available"
    continue
  fi

  have=$(sha1sum "$GEO/city.mmdb.gz.part" | cut -d' ' -f1)
  want=$(published_sha1 "$name")
  if [[ -n "$want" && "$want" != "$have" ]]; then
    echo "    $name: SHA-1 $have does not match the published $want; discarded" >&2
    continue
  fi
  if [[ -z "$want" ]]; then
    verified="no (no checksum is published for this file, or the download page could not be read)"
    if [[ "${GEOIP_REQUIRE_CHECKSUM:-0}" == 1 ]]; then
      echo "    $name: no published checksum and GEOIP_REQUIRE_CHECKSUM=1; discarded" >&2
      continue
    fi
    echo "    WARNING: $name installed without a checksum comparison" >&2
  else
    verified=yes
  fi

  gunzip -c "$GEO/city.mmdb.gz.part" > "$GEO/city.mmdb.part"
  if ! looks_like_dbip "$GEO/city.mmdb.part"; then
    echo "    $name: not a DB-IP City Lite database; discarded" >&2
    continue
  fi
  chmod 0644 "$GEO/city.mmdb.part"
  mv "$GEO/city.mmdb.part" "$DB"
  {
    echo "release=$month"
    echo "url=$url"
    echo "sha1_gz=$have"
    echo "sha1_verified=$verified"
    echo "sha256=$(sha256sum "$DB" | cut -d' ' -f1)"
    echo "fetched=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$SOURCE"
  echo "    installed dbip-city-lite-${month} (checksum compared: ${verified%% *})"

  # The API opens the file once, at start.
  if [[ $RESTART -eq 1 ]] && (cd "$HERE" && docker compose ps -q backend 2>/dev/null | grep -q .); then
    (cd "$HERE" && docker compose restart backend ingest >/dev/null)
    echo "    restarted backend and ingest on the new database"
  fi
  exit 0
done

if [[ ! -f "$DB" ]]; then
  echo "No database could be fetched; sessions will have no location until one is." >&2
  exit 1
fi
if [[ -n "$installed" && ! "$installed" < "$last_month" ]]; then
  # Early in a month, before DB-IP has published: nothing is wrong yet.
  echo "DB-IP City Lite $this_month is not out yet; keeping $installed"
  exit 0
fi
echo "No newer database could be fetched; the installed one (${installed:-age unknown}) is out of date." >&2
exit 1
