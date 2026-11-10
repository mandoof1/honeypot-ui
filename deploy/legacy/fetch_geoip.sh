#!/usr/bin/env bash
#
# Download the MaxMind GeoLite2 City database.
#
# Audit finding 17: the geoip2 wiring is correct, but the .mmdb was never
# shipped and render.yaml never fetched it, so on the deployed instance every
# lookup returned "unavailable" and every session was stored with a null
# location. The Live Map rendered correctly and had nothing to plot.
#
# GeoLite2 is free but not redistributable, so it cannot be committed to the
# repository or fetched without credentials. A free MaxMind account gives you
# a licence key:
#
#     https://www.maxmind.com/en/geolite2/signup
#
#     export MAXMIND_LICENSE_KEY=...
#     bash scripts/fetch_geoip.sh
#
# Without it the system still runs. Sessions are simply recorded with no
# location rather than a fabricated one — an earlier build derived coordinates
# from an MD5 of the IP address, which put invented countries on the map.

set -euo pipefail

DEST="${GEOIP_DB_PATH:-./backend/data/GeoLite2-City.mmdb}"
KEY="${MAXMIND_LICENSE_KEY:-}"

if [[ -z "$KEY" ]]; then
  echo "MAXMIND_LICENSE_KEY is not set." >&2
  echo "Sign up free at https://www.maxmind.com/en/geolite2/signup" >&2
  exit 1
fi

URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${KEY}&suffix=tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Downloading GeoLite2-City"
curl -fsSL "$URL" -o "$TMP/geolite2.tar.gz"

echo "==> Extracting"
tar -xzf "$TMP/geolite2.tar.gz" -C "$TMP"
FOUND="$(find "$TMP" -name '*.mmdb' -print -quit)"
[[ -n "$FOUND" ]] || { echo "No .mmdb in the archive" >&2; exit 1; }

mkdir -p "$(dirname "$DEST")"
mv "$FOUND" "$DEST"
echo "==> Installed at $DEST ($(du -h "$DEST" | cut -f1))"
echo
echo "Set GEOIP_DB_PATH to this path if it is not already the default."
echo "MaxMind refresh GeoLite2 weekly; re-run to update."
