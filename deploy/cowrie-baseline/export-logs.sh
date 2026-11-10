#!/usr/bin/env bash
#
# Copy Cowrie's JSON logs out of its volume, for the comparison tool.
#
#   sudo bash export-logs.sh [destination directory]
#
# Writes <destination>/cowrie-<time>/cowrie.json* (default destination:
# ../server/state/out, which the backend container sees as /app/out).

set -euo pipefail
cd "$(dirname "$0")"

dest=${1:-../server/state/out}
stamp=$(date -u +%Y%m%dT%H%M%SZ)
id=$(docker compose ps -q cowrie)
[[ -n "$id" ]] || { echo "the cowrie container is not running" >&2; exit 1; }
install -d "$dest/cowrie-$stamp"
docker cp "$id":/cowrie/cowrie-git/var/log/cowrie/. "$dest/cowrie-$stamp/"
# Readable by the API's user, which runs the comparison.
chown -R 10001:10001 "$dest/cowrie-$stamp"
echo "Logs copied to $dest/cowrie-$stamp ($(find "$dest/cowrie-$stamp" -name 'cowrie.json*' | wc -l) file(s))"
