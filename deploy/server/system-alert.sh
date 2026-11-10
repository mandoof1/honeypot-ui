#!/usr/bin/env bash
#
# Raise or resolve a system alert in the dashboard from the host, so an
# operational failure shows up where someone is looking, not only in the
# journal. Used by:
#
#   honeysentinel-alert@.service   the OnFailure= hook of the backup, shop
#                                  reset, GeoIP refresh and egress check units
#   honeysentinel-egress.sh watch  when the firewall rules were missing
#   host-heartbeat.sh              when a host-level check fails, and again
#                                  (--resolve) when it passes
#
#   system-alert.sh <key> <severity> <title> [description]
#   system-alert.sh --resolve <key> [note]
#
# An alert with a key that is already open is not raised twice; its count
# goes up instead. Runs inside the backend container (the only place with
# database access and the alert service), so the host needs nothing but
# docker. It cannot tell anyone the backend itself is down: that is what the
# host heartbeat's external ping is for.

set -euo pipefail
cd "$(dirname "$0")"

mode=raise
if [[ "${1:-}" == --resolve ]]; then
  mode=resolve
  shift
  key=${1:?key}; severity=low; title=""; description=${2:-Resolved by the host.}
else
  key=${1:?key}; severity=${2:?severity}; title=${3:?title}; description=${4:-}
fi

docker compose exec -T backend python - "$mode" "$key" "$severity" "$title" "$description" <<'PY'
import asyncio, sys
from app.core.database import async_session_factory
from app.models import AttackSeverity
from app.services import alerts

mode, key, severity, title, description = sys.argv[1:6]

async def main():
    async with async_session_factory() as db:
        if mode == "resolve":
            count = await alerts.resolve_system_alert(db, key, description)
            await db.commit()
            print(f"resolved {count}")
            return
        created = await alerts.raise_system_alert(
            db, key=key, severity=AttackSeverity(severity), title=title, description=description
        )
        await db.commit()
        print("raised" if created else "already open")

asyncio.run(main())
PY
