#!/usr/bin/env bash
#
# Raise a system alert in the dashboard from the host: used by systemd
# OnFailure= hooks (backup, shop reset) so an operational failure shows up
# where someone is looking, not only in the journal.
#
#   system-alert.sh <key> <severity> <title> <description>
#
# Runs inside the backend container (the only place with database access and
# the alert service), so the host needs nothing but docker.

set -euo pipefail
key=${1:?key}; severity=${2:?severity}; title=${3:?title}; description=${4:-}
cd "$(dirname "$0")"
docker compose exec -T backend python - "$key" "$severity" "$title" "$description" <<'PY'
import asyncio, sys
from app.core.database import async_session_factory
from app.models import AttackSeverity
from app.services import alerts

key, severity, title, description = sys.argv[1:5]

async def main():
    async with async_session_factory() as db:
        created = await alerts.raise_system_alert(
            db, key=key, severity=AttackSeverity(severity), title=title, description=description
        )
        await db.commit()
        print("raised" if created else "already open")

asyncio.run(main())
PY
