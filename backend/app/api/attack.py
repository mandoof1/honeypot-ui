"""ATT&CK views over the stored sessions.

Two read-only routes, both built from the ATT&CK catalog (app/ai/attack_catalog.py)
rather than from whatever names and tactics the stored rows carry:

* ``GET /attack/matrix`` — every tactic in kill-chain order with the
  techniques observed under it and how many sessions showed each. Takes the
  same filters as the session list.
* ``GET /attack/navigator-layer`` — the same counts as an ATT&CK Navigator
  layer file, for opening in MITRE's Navigator.

A technique counts once per session. One the decision model could not
confirm, or one whose id the catalog does not know, is not counted.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.attack_catalog import catalog
from app.ai.mitre_mapper import primary_tactics
from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models import HoneypotSession
from app.services.session_filters import session_filters

router = APIRouter()

#: The layer file format written, and the Navigator release it is for.
LAYER_FORMAT = "4.5"
NAVIGATOR_VERSION = "5.1.0"


async def _technique_counts(db: AsyncSession, filters) -> Tuple[Counter, Dict[str, str], int]:
    """Sessions per (tactic id, technique id), technique names, session total."""
    total_query = select(func.count(HoneypotSession.id))
    rows_query = select(HoneypotSession.mitre_techniques).where(HoneypotSession.mitre_techniques.isnot(None))
    if filters is not None:
        total_query = total_query.where(filters)
        rows_query = rows_query.where(filters)
    total = (await db.execute(total_query)).scalar() or 0

    counts: Counter = Counter()
    names: Dict[str, str] = {}
    for techniques in (await db.execute(rows_query)).scalars():
        seen = set()
        for technique in techniques if isinstance(techniques, list) else []:
            if not isinstance(technique, dict) or technique.get("unconfirmed"):
                continue
            # Stored rows may predate the catalog: resolve again rather than
            # trust the id, name and tactics a row happens to carry.
            resolution = catalog.resolve(str(technique.get("id") or ""))
            if not resolution.verified:
                continue
            tactics = technique.get("tactics")
            if not isinstance(tactics, list) or not set(tactics) <= set(resolution.tactics):
                tactics = primary_tactics(resolution)
            names[resolution.id] = resolution.name
            for tactic_id in tactics:
                seen.add((tactic_id, resolution.id))
        counts.update(seen)
    return counts, names, total


@router.get("/matrix")
async def attack_matrix(
    filters=Depends(session_filters),
    full: bool = Query(False, description="Also list catalog techniques no session showed, with a count of 0."),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Observed techniques by tactic, in kill-chain order, with session counts."""
    counts, names, total = await _technique_counts(db, filters)

    by_tactic: Dict[str, List[Dict]] = {tactic["id"]: [] for tactic in catalog.load().tactics}
    for (tactic_id, technique_id), count in counts.items():
        if tactic_id in by_tactic:
            by_tactic[tactic_id].append({"id": technique_id, "name": names[technique_id], "count": count})
    if full:
        for technique in catalog.live_techniques():
            for tactic_id in technique.get("tactics") or []:
                if (tactic_id, technique["id"]) not in counts and tactic_id in by_tactic:
                    by_tactic[tactic_id].append({"id": technique["id"], "name": technique["name"], "count": 0})

    return {
        "tactics": [
            {
                "id": tactic["id"],
                "name": tactic["name"],
                "techniques": sorted(by_tactic[tactic["id"]], key=lambda t: (-t["count"], t["id"])),
            }
            for tactic in catalog.tactics
        ],
        "sessions": total,
        "attack_version": catalog.version,
        "domain": catalog.domain,
    }


@router.get("/navigator-layer")
async def navigator_layer(
    filters=Depends(session_filters),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("analyst")),
):
    """An ATT&CK Navigator layer scoring each technique by its session count."""
    counts, _, total = await _technique_counts(db, filters)
    shortnames = {tactic["id"]: tactic["shortname"] for tactic in catalog.load().tactics}
    highest = max(counts.values(), default=0)

    layer = {
        "name": "HoneySentinel observed techniques",
        "versions": {
            # Navigator wants the major ATT&CK version only.
            "attack": catalog.version.split(".")[0],
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_FORMAT,
        },
        "domain": catalog.domain,
        "description": (
            f"Techniques observed in {total} honeypot session(s); the score is the number of "
            f"sessions that showed the technique. Generated {datetime.now(timezone.utc).date().isoformat()} "
            f"against ATT&CK {catalog.version}."
        ),
        "sorting": 3,
        "techniques": [
            {
                "techniqueID": technique_id,
                "tactic": shortnames[tactic_id],
                "score": count,
                "comment": f"{count} session(s)",
                "enabled": True,
            }
            for (tactic_id, technique_id), count in sorted(counts.items(), key=lambda item: (item[0][1], item[0][0]))
            if tactic_id in shortnames
        ],
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": max(highest, 1)},
        "legendItems": [],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": False,
        "selectSubtechniquesWithParent": False,
    }
    return Response(
        content=json.dumps(layer, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="honeysentinel_attack_layer.json"'},
    )
