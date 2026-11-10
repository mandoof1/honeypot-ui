"""The ATT&CK catalog: which technique ids exist, their names and tactics.

Every technique the system stores — from the rule map, the language model or
an import — is checked against this before it is counted. The data is the
compact file ``data/attack_catalog.json``, built from MITRE's official STIX
bundle by ``app.tools.build_attack_catalog``; nothing here is typed by hand,
because the hand-typed tables this replaces had drifted from ATT&CK (and the
framework itself moves: v20 renamed Defense Evasion and revoked T1562).

Resolution rules, in order:

1. a live id is valid, and its name and tactics come from the catalog;
2. a revoked id is followed to its replacement;
3. an unknown id whose supplied *name* exactly matches one live technique
   becomes that technique (a model that knows the technique but garbles the
   number, such as ``T1190.001`` named "Exploit Public-Facing Application");
4. anything else is unverified. An unverified technique is kept for the
   analyst to see and is never counted.

An unknown sub-technique does not fall back to its parent: ``T1059.999`` is
not evidence of T1059, it is evidence that the source made an id up.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

CATALOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "attack_catalog.json")

_ID_SHAPE = re.compile(r"T\d{4}(?:\.\d{3})?")

#: A revocation can point at a technique that was itself revoked later.
_MAX_REVOCATION_HOPS = 5

VALID = "valid"
REVOKED_FOLLOWED = "revoked_followed"
NAME_MATCHED = "name_matched"
DEPRECATED = "deprecated"
UNVERIFIED = "unverified"

#: Every status, in the order reports list them.
STATUSES = (VALID, REVOKED_FOLLOWED, NAME_MATCHED, DEPRECATED, UNVERIFIED)


@dataclass
class Resolution:
    """What one claimed technique turned out to be."""

    status: str
    #: The id as it was claimed, upper-cased.
    claimed_id: str
    #: The catalog id to store, or None when the claim could not be verified.
    id: Optional[str] = None
    name: str = ""
    tactics: List[str] = field(default_factory=list)
    #: Set when the claimed name differs from the catalog's for a valid id.
    name_mismatch: bool = False

    @property
    def verified(self) -> bool:
        return self.id is not None and self.status in (VALID, REVOKED_FOLLOWED, NAME_MATCHED)


def _normalise_name(name: str) -> str:
    return " ".join(str(name or "").lower().split())


class AttackCatalog:
    def __init__(self, path: str = CATALOG_PATH) -> None:
        self._path = path
        self._loaded = False
        self.version = ""
        self.domain = ""
        self.bundle_sha256 = ""
        self.tactics: List[Dict] = []
        self._tactic_by_id: Dict[str, Dict] = {}
        self._tactic_order: Dict[str, int] = {}
        self._techniques: Dict[str, Dict] = {}
        self._by_name: Dict[str, List[str]] = {}

    def load(self) -> "AttackCatalog":
        if self._loaded:
            return self
        with open(self._path, encoding="utf-8") as handle:
            data = json.load(handle)
        self.version = str(data.get("attack_version") or "")
        self.domain = str(data.get("domain") or "enterprise-attack")
        self.bundle_sha256 = str(data.get("bundle_sha256") or "")
        self.tactics = list(data.get("tactics") or [])
        self._tactic_by_id = {t["id"]: t for t in self.tactics}
        self._tactic_order = {t["id"]: index for index, t in enumerate(self.tactics)}
        self._techniques = {t["id"]: t for t in data.get("techniques") or []}

        # Names are matched only against live techniques. A sub-technique is
        # also findable as "Parent: Sub", the form models tend to write.
        by_name: Dict[str, List[str]] = {}
        for technique in self._techniques.values():
            if technique.get("revoked") or technique.get("deprecated"):
                continue
            by_name.setdefault(_normalise_name(technique["name"]), []).append(technique["id"])
            parent = self._techniques.get(technique.get("parent") or "")
            if parent is not None:
                composite = _normalise_name(f"{parent['name']}: {technique['name']}")
                by_name.setdefault(composite, []).append(technique["id"])
        self._by_name = by_name
        self._loaded = True
        return self

    # -- lookups ------------------------------------------------------------

    def __len__(self) -> int:
        self.load()
        return len(self._techniques)

    def get(self, technique_id: str) -> Optional[Dict]:
        """The raw catalog entry for an id, live or not."""
        self.load()
        return self._techniques.get(str(technique_id or "").strip().upper())

    def is_live(self, technique_id: str) -> bool:
        entry = self.get(technique_id)
        return entry is not None and not entry.get("revoked") and not entry.get("deprecated")

    def tactic(self, tactic_id: str) -> Optional[Dict]:
        self.load()
        return self._tactic_by_id.get(str(tactic_id or "").strip().upper())

    def tactic_name(self, tactic_id: str) -> str:
        tactic = self.tactic(tactic_id)
        return tactic["name"] if tactic else ""

    def sort_tactics(self, tactic_ids: Iterable[str]) -> List[str]:
        """Known tactic ids, de-duplicated, in kill-chain order."""
        self.load()
        known = {t for t in tactic_ids if t in self._tactic_order}
        return sorted(known, key=lambda tactic_id: self._tactic_order[tactic_id])

    def live_techniques(self) -> List[Dict]:
        self.load()
        return [
            t for t in self._techniques.values()
            if not t.get("revoked") and not t.get("deprecated")
        ]

    # -- resolution ---------------------------------------------------------

    def resolve(self, technique_id: str, name: str = "") -> Resolution:
        """Check one claimed technique against the catalog."""
        self.load()
        claimed = str(technique_id or "").strip().upper()
        entry = self._techniques.get(claimed) if _ID_SHAPE.fullmatch(claimed) else None

        if entry is not None:
            hops = 0
            followed = False
            while entry.get("revoked") and entry.get("replaced_by") and hops < _MAX_REVOCATION_HOPS:
                replacement = self._techniques.get(entry["replaced_by"])
                if replacement is None:
                    break
                entry, followed, hops = replacement, True, hops + 1
            if entry.get("revoked"):
                # Withdrawn with nothing put in its place.
                return Resolution(UNVERIFIED, claimed, name=str(name or entry["name"]))
            if entry.get("deprecated"):
                return Resolution(DEPRECATED, claimed, name=entry["name"])
            claimed_name = _normalise_name(name)
            mismatch = bool(
                claimed_name
                and not followed
                and claimed_name != _normalise_name(entry["name"])
                and claimed not in self._by_name.get(claimed_name, [])
            )
            return Resolution(
                REVOKED_FOLLOWED if followed else VALID,
                claimed,
                id=entry["id"],
                name=entry["name"],
                tactics=list(entry.get("tactics") or []),
                name_mismatch=mismatch,
            )

        matches = self._by_name.get(_normalise_name(name), []) if name else []
        if len(matches) == 1:
            entry = self._techniques[matches[0]]
            return Resolution(
                NAME_MATCHED,
                claimed,
                id=entry["id"],
                name=entry["name"],
                tactics=list(entry.get("tactics") or []),
            )
        return Resolution(UNVERIFIED, claimed, name=str(name or ""))

    def describe(self) -> Dict:
        """Provenance, for tool output and the API."""
        self.load()
        return {
            "domain": self.domain,
            "attack_version": self.version,
            "bundle_sha256": self.bundle_sha256,
            "tactics": len(self.tactics),
            "techniques": len(self._techniques),
        }


catalog = AttackCatalog()
