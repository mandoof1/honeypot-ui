"""Build the compact ATT&CK catalog from the official STIX bundle.

Technique ids used to be checked by shape alone, so ``T9999`` and
``T1059.999`` passed, and names and tactics came from two hand-typed tables
that covered 48 techniques and disagreed with ATT&CK on several of them. The
catalog this writes is the single source for all three: whether an id exists,
what it is called, and which tactics it belongs to.

The bundle is about 55 MB and is not committed. Download it somewhere outside
the repository and point this at the file:

    curl -LO https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
    python -m app.tools.build_attack_catalog --bundle enterprise-attack.json

It writes ``app/ai/data/attack_catalog.json`` (about 100 KB): every technique
and sub-technique with its name, its tactic ids in kill-chain order, its
parent, and whether it is deprecated or revoked and what replaced it. The
ATT&CK version and the bundle's SHA-256 are recorded so a reader can tell
exactly which release the system validates against.

The output is a pure function of the bundle: no timestamp, sorted ids, one
technique per line, so a rebuild from the same bundle is byte-identical and a
rebuild from a newer one diffs cleanly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Optional

DEFAULT_OUTPUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ai", "data", "attack_catalog.json",
)
BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

_TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")
_TACTIC_ID = re.compile(r"TA\d{4}")


def _attack_id(obj: dict, pattern: re.Pattern) -> Optional[str]:
    """The object's ATT&CK id, from its mitre-attack external reference."""
    for reference in obj.get("external_references") or []:
        if reference.get("source_name") != "mitre-attack":
            continue
        external_id = str(reference.get("external_id") or "")
        if pattern.fullmatch(external_id):
            return external_id
    return None


def build_catalog(bundle: dict, bundle_sha256: str) -> dict:
    """The compact catalog for one parsed STIX bundle."""
    objects = bundle.get("objects") or []

    collection = next((o for o in objects if o.get("type") == "x-mitre-collection"), {})
    matrix = next((o for o in objects if o.get("type") == "x-mitre-matrix"), None)
    if matrix is None:
        raise ValueError("the bundle has no x-mitre-matrix object; is this an ATT&CK bundle?")

    # Tactics in the order the matrix lists them, which is the kill-chain
    # order every ATT&CK view uses.
    tactic_objects = {o["id"]: o for o in objects if o.get("type") == "x-mitre-tactic"}
    tactics = []
    shortname_to_id = {}
    for reference in matrix.get("tactic_refs") or []:
        tactic = tactic_objects.get(reference)
        tactic_id = _attack_id(tactic or {}, _TACTIC_ID)
        if tactic is None or tactic_id is None:
            continue
        shortname = tactic.get("x_mitre_shortname") or ""
        tactics.append({"id": tactic_id, "name": tactic.get("name") or "", "shortname": shortname})
        shortname_to_id[shortname] = tactic_id
    tactic_order = {t["id"]: index for index, t in enumerate(tactics)}

    patterns = [o for o in objects if o.get("type") == "attack-pattern"]
    stix_to_attack = {}
    for pattern in patterns:
        technique_id = _attack_id(pattern, _TECHNIQUE_ID)
        if technique_id:
            stix_to_attack[pattern["id"]] = technique_id

    replaced_by = {}
    for relationship in objects:
        if relationship.get("type") != "relationship":
            continue
        if relationship.get("relationship_type") != "revoked-by":
            continue
        source = stix_to_attack.get(relationship.get("source_ref"))
        target = stix_to_attack.get(relationship.get("target_ref"))
        if source and target and source != target:
            replaced_by[source] = target

    techniques = {}
    for pattern in patterns:
        technique_id = stix_to_attack.get(pattern["id"])
        if technique_id is None:
            continue
        revoked = bool(pattern.get("revoked"))
        deprecated = bool(pattern.get("x_mitre_deprecated"))
        existing = techniques.get(technique_id)
        # An id can appear twice when an object was revoked and re-issued;
        # the live one is the definition.
        if existing is not None and not (existing.get("revoked") or existing.get("deprecated")):
            continue

        phases = [
            phase.get("phase_name")
            for phase in pattern.get("kill_chain_phases") or []
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        tactic_ids = sorted(
            {shortname_to_id[p] for p in phases if p in shortname_to_id},
            key=lambda tactic_id: tactic_order[tactic_id],
        )
        entry = {"id": technique_id, "name": pattern.get("name") or "", "tactics": tactic_ids}
        if "." in technique_id:
            entry["parent"] = technique_id.split(".")[0]
        if deprecated:
            entry["deprecated"] = True
        if revoked:
            entry["revoked"] = True
            if technique_id in replaced_by:
                entry["replaced_by"] = replaced_by[technique_id]
        techniques[technique_id] = entry

    return {
        "domain": "enterprise-attack",
        "attack_version": str(collection.get("x_mitre_version") or ""),
        "attack_spec_version": str(collection.get("x_mitre_attack_spec_version") or ""),
        "bundle_modified": str(collection.get("modified") or ""),
        "bundle_sha256": bundle_sha256,
        "source": BUNDLE_URL,
        "tactics": tactics,
        "techniques": [techniques[key] for key in sorted(techniques)],
    }


def render(catalog: dict) -> str:
    """Serialise with one technique per line, so releases diff readably."""
    head = {key: value for key, value in catalog.items() if key not in ("tactics", "techniques")}
    lines = ["{"]
    for key, value in head.items():
        lines.append(f"  {json.dumps(key)}: {json.dumps(value)},")
    lines.append('  "tactics": [')
    lines.append(",\n".join("    " + json.dumps(t, sort_keys=False) for t in catalog["tactics"]))
    lines.append("  ],")
    lines.append('  "techniques": [')
    lines.append(",\n".join("    " + json.dumps(t, sort_keys=False) for t in catalog["techniques"]))
    lines.append("  ]")
    lines.append("}")
    return "\n".join(lines) + "\n"


def sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bundle", required=True, help="path to enterprise-attack.json")
    parser.add_argument("--out", default=DEFAULT_OUTPUT, help="where to write the catalog")
    args = parser.parse_args(argv)

    digest = sha256_of(args.bundle)
    with open(args.bundle, encoding="utf-8") as handle:
        bundle = json.load(handle)
    catalog = build_catalog(bundle, digest)
    if not catalog["tactics"] or not catalog["techniques"]:
        print("The bundle produced an empty catalog; nothing written.", file=sys.stderr)
        return 1

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(render(catalog))

    live = [t for t in catalog["techniques"] if not t.get("revoked") and not t.get("deprecated")]
    print(
        f"ATT&CK {catalog['attack_version']} ({catalog['domain']}): "
        f"{len(catalog['tactics'])} tactics, {len(catalog['techniques'])} technique ids "
        f"({len(live)} live, "
        f"{sum(1 for t in catalog['techniques'] if t.get('revoked'))} revoked, "
        f"{sum(1 for t in catalog['techniques'] if t.get('deprecated'))} deprecated)"
    )
    print(f"bundle sha256 {digest}")
    print(f"catalog -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
