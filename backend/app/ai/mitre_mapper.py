"""Mapping findings onto MITRE ATT&CK, checked against the catalog.

Two things used to be wrong here. Technique ids were accepted on their shape
alone, so ``T9999`` and ``T1059.999`` were stored; and names and tactics came
from two hand-typed tables that disagreed with ATT&CK for several techniques
(T1059 under Initial Access, T1105 under Exfiltration, T1046 and T1082 under
Reconnaissance) and gave web signatures, brute force and uploads a tactic and
no technique at all.

Now the only thing written by hand is which technique a *finding* evidences
(``RULE_TECHNIQUES``): ids, nothing else. Whether an id exists, what it is
called and which tactics it belongs to come from the catalog
(``attack_catalog``), for rule findings and for model output alike. An id
the catalog does not know is not stored as a technique.
"""

from __future__ import annotations

import logging
from typing import Dict, Iterable, List, Optional, Tuple

from app.ai.attack_catalog import STATUSES, UNVERIFIED, Resolution, catalog

logger = logging.getLogger(__name__)

#: Finding key -> the techniques it evidences, each optionally with the
#: tactic the finding shows when the technique belongs to several (a cron
#: entry written by an intruder is Persistence; ATT&CK also lists T1053.003
#: under Execution and Privilege Escalation). A pinned tactic is only used if
#: the catalog lists it for that technique.
#:
#: Ids are written as commonly known; one that a later ATT&CK release revoked
#: (T1562.001, T1070.002) is followed to its replacement by the catalog, so
#: this table does not need editing when the framework renumbers.
RULE_TECHNIQUES: Dict[str, Tuple[Tuple[str, Optional[str]], ...]] = {
    # Discovery
    "system_info": (("T1082", None),),
    "user_discovery": (("T1033", None),),
    "account_discovery": (("T1087.001", None),),
    "group_discovery": (("T1069.001", None),),
    "network_config": (("T1016", None),),
    "network_connections": (("T1049", None),),
    "process_discovery": (("T1057", None),),
    "service_discovery": (("T1007", None),),
    "file_discovery": (("T1083", None),),
    "suid_search": (("T1083", None),),
    "shell_history_read": (("T1552.003", None),),
    "credential_search": (("T1552.001", None),),
    "windows_system_info": (("T1082", None),),
    "windows_account_discovery": (("T1087.001", None),),
    "windows_group_discovery": (("T1069.001", None),),
    "windows_network_config": (("T1016", None),),
    "port_scan": (("T1046", None),),
    "network_sniff": (("T1040", "TA0007"),),
    # Tools run from the decoy against other targets
    "dir_enum_tool": (("T1595.003", None),),
    "vuln_scan_tool": (("T1595.002", None),),
    "sqlmap": (("T1190", None),),
    "password_attack_tool": (("T1110", None),),
    # Getting tools in and running them
    "download": (("T1105", None),),
    "iot_bot_download": (("T1105", None),),
    "download_execute": (("T1105", None), ("T1059.004", None)),
    "decode": (("T1140", None),),
    "decode_execute": (("T1140", None), ("T1059.004", None)),
    "pipe_to_shell": (("T1059.004", None),),
    "run_dropped_file": (("T1059.004", None),),
    "interpreter_inline": (("T1059", None),),
    "reverse_shell": (("T1059.004", None),),
    "make_executable": (("T1222.002", None),),
    "immutable_flag": (("T1222.002", None),),
    "ftp_site_exec": (("T1059", None),),
    "obfuscation": (("T1027.010", None),),
    # Persistence and privilege
    "cron_persist": (("T1053.003", "TA0003"),),
    "service_persist": (("T1543.002", "TA0003"),),
    "boot_persist": (("T1037.004", "TA0003"),),
    "shell_profile_persist": (("T1546.004", "TA0003"),),
    "ssh_key_persist": (("T1098.004", "TA0003"),),
    "preload_hijack": (("T1574.006", None),),
    "account_create": (("T1136.001", None),),
    "account_modify": (("T1098", "TA0003"),),
    "sudo_exec": (("T1548.003", None),),
    "switch_user": (("T1548.003", None),),
    "setuid": (("T1548.001", None),),
    "privesc_exploit": (("T1068", None),),
    # Credentials
    "credential_dump": (("T1003.008", None),),
    "private_key_read": (("T1552.004", None),),
    "credential_file_read": (("T1552.001", None),),
    "mimikatz": (("T1003.001", None),),
    "password_cracking": (("T1110.002", None),),
    "brute_force": (("T1110", None),),
    "password_guessing": (("T1110.001", None),),
    "password_spraying": (("T1110.003", None),),
    "honeytoken_use": (("T1078", "TA0001"),),
    # Moving on
    "remote_login": (("T1021.004", None),),
    "remote_desktop": (("T1021.001", None),),
    "smb_access": (("T1021.002", None),),
    "remote_exec": (("T1021", None),),
    "tunnel": (("T1572", None),),
    "ssh_forward": (("T1572", None),),
    # Covering tracks and weakening defences
    "history_evasion": (("T1070.003", None),),
    "log_clear": (("T1070.002", None),),
    "timestomp": (("T1070.006", None),),
    "firewall_disable": (("T1562.004", None),),
    "defence_disable": (("T1562.001", None),),
    # Impact
    "service_stop": (("T1489", None),),
    "data_destruction": (("T1485", None),),
    "encrypt_files": (("T1486", None),),
    "denial_of_service": (("T1498", None),),
    "defacement": (("T1491", None),),
    "cryptominer": (("T1496", None),),
    # Collection and exfiltration
    "db_dump": (("T1005", None),),
    "exfil_upload": (("T1048", None),),
    "exfil_netcat": (("T1048.003", None),),
    "exfil_copy": (("T1048", None),),
    # Captured files
    "upload": (("T1105", None),),
    # Web requests: an attack on the decoy application itself
    "web:sql_injection": (("T1190", None),),
    "web:xss": (("T1190", None),),
    "web:command_injection": (("T1190", None),),
    "web:log4shell": (("T1190", None),),
    "web:lfi_rfi": (("T1190", None),),
    "web:path_traversal": (("T1190", None),),
    "web:ssrf": (("T1190", None), ("T1552.005", None)),
    "web:webshell": (("T1505.003", None),),
    # Scanners that name themselves in the User-Agent
    "ua:sqlmap": (("T1190", None),),
    "ua:metasploit": (("T1190", None),),
    "ua:hydra": (("T1110", None),),
    "ua:nikto": (("T1595.002", None),),
    "ua:nuclei": (("T1595.002", None),),
    "ua:wpscan": (("T1595.002", None),),
    "ua:acunetix": (("T1595.002", None),),
    "ua:nessus": (("T1595.002", None),),
    "ua:openvas": (("T1595.002", None),),
    "ua:gobuster": (("T1595.003", None),),
    "ua:dirbuster": (("T1595.003", None),),
    "ua:ffuf": (("T1595.003", None),),
    "ua:wfuzz": (("T1595.003", None),),
    "ua:masscan": (("T1595.001", None),),
    "ua:zgrab": (("T1595", None),),
    "ua:nmap": (("T1595", None),),
}

#: Tactic shown for a technique that belongs to several, when the finding did
#: not pin one: the reading most sessions on a decoy support. Only ever one
#: of the technique's own catalog tactics; anything else is ignored.
PREFERRED_TACTIC = {
    "T1053": "TA0003",
    "T1078": "TA0001",
    "T1098": "TA0003",
    "T1543": "TA0003",
    "T1546": "TA0003",
    "T1037": "TA0003",
    "T1133": "TA0001",
}

TACTIC_COLORS = {
    "TA0043": "#8b5cf6",
    "TA0042": "#a855f7",
    "TA0001": "#ef4444",
    "TA0002": "#f97316",
    "TA0003": "#6366f1",
    "TA0004": "#10b981",
    "TA0005": "#84cc16",
    "TA0112": "#65a30d",
    "TA0006": "#f59e0b",
    "TA0007": "#06b6d4",
    "TA0008": "#3b82f6",
    "TA0009": "#0ea5e9",
    "TA0011": "#14b8a6",
    "TA0010": "#ec4899",
    "TA0040": "#dc2626",
}
_DEFAULT_COLOR = "#6b7280"

#: Confidence recorded for a technique a rule finding evidences. A fixed
#: heuristic value, deliberately below 1: the rule read text, it did not
#: observe an effect.
RULE_CONFIDENCE = 0.8


def primary_tactics(resolution: Resolution, pinned: Optional[str] = None) -> List[str]:
    """The tactic a verified technique is filed under.

    A technique with one tactic has no choice. One with several takes the
    pinned tactic if the catalog lists it, then the preferred one for its
    parent, then the first in kill-chain order.
    """
    tactics = resolution.tactics
    if len(tactics) <= 1:
        return list(tactics)
    if pinned in tactics:
        return [pinned]
    preferred = PREFERRED_TACTIC.get((resolution.id or "").split(".")[0])
    if preferred in tactics:
        return [preferred]
    return tactics[:1]


def validate_technique(
    technique_id: str,
    name: str = "",
    source: str = "",
    pinned_tactic: Optional[str] = None,
) -> Tuple[Optional[Dict], Resolution]:
    """Check one claimed technique. Returns (entry to store or None, resolution).

    The entry's name and tactics are the catalog's. The claimed name is only
    kept, beside it, when it disagrees — so an analyst can see that a model
    filed "SQL injection" under an id that means something else.
    """
    resolution = catalog.resolve(technique_id, name)
    if not resolution.verified:
        return None, resolution
    entry: Dict = {
        "id": resolution.id,
        "name": resolution.name,
        "tactics": primary_tactics(resolution, pinned_tactic),
    }
    if source:
        entry["source"] = source
    if resolution.claimed_id != resolution.id:
        entry["claimed_id"] = resolution.claimed_id
    if resolution.name_mismatch:
        entry["claimed_name"] = str(name)[:120]
    return entry, resolution


def validate_techniques(techniques: Iterable[Dict], source: str = "") -> Dict:
    """Split claimed techniques into verified entries and the rest.

    Returns ``{"verified": [...], "unverified": [...], "counts": {...}}``.
    Unverified ones keep the id and name as claimed and are never counted.
    """
    verified: List[Dict] = []
    unverified: List[Dict] = []
    counts = {status: 0 for status in STATUSES}
    seen = set()
    for technique in techniques or []:
        if not isinstance(technique, dict):
            continue
        claimed_id = str(technique.get("id") or "")
        claimed_name = str(technique.get("name") or "")
        entry, resolution = validate_technique(
            claimed_id, claimed_name, source or str(technique.get("source") or "")
        )
        counts[resolution.status] += 1
        if entry is None:
            unverified.append({
                "id": resolution.claimed_id[:16],
                "name": claimed_name[:120],
                "reason": resolution.status if resolution.status != UNVERIFIED else "not in the ATT&CK catalog",
            })
            continue
        if entry["id"] in seen:
            continue
        seen.add(entry["id"])
        # Fields the pipeline attached to the claim travel with it, and so
        # does what an earlier validation recorded about the original claim.
        for key in ("confidence", "support", "unconfirmed", "claimed_id", "claimed_name"):
            if technique.get(key) is not None:
                entry.setdefault(key, technique[key])
        verified.append(entry)
    return {"verified": verified, "unverified": unverified, "counts": counts}


def tactics_of(techniques: Iterable[Dict]) -> List[str]:
    """Tactic ids covered by stored technique entries, in kill-chain order.

    A technique the decision model could not confirm is listed on the
    session but does not add a tactic on its own say-so.
    """
    found = []
    for technique in techniques or []:
        if not isinstance(technique, dict) or technique.get("unconfirmed"):
            continue
        tactics = technique.get("tactics")
        if not isinstance(tactics, list):
            # A row stored before entries carried their tactics.
            resolution = catalog.resolve(str(technique.get("id") or ""))
            tactics = primary_tactics(resolution) if resolution.verified else []
        found.extend(str(t) for t in tactics)
    return catalog.sort_tactics(found)


class MitreAttckMapper:
    def tactic_for_technique(self, technique_id: str) -> Optional[str]:
        """The tactic a technique is filed under, from the catalog."""
        resolution = catalog.resolve(technique_id)
        if not resolution.verified:
            return None
        tactics = primary_tactics(resolution)
        return tactics[0] if tactics else None

    def technique_name(self, technique_id: str) -> Optional[str]:
        """The catalog's name for an id. None for an id it does not know:
        an unknown sub-technique no longer borrows its parent's name."""
        resolution = catalog.resolve(technique_id)
        return resolution.name if resolution.verified else None

    def map_evidence(self, evidence: Iterable[Dict]) -> Dict:
        """ATT&CK techniques and tactics for a session's findings."""
        techniques: List[Dict] = []
        by_id: Dict[str, Dict] = {}
        matched: List[str] = []

        for item in evidence or []:
            key = str(item.get("key") or "")
            for technique_id, pinned in RULE_TECHNIQUES.get(key, ()):
                entry, _ = validate_technique(technique_id, source=f"rule:{key}", pinned_tactic=pinned)
                if entry is None:
                    # A rule that names an id the catalog lacks is a bug in
                    # the table above; say so rather than store it.
                    logger.warning("Rule %s maps to %s, which the ATT&CK catalog does not have", key, technique_id)
                    continue
                if key not in matched:
                    matched.append(key)
                existing = by_id.get(entry["id"])
                if existing is None:
                    entry["confidence"] = RULE_CONFIDENCE
                    by_id[entry["id"]] = entry
                    techniques.append(entry)
                    continue
                # One entry per technique, every finding that showed it.
                sources = existing["source"].split(", ")
                if entry["source"] not in sources:
                    existing["source"] = ", ".join(sources + [entry["source"]])
                existing["tactics"] = catalog.sort_tactics(existing["tactics"] + entry["tactics"])

        tactic_ids = tactics_of(techniques)
        return {
            "tactics": [
                {"id": t, "name": catalog.tactic_name(t), "color": TACTIC_COLORS.get(t, _DEFAULT_COLOR)}
                for t in tactic_ids
            ],
            "tactic_ids": tactic_ids,
            "techniques": techniques,
            "matched_tools": matched,
            "coverage_score": round(len(tactic_ids) / max(1, len(catalog.load().tactics)), 3),
        }

    def map_analysis(self, nlp_results: Dict, ai_results: Dict, session_data: Dict) -> Dict:
        """ATT&CK mapping for one session's rule findings.

        Kept for callers that hold the three analysis inputs; the findings
        are the rule layer's own evidence plus what the session itself shows
        (logins, uploads, events).
        """
        from app.ai.verdict import collect_evidence

        return self.map_evidence(collect_evidence(nlp_results, session_data))

    def get_full_framework(self) -> Dict:
        """Every tactic with the techniques the rule layer can evidence."""
        framework: Dict[str, Dict] = {}
        for tactic in catalog.load().tactics:
            framework[tactic["id"]] = {
                "tactic": {"id": tactic["id"], "name": tactic["name"]},
                "color": TACTIC_COLORS.get(tactic["id"], _DEFAULT_COLOR),
                "techniques": [],
            }
        seen = set()
        for mappings in RULE_TECHNIQUES.values():
            for technique_id, pinned in mappings:
                entry, _ = validate_technique(technique_id, pinned_tactic=pinned)
                if entry is None:
                    continue
                for tactic_id in entry["tactics"]:
                    if (tactic_id, entry["id"]) not in seen:
                        seen.add((tactic_id, entry["id"]))
                        framework[tactic_id]["techniques"].append({"id": entry["id"], "name": entry["name"]})
        return framework


def merge_duplicate_techniques(techniques: List[Dict]) -> List[Dict]:
    """One entry per technique ID.

    A tool and an intent can both point at the same technique (a crontab
    write is both the "persistence" tool and the persistence intent), which
    listed T1053 twice on the session and in its alert. Keep the first
    entry's place and name, the highest confidence, and every source.
    """
    merged: Dict[str, Dict] = {}
    for tech in techniques:
        tid = tech.get("id")
        if tid not in merged:
            merged[tid] = dict(tech)
            continue
        entry = merged[tid]
        entry["confidence"] = max(entry.get("confidence") or 0, tech.get("confidence") or 0)
        sources = [s for s in str(entry.get("source") or "").split(", ") if s]
        new = tech.get("source")
        if new and new not in sources:
            sources.append(new)
        entry["source"] = ", ".join(sources)
    return list(merged.values())


mitre_mapper = MitreAttckMapper()
