"""The threat level and the measurements of an investigation report.

Everything here is computed from the evidence snapshot the report is written
from, never from the language model's prose, so the same selection always
gets the same level and the same numbers.

The level reuses the console's per-session severity (``verdict.stored_severity``)
rather than defining a second scale: a session the dashboard shows as high is
high in the report too. The report is as severe as its most severe session,
and the 0-100 index places it inside that level's band using six
aggravating factors, each of which is printed with the points it added.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from statistics import mean, median
from typing import Iterable, Optional

from app.ai import verdict as verdicts
from app.ai.rules import STAGE_RANK

LEVELS = verdicts.SEVERITY_LEVELS  # ("low", "medium", "high", "critical")

#: The console's severity ramp (src/index.css, --color-s1..s4), so a level
#: has the same colour on the dashboard and on paper.
SCALE = {
    "low": {
        "name": "LOW",
        "colour": "#19b287",
        "colour_name": "Green",
        "band": (0, 24),
        "meaning": (
            "No harmful step was recorded: connections, banner reads, benign "
            "requests or low-confidence probing."
        ),
        "handling": "No action required. Keep for trend analysis.",
    },
    "medium": {
        "name": "MEDIUM",
        "colour": "#fab219",
        "colour_name": "Yellow",
        "band": (25, 49),
        "meaning": (
            "Reconnaissance: the source mapped services, probed paths or tested "
            "logins, and no compromise attempt was recorded."
        ),
        "handling": "Review in routine triage. Consider blocking sources that return.",
    },
    "high": {
        "name": "HIGH",
        "colour": "#ec835a",
        "colour_name": "Orange",
        "band": (50, 74),
        "meaning": (
            "Attempted compromise: commands or requests that would run, download, "
            "change or exfiltrate something were captured on the decoy."
        ),
        "handling": (
            "Analyst review within one working day. Block the sources and check "
            "the indicators against production systems."
        ),
    },
    "critical": {
        "name": "CRITICAL",
        "colour": "#d5405f",
        "colour_name": "Red",
        "band": (75, 100),
        "meaning": (
            "Attempted compromise with aggravating evidence: a critical offensive "
            "tool, or goals such as credential harvesting, lateral movement or "
            "data exfiltration on top of the attack itself."
        ),
        "handling": (
            "Immediate review. Search production assets for the indicators and "
            "escalate to the incident response lead."
        ),
    },
}

#: Enterprise ATT&CK tactics in kill-chain order, as of the bundled catalog's
#: release (20.1). Used only if the catalog file cannot be read.
_FALLBACK_TACTICS = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Stealth"),
    ("TA0112", "Defense Impairment"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]


def _catalog_tactics():
    """The tactics of the ATT&CK catalog the mapper itself uses.

    Read from the catalog rather than written out here, so a catalog update
    (ATT&CK 18 split Defense Evasion into Stealth and Defense Impairment)
    reaches the report too.
    """
    try:
        from app.ai.attack_catalog import catalog

        catalog.load()
        tactics = [(t["id"], t["name"]) for t in catalog.tactics if t.get("id") and t.get("name")]
        if tactics:
            return tactics, catalog.version or None
    except Exception:  # noqa: BLE001 - the report must render without it
        pass
    return list(_FALLBACK_TACTICS), None


TACTICS, ATTACK_VERSION = _catalog_tactics()
TACTIC_NAMES = dict(TACTICS)

#: Indicator types that point at attacker infrastructure.
_NETWORK_IOC_TYPES = {"url", "ip", "ipv4", "ipv6", "domain", "host", "hostname", "uri"}

#: Below this checker support a model-proposed technique is not counted as
#: observed (the decider's own DECIDER_SUPPORT_THRESHOLD default).
SUPPORT_THRESHOLD = 0.3

#: (key, title, weight). The weights add up to 25, one level's band.
FACTORS = [
    ("breadth", "Breadth of elevated activity", 5),
    ("depth", "ATT&CK kill-chain depth", 6),
    ("access", "Decoy access achieved", 4),
    ("infrastructure", "Attacker infrastructure and payloads", 4),
    ("impact", "High-impact goals or critical tools", 3),
    ("triage", "AI triage compromise estimate", 3),
]


# -- small readers ----------------------------------------------------------


def parse_time(value) -> Optional[datetime]:
    if isinstance(value, datetime):
        moment = value
    elif value:
        try:
            moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def format_time(value, seconds=True) -> str:
    moment = parse_time(value)
    if moment is None:
        return "Not recorded"
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%d %b %Y, %H:%M:%S UTC" if seconds else "%d %b %Y, %H:%M UTC")


def format_span(seconds: Optional[float]) -> str:
    if seconds is None:
        return "Not recorded"
    seconds = max(0, int(round(seconds)))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return f"{days} d {hours} h"
    if hours:
        return f"{hours} h {minutes} min"
    if minutes:
        return f"{minutes} min {secs} s"
    return f"{secs} s"


def format_ms(ms: Optional[float]) -> str:
    if ms is None:
        return "Not recorded"
    if ms < 1000:
        return f"{ms:.0f} ms"
    return format_span(ms / 1000) if ms >= 60000 else f"{ms / 1000:.1f} s"


def _tools(analysis) -> list[str]:
    return [
        str(t.get("name", "")) if isinstance(t, dict) else str(t)
        for t in (analysis.get("detected_tools") or [])
    ]


def _category(analysis) -> Optional[str]:
    category = analysis.get("category")
    return category if category in STAGE_RANK else None


def is_simulated(session) -> bool:
    return str(session.get("session_uuid", "")).startswith("demo-")


def is_controlled(session) -> bool:
    return "controlled-test" in str(session.get("node") or "")


def session_severity(session, analysis) -> tuple[str, float]:
    """The console's severity for one session, and the score it was cut from."""
    signals = session.get("signals") if isinstance(session.get("signals"), dict) else None
    intents = [str(i) for i in (analysis.get("detected_intents") or [])]
    level = verdicts.stored_severity(
        _category(analysis),
        analysis.get("confidence"),
        analysis.get("model_source"),
        _tools(analysis),
        intents,
        signals,
    )
    score = (signals or {}).get("severity_score")
    if not isinstance(score, (int, float)):
        confidence = analysis.get("confidence") if analysis.get("model_source") == "rules" else 0.0
        critical = [t for t in _tools(analysis) if t in verdicts.CRITICAL_TOOLS]
        score = verdicts.severity_score(
            _category(analysis) or "benign", float(confidence or 0.0), intents, critical
        )
    return level, float(score)


def techniques_of(analysis) -> list[dict]:
    """One entry per technique id for a session, with how it was established."""
    found: dict[str, dict] = {}
    enrichment = analysis.get("enrichment") if isinstance(analysis.get("enrichment"), dict) else {}
    items = list((analysis.get("mitre") or {}).get("techniques") or [])
    items += list(enrichment.get("mitre_techniques") or [])
    for item in items:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        source = str(item.get("source") or "")
        rule = source.startswith("rule")
        support = item.get("support")
        unconfirmed = bool(item.get("unconfirmed")) or item.get("confirmed") is False
        if rule or item.get("confirmed") is True:
            state = "rule"
        elif not unconfirmed and isinstance(support, (int, float)) and support >= SUPPORT_THRESHOLD:
            state = "supported"
        else:
            state = "unconfirmed"
        current = found.get(item["id"])
        rank = {"rule": 2, "supported": 1, "unconfirmed": 0}
        if current is None or rank[state] > rank[current["state"]]:
            found[item["id"]] = {
                "id": str(item["id"]),
                "name": str(item.get("name") or ""),
                "tactics": [str(t) for t in (item.get("tactics") or [])],
                "state": state,
                "support": support if isinstance(support, (int, float)) else None,
                "source": source or "not recorded",
                "evidence": item.get("evidence") or item.get("description"),
            }
    return list(found.values())


# -- the threat level -------------------------------------------------------


def threat_assessment(records) -> dict:
    """The report's level, its 0-100 index and the reasons for both."""
    severities = [session_severity(s, a) for s, a in records]
    by_uuid = {
        str(s.get("session_uuid")): severity for (s, _), severity in zip(records, severities)
    }
    total = len(records)
    peak_index = max((LEVELS.index(level) for level, _ in severities), default=0)
    peak_level = LEVELS[peak_index]

    peak_record = None
    if records:
        order = sorted(
            range(total),
            key=lambda i: (LEVELS.index(severities[i][0]), severities[i][1]),
            reverse=True,
        )
        s, a = records[order[0]]
        peak_record = {
            "uuid": s.get("session_uuid"),
            "protocol": str(s.get("protocol") or "unknown").upper(),
            "source": s.get("attacker_ip") or "an unrecorded address",
            "category": a.get("category") or "unknown",
            "reason": a.get("rule_reason"),
            "score": severities[order[0]][1],
            "level": severities[order[0]][0],
        }

    elevated = sum(LEVELS.index(level) >= 1 for level, _ in severities)
    tactics = set()
    for _, a in records:
        for technique in techniques_of(a):
            if technique["state"] != "unconfirmed":
                tactics.update(t for t in technique["tactics"] if t in TACTIC_NAMES)
    accepted = sum(int(a.get("decoy_accepts") or 0) for _, a in records)
    interactive = sum(
        1
        for s, a in records
        if str(s.get("protocol") or "").lower() in {"ssh", "telnet"}
        and int(a.get("command_count") or 0) > 0
    )
    network_iocs = {
        (str(i.get("type")).lower(), str(i.get("value")))
        for _, a in records
        for i in (a.get("iocs") or [])
        if isinstance(i, dict) and str(i.get("type") or "").lower() in _NETWORK_IOC_TYPES
    }
    uploads = sum(len(s.get("uploads") or []) for s, _ in records)
    impact = set()
    for _, a in records:
        impact.update(i for i in (a.get("detected_intents") or []) if i in verdicts._HIGH_IMPACT_INTENTS)
        impact.update(t for t in _tools(a) if t in verdicts.CRITICAL_TOOLS)
    compromise = [
        float(a["triage"]["p_compromise"])
        for _, a in records
        if isinstance(a.get("triage"), dict)
        and isinstance(a["triage"].get("p_compromise"), (int, float))
    ]

    access_fraction = 1.0 if accepted else (0.5 if interactive else 0.0)
    fractions = {
        "breadth": elevated / total if total else 0.0,
        "depth": min(1.0, len(tactics) / 6),
        "access": access_fraction,
        "infrastructure": min(1.0, (len(network_iocs) + uploads) / 4),
        "impact": min(1.0, len(impact) / 2),
        "triage": max(compromise) if compromise else 0.0,
    }
    observed = {
        "breadth": f"{elevated} of {total} session(s) rated medium or above",
        "depth": (
            f"{len(tactics)} tactic(s): "
            + ", ".join(TACTIC_NAMES[t] for t, _ in TACTICS if t in tactics)
            if tactics
            else "No confirmed ATT&CK tactic"
        ),
        "access": (
            f"{accepted} login(s) accepted by the decoy"
            if accepted
            else f"{interactive} interactive shell session(s) with commands"
            if interactive
            else "No decoy login or shell command recorded"
        ),
        "infrastructure": f"{len(network_iocs)} network indicator(s), {uploads} upload record(s)",
        "impact": ", ".join(sorted(i.replace("_", " ") for i in impact)) or "None recorded",
        "triage": (
            f"Highest p(compromise) {max(compromise):.2f} over {len(compromise)} triaged session(s)"
            if compromise
            else "No session was triaged by the decider model"
        ),
    }
    factors = []
    for key, title, weight in FACTORS:
        fraction = max(0.0, min(1.0, fractions[key]))
        factors.append(
            {
                "key": key,
                "title": title,
                "weight": weight,
                "fraction": fraction,
                "points": round(weight * fraction, 1),
                "observed": observed[key],
            }
        )
    bonus = sum(f["points"] for f in factors)
    index = int(min(100, round(25 * peak_index + bonus)))
    low, high = SCALE[peak_level]["band"]
    index = max(low, min(high, index))
    distribution = Counter(level for level, _ in severities)
    return {
        "level": peak_level,
        "level_number": peak_index + 1,
        "index": index,
        "name": SCALE[peak_level]["name"],
        "colour": SCALE[peak_level]["colour"],
        "colour_name": SCALE[peak_level]["colour_name"],
        "band": SCALE[peak_level]["band"],
        "factors": factors,
        "bonus": round(bonus, 1),
        "peak": peak_record,
        "distribution": {level: distribution.get(level, 0) for level in LEVELS},
        "by_uuid": by_uuid,
        "tactics": sorted(tactics),
        "simulated": total > 0 and all(is_simulated(s) for s, _ in records),
        "any_simulated": any(is_simulated(s) for s, _ in records),
        "controlled": sum(is_controlled(s) for s, _ in records),
    }


def group_level(group, assessment) -> str:
    """Severity of an evidence case: its most severe session."""
    levels = [
        assessment["by_uuid"].get(str(s.get("uuid")), ("low", 0.0))[0]
        for s in group["sessions"]
    ]
    return max(levels, key=LEVELS.index) if levels else "low"


def level_reason(assessment) -> str:
    """One sentence on why the report has its level, from recorded values."""
    peak = assessment["peak"]
    if not peak:
        return "No sessions were selected."
    reason = f" ({peak['reason']})" if peak.get("reason") else ""
    return (
        f"The most severe session is {peak['category']} over {peak['protocol']} from "
        f"{peak['source']}{reason}, rated {peak['level']} by the analysis pipeline "
        f"(severity score {peak['score']:.1f})."
    )


# -- measurements -----------------------------------------------------------


def _bucket(span: timedelta) -> tuple[timedelta, str]:
    for size, label in [
        (timedelta(minutes=5), "5-minute"),
        (timedelta(minutes=15), "15-minute"),
        (timedelta(hours=1), "hourly"),
        (timedelta(hours=6), "6-hour"),
        (timedelta(days=1), "daily"),
        (timedelta(days=7), "weekly"),
    ]:
        if span / size <= 48:
            return size, label
    return timedelta(days=30), "30-day"


def timeline(records, assessment) -> dict:
    moments = [
        (parse_time(s.get("started_at")), assessment["by_uuid"].get(str(s.get("session_uuid")), ("low", 0))[0])
        for s, _ in records
    ]
    moments = [(m, level) for m, level in moments if m is not None]
    if not moments:
        return {"buckets": [], "label": None}
    first = min(m for m, _ in moments)
    last = max(m for m, _ in moments)
    size, label = _bucket(max(last - first, timedelta(minutes=1)))
    start = datetime.fromtimestamp(
        (first.timestamp() // size.total_seconds()) * size.total_seconds(), tz=timezone.utc
    )
    count = int((last - start) / size) + 1
    buckets = [{"start": start + i * size, "count": 0, "level": None} for i in range(count)]
    for moment, level in moments:
        bucket = buckets[int((moment - start) / size)]
        bucket["count"] += 1
        if bucket["level"] is None or LEVELS.index(level) > LEVELS.index(bucket["level"]):
            bucket["level"] = level
    return {"buckets": buckets, "label": label, "size": size}


def report_metrics(records, assessment, narrative=None) -> dict:
    """Aggregate counts, rates and distributions over the selected evidence."""
    total = len(records)
    sources = Counter(str(s.get("attacker_ip") or "Not recorded") for s, _ in records)
    starts = [parse_time(s.get("started_at")) for s, _ in records]
    ends = [parse_time(s.get("ended_at")) or parse_time(s.get("started_at")) for s, _ in records]
    starts = [m for m in starts if m]
    ends = [m for m in ends if m]
    first = min(starts) if starts else None
    last = max(ends) if ends else None

    techniques: dict[str, dict] = {}
    for s, a in records:
        for t in techniques_of(a):
            entry = techniques.setdefault(
                t["id"],
                {**t, "sessions": 0, "states": Counter(), "max_support": None},
            )
            entry["sessions"] += 1
            entry["states"][t["state"]] += 1
            if t["support"] is not None:
                entry["max_support"] = max(entry["max_support"] or 0.0, t["support"])
            rank = {"rule": 2, "supported": 1, "unconfirmed": 0}
            if rank[t["state"]] > rank[entry["state"]]:
                entry["state"] = t["state"]
            for tactic in t["tactics"]:
                if tactic not in entry["tactics"]:
                    entry["tactics"].append(tactic)
    tactic_counts = Counter()
    for t in techniques.values():
        if t["state"] != "unconfirmed":
            for tactic in t["tactics"]:
                tactic_counts[tactic] += t["sessions"]

    iocs: dict[tuple, dict] = {}
    for s, a in records:
        for item in a.get("iocs") or []:
            if not isinstance(item, dict):
                continue
            key = (str(item.get("type") or "unknown").lower(), str(item.get("value") or ""))
            entry = iocs.setdefault(
                key,
                {"type": key[0], "value": key[1], "sessions": 0, "first_seen": None, "confidence": item.get("confidence")},
            )
            entry["sessions"] += 1
            seen = parse_time(item.get("first_seen")) or parse_time(s.get("started_at"))
            if seen and (entry["first_seen"] is None or seen < entry["first_seen"]):
                entry["first_seen"] = seen

    usernames = Counter()
    for _, a in records:
        for name, count in (a.get("credential_usernames") or {}).items():
            usernames[str(name)] += int(count or 0)

    per_source = defaultdict(lambda: {"sessions": 0, "level": "low", "categories": Counter(), "country": None, "protocols": set()})
    for s, a in records:
        entry = per_source[str(s.get("attacker_ip") or "Not recorded")]
        entry["sessions"] += 1
        level = assessment["by_uuid"].get(str(s.get("session_uuid")), ("low", 0))[0]
        if LEVELS.index(level) > LEVELS.index(entry["level"]):
            entry["level"] = level
        entry["categories"][a.get("category") or "unknown"] += 1
        entry["protocols"].add(str(s.get("protocol") or "unknown").upper())
        geo = s.get("geo") or {}
        entry["country"] = entry["country"] or geo.get("country_name") or geo.get("country")

    analysis_ms = [float(a["analysis_ms"]) for _, a in records if isinstance(a.get("analysis_ms"), (int, float))]
    enriched = sum(
        bool(isinstance(a.get("enrichment"), dict) and a["enrichment"].get("intent")) for _, a in records
    )
    enrichment_models = Counter(
        str(a["enrichment"].get("model"))
        for _, a in records
        if isinstance(a.get("enrichment"), dict) and a["enrichment"].get("model")
    )
    triaged = [a["triage"] for _, a in records if isinstance(a.get("triage"), dict) and a["triage"].get("model")]
    agreements = [t.get("agrees_with_rules") for t in triaged if isinstance(t.get("agrees_with_rules"), bool)]
    triage_ms = [float(t["ms"]) for t in triaged if isinstance(t.get("ms"), (int, float))]
    operators = Counter(str(t.get("operator")) for t in triaged if t.get("operator"))

    flows = [
        s["signals"]["verdict"]["flow"]
        for s, _ in records
        if isinstance(s.get("signals"), dict)
        and isinstance(s["signals"].get("verdict"), dict)
        and isinstance(s["signals"]["verdict"].get("flow"), dict)
    ]
    anomaly_meta = [
        s["signals"]["anomaly"]
        for s, _ in records
        if isinstance(s.get("signals"), dict) and isinstance(s["signals"].get("anomaly"), dict)
    ]
    anomaly_scores = [float(a["anomaly_score"]) for _, a in records if isinstance(a.get("anomaly_score"), (int, float))]
    clusters = Counter(a.get("cluster_id") for _, a in records if a.get("cluster_id") is not None)
    outliers = sum(bool(a.get("cluster_is_outlier")) for _, a in records)
    rule_confidences = [
        float(a["confidence"]) for _, a in records
        if a.get("model_source") == "rules" and isinstance(a.get("confidence"), (int, float))
    ]
    fingerprints = Counter()
    for s, _ in records:
        prints = s.get("fingerprints") if isinstance(s.get("fingerprints"), dict) else {}
        for key in ("hassh", "ja3", "ja4", "http_header_order"):
            if prints.get(key):
                fingerprints[key] += 1

    scope = (narrative or {}).get("scope") or {}
    groups = scope.get("unique_activity_groups")
    reviewed = scope.get("model_reviewed_groups")

    def rate(part, whole):
        return (part / whole) if whole else None

    return {
        "sessions": total,
        "sources": len(sources),
        "source_counts": sources,
        "per_source": dict(per_source),
        "protocols": Counter(str(s.get("protocol") or "unknown").upper() for s, _ in records),
        "categories": Counter(str(a.get("category") or "unknown") for _, a in records),
        "countries": Counter(
            (s.get("geo") or {}).get("country_name") or (s.get("geo") or {}).get("country") or "Unknown"
            for s, _ in records
        ),
        "sensors": Counter(str(s.get("node") or "Not recorded") for s, _ in records),
        "first": first,
        "last": last,
        "span_seconds": (last - first).total_seconds() if first and last else None,
        "durations": [float(s["duration_seconds"]) for s, _ in records if isinstance(s.get("duration_seconds"), (int, float))],
        "commands": sum(int(a.get("command_count") or 0) for _, a in records),
        "keystrokes": sum(int(a.get("keystroke_count") or 0) for _, a in records),
        "credential_attempts": sum(int(a.get("credentials_total") or 0) for _, a in records),
        "decoy_accepts": sum(int(a.get("decoy_accepts") or 0) for _, a in records),
        "usernames": usernames,
        "uploads": sum(len(s.get("uploads") or []) for s, _ in records),
        "iocs": sorted(iocs.values(), key=lambda i: (-i["sessions"], i["type"], i["value"])),
        "techniques": sorted(techniques.values(), key=lambda t: (-{"rule": 2, "supported": 1, "unconfirmed": 0}[t["state"]], -t["sessions"], t["id"])),
        "tactic_counts": tactic_counts,
        "analysis_ms": {
            "count": len(analysis_ms),
            "mean": mean(analysis_ms) if analysis_ms else None,
            "median": median(analysis_ms) if analysis_ms else None,
            "max": max(analysis_ms) if analysis_ms else None,
        },
        "enriched": enriched,
        "enrichment_models": enrichment_models,
        "triaged": len(triaged),
        "triage_models": Counter(str(t.get("model")) for t in triaged),
        "triage_ms_mean": mean(triage_ms) if triage_ms else None,
        "agreements": sum(1 for x in agreements if x),
        "agreement_total": len(agreements),
        "operators": operators,
        "flow_models": Counter(str(f.get("model_source") or "not recorded") for f in flows),
        "flow_disagreements": sum(bool(f.get("disagrees")) for f in flows),
        "flow_total": len(flows),
        "anomaly_calibrated": any(bool(m.get("calibrated")) for m in anomaly_meta),
        "anomaly_sources": Counter(str(m.get("model_source") or "not recorded") for m in anomaly_meta),
        "anomaly_scores": anomaly_scores,
        "anomalous": sum(bool(a.get("is_anomalous")) for _, a in records),
        "clusters": len(clusters),
        "cluster_outliers": outliers,
        "rule_confidence_mean": mean(rule_confidences) if rule_confidences else None,
        "fingerprints": fingerprints,
        "groups": groups,
        "reviewed_groups": reviewed,
        "rates": {
            "evidence_coverage": rate(reviewed, groups) if reviewed is not None else None,
            "enrichment_coverage": rate(enriched, total),
            "agreement": rate(sum(1 for x in agreements if x), len(agreements)),
            "rule_confidence": mean(rule_confidences) if rule_confidences else None,
        },
        "timeline": timeline(records, assessment),
    }


def analytic_confidence(metrics) -> tuple[str, str]:
    """How far the evidence supports the report's conclusions, with the reason."""
    coverage = metrics["rates"]["evidence_coverage"]
    agreement = metrics["rates"]["agreement"]
    if coverage is None:
        return "Not assessed", "No AI narrative was written for this export."
    reasons = [f"the model reviewed {coverage:.0%} of the distinct activity groups"]
    if agreement is not None:
        reasons.append(f"the triage model agreed with the rule layer on {agreement:.0%} of triaged sessions")
    else:
        reasons.append("no session in the selection was triaged by the decider model")
    if coverage >= 0.8 and (agreement is None or agreement >= 0.8):
        level = "High"
    elif coverage >= 0.5 and (agreement is None or agreement >= 0.5):
        level = "Moderate"
    else:
        level = "Low"
    return level, "; ".join(reasons) + "."


def distinct(values: Iterable) -> list:
    return list(dict.fromkeys(v for v in values if v))
