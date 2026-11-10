"""From findings to a verdict: category, confidence, severity.

One place decides, for the ingest pipeline, the reanalysis tool and the
evaluation tools alike:

* which evidence a session carries (what the rule layer found in its
  commands, plus what the session itself shows: logins, uploads, the decoy's
  own flags);
* the category that evidence supports, and how sure the rules are of it;
* how the flow classifier's opinion relates to that (it does not decide);
* the severity, from the evidence that set the category.

No database and no model objects, so it can be run on a file of sessions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.ai.config import get_analysis_settings
from app.ai.rules import BENIGN, EXFIL, EXPLOIT, RECON, STAGE_RANK

#: Tool categories and intents as stages, for analysis results that carry
#: labels but no evidence list (older stored results, hand-built inputs).
_RECON_SIGNALS = {
    "scanner", "directory_enum", "vulnerability_scanner", "reconnaissance", "path_traversal",
}
_EXPLOIT_SIGNALS = {
    "sql_injection", "xss", "command_injection", "log4shell", "lfi_rfi",
    "webshell", "ssrf", "exploitation_framework", "reverse_shell", "c2_framework",
    "credential_theft", "password_cracker", "privilege_modification",
    "persistence", "lateral_movement", "web_proxy", "cryptomining", "iot_botnet",
}
_EXFIL_SIGNALS = {"exfiltration"}
_EXPLOIT_INTENTS = {
    "credential_harvesting", "privilege_escalation", "lateral_movement",
    "persistence", "ransomware", "botnet", "defacement", "denial_of_service",
    "web_exploitation", "cryptomining",
}

#: Offensive frameworks whose use raises the severity on its own. The rule
#: layer marks the same set on its findings (``Finding.critical``); this copy
#: serves rows stored before sessions carried their evidence.
CRITICAL_TOOLS = frozenset({"metasploit", "mimikatz", "cobalt_strike", "empire"})

#: Intents that describe a goal beyond the category itself.
_HIGH_IMPACT_INTENTS = ("credential_harvesting", "lateral_movement", "data_exfiltration")

#: Confidence of a rule verdict. Deliberately not 1.0: strong heuristics over
#: recorded text, not proof. Higher when independent findings agree.
CONFIDENCE_SINGLE = 0.75
CONFIDENCE_CORROBORATED = 0.9

SEVERITY_LEVELS = ("low", "medium", "high", "critical")


def _item(key: str, stage: str, origin: str, label: str) -> Dict:
    return {"key": key, "stage": stage, "origin": origin, "label": label, "line": -1}


def session_evidence(session_data: Dict) -> List[Dict]:
    """What the session shows apart from its commands."""
    evidence: List[Dict] = []
    session_data = session_data or {}

    brute = brute_force_key(session_data)
    if brute is not None:
        failed = int(session_data.get("failed_logins") or 0)
        evidence.append(_item(brute, EXPLOIT, "logins", f"{failed} failed logins (brute force)"))

    upload_count = len(session_data.get("uploads") or [])
    if upload_count:
        evidence.append(_item("upload", EXPLOIT, "uploads", f"{upload_count} file upload(s)"))

    probe_count = sum(
        1
        for packet in (session_data.get("packets") or [])
        if isinstance(packet, dict) and packet.get("type") == "attack_detected"
    )
    if probe_count:
        # The decoy flagged a probe whose kind isn't forwarded in detail; a
        # recon floor is the honest minimum (the rules catch the specific ones).
        evidence.append(_item("decoy_probe", RECON, "probe", f"{probe_count} flagged attack probe(s)"))

    events = [e for e in (session_data.get("events") or []) if isinstance(e, dict)]
    diversion = next((e for e in events if e.get("event_type") == "http_diversion"), None)
    if diversion:
        # The client gave itself away earlier, maybe on another connection,
        # so this session can look like plain browsing on its own.
        reason = str(diversion.get("reason") or "earlier attack")[:120]
        evidence.append(_item(
            "diversion", RECON, "event:http_diversion",
            f"diverted to the decoy application ({reason})",
        ))
    forwards = sum(1 for e in events if e.get("event_type") == "direct_tcpip")
    if forwards:
        # An SSH client asking the host to open connections for it is using
        # the host as a relay.
        evidence.append(_item(
            "ssh_forward", EXPLOIT, "event:direct_tcpip",
            f"{forwards} forwarded connection request(s)",
        ))
    if any(e.get("event_type") == "honeytoken_used" for e in events):
        evidence.append(_item(
            "honeytoken_use", EXPLOIT, "event:honeytoken_used", "used a planted honeytoken",
        ))
    return evidence


def brute_force_key(session_data: Dict) -> Optional[str]:
    """Which brute-force finding the logins support, or None.

    A count of failures alone used to be enough at three. It now takes
    BRUTE_FORCE_MIN_FAILED_LOGINS, and when the attempts themselves were
    recorded they must differ: a person retyping one password is not a
    dictionary attack.
    """
    failed = int((session_data or {}).get("failed_logins") or 0)
    if failed < get_analysis_settings().BRUTE_FORCE_MIN_FAILED_LOGINS:
        return None
    attempts = [
        (str(c.get("username") or ""), str(c.get("password") or ""))
        for c in (session_data.get("credentials") or [])
        if isinstance(c, dict) and not c.get("success")
    ]
    if not attempts:
        return "brute_force"
    if len(set(attempts)) < 3:
        return None
    usernames = {u for u, _ in attempts}
    passwords = {p for _, p in attempts}
    if len(usernames) == 1 and len(passwords) >= 3:
        return "password_guessing"
    if len(passwords) == 1 and len(usernames) >= 3:
        return "password_spraying"
    return "brute_force"


def _label(key: str) -> str:
    if key.startswith("web:"):
        return key[4:].replace("_", " ") + " signature"
    if key.startswith("ua:"):
        return key[3:] + " user agent"
    return key.replace("_", " ")


def _labelled_evidence(nlp_result: Dict) -> List[Dict]:
    """The rule layer's findings, in the shape used here.

    A finding's origin is the finding itself: the same thing seen in three
    commands is one piece of evidence, and two different findings from one
    command are two.
    """
    items = (nlp_result or {}).get("evidence")
    if isinstance(items, list):
        out = []
        for item in items:
            if not isinstance(item, dict) or item.get("stage") not in STAGE_RANK:
                continue
            key = str(item.get("key") or "")
            out.append({
                "key": key, "stage": item["stage"], "origin": f"rule:{key}",
                "label": _label(key), "line": int(item.get("line", -1)),
            })
        if (nlp_result or {}).get("is_obfuscated"):
            out.append(_item("obfuscation", BENIGN, "rule:obfuscation", "obfuscated commands"))
        return out

    # Labels only: fold them onto stages the way the pipeline always has.
    out = []
    categories = set((nlp_result or {}).get("categories") or [])
    intents = set((nlp_result or {}).get("detected_intents") or [])
    for name in sorted(categories):
        if name in _EXFIL_SIGNALS:
            out.append(_item(f"category:{name}", EXFIL, f"category:{name}", "data-exfiltration behaviour"))
        elif name in _EXPLOIT_SIGNALS:
            out.append(_item(f"category:{name}", EXPLOIT, f"category:{name}", name.replace("_", " ")))
        elif name in _RECON_SIGNALS:
            out.append(_item(f"category:{name}", RECON, f"category:{name}", name.replace("_", " ")))
    for name in sorted(intents):
        if name == "data_exfiltration":
            out.append(_item(f"intent:{name}", EXFIL, f"intent:{name}", "data-exfiltration behaviour"))
        elif name in _EXPLOIT_INTENTS:
            out.append(_item(f"intent:{name}", EXPLOIT, f"intent:{name}", name.replace("_", " ")))
        elif name == "reconnaissance":
            out.append(_item(f"intent:{name}", RECON, f"intent:{name}", "reconnaissance"))
    return out


def collect_evidence(nlp_result: Dict, session_data: Dict) -> List[Dict]:
    """All of a session's evidence: the rule layer's and the session's own."""
    return _labelled_evidence(nlp_result) + session_evidence(session_data)


@dataclass
class RuleVerdict:
    category: str = BENIGN
    confidence: float = 0.0
    reason: str = ""
    evidence: List[Dict] = field(default_factory=list)
    #: Distinct findings that support the category.
    supporting: List[str] = field(default_factory=list)


def rule_verdict(nlp_result: Dict, session_data: Dict) -> RuleVerdict:
    """The category the evidence supports, how sure, and why.

    The category is the furthest stage any finding reaches. Confidence rises
    only when *different* findings reach it: ``sudo -l`` used to score 0.9
    because two rules fired on the same command.
    """
    evidence = collect_evidence(nlp_result, session_data)
    top = max((STAGE_RANK[item["stage"]] for item in evidence), default=0)
    if top == 0:
        return RuleVerdict(evidence=evidence)

    category = next(stage for stage, rank in STAGE_RANK.items() if rank == top)
    supporting: List[str] = []
    for item in evidence:
        if item["stage"] == category and item["origin"] not in supporting:
            supporting.append(item["origin"])
    confidence = CONFIDENCE_CORROBORATED if len(supporting) > 1 else CONFIDENCE_SINGLE

    # The most serious findings first; labels only, never the command text
    # (the reason is stored unencrypted beside the encrypted transcript).
    labels: List[str] = []
    for item in sorted(evidence, key=lambda e: -STAGE_RANK[e["stage"]]):
        if STAGE_RANK[item["stage"]] > 0 and item["label"] not in labels:
            labels.append(item["label"])
    return RuleVerdict(
        category=category,
        confidence=confidence,
        reason="; ".join(labels[:6]),
        evidence=evidence,
        supporting=[item["key"] for item in evidence if item["stage"] == category],
    )


def reconcile(flow_result: Optional[Dict], rules: RuleVerdict) -> Dict:
    """The stored verdict, and the flow classifier's place beside it.

    Precedence, stated once:

    1. The category is the rule layer's. Rule evidence is the only thing
       that moves a session off benign.
    2. The flow classifier's output is advisory. Its class distribution is
       stored verbatim (``class_probabilities``) and its label is reported
       beside the verdict, flagged when it disagrees, but it never sets the
       category: not above rule evidence, and not in its absence.

    The second half is the conservative reading of what the model is. It was
    trained on CIC-IDS2017 flows whose attack classes (DoS floods for
    "exploitation", botnet traffic for "exfiltration") do not resemble decoy
    sessions, its exfiltration precision on that set's own test split is
    0.47, and on the deployment's stored sessions it has never produced a
    non-benign label. A session-native model (``ml.train_sessions``) is the
    intended replacement once labelled sessions exist; this is the function
    to revisit then.
    """
    flow_result = flow_result or {}
    flow_category = str(flow_result.get("category") or BENIGN)
    if flow_category not in STAGE_RANK:
        flow_category = BENIGN
    return {
        "category": rules.category,
        "confidence": rules.confidence,
        "source": "rules",
        "flow": {
            "role": "advisory",
            "category": flow_category,
            "confidence": float(flow_result.get("confidence") or 0.0),
            "model_source": flow_result.get("model_source"),
            "disagrees": STAGE_RANK[flow_category] > STAGE_RANK[rules.category],
        },
    }


def severity_score(
    category: str,
    confidence: float,
    intents: Optional[List[str]] = None,
    critical_tools: Optional[List[str]] = None,
    anomalous: bool = False,
) -> float:
    """The number the severity level is cut from.

    Driven by what set the category: its stage and the rule layer's
    confidence in it. The classifier's confidence used to be added here even
    after the rules had replaced its verdict, so a session the rules called
    exploitation was scored on how sure the forest was that it was benign;
    and the anomaly score was added whether or not the detector had ever
    been fitted on real sessions.

    ``anomalous`` is only ever true from a calibrated detector.
    """
    score = {BENIGN: 0.0, RECON: 2.0, EXPLOIT: 4.0, EXFIL: 5.0}.get(category, 0.0)
    score += 2.0 * max(0.0, min(1.0, float(confidence or 0.0)))

    if critical_tools:
        score += 3.0

    # An intent the category already says is not counted again.
    extra = [
        intent for intent in _HIGH_IMPACT_INTENTS
        if intent in (intents or []) and not (intent == "data_exfiltration" and category == EXFIL)
    ]
    if extra:
        score += 2.0 + (1.0 if len(extra) > 1 else 0.0)

    if anomalous:
        score += 1.0
    return round(score, 2)


def severity_level(score: float, floor: str = "low") -> str:
    """low / medium / high / critical for a score, never below ``floor``."""
    if score >= 8:
        level = "critical"
    elif score >= 5:
        level = "high"
    elif score >= 3:
        level = "medium"
    else:
        level = "low"
    return max(level, floor, key=SEVERITY_LEVELS.index)


def stored_severity(
    category: Optional[str],
    confidence: Optional[float],
    model_source: Optional[str],
    tools: Optional[List[str]],
    intents: Optional[List[str]],
    signals: Optional[Dict],
) -> str:
    """Severity of a stored session, by the same definition as at ingest.

    Sessions analysed since severity was recorded carry it in ``signals``.
    Older rows are scored from their columns with the same function; a
    confidence that came from the flow model rather than the rules counts
    for nothing, as it would today.
    """
    if isinstance(signals, dict) and signals.get("severity") in SEVERITY_LEVELS:
        return signals["severity"]
    rule_confidence = float(confidence or 0.0) if model_source == "rules" else 0.0
    critical = [t for t in (tools or []) if t in CRITICAL_TOOLS]
    return severity_level(severity_score(category or BENIGN, rule_confidence, intents, critical))
