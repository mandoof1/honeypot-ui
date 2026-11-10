from __future__ import annotations
import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import String, cast, select, func, desc, or_

from app.models import (
    Alert, AlertStatus, AttackCategory, AttackerProfile, AttackSeverity,
    HoneypotNode, HoneypotSession, IndicatorOfCompromise, SessionStatus,
)
from app.schemas import DashboardStats
# AI modules imported lazily below
from app.ai import verdict as verdicts
from app.ai.config import get_analysis_settings
from app.ai.signals import ai_agent_signal, cap_fingerprints, honeytoken_signal
from app.ai.signals import fit_indicator_value as fit_ioc_value
from app.core.sql import LIKE_ESCAPE, escape_like
from app.services.geoip import geoip_service
from app.services import thresholds
from app.services import alerts as alert_service
from app.services import enrichment
from app.services.scanners import scanner_registry
from app.services.thresholds import AlertDecision
from app.core.encryption import decrypt_data, encrypt_data, session_context

logger = logging.getLogger(__name__)

#: NFR-2: classification turnaround must stay under this after a session ends.
ANALYSIS_BUDGET_MS = 200

#: A single session's command list is attacker-controlled; cap what we store.
MAX_COMMANDS = 5000
MAX_PAYLOAD_CHARS = 1_000_000
#: Columns of a session that hold sealed text. Each is bound to its row and
#: column when the row is stored.
_SEALED_COLUMNS = (
    "raw_commands_encrypted", "raw_payloads_encrypted", "transcript_encrypted", "credentials_encrypted",
)

#: Protocols whose "commands" are requests: the request line first, then the
#: body on the following lines.
_WEB_PROTOCOLS = frozenset({"http", "https"})
#: Query parameters whose value is a secret, masked in the plain summary.
_SECRET_PARAM = re.compile(
    r"([?&;](?:password|passwd|pass|pwd|pma_password|token|secret|api_key|apikey|cvc|cvv)=)[^&;#\s]*",
    re.IGNORECASE,
)
#: Requests a research scanner makes: it asks, it does not send a body.
_BANNER_METHODS = ("GET ", "HEAD ", "OPTIONS ")
_MAX_SCAN_REQUESTS = 30


def summarise_commands(commands: List[str], protocol: str) -> Optional[str]:
    """The plain-text summary kept beside the encrypted transcript.

    It is there for search and the session list, so it is not encrypted. For
    web sessions each command is a request line followed by its body, and the
    body is where a login form's password is: copying the commands verbatim
    put every password typed into a decoy form into a plain column, next to
    the credentials that are encrypted and revealed only through an audited
    action. Web summaries keep the request line (method, path, user agent)
    with secret-looking query values masked; bodies stay in the encrypted
    transcript.
    """
    if not commands:
        return None
    if (protocol or "").lower() in _WEB_PROTOCOLS:
        commands = [_SECRET_PARAM.sub(r"\1[redacted]", c.split("\n", 1)[0]) for c in commands]
    return " ".join(commands[:100])[:10000]


def _coerce_enum(enum_cls, value, default):
    """Map an untrusted string onto an enum, falling back to a default."""
    if value is None:
        return default
    try:
        return enum_cls(str(value).strip().lower())
    except ValueError:
        logger.warning(
            "Unrecognised %s value %r from honeypot; using %s",
            enum_cls.__name__,
            value,
            default.value,
        )
        return default


def _parse_timestamp(value, fallback: datetime) -> datetime:
    if not value:
        return fallback
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        logger.warning("Unparseable started_at %r; using ingest time", value)
        return fallback
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _summarise_packets(packets) -> Optional[Dict]:
    """Counts and sizes by event type.

    The raw list is unbounded and mostly redundant; the summary is what the
    column was always meant to hold, and what a dashboard can aggregate.
    """
    if not packets:
        return None
    by_type: Dict[str, Dict[str, int]] = {}
    total = 0
    for packet in packets:
        if not isinstance(packet, dict):
            continue
        kind = str(packet.get("type") or "unknown")[:40]
        size = int(packet.get("size") or 0)
        entry = by_type.setdefault(kind, {"count": 0, "bytes": 0})
        entry["count"] += 1
        entry["bytes"] += size
        total += size
    if not by_type:
        return None
    return {"total_bytes": total, "count": sum(v["count"] for v in by_type.values()),
            "by_type": by_type}


#: Kill-chain ordering, used to keep the more advanced of two verdicts.
_CATEGORY_RANK = {
    AttackCategory.BENIGN: 0,
    AttackCategory.RECONNAISSANCE: 1,
    AttackCategory.EXPLOITATION: 2,
    AttackCategory.EXFILTRATION: 3,
}


def _valid_uuid(value) -> Optional[str]:
    """The engine's own session id, when it sent a well-formed one.

    Used as the stored session_uuid so a retried ingest (the engine spools
    and resends when the backend was unreachable) is recognised as the same
    session rather than stored twice.
    """
    if not value:
        return None
    try:
        import uuid as _uuid

        return str(_uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        return None


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def scan_consistency(session_data: Dict, rules: verdicts.RuleVerdict) -> Tuple[bool, List[str]]:
    """Whether a session behaved like a research scan, and why not if not.

    An address inside a scanner's published range used to be enough to
    silence alerts and skip the language model whatever the session did.
    The range is now only half of it. A scan connects, reads a banner or
    asks for a page, and leaves: it does not log in, type commands, upload
    anything or send what the rules read as an exploit.
    """
    reasons: List[str] = []
    credentials = [c for c in (session_data.get("credentials") or []) if isinstance(c, dict)]
    if any(c.get("success") for c in credentials):
        reasons.append("logged in")
    if verdicts.STAGE_RANK.get(rules.category, 0) >= verdicts.STAGE_RANK[verdicts.EXPLOIT]:
        reasons.append("exploitation evidence")
    if session_data.get("uploads"):
        reasons.append("uploaded a file")
    events = [e for e in (session_data.get("events") or []) if isinstance(e, dict)]
    if any(e.get("event_type") in ("ai_canary_triggered", "honeytoken_used", "direct_tcpip") for e in events):
        reasons.append("triggered a canary, honeytoken or forward")

    commands = [str(c) for c in (session_data.get("commands") or [])]
    if (str(session_data.get("protocol") or "")).lower() in _WEB_PROTOCOLS:
        if len(commands) > _MAX_SCAN_REQUESTS:
            reasons.append(f"more than {_MAX_SCAN_REQUESTS} requests")
        elif any(not c.startswith(_BANNER_METHODS) or "\n" in c.strip() for c in commands):
            reasons.append("sent a request with a body or an unusual method")
    elif commands:
        reasons.append("ran commands")
    return not reasons, reasons


# -- running the CPU part off the event loop --------------------------------

_executor: Optional[ThreadPoolExecutor] = None
#: False until the models have been loaded in this process. A session
#: analysed before that pays for loading them and is recorded as cold.
_models_ready = False


def _pool() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(
            max_workers=max(1, get_analysis_settings().ANALYSIS_EXECUTOR_THREADS),
            thread_name_prefix="analysis",
        )
    return _executor


def preload_models() -> None:
    """Load everything the ingest path needs, before the first session.

    Each model used to be loaded (or, for the bootstraps, fitted) lazily
    inside the first timed analysis of every worker process, which is where
    part of the 200 ms overruns came from.
    """
    global _models_ready
    from app.ai.anomaly_detector import anomaly_detector
    from app.ai.attack_catalog import catalog
    from app.ai.classifier import classifier
    from app.ai.clustering import clusterer
    from app.ai.session_view import run_rules

    classifier.preload()
    anomaly_detector.preload()
    clusterer.preload()
    catalog.load()
    scanner_registry.load()
    # Compiles nothing new (patterns are built at import) but touches every
    # code path once, so the first real session does not.
    run_rules({"commands": ["true"], "protocol": "ssh"})
    _models_ready = True


async def warm_up() -> None:
    """Preload the models at start-up without blocking the event loop."""
    try:
        await asyncio.get_running_loop().run_in_executor(_pool(), preload_models)
        logger.info("Analysis models loaded")
    except Exception:
        # Start-up must not fail on this: the first session will load them.
        logger.exception("Could not preload the analysis models; they will load on first use")


class AnalysisPipeline:
    def analyse(self, session_data: Dict) -> Dict:
        """Everything about a session that needs no database.

        Pure computation: the models, the rules, the verdict, the indicators
        and the encryption of what will be stored. ``process_session`` runs
        it on a worker thread; the evaluation tools call it directly.
        """
        global _models_ready
        cpu_started = time.perf_counter()
        cold = not _models_ready

        # Import the singletons, not the modules: `from app.ai import
        # classifier` bound the *module* (app/ai/__init__.py is empty), so
        # every call raised AttributeError and no session was ever ingested.
        from app.ai.anomaly_detector import anomaly_detector, features_from_session
        from app.ai.attacker_profiler import attacker_profiler
        from app.ai.classifier import classifier
        from app.ai.clustering import clusterer
        from app.ai.mitre_mapper import mitre_mapper
        from app.ai.session_view import is_refusal, run_rules

        attacker_ip = str(session_data.get("attacker_ip", ""))[:45]
        protocol = str(session_data.get("protocol") or "")
        commands = [
            str(c) for c in (session_data.get("commands") or [])[:MAX_COMMANDS]
        ]
        # One view of the session for every stage below.
        view = {**session_data, "commands": commands}
        refusal = is_refusal(session_data)

        # Stage 1 classifies the traffic's shape, measured at the engine's
        # socket. Its verdict is advisory (see verdict.reconcile).
        ai_result = classifier.classify_flow(session_data.get("flow"), protocol)

        nlp_result = run_rules(view)
        anomaly_result = anomaly_detector.detect(features_from_session(view))
        profile_result = attacker_profiler.profile_from_session(view, nlp_result, ai_result)

        # Behavioural clustering runs alongside the rule-based profile rather
        # than replacing it, and the two are reported separately. The scorecard
        # is interpretable and works on the first session ever seen; clustering
        # cannot do either, but it groups sessions that behave alike without
        # anyone deciding in advance what alike means — which is how a campaign
        # reusing one toolkit becomes visible across many sessions.
        cluster_result = (
            {"fitted": False, "cluster": None, "distance": None}
            if refusal else clusterer.assign_session(view, nlp_result)
        )

        # The category is the rule layer's; the flow model's label sits
        # beside it. Its own distribution is kept verbatim in
        # class_probabilities.
        rules = verdicts.rule_verdict(nlp_result, view)
        final = verdicts.reconcile(ai_result, rules)
        flow_probabilities = ai_result.get("probabilities")
        # What downstream readers of the result see as the classification.
        classification = {
            "category": final["category"],
            "confidence": final["confidence"],
            "model_source": final["source"],
            "probabilities": flow_probabilities,
            "flow": final["flow"],
        }

        mitre_result = mitre_mapper.map_evidence(rules.evidence)
        iocs = [] if refusal else self._extract_iocs(attacker_ip, nlp_result, view)

        honeytoken = honeytoken_signal(view)
        ai_agent = ai_agent_signal(view)
        score = verdicts.severity_score(
            final["category"],
            final["confidence"],
            nlp_result.get("detected_intents"),
            nlp_result.get("critical_tools"),
            anomalous=bool(anomaly_result["is_anomalous"]),
        )
        # A planted credential being used is serious whatever else the
        # session shows.
        severity = verdicts.severity_level(score, floor="high" if honeytoken else "low")

        operator = None if refusal else scanner_registry.identify(attacker_ip)
        scan_like, scan_reasons = scan_consistency(view, rules) if operator else (False, [])

        signals: Dict = {
            "severity": severity,
            "severity_score": score,
            "verdict": {
                "source": final["source"],
                "evidence": list(dict.fromkeys(item["key"] for item in rules.evidence))[:40],
                "independent_findings": len(rules.supporting),
                "flow": final["flow"],
                # The rules read the start and end of a session too long for
                # their budget; silence from a partial read is not clearance.
                "rules_truncated": bool(nlp_result.get("truncated")),
            },
            "anomaly": {
                "calibrated": bool(anomaly_result["calibrated"]),
                "model_source": anomaly_result["model_source"],
                "fitted_at": anomaly_result.get("fitted_at"),
                "fitted_on": anomaly_result.get("fitted_on"),
            },
        }
        if ai_agent is not None:
            signals["ai_agent"] = ai_agent
        if honeytoken is not None:
            signals["honeytoken"] = honeytoken
        if operator:
            signals["scanner"] = {
                "operator": operator,
                "consistent_with_scanning": scan_like,
                "reasons": scan_reasons,
            }
        if refusal:
            signals["refusal"] = True
        # What the engine had to cut to stay within its caps. Without this a
        # session that was cut looked complete.
        cut = {
            str(name)[:40]: int(count)
            for name, count in list((session_data.get("truncated") or {}).items())[:16]
            if isinstance(count, (int, float)) and not isinstance(count, bool) and count > 0
        } if isinstance(session_data.get("truncated"), dict) else {}
        if cut:
            signals["truncated"] = cut
        profile = session_data.get("threat_profile")
        if isinstance(profile, str) and profile:
            signals["engine_profile"] = profile[:64]
        elif isinstance(profile, dict) and profile:
            signals["engine_profile"] = {
                str(k)[:40]: (v if isinstance(v, (int, float, bool)) else str(v)[:120])
                for k, v in list(profile.items())[:12]
            }

        payload = str(session_data.get("payload") or "")[:MAX_PAYLOAD_CHARS]
        # Transcript and credentials are encrypted with the same AES-256-GCM
        # as the command list. Credentials in particular are live passwords in
        # circulation against real hosts; storing them readable would make the
        # honeypot's database more dangerous than the attack it recorded.
        transcript = session_data.get("transcript") or []
        credentials = session_data.get("credentials") or []
        joined = "\n".join(commands)
        stored = {
            "raw_commands_encrypted": encrypt_data(joined) if commands else None,
            "raw_payloads_encrypted": encrypt_data(payload) if payload else None,
            "transcript_encrypted": encrypt_data(json.dumps(transcript)) if transcript else None,
            "credentials_encrypted": encrypt_data(json.dumps(credentials)) if credentials else None,
            "transcript_sha256": (
                hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest() if commands else None
            ),
            "command_summary": summarise_commands(commands, protocol),
        }

        _models_ready = True
        return {
            "attacker_ip": attacker_ip,
            "protocol": protocol,
            "commands": commands,
            "refusal": refusal,
            "ai_result": ai_result,
            "classification": classification,
            "nlp_result": nlp_result,
            "anomaly_result": anomaly_result,
            "profile_result": profile_result,
            "cluster_result": cluster_result,
            "rules": rules,
            "mitre_result": mitre_result,
            "iocs": iocs,
            "severity": severity,
            "severity_score": score,
            "signals": signals,
            "scanner_operator": operator if scan_like else None,
            "fingerprints": cap_fingerprints(session_data.get("fingerprints")),
            "stored": stored,
            "cold": cold,
            "cpu_ms": round((time.perf_counter() - cpu_started) * 1000.0, 2),
        }

    async def process_session(
        self,
        db: AsyncSession,
        session_data: Dict,
        node_id: int,
    ) -> Dict:
        # NFR-2 commits the classification path to under 200 ms. Nothing
        # measured it, so the requirement could not be evaluated at all —
        # only asserted. This times the analysis span: feature extraction
        # through the verdict being committed (and any alert dispatched), so
        # it includes the database writes as well as the models.
        started = time.perf_counter()

        # The models, the rules and the encryption are CPU work on text an
        # attacker chose. On the event loop they stopped this worker from
        # accepting anything else for as long as one session took.
        result = await asyncio.get_running_loop().run_in_executor(_pool(), self.analyse, session_data)

        attacker_ip = result["attacker_ip"]
        commands = result["commands"]
        nlp_result = result["nlp_result"]
        anomaly_result = result["anomaly_result"]
        profile_result = result["profile_result"]
        cluster_result = result["cluster_result"]
        classification = result["classification"]
        mitre_result = result["mitre_result"]
        rules: verdicts.RuleVerdict = result["rules"]
        signals = result["signals"]
        refusal = result["refusal"]
        stored = result["stored"]
        severity = AttackSeverity(result["severity"])
        final_category = AttackCategory(classification["category"])
        duration = float(session_data.get("duration_seconds") or 0)

        geo = geoip_service.lookup(attacker_ip)
        _now = datetime.now(timezone.utc)
        engine_uuid = _valid_uuid(session_data.get("session_id"))

        db_session = HoneypotSession(
            **({"session_uuid": engine_uuid} if engine_uuid else {}),
            node_id=node_id,
            protocol=str(session_data.get("protocol") or "unknown")[:20],
            attacker_ip=attacker_ip,
            attacker_port=session_data.get("attacker_port"),
            geo_country=geo.get("country"),
            geo_country_name=geo.get("country_name"),
            geo_city=geo.get("city"),
            geo_lat=geo.get("lat"),
            geo_lon=geo.get("lon"),
            status=_coerce_enum(
                SessionStatus, session_data.get("status"), SessionStatus.COMPLETED
            ),
            started_at=_parse_timestamp(session_data.get("started_at"), _now),
            ended_at=_now,
            duration_seconds=duration,
            attack_category=final_category,
            attack_confidence=classification["confidence"],
            attacker_profile=_coerce_enum(
                AttackerProfile,
                profile_result.get("profile"),
                AttackerProfile.UNKNOWN,
            ),
            anomaly_score=anomaly_result["anomaly_score"],
            # Never set by an uncalibrated detector (ai/anomaly_detector.py).
            is_anomalous=anomaly_result["is_anomalous"],
            detected_tools=nlp_result.get("tool_names", []),
            detected_intents=nlp_result.get("detected_intents", []),
            command_summary=stored["command_summary"],
            command_count=len(commands),
            mitre_tactics=mitre_result.get("tactic_ids", []),
            mitre_techniques=mitre_result.get("techniques", []),
            model_source=classification["model_source"],
            cluster_id=cluster_result.get("cluster"),
            cluster_distance=cluster_result.get("distance"),
            cluster_is_outlier=cluster_result.get("is_outlier"),
            raw_commands_encrypted=stored["raw_commands_encrypted"],
            raw_payloads_encrypted=stored["raw_payloads_encrypted"],
            transcript_encrypted=stored["transcript_encrypted"],
            credentials_encrypted=stored["credentials_encrypted"],
            network_events=session_data.get("events") or [],
            keystroke_count=int(session_data.get("keystroke_count") or 0),
            # Only when the session also behaved like a scan; the range
            # alone is recorded in signals.scanner.
            scanner_operator=result["scanner_operator"],
            rule_reason=(rules.reason or None) and rules.reason[:300],
            transcript_sha256=stored["transcript_sha256"],
            class_probabilities=classification["probabilities"],
            # The packet summary column has been indexed since the first
            # migration and never written.
            network_packets_summary=_summarise_packets(session_data.get("packets")),
            uploaded_files=[
                str(u.get("filename") or u.get("url") or "")
                for u in (session_data.get("uploads") or [])
                if isinstance(u, dict)
            ],
            fingerprints=result["fingerprints"],
            signals=signals,
        )
        db.add(db_session)
        await db.flush()

        # Sealed again now that the row has an id, bound to this session and
        # this column. Before, the four blobs carried no binding, and an
        # unbound blob opens wherever it is put: a credentials blob copied
        # into the transcript column was served to anyone allowed to read
        # transcripts.
        for column in _SEALED_COLUMNS:
            blob = getattr(db_session, column)
            if blob:
                setattr(db_session, column, encrypt_data(
                    decrypt_data(blob), session_context(db_session.id, column),
                ))

        for ioc in result["iocs"]:
            db.add(IndicatorOfCompromise(
                session_id=db_session.id,
                ioc_type=ioc["type"],
                value=ioc["value"],
                confidence=ioc.get("confidence", 0.8),
                tags=ioc.get("tags", []),
            ))

        if "honeytoken" in signals:
            related = await self._related_honeytoken_sessions(db, db_session, signals["honeytoken"])
            if related:
                signals["honeytoken"]["related_sessions"] = related

        alert_outcome = None
        signal_alerts: List[Dict] = []
        if not refusal:
            # Alerting policy comes from the configured thresholds, not from a
            # constant. An operator who sets a threshold and sees it saved is
            # entitled to have it affect something. The anomaly score only
            # takes part once the detector is calibrated.
            policy_anomaly = anomaly_result["anomaly_score"] if anomaly_result["calibrated"] else 0.0
            decision = await thresholds.evaluate(db, severity, policy_anomaly)
            context = dict(
                session=db_session,
                category=final_category.value,
                profile=profile_result["profile"],
                tools=nlp_result.get("tool_names", []),
                mitre_result=mitre_result,
                geo=geo,
                score=result["severity_score"],
            )
            if decision.should_alert:
                alert_outcome = await alert_service.raise_session_alert(
                    db, severity=severity, decision=decision, rule_reason=rules.reason, **context,
                )
            signal_alerts = await self._raise_signal_alerts(db, signals, severity, context)

            # Queue stage 2 for the sessions worth a model's time: triage by the
            # decision model first when one is configured, then the language
            # model. The worker in the backend service drains both; nothing here
            # waits on either.
            enrichment.queue_at_ingest(db_session, nlp_result, session_data)

        db_session.signals = dict(signals)
        await db.commit()

        analysis_ms = (time.perf_counter() - started) * 1000.0
        if analysis_ms > ANALYSIS_BUDGET_MS:
            logger.warning(
                "Session analysis took %.1f ms (%s), over the %d ms NFR-2 budget",
                analysis_ms,
                "cold: models loaded during it" if result["cold"] else "warm",
                ANALYSIS_BUDGET_MS,
            )

        # Persisted, not just logged: NFR-2 is a claim about the system under
        # real traffic, and a number that only ever reached a log line cannot
        # be aggregated into evidence for it. Cold runs are marked so they
        # can be reported apart from the steady state.
        db_session.analysis_ms = round(analysis_ms, 2)
        db_session.signals = {**signals, "timing": {"cold": result["cold"], "cpu_ms": result["cpu_ms"]}}
        await db.commit()

        return {
            "session_id": db_session.id,
            "session_uuid": db_session.session_uuid,
            # Reported per session so the requirement can be measured over
            # real traffic rather than estimated from a single run.
            "analysis_ms": round(analysis_ms, 2),
            "analysis_within_budget": analysis_ms <= ANALYSIS_BUDGET_MS,
            "analysis_cold": result["cold"],
            "analysis_cpu_ms": result["cpu_ms"],
            "ai_classification": classification,
            "nlp_analysis": nlp_result,
            "anomaly_detection": anomaly_result,
            "attacker_profile": profile_result,
            "behavioural_cluster": cluster_result,
            "mitre_attack": mitre_result,
            "severity": severity.value,
            "signals": db_session.signals,
            "iocs": result["iocs"],
            "alert": alert_outcome,
            "signal_alerts": signal_alerts,
            "enrichment_status": db_session.enrichment_status,
            "triage_status": db_session.triage_status,
        }

    async def _raise_signal_alerts(
        self, db: AsyncSession, signals: Dict, severity: AttackSeverity, context: Dict
    ) -> List[Dict]:
        """Alerts a signal raises on its own: a canary trigger, a honeytoken.

        Kept apart from the per-source alert (their own group), so neither
        is folded into a brute-force alert and lost. The alert is always
        created; whether anyone is notified still follows the thresholds.
        """
        outcomes: List[Dict] = []
        ip = context["session"].attacker_ip

        async def raise_one(group: str, floor: AttackSeverity, title: str, description: str) -> None:
            level = max(severity, floor, key=lambda s: thresholds.SEVERITY_RANK[s])
            policy = await thresholds.evaluate(db, level, 0.0)
            notify = AlertDecision(
                should_alert=True,
                email=policy.email and policy.should_alert,
                webhook=policy.webhook and policy.should_alert,
                matched=policy.matched,
            )
            outcome = await alert_service.raise_session_alert(
                db, severity=level, decision=notify, group=group,
                title=title, description=description, **context,
            )
            outcomes.append({"signal": group.split(":")[0], **outcome})

        agent = signals.get("ai_agent") or {}
        if agent.get("canary"):
            names = ", ".join(agent.get("canaries") or []) or "unnamed"
            await raise_one(
                "canary", AttackSeverity.MEDIUM,
                f"AI agent canary triggered by {ip}",
                f"The session acted on canary text only a model reading the output would act on "
                f"({names}). This identifies an AI-driven agent; it says nothing by itself about "
                f"how far the session got.",
            )
        token = signals.get("honeytoken") or {}
        if token:
            ids = ", ".join(token.get("token_ids") or []) or "unidentified"
            await raise_one(
                f"honeytoken:{ids}"[:100], AttackSeverity.HIGH,
                f"Honeytoken used by {ip}",
                f"A planted honeytoken was used ({ids}; kind: "
                f"{', '.join(token.get('kinds') or []) or 'unspecified'}). Whoever used it had read it first.",
            )
        return outcomes

    async def _related_honeytoken_sessions(
        self, db: AsyncSession, session: HoneypotSession, token: Dict
    ) -> List[Dict]:
        """Earlier sessions that touched the same token, as far as stored data shows.

        Two things can be determined from what is stored: another session
        whose events or signals name the same token id, and one whose plain
        command summary names the file the token was planted in (when the
        engine's event says which file that is). A read buried in a long
        session past the summary's first hundred commands is not found.
        """
        found: Dict[int, str] = {}
        for token_id in (token.get("token_ids") or [])[:5]:
            pattern = f'%"{escape_like(token_id)}"%'
            rows = (
                await db.execute(
                    select(HoneypotSession.id)
                    .where(
                        HoneypotSession.id != session.id,
                        or_(
                            cast(HoneypotSession.network_events, String).like(pattern, escape=LIKE_ESCAPE),
                            cast(HoneypotSession.signals, String).like(pattern, escape=LIKE_ESCAPE),
                        ),
                    )
                    .order_by(HoneypotSession.id.desc())
                    .limit(20)
                )
            ).scalars().all()
            for row_id in rows:
                found.setdefault(row_id, f"same token {token_id}")
        for path in (token.get("paths") or [])[:5]:
            rows = (
                await db.execute(
                    select(HoneypotSession.id)
                    .where(
                        HoneypotSession.id != session.id,
                        HoneypotSession.command_summary.ilike(f"%{escape_like(path)}%", escape=LIKE_ESCAPE),
                    )
                    .order_by(HoneypotSession.id.desc())
                    .limit(20)
                )
            ).scalars().all()
            for row_id in rows:
                found.setdefault(row_id, f"command summary names {path}")
        return [{"session_id": row_id, "why": why} for row_id, why in sorted(found.items())][:20]

    def _extract_iocs(self, attacker_ip: str, nlp_result: Dict, session_data: Dict) -> List[Dict]:
        iocs = []

        def add(kind: str, value, confidence: float, tags: List[str]) -> None:
            fitted, cut = fit_ioc_value(str(value))
            if fitted:
                iocs.append({
                    "type": kind, "value": fitted, "confidence": confidence,
                    "tags": tags + (["truncated"] if cut else []),
                })

        if attacker_ip:
            add("ip", attacker_ip, 0.95, ["attacker_ip"])

        # Retrieval events are the highest-confidence indicators the honeypot
        # produces. An attacker who types a URL might be pasting from a blog;
        # one whose dropper fetched it chose it. The URL, the host and the
        # payload name are each recorded, because a takedown request needs the
        # host and a detection rule needs the filename.
        contacted = set()
        for event in session_data.get("events") or []:
            if not isinstance(event, dict):
                continue
            kind = event.get("event_type")
            if kind == "file_download":
                url, host = event.get("url"), event.get("host")
                tags = ["c2_url", "dropper"] + (["piped_to_shell"] if event.get("piped_to_shell") else [])
                if url:
                    add("url", url, 0.95, tags)
                if host and host != attacker_ip:
                    contacted.add(str(host))
                    add("ip" if _looks_like_ip(str(host)) else "domain", host, 0.9, ["c2_host", "dropper"])
                if event.get("filename"):
                    add("filename", event["filename"], 0.75, ["payload_name"])
            elif kind == "direct_tcpip":
                # Where an SSH client asked the host to connect on its behalf.
                host = event.get("dest_host")
                if host and host != attacker_ip:
                    contacted.add(str(host))
                    add("ip" if _looks_like_ip(str(host)) else "domain", host, 0.9, ["forward_target"])

        # An address that merely appears in typed text is not the session's
        # source and was not contacted: its own type, so a blocklist built
        # from "ip" never picks up something an attacker only mentioned.
        for ip in nlp_result.get("extracted_ips", []):
            if ip != attacker_ip and ip not in contacted:
                add("referenced_ip", ip, 0.7, ["referenced_ip"])

        for url in nlp_result.get("extracted_urls", []):
            add("url", url, 0.8, ["referenced_url"])

        for tool in nlp_result.get("detected_tools", []):
            tool_name = tool.get("name", tool) if isinstance(tool, dict) else tool
            add("tool", tool_name, 0.85, ["offensive_tool"])

        for f in session_data.get("uploads", []) or []:
            if isinstance(f, dict):
                sha = f.get("sha256", f.get("md5", ""))
                if sha:
                    add("file_hash", sha, 0.9, ["uploaded_malware"])

        # De-duplicate: a session that fetches the same stage twice should not
        # write the indicator twice. The first entry wins, and the event-based
        # ones come first, so a URL both fetched and typed keeps its stronger
        # tags.
        seen, unique = set(), []
        for ioc in iocs:
            key = (ioc["type"], ioc["value"])
            if key not in seen:
                seen.add(key)
                unique.append(ioc)
        return unique

    def _rule_based_category(self, nlp_result: Dict, session_data: Dict):
        """Category, confidence and reason from the rule evidence.

        The definition lives in ``app.ai.verdict`` so the tools can use it
        without the pipeline; this keeps the shape older callers expect.
        """
        rules = verdicts.rule_verdict(nlp_result, session_data)
        return AttackCategory(rules.category), rules.confidence, rules.reason


analysis_pipeline = AnalysisPipeline()


#: A refused connection is recorded with source port 0. It is not a session
#: and is kept out of the counts that describe sessions.
def _not_refusal():
    return or_(HoneypotSession.attacker_port.is_(None), HoneypotSession.attacker_port != 0)


class DashboardService:
    async def get_stats(self, db: AsyncSession) -> DashboardStats:
        counted = _not_refusal()
        total_q = select(func.count(HoneypotSession.id)).where(counted)
        total = (await db.execute(total_q)).scalar() or 0

        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        today_q = select(func.count(HoneypotSession.id)).where(HoneypotSession.started_at >= today_start, counted)
        sessions_today = (await db.execute(today_q)).scalar() or 0

        active_q = select(func.count(HoneypotSession.id)).where(HoneypotSession.status == SessionStatus.ACTIVE)
        active_sessions = (await db.execute(active_q)).scalar() or 0

        high_alerts_q = select(func.count(Alert.id)).where(
            Alert.severity.in_([AttackSeverity.HIGH, AttackSeverity.CRITICAL]),
            Alert.status == AlertStatus.NEW,
        )
        high_alerts = (await db.execute(high_alerts_q)).scalar() or 0

        active_nodes_q = select(func.count(HoneypotNode.id)).where(HoneypotNode.is_active.is_(True))
        active_nodes = (await db.execute(active_nodes_q)).scalar() or 0

        unique_ips_q = select(func.count(func.distinct(HoneypotSession.attacker_ip))).where(counted)
        unique_ips = (await db.execute(unique_ips_q)).scalar() or 0

        unique_countries_q = select(func.count(func.distinct(HoneypotSession.geo_country))).where(
            HoneypotSession.geo_country.isnot(None), counted
        )
        unique_countries = (await db.execute(unique_countries_q)).scalar() or 0

        cat_q = (
            select(HoneypotSession.attack_category, func.count(HoneypotSession.id))
            .where(counted)
            .group_by(HoneypotSession.attack_category)
        )
        cat_result = await db.execute(cat_q)
        attack_distribution = {cat.value if cat else "unknown": count for cat, count in cat_result.all()}

        sev_q = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
        sev_result = await db.execute(sev_q)
        severity_distribution = {s.value if s else "unknown": count for s, count in sev_result.all()}

        # Hour of day in UTC, whatever zone the database session is set to:
        # PostgreSQL extracts from a timestamptz in the connection's zone,
        # so the buckets moved with a server setting nobody chose. (SQLite,
        # in the tests, stores UTC and has no zones to apply.)
        started_utc = HoneypotSession.started_at
        bind = db.get_bind()
        if bind is not None and bind.dialect.name == "postgresql":
            started_utc = func.timezone("UTC", HoneypotSession.started_at)
        hour = func.extract("hour", started_utc)
        hour_q = select(hour.label("hour"), func.count(HoneypotSession.id)).where(counted).group_by(hour)
        hour_result = await db.execute(hour_q)
        sessions_by_hour = {str(int(hour)).zfill(2): count for hour, count in hour_result.all()}

        top_ips_q = select(
            HoneypotSession.attacker_ip,
            HoneypotSession.geo_country,
            func.count(HoneypotSession.id).label("count")
        ).where(counted).group_by(
            HoneypotSession.attacker_ip, HoneypotSession.geo_country
        ).order_by(desc("count")).limit(10)
        top_ips_result = await db.execute(top_ips_q)
        top_attacker_ips = [{"ip": ip, "country": country, "count": count} for ip, country, count in top_ips_result.all()]

        top_tools_detected = await self._top_tools(db)

        return DashboardStats(
            total_sessions=total,
            sessions_today=sessions_today,
            active_sessions=active_sessions,
            high_severity_alerts=high_alerts,
            active_honeypots=active_nodes,
            unique_threat_origins=unique_ips,
            unique_countries=unique_countries,
            attack_distribution=attack_distribution,
            severity_distribution=severity_distribution,
            sessions_by_hour=sessions_by_hour,
            timezone="UTC",
            top_attacker_ips=top_attacker_ips,
            top_tools_detected=top_tools_detected,
        )

    async def _top_tools(self, db: AsyncSession) -> List[Dict]:
        """Tool frequency across sessions.

        On Postgres the JSONB array is unnested and counted in SQL; the old
        version pulled every session's list into Python on each dashboard
        poll, which does not scale past a few thousand sessions. SQLite (the
        test database) keeps the Python fallback.
        """
        bind = db.get_bind()
        if bind is not None and bind.dialect.name == "postgresql":
            from sqlalchemy import text

            rows = (
                await db.execute(
                    text(
                        "SELECT tool, COUNT(*) AS n FROM honeypot_sessions, "
                        "jsonb_array_elements_text(detected_tools) AS tool "
                        "WHERE detected_tools IS NOT NULL AND jsonb_typeof(detected_tools) = 'array' "
                        "GROUP BY tool ORDER BY n DESC LIMIT 10"
                    )
                )
            ).all()
            return [{"tool": r.tool, "count": int(r.n)} for r in rows]

        result = await db.execute(
            select(HoneypotSession.detected_tools).where(HoneypotSession.detected_tools.isnot(None))
        )
        tool_counts: Dict[str, int] = {}
        for row in result.scalars().all():
            if isinstance(row, list):
                for tool in row:
                    tool_counts[tool] = tool_counts.get(tool, 0) + 1
        return sorted(
            [{"tool": k, "count": v} for k, v in tool_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]

    async def get_live_events(self, db: AsyncSession, limit: int = 50) -> List[Dict]:
        q = (
            select(HoneypotSession)
            .order_by(desc(HoneypotSession.started_at))
            .limit(limit)
        )
        result = await db.execute(q)
        sessions = result.scalars().all()

        events = []
        for s in sessions:
            events.append({
                # The UI joins alerts to their source session by numeric id;
                # only the UUID was exposed, so the join never matched.
                "session_id": s.id,
                "session_uuid": s.session_uuid,
                "protocol": s.protocol,
                "attacker_ip": s.attacker_ip,
                "geo_country": s.geo_country,
                "geo_country_name": s.geo_country_name,
                "geo_lat": s.geo_lat,
                "geo_lon": s.geo_lon,
                "attack_category": s.attack_category.value if s.attack_category else None,
                # The feed's hands-on marker reads this; it was never sent.
                "attacker_profile": s.attacker_profile.value if s.attacker_profile else None,
                "severity": self._session_severity(s),
                "timestamp": s.started_at.isoformat(),
            })
        return events

    def _session_severity(self, session: HoneypotSession) -> str:
        """Severity of a stored session, by the definition used at ingest.

        The feed had its own (exploitation is critical above 0.8 confidence,
        reconnaissance always medium), which disagreed with the severity the
        same session's alert carried.
        """
        return verdicts.stored_severity(
            session.attack_category.value if session.attack_category else None,
            session.attack_confidence,
            session.model_source,
            session.detected_tools,
            session.detected_intents,
            session.signals,
        )


dashboard_service = DashboardService()
