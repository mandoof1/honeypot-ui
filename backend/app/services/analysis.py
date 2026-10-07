from __future__ import annotations
import hashlib
import ipaddress
import json
import logging
import time
from typing import Dict, List, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.models import (
    Alert, AlertStatus, AttackCategory, AttackerProfile, AttackSeverity,
    HoneypotNode, HoneypotSession, IndicatorOfCompromise, SessionStatus,
)
from app.schemas import DashboardStats
# AI modules imported lazily below
from app.services.geoip import geoip_service
from app.services import thresholds
from app.services import alerts as alert_service
from app.services import enrichment
from app.services.scanners import scanner_registry
from app.core.encryption import encrypt_data

logger = logging.getLogger(__name__)

#: NFR-2: classification turnaround must stay under this after a session ends.
ANALYSIS_BUDGET_MS = 200

#: A single session's command list is attacker-controlled; cap what we store.
MAX_COMMANDS = 5000
MAX_PAYLOAD_CHARS = 1_000_000


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

#: NLP tool/web-signature categories collapsed onto the four stored classes. The
#: NLP layer recognises far more specific categories than the flow model's four;
#: this is how a signature hit (sqlmap, a UNION SELECT, a webshell upload) sets
#: the session's category even when the flow model — trained on CIC-IDS2017
#: network flows and domain-shifted onto command/web sessions — calls it benign.
_RECON_SIGNALS = {
    "scanner", "directory_enum", "vulnerability_scanner", "reconnaissance",
    "path_traversal",
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

#: Failed logins at or above this in one session read as a brute-force attempt.
_BRUTE_FORCE_THRESHOLD = 3


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


class AnalysisPipeline:
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

        # Import the singletons, not the modules: `from app.ai import
        # classifier` bound the *module* (app/ai/__init__.py is empty), so
        # every call raised AttributeError and no session was ever ingested.
        # Imported lazily so loading the AI stack does not block app startup.
        from app.ai.anomaly_detector import anomaly_detector
        from app.ai.attacker_profiler import attacker_profiler
        from app.ai.classifier import classifier
        from app.ai.mitre_mapper import mitre_mapper
        from app.ai.nlp_engine import nlp_engine
        attacker_ip = str(session_data.get("attacker_ip", ""))[:45]
        commands = [
            str(c) for c in (session_data.get("commands") or [])[:MAX_COMMANDS]
        ]
        duration = float(session_data.get("duration_seconds") or 0)

        geo = geoip_service.lookup(attacker_ip)

        # Stage 1 classifies the traffic's shape, measured at the engine's
        # socket; the commands are stage 2's (NLP and Chimera) to read.
        ai_result = classifier.classify_flow(
            session_data.get("flow"), str(session_data.get("protocol") or "")
        )

        protocol = str(session_data.get("protocol") or "")
        nlp_result = nlp_engine.analyze_commands(commands, protocol)

        payload = str(session_data.get("payload") or "")[:MAX_PAYLOAD_CHARS]
        if payload:
            payload_analysis = nlp_engine.analyze_payload(payload)
        else:
            payload_analysis = {"is_suspicious": False, "suspicion_score": 0.0}

        _now = datetime.now(timezone.utc)
        anomaly_features = {
            "session_duration": min(duration / 600, 1),
            "command_count": min(len(commands) / 50, 1),
            "unique_commands": min(len(set(commands)) / 30, 1) if commands else 0,
            "failed_login_attempts": min(session_data.get("failed_logins", 0) / 20, 1),
            "file_upload_count": min(len(session_data.get("uploads", [])) / 5, 1),
            "connection_rate": min(session_data.get("connection_rate", 0) / 100, 1),
            "payload_size_avg": min(len(payload) / 5000, 1) if payload else 0,
            "payload_entropy": payload_analysis.get("suspicion_score", 0),
            "port_scan_count": min(session_data.get("port_scan_count", 0) / 50, 1),
            "error_rate": min(session_data.get("error_rate", 0) / 0.5, 1),
            "off_hours": 1 if _now.hour < 6 or _now.hour > 22 else 0,
        }
        anomaly_result = anomaly_detector.detect(anomaly_features)

        profile_result = attacker_profiler.profile_from_session(
            session_data, nlp_result, ai_result
        )

        # Behavioural clustering runs alongside the rule-based profile rather
        # than replacing it, and the two are reported separately. The scorecard
        # is interpretable and works on the first session ever seen; clustering
        # cannot do either, but it groups sessions that behave alike without
        # anyone deciding in advance what alike means — which is how a campaign
        # reusing one toolkit becomes visible across many sessions.
        from app.ai.clustering import clusterer, extract as extract_behaviour

        cluster_result = clusterer.assign(
            extract_behaviour(session_data, nlp_result)
        )

        # Reconcile the flow model's verdict with the rule-based evidence. The
        # flow model (stage 1, FR-2) classifies the traffic's *shape* and is
        # domain-shifted on command/web sessions, so on its own it labels almost
        # everything benign. The rule layer reads the recorded commands, probes,
        # logins and uploads; when it finds a more advanced stage, that becomes
        # the session's category. The flow model's own distribution is still
        # kept verbatim in class_probabilities, and model_source records which
        # layer the stored category actually came from.
        flow_category = _coerce_enum(
            AttackCategory, ai_result.get("category"), AttackCategory.BENIGN
        )
        rule_category, rule_confidence, rule_reason = self._rule_based_category(
            nlp_result, session_data
        )
        if _CATEGORY_RANK[rule_category] > _CATEGORY_RANK[flow_category]:
            final_category = rule_category
            final_confidence = rule_confidence
            category_source = "rules"
        else:
            final_category = flow_category
            final_confidence = float(ai_result.get("confidence") or 0.0)
            category_source = ai_result.get("model_source")

        # Downstream stages (MITRE mapping, severity) read the agreed verdict.
        ai_result["category"] = final_category.value

        mitre_result = mitre_mapper.map_analysis(nlp_result, ai_result, session_data)

        iocs = self._extract_iocs(attacker_ip, nlp_result, session_data)

        severity = self._determine_severity(ai_result, anomaly_result, nlp_result)

        raw_commands_encrypted = encrypt_data("\n".join(commands)) if commands else None
        raw_payloads_encrypted = encrypt_data(payload) if payload else None

        # Transcript and credentials are encrypted with the same AES-256-GCM
        # as the command list. Credentials in particular are live passwords in
        # circulation against real hosts; storing them readable would make the
        # honeypot's database more dangerous than the attack it recorded.
        transcript = session_data.get("transcript") or []
        transcript_encrypted = (
            encrypt_data(json.dumps(transcript)) if transcript else None
        )
        credentials = session_data.get("credentials") or []
        credentials_encrypted = (
            encrypt_data(json.dumps(credentials)) if credentials else None
        )

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
            attack_confidence=final_confidence,
            attacker_profile=_coerce_enum(
                AttackerProfile,
                profile_result.get("profile"),
                AttackerProfile.UNKNOWN,
            ),
            anomaly_score=anomaly_result["anomaly_score"],
            is_anomalous=anomaly_result["is_anomalous"],
            detected_tools=nlp_result.get("tool_names", []),
            detected_intents=nlp_result.get("detected_intents", []),
            command_summary=" ".join(commands[:100])[:10000] if commands else None,
            command_count=len(commands),
            mitre_tactics=mitre_result.get("tactic_ids", []),
            mitre_techniques=mitre_result.get("techniques", []),
            model_source=category_source,
            cluster_id=cluster_result.get("cluster"),
            cluster_distance=cluster_result.get("distance"),
            cluster_is_outlier=cluster_result.get("is_outlier"),
            raw_commands_encrypted=raw_commands_encrypted,
            raw_payloads_encrypted=raw_payloads_encrypted,
            transcript_encrypted=transcript_encrypted,
            credentials_encrypted=credentials_encrypted,
            network_events=session_data.get("events") or [],
            keystroke_count=int(session_data.get("keystroke_count") or 0),
            scanner_operator=scanner_registry.identify(attacker_ip),
            rule_reason=(rule_reason or None) and rule_reason[:300],
            transcript_sha256=(
                hashlib.sha256("\n".join(commands).encode("utf-8", "replace")).hexdigest()
                if commands else None
            ),
            class_probabilities=ai_result.get("probabilities"),
            # The packet summary column has been indexed since the first
            # migration and never written.
            network_packets_summary=_summarise_packets(session_data.get("packets")),
            uploaded_files=[
                str(u.get("filename") or u.get("url") or "")
                for u in (session_data.get("uploads") or [])
                if isinstance(u, dict)
            ],
        )
        db.add(db_session)
        await db.flush()

        for ioc in iocs:
            db_ioc = IndicatorOfCompromise(
                session_id=db_session.id,
                ioc_type=ioc["type"],
                value=ioc["value"],
                confidence=ioc.get("confidence", 0.8),
                tags=ioc.get("tags", []),
            )
            db.add(db_ioc)

        # Alerting policy comes from the configured thresholds, not from a
        # constant. An operator who sets a threshold and sees it saved is
        # entitled to have it affect something.
        decision = await thresholds.evaluate(
            db, severity, anomaly_result["anomaly_score"]
        )

        alert_outcome = None
        if decision.should_alert:
            alert_outcome = await alert_service.raise_session_alert(
                db,
                session=db_session,
                severity=severity,
                category=ai_result["category"],
                confidence=float(ai_result.get("confidence") or 0.0),
                profile=profile_result["profile"],
                tools=nlp_result.get("tool_names", []),
                mitre_result=mitre_result,
                geo=geo,
                decision=decision,
                rule_reason=rule_reason,
            )

        # Queue stage 2 for the sessions worth a model's time. The worker in
        # the backend service drains this; nothing here waits on it.
        db_session.enrichment_status = enrichment.initial_status(
            db_session, nlp_result, session_data
        )

        await db.commit()

        analysis_ms = (time.perf_counter() - started) * 1000.0
        if analysis_ms > ANALYSIS_BUDGET_MS:
            logger.warning(
                "Session analysis took %.1f ms, over the %d ms NFR-2 budget",
                analysis_ms,
                ANALYSIS_BUDGET_MS,
            )

        # Persisted, not just logged: NFR-2 is a claim about the system under
        # real traffic, and a number that only ever reached a log line cannot
        # be aggregated into evidence for it.
        db_session.analysis_ms = round(analysis_ms, 2)
        await db.commit()

        return {
            "session_id": db_session.id,
            "session_uuid": db_session.session_uuid,
            # Reported per session so the requirement can be measured over
            # real traffic rather than estimated from a single run.
            "analysis_ms": round(analysis_ms, 2),
            "analysis_within_budget": analysis_ms <= ANALYSIS_BUDGET_MS,
            "ai_classification": ai_result,
            "nlp_analysis": nlp_result,
            "anomaly_detection": anomaly_result,
            "attacker_profile": profile_result,
            "behavioural_cluster": cluster_result,
            "mitre_attack": mitre_result,
            "severity": severity.value,
            "iocs": iocs,
            "alert": alert_outcome,
            "enrichment_status": db_session.enrichment_status,
        }

    def _extract_iocs(self, attacker_ip: str, nlp_result: Dict, session_data: Dict) -> List[Dict]:
        iocs = []
        if attacker_ip:
            iocs.append({"type": "ip", "value": attacker_ip, "confidence": 0.95, "tags": ["attacker_ip"]})

        for ip in nlp_result.get("extracted_ips", []):
            if ip != attacker_ip:
                iocs.append({"type": "ip", "value": ip, "confidence": 0.7, "tags": ["referenced_ip"]})

        for url in nlp_result.get("extracted_urls", []):
            iocs.append({"type": "url", "value": url, "confidence": 0.8, "tags": ["c2_url", "download_url"]})

        for tool in nlp_result.get("detected_tools", []):
            tool_name = tool.get("name", tool) if isinstance(tool, dict) else tool
            iocs.append({"type": "tool", "value": tool_name, "confidence": 0.85, "tags": ["offensive_tool"]})

        for f in session_data.get("uploads", []):
            if isinstance(f, dict):
                sha = f.get("sha256", f.get("md5", ""))
                if sha:
                    iocs.append({"type": "file_hash", "value": sha, "confidence": 0.9, "tags": ["uploaded_malware"]})

        # Retrieval events are the highest-confidence indicators the honeypot
        # produces. An attacker who types a URL might be pasting from a blog;
        # one whose dropper fetched it chose it. The URL, the host and the
        # payload name are each recorded, because a takedown request needs the
        # host and a detection rule needs the filename.
        for event in session_data.get("events") or []:
            if not isinstance(event, dict):
                continue
            if event.get("event_type") != "file_download":
                continue
            url, host = event.get("url"), event.get("host")
            tags = ["c2_url", "dropper"] + (["piped_to_shell"] if event.get("piped_to_shell") else [])
            if url:
                iocs.append({"type": "url", "value": str(url)[:500], "confidence": 0.95, "tags": tags})
            if host and host != attacker_ip:
                ioc_type = "ip" if _looks_like_ip(str(host)) else "domain"
                iocs.append({
                    "type": ioc_type,
                    "value": str(host)[:500],
                    "confidence": 0.9,
                    "tags": ["c2_host", "dropper"],
                })
            if event.get("filename"):
                iocs.append({
                    "type": "filename",
                    "value": str(event["filename"])[:500],
                    "confidence": 0.75,
                    "tags": ["payload_name"],
                })

        # De-duplicate: a session that fetches the same stage twice should not
        # write the indicator twice.
        seen, unique = set(), []
        for ioc in iocs:
            key = (ioc["type"], ioc["value"])
            if key not in seen:
                seen.add(key)
                unique.append(ioc)
        return unique

    def _rule_based_category(self, nlp_result: Dict, session_data: Dict):
        """Derive a category from deterministic evidence in the session.

        Reads the NLP categories/intents (which now include web-exploitation
        signatures), the failed-login count, uploaded files and the count of
        attack probes the decoy flagged. Returns the highest kill-chain stage
        any of them implies, a confidence for that signature match, and a short
        reason. Benign when nothing matched — the flow model then stands.
        """
        categories = set(nlp_result.get("categories") or [])
        intents = set(nlp_result.get("detected_intents") or [])
        failed_logins = int(session_data.get("failed_logins") or 0)
        upload_count = len(session_data.get("uploads") or [])
        probe_count = sum(
            1
            for packet in (session_data.get("packets") or [])
            if isinstance(packet, dict) and packet.get("type") == "attack_detected"
        )

        category = AttackCategory.BENIGN
        reasons: List[str] = []

        def bump(to: AttackCategory, why: str):
            nonlocal category
            reasons.append(why)
            if _CATEGORY_RANK[to] > _CATEGORY_RANK[category]:
                category = to

        if categories & _RECON_SIGNALS or "reconnaissance" in intents:
            bump(AttackCategory.RECONNAISSANCE, "reconnaissance tooling or behaviour")
        if probe_count:
            # The decoy flagged a probe whose kind isn't forwarded in detail; a
            # recon floor is the honest minimum (NLP catches the specific ones).
            bump(AttackCategory.RECONNAISSANCE, f"{probe_count} flagged attack probe(s)")
        diversion = next(
            (
                e for e in (session_data.get("events") or [])
                if isinstance(e, dict) and e.get("event_type") == "http_diversion"
            ),
            None,
        )
        if diversion:
            # The client gave itself away earlier, maybe on another connection,
            # so this session can look like plain browsing on its own.
            bump(
                AttackCategory.RECONNAISSANCE,
                f"diverted to the decoy application ({diversion.get('reason') or 'earlier attack'})",
            )
        if categories & _EXPLOIT_SIGNALS or intents & _EXPLOIT_INTENTS:
            bump(AttackCategory.EXPLOITATION, "exploitation signature or intent")
        if failed_logins >= _BRUTE_FORCE_THRESHOLD:
            bump(AttackCategory.EXPLOITATION, f"{failed_logins} failed logins (brute force)")
        if upload_count:
            bump(AttackCategory.EXPLOITATION, f"{upload_count} file upload(s)")
        if categories & _EXFIL_SIGNALS or "data_exfiltration" in intents:
            bump(AttackCategory.EXFILTRATION, "data-exfiltration behaviour")

        if category is AttackCategory.BENIGN:
            return category, 0.0, ""
        # Deliberately not 1.0: strong heuristics over recorded text, not proof.
        # A little higher when several independent signals agree.
        confidence = 0.9 if len(reasons) > 1 else 0.75
        reason = "; ".join(reasons[:4])
        logger.debug("Rule-based category %s: %s", category.value, reason)
        return category, confidence, reason

    def _determine_severity(
        self,
        ai_result: Dict,
        anomaly_result: Dict,
        nlp_result: Dict,
    ) -> AttackSeverity:
        category = ai_result.get("category", "benign")
        confidence = ai_result.get("confidence", 0)
        anomaly_score = anomaly_result.get("anomaly_score", 0)
        tools = nlp_result.get("tool_names", [])
        intents = nlp_result.get("detected_intents", [])

        score = 0
        if category == "exploitation":
            score += 4
        elif category == "exfiltration":
            score += 5
        elif category == "reconnaissance":
            score += 2
        elif category == "benign":
            score += 0

        score += confidence * 2
        score += anomaly_score * 2

        critical_tools = {"metasploit", "mimikatz", "cobalt_strike", "empire"}
        if any(t in critical_tools for t in tools):
            score += 3

        if "data_exfiltration" in intents:
            score += 2
        if "lateral_movement" in intents:
            score += 2
        if "credential_harvesting" in intents:
            score += 2

        if score >= 8:
            return AttackSeverity.CRITICAL
        elif score >= 5:
            return AttackSeverity.HIGH
        elif score >= 3:
            return AttackSeverity.MEDIUM
        else:
            return AttackSeverity.LOW


analysis_pipeline = AnalysisPipeline()


class DashboardService:
    async def get_stats(self, db: AsyncSession) -> DashboardStats:
        total_q = select(func.count(HoneypotSession.id))
        total = (await db.execute(total_q)).scalar() or 0

        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        today_q = select(func.count(HoneypotSession.id)).where(HoneypotSession.started_at >= today_start)
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

        unique_ips_q = select(func.count(func.distinct(HoneypotSession.attacker_ip)))
        unique_ips = (await db.execute(unique_ips_q)).scalar() or 0

        unique_countries_q = select(func.count(func.distinct(HoneypotSession.geo_country))).where(
            HoneypotSession.geo_country.isnot(None)
        )
        unique_countries = (await db.execute(unique_countries_q)).scalar() or 0

        cat_q = select(HoneypotSession.attack_category, func.count(HoneypotSession.id)).group_by(HoneypotSession.attack_category)
        cat_result = await db.execute(cat_q)
        attack_distribution = {cat.value if cat else "unknown": count for cat, count in cat_result.all()}

        sev_q = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
        sev_result = await db.execute(sev_q)
        severity_distribution = {s.value if s else "unknown": count for s, count in sev_result.all()}

        hour_q = select(
            func.extract('hour', HoneypotSession.started_at).label('hour'),
            func.count(HoneypotSession.id)
        ).group_by(func.extract('hour', HoneypotSession.started_at))
        hour_result = await db.execute(hour_q)
        sessions_by_hour = {str(int(hour)).zfill(2): count for hour, count in hour_result.all()}

        top_ips_q = select(
            HoneypotSession.attacker_ip,
            HoneypotSession.geo_country,
            func.count(HoneypotSession.id).label("count")
        ).group_by(HoneypotSession.attacker_ip, HoneypotSession.geo_country).order_by(desc("count")).limit(10)
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
        if session.attack_category == AttackCategory.EXPLOITATION:
            return "critical" if (session.attack_confidence or 0) > 0.8 else "high"
        elif session.attack_category == AttackCategory.EXFILTRATION:
            return "critical"
        elif session.attack_category == AttackCategory.RECONNAISSANCE:
            return "medium"
        return "low"


dashboard_service = DashboardService()
