from __future__ import annotations
import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from sqlalchemy.orm import selectinload

from app.models import (
    HoneypotSession, HoneypotNode, Alert, IndicatorOfCompromise,
    User, AlertThreshold, AuditLog,
    SessionStatus, AttackCategory, AttackSeverity, AttackerProfile,
    AlertStatus,
)
from app.schemas import DashboardStats, SessionFilter
from app.ai import classifier, nlp_engine, anomaly_detector, attacker_profiler, mitre_mapper
from app.services.geoip import geoip_service
from app.services.alerting import alerting_service
from app.services.report_generator import report_generator
from app.core.encryption import encrypt_data

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    async def process_session(
        self,
        db: AsyncSession,
        session_data: Dict,
        node_id: int,
    ) -> Dict:
        attacker_ip = session_data.get("attacker_ip", "")
        commands = session_data.get("commands", [])
        packets = session_data.get("packets", [])
        duration = session_data.get("duration_seconds", 0) or 0

        geo = geoip_service.lookup(attacker_ip)

        ai_result = classifier.classify_raw(packets, commands, duration)

        nlp_result = nlp_engine.analyze_commands(commands)

        payload = session_data.get("payload", "")
        if payload:
            payload_analysis = nlp_engine.analyze_payload(payload)
        else:
            payload_analysis = {"is_suspicious": False, "suspicion_score": 0.0}

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
            "off_hours": 1 if datetime.utcnow().hour < 6 or datetime.utcnow().hour > 22 else 0,
        }
        anomaly_result = anomaly_detector.detect(anomaly_features)

        profile_result = attacker_profiler.profile_from_session(
            session_data, nlp_result, ai_result
        )

        mitre_result = mitre_mapper.map_analysis(nlp_result, ai_result, session_data)

        iocs = self._extract_iocs(attacker_ip, nlp_result, session_data)

        severity = self._determine_severity(ai_result, anomaly_result, nlp_result)

        raw_commands_encrypted = encrypt_data("\n".join(commands)) if commands else None
        raw_payloads_encrypted = encrypt_data(payload) if payload else None

        db_session = HoneypotSession(
            node_id=node_id,
            attacker_ip=attacker_ip,
            attacker_port=session_data.get("attacker_port"),
            geo_country=geo.get("country"),
            geo_country_name=geo.get("country_name"),
            geo_city=geo.get("city"),
            geo_lat=geo.get("lat"),
            geo_lon=geo.get("lon"),
            status=SessionStatus(session_data.get("status", "completed")),
            started_at=datetime.fromisoformat(session_data["started_at"].replace("Z", "+00:00")) if session_data.get("started_at") else datetime.now(timezone.utc),
            ended_at=datetime.now(timezone.utc),
            duration_seconds=duration,
            attack_category=AttackCategory(ai_result["category"]),
            attack_confidence=ai_result["confidence"],
            attacker_profile=AttackerProfile(profile_result["profile"]),
            anomaly_score=anomaly_result["anomaly_score"],
            is_anomalous=anomaly_result["is_anomalous"],
            detected_tools=nlp_result.get("tool_names", []),
            detected_intents=nlp_result.get("detected_intents", []),
            command_summary=" ".join(commands[:100]) if commands else None,
            mitre_tactics=mitre_result.get("tactic_ids", []),
            mitre_techniques=mitre_result.get("techniques", []),
            raw_commands_encrypted=raw_commands_encrypted,
            raw_payloads_encrypted=raw_payloads_encrypted,
            uploaded_files=[u.get("filename", u.get("url", "")) for u in session_data.get("uploads", [])],
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

        if severity in (AttackSeverity.HIGH, AttackSeverity.CRITICAL):
            alert = Alert(
                session_id=db_session.id,
                severity=severity,
                title=f"{ai_result['category'].title()} attack from {attacker_ip}",
                description=f"AI classified session as {ai_result['category']} with {ai_result['confidence']:.1%} confidence. "
                            f"Profile: {profile_result['profile']}. "
                            f"Tools: {', '.join(nlp_result.get('tool_names', ['none']))}.",
                mitre_tactics=mitre_result.get("tactic_ids", []),
                mitre_techniques=mitre_result.get("techniques", []),
            )
            db.add(alert)
            await db.flush()

            await alerting_service.send_alert({
                "severity": severity.value,
                "title": alert.title,
                "description": alert.description,
                "attacker_ip": attacker_ip,
                "geo": geo,
                "attack_category": ai_result["category"],
                "attacker_profile": profile_result["profile"],
                "detected_tools": nlp_result.get("tool_names", []),
                "mitre_techniques": mitre_result.get("techniques", []),
                "timestamp": db_session.started_at.isoformat(),
                "session_uuid": db_session.session_uuid,
            })

        await db.commit()

        return {
            "session_id": db_session.id,
            "session_uuid": db_session.session_uuid,
            "ai_classification": ai_result,
            "nlp_analysis": nlp_result,
            "anomaly_detection": anomaly_result,
            "attacker_profile": profile_result,
            "mitre_attack": mitre_result,
            "severity": severity.value,
            "iocs": iocs,
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

        return iocs

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

        active_nodes_q = select(func.count(HoneypotNode.id)).where(HoneypotNode.is_active == True)
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

        top_tools_q = select(HoneypotSession.detected_tools).where(HoneypotSession.detected_tools.isnot(None))
        top_tools_result = await db.execute(top_tools_q)
        tool_counts = {}
        for row in top_tools_result.scalars().all():
            if isinstance(row, list):
                for tool in row:
                    tool_counts[tool] = tool_counts.get(tool, 0) + 1
        top_tools_detected = sorted(
            [{"tool": k, "count": v} for k, v in tool_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]

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
                "session_uuid": s.session_uuid,
                "attacker_ip": s.attacker_ip,
                "geo_country": s.geo_country,
                "geo_lat": s.geo_lat,
                "geo_lon": s.geo_lon,
                "attack_category": s.attack_category.value if s.attack_category else None,
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
