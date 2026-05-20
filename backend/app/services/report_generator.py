from __future__ import annotations
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from stix2 import Indicator, Malware, AttackPattern, Identity, Bundle, Indicator as STIXIndicator
from app.core.config import get_settings

settings = get_settings()


class ReportGenerator:
    def generate_json_report(self, session_data: Dict, analysis: Dict) -> str:
        report = {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "generator": "HoneySentinel AI",
                "version": settings.VERSION,
            },
            "session": {
                "uuid": session_data.get("session_uuid"),
                "protocol": session_data.get("protocol"),
                "attacker_ip": session_data.get("attacker_ip"),
                "attacker_port": session_data.get("attacker_port"),
                "geo_location": session_data.get("geo"),
                "started_at": session_data.get("started_at"),
                "ended_at": session_data.get("ended_at"),
                "duration_seconds": session_data.get("duration_seconds"),
                "status": session_data.get("status"),
            },
            "ai_analysis": {
                "attack_category": analysis.get("category"),
                "confidence": analysis.get("confidence"),
                "attacker_profile": analysis.get("profile"),
                "profile_confidence": analysis.get("profile_confidence"),
                "anomaly_score": analysis.get("anomaly_score"),
                "is_anomalous": analysis.get("is_anomalous"),
            },
            "nlp_analysis": {
                "detected_tools": analysis.get("detected_tools", []),
                "detected_intents": analysis.get("detected_intents", []),
                "complexity_score": analysis.get("complexity_score"),
                "command_count": analysis.get("command_count"),
            },
            "mitre_attack": analysis.get("mitre", {}),
            "indicators_of_compromise": analysis.get("iocs", []),
            "raw_data_summary": {
                "command_count": len(session_data.get("commands", [])),
                "upload_count": len(session_data.get("uploads", [])),
                "packet_summary": session_data.get("packet_summary"),
            },
        }
        return json.dumps(report, indent=2, default=str)

    def generate_cef_report(self, session_data: Dict, analysis: Dict) -> str:
        severity_map = {"benign": 0, "reconnaissance": 3, "exploitation": 7, "exfiltration": 9}
        severity = severity_map.get(analysis.get("category", "benign"), 0)

        geo = session_data.get("geo", {})
        attacker_profile = analysis.get("profile", "unknown")
        mitre_techniques = analysis.get("mitre", {}).get("techniques", [])
        technique_ids = [t.get("id", "") for t in mitre_techniques]

        extensions = (
            f"src={session_data.get('attacker_ip', '')} "
            f"spt={session_data.get('attacker_port', 0)} "
            f"deviceProcessName={session_data.get('protocol', '')} "
            f"requestContext={session_data.get('session_uuid', '')} "
            f"deviceCustomString1={attacker_profile} "
            f"deviceCustomString2={','.join(technique_ids)} "
            f"deviceCustomNumber1={analysis.get('anomaly_score', 0)} "
            f"deviceCustomNumber2={analysis.get('confidence', 0)} "
            f"deviceCustomString3={','.join(analysis.get('detected_tools', []))} "
            f"deviceCustomString4={','.join(analysis.get('detected_intents', []))} "
            f"destinationDnsDomain={geo.get('country', '')} "
            f"sourceGeoCountry={geo.get('country_name', '')} "
            f"sourceGeoCity={geo.get('city', '')} "
            f"sourceGeoLatitude={geo.get('lat', 0)} "
            f"sourceGeoLongitude={geo.get('lon', 0)}"
        )

        cef_header = (
            f"CEF:0|HoneySentinel|HoneySentinelAI|{settings.VERSION}|"
            f"{analysis.get('category', 'unknown').upper()}|"
            f"Attack Detected|{severity}|{extensions}"
        )

        return cef_header

    def generate_stix_report(self, session_data: Dict, analysis: Dict) -> str:
        attacker_ip = session_data.get("attacker_ip", "")
        session_uuid = session_data.get("session_uuid", "")
        attack_category = analysis.get("category", "unknown")

        identity = Identity(
            identity_class="organization",
            name="HoneySentinel AI Honeypot",
        )

        indicator_patterns = []
        if attacker_ip:
            indicator_patterns.append(
                STIXIndicator(
                    indicator_types=["malicious-activity"],
                    pattern=f"[ipv4-addr:value = '{attacker_ip}']",
                    pattern_type="stix",
                    name=f"Malicious IP: {attacker_ip}",
                    description=f"IP address observed during {attack_category} attack in session {session_uuid}",
                )
            )

        detected_tools = analysis.get("detected_tools", [])
        for tool in detected_tools:
            if isinstance(tool, dict):
                tool_name = tool.get("name", tool)
            else:
                tool_name = tool
            indicator_patterns.append(
                STIXIndicator(
                    indicator_types=["malicious-activity"],
                    pattern=f"[file:name = '{tool_name}']",
                    pattern_type="stix",
                    name=f"Offensive Tool: {tool_name}",
                    description=f"Tool detected during session {session_uuid}",
                )
            )

        mitre_techniques = analysis.get("mitre", {}).get("techniques", [])
        attack_patterns = []
        for tech in mitre_techniques:
            attack_patterns.append(
                AttackPattern(
                    name=tech.get("name", ""),
                    external_references=[{
                        "source_name": "mitre-attack",
                        "external_id": tech.get("id", ""),
                    }],
                )
            )

        bundle = Bundle(objects=[identity] + indicator_patterns + attack_patterns)
        return bundle.serialize(pretty=True)

    def generate_structured_report(self, session_data: Dict, analysis: Dict, format: str = "json") -> str:
        if format == "cef":
            return self.generate_cef_report(session_data, analysis)
        elif format == "stix":
            return self.generate_stix_report(session_data, analysis)
        else:
            return self.generate_json_report(session_data, analysis)


report_generator = ReportGenerator()
