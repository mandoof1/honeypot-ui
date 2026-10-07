from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Dict

from stix2 import AttackPattern, Bundle, Identity
from stix2 import Indicator as STIXIndicator

from app.core.config import get_settings

settings = get_settings()

#: In CEF, a backslash, equals sign or newline inside an extension value
#: terminates or corrupts the field. Attacker-controlled values (IPs, tool
#: names, intents) reached these fields unescaped, letting an attacker forge
#: additional CEF fields in whatever SIEM ingests the export.
_CEF_EXTENSION_ESCAPES = {
    "\\": "\\\\",
    "=": "\\=",
    "\n": "\\n",
    "\r": "\\r",
}

#: Header fields are pipe-delimited.
_CEF_HEADER_ESCAPES = {"\\": "\\\\", "|": "\\|"}


def _cef_extension(value) -> str:
    text = "" if value is None else str(value)
    for char, replacement in _CEF_EXTENSION_ESCAPES.items():
        text = text.replace(char, replacement)
    return text


def _cef_header(value) -> str:
    text = "" if value is None else str(value)
    for char, replacement in _CEF_HEADER_ESCAPES.items():
        text = text.replace(char, replacement)
    return text.replace("\n", " ").replace("\r", " ")


def _stix_literal(value) -> str:
    """Escape a value for a single-quoted STIX pattern literal."""
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("'", "\\'")


def _is_ipv4(value) -> bool:
    import ipaddress

    try:
        return isinstance(ipaddress.ip_address(str(value)), ipaddress.IPv4Address)
    except ValueError:
        return False


def _valid_technique_id(value) -> bool:
    return bool(re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(value or "")))


class ReportGenerator:
    def generate_json_report(self, session_data: Dict, analysis: Dict) -> str:
        report = {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
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
                "command_count": len(session_data.get("commands") or [])
                or analysis.get("command_count") or 0,
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
        technique_ids = [
            t.get("id", "")
            for t in mitre_techniques
            if isinstance(t, dict) and _valid_technique_id(t.get("id"))
        ]

        tools = [
            t.get("name", "") if isinstance(t, dict) else str(t)
            for t in (analysis.get("detected_tools") or [])
        ]

        fields = {
            "src": session_data.get("attacker_ip", ""),
            "spt": session_data.get("attacker_port", 0),
            "deviceProcessName": session_data.get("protocol", ""),
            "requestContext": session_data.get("session_uuid", ""),
            "deviceCustomString1": attacker_profile,
            "deviceCustomString2": ",".join(technique_ids),
            "deviceCustomNumber1": analysis.get("anomaly_score", 0),
            "deviceCustomNumber2": analysis.get("confidence", 0),
            "deviceCustomString3": ",".join(tools),
            "deviceCustomString4": ",".join(
                analysis.get("detected_intents") or []
            ),
            "sourceGeoCountryCode": geo.get("country", ""),
            "sourceGeoCountry": geo.get("country_name", ""),
            "sourceGeoCity": geo.get("city", ""),
            "sourceGeoLatitude": geo.get("lat", 0),
            "sourceGeoLongitude": geo.get("lon", 0),
        }
        extensions = " ".join(
            f"{key}={_cef_extension(value)}" for key, value in fields.items()
        )

        return (
            f"CEF:0|HoneySentinel|HoneySentinelAI|"
            f"{_cef_header(settings.VERSION)}|"
            f"{_cef_header(str(analysis.get('category', 'unknown')).upper())}|"
            f"Attack Detected|{severity}|{extensions}"
        )

    def generate_stix_report(self, session_data: Dict, analysis: Dict) -> str:
        attacker_ip = session_data.get("attacker_ip", "")
        session_uuid = session_data.get("session_uuid", "")
        attack_category = analysis.get("category", "unknown")

        identity = Identity(
            identity_class="organization",
            name="HoneySentinel AI Honeypot",
        )

        indicator_patterns = []
        if _is_ipv4(attacker_ip):
            indicator_patterns.append(
                STIXIndicator(
                    indicator_types=["malicious-activity"],
                    pattern=f"[ipv4-addr:value = '{_stix_literal(attacker_ip)}']",
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
                    pattern=f"[file:name = '{_stix_literal(tool_name)}']",
                    pattern_type="stix",
                    name=f"Offensive Tool: {tool_name}",
                    description=f"Tool detected during session {session_uuid}",
                )
            )

        mitre_techniques = analysis.get("mitre", {}).get("techniques", [])
        attack_patterns = []
        for tech in mitre_techniques:
            if not isinstance(tech, dict) or not _valid_technique_id(
                tech.get("id")
            ):
                continue
            attack_patterns.append(
                AttackPattern(
                    name=str(tech.get("name", ""))[:200],
                    external_references=[
                        {
                            "source_name": "mitre-attack",
                            "external_id": tech["id"],
                        }
                    ],
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
