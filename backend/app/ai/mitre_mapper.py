from __future__ import annotations
from typing import Dict, List, Set, Optional

MITRE_ATTACK_MAP = {
    "reconnaissance": {
        "tactic": {"id": "TA0043", "name": "Reconnaissance"},
        "techniques": {
            "nmap": {"id": "T1046", "name": "Network Service Discovery"},
            "nikto": {"id": "T1595", "name": "Active Scanning"},
            "gobuster": {"id": "T1595.001", "name": "Scanning IP Blocks"},
            "enum_linux": {"id": "T1082", "name": "System Information Discovery"},
            "enum_windows": {"id": "T1082", "name": "System Information Discovery"},
            "port_scan": {"id": "T1046", "name": "Network Service Scanning"},
        },
    },
    "exploitation": {
        "tactic": {"id": "TA0001", "name": "Initial Access"},
        "techniques": {
            "metasploit": {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
            "sqlmap": {"id": "T1190", "name": "Exploit Public-Facing Application"},
            "reverse_shell": {"id": "T1059", "name": "Command and Scripting Interpreter"},
            "ssh_brute": {"id": "T1110.001", "name": "Password Guessing"},
            "ftp_brute": {"id": "T1110.001", "name": "Password Guessing"},
            "rdp_exploit": {"id": "T1190", "name": "Exploit Public-Facing Application"},
        },
    },
    "credential_theft": {
        "tactic": {"id": "TA0006", "name": "Credential Access"},
        "techniques": {
            "mimikatz": {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory"},
            "hydra": {"id": "T1110", "name": "Brute Force"},
            "hashcat": {"id": "T1110", "name": "Brute Force"},
            "credential_harvesting": {"id": "T1555", "name": "Credentials from Password Stores"},
        },
    },
    "privilege_escalation": {
        "tactic": {"id": "TA0004", "name": "Privilege Escalation"},
        "techniques": {
            "chmod_chown": {"id": "T1222", "name": "File and Directory Permissions Modification"},
            "sudo_exploit": {"id": "T1548.003", "name": "Sudo and Sudo Caching"},
            "privilege_escalation": {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
        },
    },
    "lateral_movement": {
        "tactic": {"id": "TA0008", "name": "Lateral Movement"},
        "techniques": {
            "lateral_movement": {"id": "T1021", "name": "Remote Services"},
            "psexec": {"id": "T1570", "name": "Lateral Tool Transfer"},
            "ssh_pivot": {"id": "T1021.004", "name": "SSH"},
            "rdp": {"id": "T1021.001", "name": "Remote Desktop Protocol"},
        },
    },
    "persistence": {
        "tactic": {"id": "TA0003", "name": "Persistence"},
        "techniques": {
            "persistence": {"id": "T1053", "name": "Scheduled Task/Job"},
            "crontab": {"id": "T1053.003", "name": "Cron"},
            "systemd": {"id": "T1543.002", "name": "Systemd Service"},
            "backdoor": {"id": "T1571", "name": "Non-Standard Port"},
        },
    },
    "exfiltration": {
        "tactic": {"id": "TA0010", "name": "Exfiltration"},
        "techniques": {
            "data_exfil": {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
            "wget_curl": {"id": "T1105", "name": "Ingress Tool Transfer"},
            "base64": {"id": "T1027", "name": "Obfuscated Files or Information"},
            "scp_transfer": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"},
        },
    },
    "command_and_control": {
        "tactic": {"id": "TA0011", "name": "Command and Control"},
        "techniques": {
            "cobalt_strike": {"id": "T1071", "name": "Application Layer Protocol"},
            "empire": {"id": "T1071.001", "name": "Web Protocols"},
            "botnet": {"id": "T1095", "name": "Non-Application Layer Protocol"},
            "netcat": {"id": "T1571", "name": "Non-Standard Port"},
        },
    },
    "defense_evasion": {
        "tactic": {"id": "TA0005", "name": "Defense Evasion"},
        "techniques": {
            "obfuscation": {"id": "T1027", "name": "Obfuscated Files or Information"},
            "timestomp": {"id": "T1070.006", "name": "Timestomp"},
            "disable_logging": {"id": "T1070", "name": "Indicator Removal"},
        },
    },
    "impact": {
        "tactic": {"id": "TA0040", "name": "Impact"},
        "techniques": {
            "ransomware": {"id": "T1486", "name": "Data Encrypted for Impact"},
            "denial_of_service": {"id": "T1498", "name": "Network Denial of Service"},
            "defacement": {"id": "T1491.001", "name": "Defacement: Internal Defacement"},
            "data_destruction": {"id": "T1485", "name": "Data Destruction"},
        },
    },
}

TACTIC_COLORS = {
    "TA0043": "#8b5cf6",
    "TA0001": "#ef4444",
    "TA0006": "#f59e0b",
    "TA0004": "#10b981",
    "TA0008": "#3b82f6",
    "TA0003": "#6366f1",
    "TA0010": "#ec4899",
    "TA0011": "#14b8a6",
    "TA0005": "#84cc16",
    "TA0040": "#dc2626",
}


class MitreAttckMapper:
    def map_analysis(self, nlp_results: Dict, ai_results: Dict, session_data: Dict) -> Dict:
        detected_tactics: Set[str] = set()
        detected_techniques: List[Dict] = []
        matched_tools: Set[str] = set()

        tool_names = set(nlp_results.get("tool_names", []))
        categories = set(nlp_results.get("categories", []))
        intents = set(nlp_results.get("detected_intents", []))
        attack_category = ai_results.get("category", "")

        for tactic_key, tactic_data in MITRE_ATTACK_MAP.items():
            tactic_matched = False

            for tool_name in tool_names:
                if tool_name in tactic_data["techniques"]:
                    tech = tactic_data["techniques"][tool_name]
                    technique_entry = {
                        "id": tech["id"],
                        "name": tech["name"],
                        "source": f"tool:{tool_name}",
                        "confidence": 0.85,
                    }
                    if technique_entry not in detected_techniques:
                        detected_techniques.append(technique_entry)
                        tactic_matched = True
                        matched_tools.add(tool_name)

            for cat in categories:
                if cat == tactic_key:
                    tactic_matched = True

            for intent in intents:
                if intent in tactic_data["techniques"]:
                    tech = tactic_data["techniques"][intent]
                    technique_entry = {
                        "id": tech["id"],
                        "name": tech["name"],
                        "source": f"intent:{intent}",
                        "confidence": 0.7,
                    }
                    if technique_entry not in detected_techniques:
                        detected_techniques.append(technique_entry)
                        tactic_matched = True

            if attack_category == "reconnaissance" and tactic_key == "reconnaissance":
                tactic_matched = True
            elif attack_category == "exploitation" and tactic_key == "exploitation":
                tactic_matched = True
            elif attack_category == "exfiltration" and tactic_key == "exfiltration":
                tactic_matched = True

            if tactic_matched:
                tactic_info = tactic_data["tactic"]
                detected_tactics.add(tactic_info["id"])

        tactics_list = []
        for tactic_id in detected_tactics:
            for tactic_data in MITRE_ATTACK_MAP.values():
                if tactic_data["tactic"]["id"] == tactic_id:
                    tactics_list.append({
                        "id": tactic_id,
                        "name": tactic_data["tactic"]["name"],
                        "color": TACTIC_COLORS.get(tactic_id, "#6b7280"),
                    })
                    break

        return {
            "tactics": tactics_list,
            "tactic_ids": list(detected_tactics),
            "techniques": detected_techniques,
            "matched_tools": list(matched_tools),
            "coverage_score": round(len(detected_tactics) / len(MITRE_ATTACK_MAP), 3),
        }

    def get_full_framework(self) -> Dict:
        return {
            tactic_data["tactic"]["id"]: {
                "tactic": tactic_data["tactic"],
                "color": TACTIC_COLORS.get(tactic_data["tactic"]["id"], "#6b7280"),
                "techniques": list(tactic_data["techniques"].values()),
            }
            for tactic_data in MITRE_ATTACK_MAP.values()
        }


mitre_mapper = MitreAttckMapper()
