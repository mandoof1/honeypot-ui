from __future__ import annotations
import re
import spacy
from typing import List, Dict, Optional, Set
from app.core.config import get_settings

settings = get_settings()

OFFENSIVE_TOOLS = {
    "metasploit": {"pattern": r"(?:msf|metasploit|msfconsole|meterpreter)", "category": "exploitation_framework"},
    "mimikatz": {"pattern": r"(?:mimikatz|sekurlsa|lsadump|kerberos::list)", "category": "credential_theft"},
    "nmap": {"pattern": r"(?:nmap|nmap\s+-|masscan|zmap)", "category": "scanner"},
    "burpsuite": {"pattern": r"(?:burp|burpsuite|intruder|repeater)", "category": "web_proxy"},
    "sqlmap": {"pattern": r"(?:sqlmap|sql\s*injection|union\s+select)", "category": "sql_injection"},
    "hydra": {"pattern": r"(?:hydra|medusa|ncrack|bruteforce)", "category": "password_cracker"},
    "hashcat": {"pattern": r"(?:hashcat|john\s+the\s+ripper|jtr)", "category": "password_cracker"},
    "cobalt_strike": {"pattern": r"(?:cobalt\s*strike|beacon|c2\s*profile)", "category": "c2_framework"},
    "empire": {"pattern": r"(?:powershell\s*empire|empire\s*agent)", "category": "c2_framework"},
    "gobuster": {"pattern": r"(?:gobuster|dirb|dirbuster|ffuf|wfuzz)", "category": "directory_enum"},
    "nikto": {"pattern": r"(?:nikto|openvas|nessus)", "category": "vulnerability_scanner"},
    "netcat": {"pattern": r"(?:nc\s|netcat|ncat|socat)", "category": "network_utility"},
    "wget_curl": {"pattern": r"(?:wget|curl)\s+.*(?:-o|--output)", "category": "file_download"},
    "chmod_chown": {"pattern": r"(?:chmod\s+[0-7]{3,4}|chown\s)", "category": "privilege_modification"},
    "reverse_shell": {"pattern": r"(?:/dev/tcp|bash\s+-i|python.*pty|nc\s+-e|mkfifo)", "category": "reverse_shell"},
    "lateral_movement": {"pattern": r"(?:psexec|wmic|ssh\s+.*@|rdp|rdesktop)", "category": "lateral_movement"},
    "data_exfil": {"pattern": r"(?:base64\s+-d|tar\s+.*\|.*nc|scp\s+|rsync\s+)", "category": "exfiltration"},
    "persistence": {"pattern": r"(?:crontab|systemctl\s+enable|rc\.local|\.bashrc)", "category": "persistence"},
    "enum_linux": {"pattern": r"(?:uname\s+-a|cat\s+/etc/passwd|id\s|whoami|sudo\s+-l)", "category": "reconnaissance"},
    "enum_windows": {"pattern": r"(?:systeminfo|net\s+user|net\s+localgroup|ipconfig\s+/all)", "category": "reconnaissance"},
}

ATTACK_INTENTS = {
    "credential_harvesting": ["password", "credential", "hash", "dump", "lsass", "sam", "shadow", "ntds"],
    "privilege_escalation": ["sudo", "root", "admin", "privilege", "escalat", "setuid", "suid"],
    "reconnaissance": ["scan", "enum", "discover", "probe", "nmap", "port", "service", "version"],
    "lateral_movement": ["pivot", "lateral", "internal", "network", "share", "remote"],
    "data_exfiltration": ["exfil", "extract", "steal", "download", "upload", "transfer", "copy"],
    "persistence": ["persist", "backdoor", "cron", "service", "startup", "registry"],
    "denial_of_service": ["flood", "dos", "ddos", "stress", "overload", "exhaust"],
    "defacement": ["deface", "modify", "replace", "overwrite", "vandal"],
    "ransomware": ["encrypt", "ransom", "bitcoin", "decrypt", "locked"],
    "botnet": ["bot", "c2", "command", "control", "beacon", "callback"],
}


class NLPEngine:
    def __init__(self):
        self.nlp: Optional[spacy.language.Language] = None
        self._load_model()

    def _load_model(self):
        try:
            self.nlp = spacy.load(settings.SPACY_MODEL)
        except OSError:
            import subprocess
            subprocess.run(["python", "-m", "spacy", "download", settings.SPACY_MODEL], check=True)
            self.nlp = spacy.load(settings.SPACY_MODEL)

    def analyze_commands(self, commands: List[str]) -> Dict:
        detected_tools: List[Dict] = []
        detected_intents: Set[str] = set()
        tool_names: Set[str] = set()
        categories: Set[str] = set()

        full_text = " ".join(commands).lower()

        for tool_name, tool_info in OFFENSIVE_TOOLS.items():
            if re.search(tool_info["pattern"], full_text):
                tool_names.add(tool_name)
                categories.add(tool_info["category"])
                detected_tools.append({
                    "name": tool_name,
                    "category": tool_info["category"],
                    "confidence": 0.85,
                })

        for intent, keywords in ATTACK_INTENTS.items():
            for keyword in keywords:
                if keyword in full_text:
                    detected_intents.add(intent)
                    break

        doc = self.nlp(full_text)
        entities = [(ent.text, ent.label_) for ent in doc.ents]

        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ips = re.findall(ip_pattern, full_text)

        url_pattern = r"https?://\S+|ftp://\S+"
        urls = re.findall(url_pattern, full_text)

        file_pattern = r"(?:/[\w./\-]+|[\w]+\.\w{2,4})"
        files = list(set(re.findall(file_pattern, full_text)))[:20]

        complexity_score = self._calculate_complexity(commands)

        return {
            "detected_tools": detected_tools,
            "tool_names": list(tool_names),
            "detected_intents": list(detected_intents),
            "categories": list(categories),
            "entities": entities,
            "extracted_ips": ips,
            "extracted_urls": urls,
            "extracted_files": files,
            "complexity_score": complexity_score,
            "command_count": len(commands),
        }

    def analyze_payload(self, payload: str) -> Dict:
        doc = self.nlp(payload.lower())
        results = {
            "is_suspicious": False,
            "suspicion_score": 0.0,
            "detected_patterns": [],
            "language_indicators": [],
        }

        for tool_name, tool_info in OFFENSIVE_TOOLS.items():
            if re.search(tool_info["pattern"], payload.lower()):
                results["detected_patterns"].append({
                    "tool": tool_name,
                    "category": tool_info["category"],
                })
                results["suspicion_score"] += 0.3

        suspicious_keywords = [
            "exec", "eval", "system", "shell", "cmd", "command",
            "exploit", "payload", "shellcode", "nop", "overflow",
            "injection", "traversal", "bypass", "encode", "decode",
        ]
        for keyword in suspicious_keywords:
            if keyword in payload.lower():
                results["detected_patterns"].append({"keyword": keyword})
                results["suspicion_score"] += 0.1

        if len(payload) > 1000:
            results["suspicion_score"] += 0.1

        entropy = self._shannon_entropy(payload)
        if entropy > 4.5:
            results["suspicion_score"] += 0.15
            results["language_indicators"].append("high_entropy")

        results["suspicion_score"] = min(results["suspicion_score"], 1.0)
        results["is_suspicious"] = results["suspicion_score"] > 0.3

        return results

    def _calculate_complexity(self, commands: List[str]) -> float:
        if not commands:
            return 0.0
        unique_ratio = len(set(commands)) / len(commands)
        avg_length = sum(len(c) for c in commands) / len(commands)
        pipe_count = sum(c.count("|") for c in commands)
        redirect_count = sum(c.count(">") + c.count(">>") for c in commands)
        special_chars = sum(1 for c in " ".join(commands) if c in "&;`$(){}[]")

        score = (unique_ratio * 0.2 +
                 min(avg_length / 100, 1) * 0.2 +
                 min(pipe_count / 5, 1) * 0.2 +
                 min(redirect_count / 3, 1) * 0.15 +
                 min(special_chars / 20, 1) * 0.25)
        return round(min(score, 1.0), 3)

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        import numpy as np
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        return -sum((count / length) * np.log2(count / length) for count in freq.values())


nlp_engine = NLPEngine()
