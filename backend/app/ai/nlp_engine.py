from __future__ import annotations
import logging
import math
import re
from collections import Counter

import spacy
from typing import List, Dict, Optional, Set

from app.ai.deobfuscate import deobfuscate_commands
from app.core.config import get_settings

logger = logging.getLogger(__name__)
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

#: Web-exploitation signatures matched against the request text itself (the
#: HTTP decoy records each request line as a "command"). The flow classifier is
#: blind to these — they live in the payload, not the flow shape — and the tool
#: table above only catches sqlmap-style strings, so web probes used to leave no
#: category behind. Each maps to one of the engine's category tags, consumed by
#: the analysis pipeline's rule-based category.
WEB_ATTACK_SIGNATURES = {
    "sql_injection": r"(?:union(?:\s|\+|%20)+select|'\s*or\s*'?1'?\s*=\s*'?1|\bor\s+1=1\b|;\s*drop\s+table|sleep\(\d|benchmark\()",
    "xss": r"(?:<script|%3cscript|onerror\s*=|onerror%3d|javascript:)",
    "path_traversal": r"(?:\.\./\.\.|\.\.%2f|\.\.\\|/etc/passwd|/etc/shadow|%2fetc%2f)",
    "log4shell": r"(?:\$\{jndi:|%24%7bjndi)",
    "command_injection": r"(?:;\s*(?:id|whoami|uname)\b|\|\s*(?:bash|sh)\b|\$\(.*\)|/dev/tcp/)",
    "lfi_rfi": r"(?:php://(?:filter|input)|data://text|expect://)",
    "webshell": r"(?:<\?php|eval\(\$_(?:get|post|request|server)|system\(\$_|passthru\(|assert\(\$_)",
}

#: Which of the four stored classes each web signature implies.
WEB_ATTACK_CATEGORY = {
    "sql_injection": "exploitation",
    "xss": "exploitation",
    "command_injection": "exploitation",
    "log4shell": "exploitation",
    "lfi_rfi": "exploitation",
    "webshell": "exploitation",
    "path_traversal": "reconnaissance",
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
    MAX_ANALYSIS_CHARS = 100_000

    def __init__(self):
        self.nlp: Optional[spacy.language.Language] = None
        self._loaded = False

    def _ensure_loaded(self):
        """Load the spaCy model once, tolerating its absence.

        Downloading a model at request time (the previous behaviour) needs
        network access and write permission inside the container, and blocks
        the event loop for tens of seconds. Install it at build time instead;
        if it is missing we degrade to regex-only analysis rather than failing
        the whole ingest.
        """
        if self._loaded:
            return
        try:
            self.nlp = spacy.load(settings.SPACY_MODEL)
        except (OSError, IOError):
            logger.warning(
                "spaCy model %r unavailable; named-entity extraction disabled. "
                "Install it with: python -m spacy download %s",
                settings.SPACY_MODEL,
                settings.SPACY_MODEL,
            )
            self.nlp = None
        self._loaded = True

    def _entities(self, text: str) -> List[tuple]:
        self._ensure_loaded()
        if self.nlp is None or not text:
            return []
        # spaCy's default max_length is 1_000_000 chars; attacker-controlled
        # input should never get near it.
        return [
            (ent.text, ent.label_)
            for ent in self.nlp(text[: self.MAX_ANALYSIS_CHARS]).ents
        ]

    def analyze_commands(self, commands: List[str]) -> Dict:
        detected_tools: List[Dict] = []
        detected_intents: Set[str] = set()
        tool_names: Set[str] = set()
        categories: Set[str] = set()

        # Decode nested encodings first, then match over the original *and*
        # everything recovered from it. The expert interviews in section V.B.2
        # asked for exactly this: an outer command is deliberately unremarkable,
        # and the payload naming the C2 host only appears once it is unwrapped.
        decoded = deobfuscate_commands(commands)
        full_text = decoded.combined.lower()[: self.MAX_ANALYSIS_CHARS]

        for tool_name, tool_info in OFFENSIVE_TOOLS.items():
            if re.search(tool_info["pattern"], full_text):
                tool_names.add(tool_name)
                categories.add(tool_info["category"])
                detected_tools.append({
                    "name": tool_name,
                    "category": tool_info["category"],
                    "confidence": 0.85,
                })

        # Web-exploitation signatures over the raw request text.
        web_attacks: Set[str] = set()
        for name, pattern in WEB_ATTACK_SIGNATURES.items():
            if re.search(pattern, full_text):
                web_attacks.add(name)
                categories.add(name)
                detected_intents.add("web_exploitation")

        for intent, keywords in ATTACK_INTENTS.items():
            for keyword in keywords:
                if keyword in full_text:
                    detected_intents.add(intent)
                    break

        entities = self._entities(full_text)

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
            "web_attacks": list(web_attacks),
            "entities": entities,
            "extracted_ips": ips,
            "extracted_urls": urls,
            "extracted_files": files,
            "complexity_score": complexity_score,
            "command_count": len(commands),
            # Surfaced so an analyst can see the decode chain rather than
            # having to trust that something was unwrapped.
            "deobfuscation": decoded.as_dict(),
            "is_obfuscated": bool(decoded.layers),
        }

    def analyze_payload(self, payload: str) -> Dict:
        payload = payload[: self.MAX_ANALYSIS_CHARS]
        lowered = payload.lower()
        results = {
            "is_suspicious": False,
            "suspicion_score": 0.0,
            "detected_patterns": [],
            "language_indicators": [],
        }

        for tool_name, tool_info in OFFENSIVE_TOOLS.items():
            if re.search(tool_info["pattern"], lowered):
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
            if keyword in lowered:
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
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )


nlp_engine = NLPEngine()
