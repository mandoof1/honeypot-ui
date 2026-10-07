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
    "metasploit": {"pattern": r"\b(?:msf|metasploit|msfconsole|msfvenom|meterpreter)\b", "category": "exploitation_framework"},
    "mimikatz": {"pattern": r"(?:\bmimikatz\b|sekurlsa|lsadump|kerberos::list)", "category": "credential_theft"},
    "nmap": {"pattern": r"\b(?:nmap|masscan|zmap)\b", "category": "scanner"},
    "burpsuite": {"pattern": r"\b(?:burp|burpsuite|intruder|repeater)\b", "category": "web_proxy"},
    "sqlmap": {"pattern": r"(?:\bsqlmap\b|sql\s*injection|union\s+select)", "category": "sql_injection"},
    "hydra": {"pattern": r"\b(?:hydra|medusa|ncrack|bruteforce)\b", "category": "password_cracker"},
    "hashcat": {"pattern": r"(?:\bhashcat\b|john\s+the\s+ripper|\bjtr\b)", "category": "password_cracker"},
    "cobalt_strike": {"pattern": r"(?:cobalt\s*strike|\bbeacon\b|c2\s*profile)", "category": "c2_framework"},
    "empire": {"pattern": r"(?:powershell\s*empire|empire\s*agent)", "category": "c2_framework"},
    "gobuster": {"pattern": r"\b(?:gobuster|dirb|dirbuster|ffuf|wfuzz|feroxbuster)\b", "category": "directory_enum"},
    "nikto": {"pattern": r"\b(?:nikto|openvas|nessus|nuclei)\b", "category": "vulnerability_scanner"},
    # Word-bounded: "nc " used to match inside "sync " and "func ", and
    # "id " inside "valid ".
    "netcat": {"pattern": r"(?:\bnc\s|\bnetcat\b|\bncat\b|\bsocat\b)", "category": "network_utility"},
    "wget_curl": {"pattern": r"\b(?:wget|curl)\s+[^\n]{0,400}?(?:-o\s|--output|-O\s)", "category": "file_download"},
    "chmod_chown": {"pattern": r"(?:\bchmod\s+[0-7]{3,4}\b|\bchown\s)", "category": "privilege_modification"},
    "reverse_shell": {"pattern": r"(?:/dev/tcp/|\bbash\s+-i\b|python[23]?\s+-c\s+[^\n]{0,200}pty|\bnc\s+[^\n]{0,100}-e\s|\bmkfifo\b)", "category": "reverse_shell"},
    "lateral_movement": {"pattern": r"(?:\bpsexec\b|\bwmic\b|\bssh\s+[^\n]{0,100}@|\brdp\b|\brdesktop\b|\bxfreerdp\b|\bsmbclient\b|\bproxychains\b)", "category": "lateral_movement"},
    "data_exfil": {"pattern": r"(?:\bbase64\s+-d\b|\btar\s+[^\n]{0,200}\|[^\n]{0,100}\b(?:nc|curl)\b|\bscp\s+|\brsync\s+|\bcurl\s+[^\n]{0,200}(?:-T\s|--upload-file|-F\s|-d\s*@))", "category": "exfiltration"},
    "persistence": {"pattern": r"(?:\bcrontab\b|systemctl\s+enable|rc\.local|\.bashrc\b|authorized_keys|/etc/init\.d/|chattr\s+\+i)", "category": "persistence"},
    "enum_linux": {"pattern": r"(?:\buname\s+-a\b|cat\s+/etc/passwd|\bid\s|\bwhoami\b|sudo\s+-l\b|/proc/cpuinfo|\bnproc\b|\blscpu\b)", "category": "reconnaissance"},
    "enum_windows": {"pattern": r"(?:\bsysteminfo\b|net\s+user\b|net\s+localgroup\b|ipconfig\s+/all)", "category": "reconnaissance"},
    "cryptominer": {"pattern": r"(?:\bxmrig\b|\bminerd\b|\bcpuminer\b|stratum\+tcp|\bkdevtmpfsi\b|\bkinsing\b|\bxmr\b|monero|\bminexmr\b|\bnanopool\b|\bsupportxmr\b)", "category": "cryptomining"},
    "busybox_bot": {"pattern": r"(?:/bin/busybox\s+\w+|\bbusybox\s+(?:wget|tftp|ftpget)\b|\btftp\s+-g\b|\bftpget\b)", "category": "iot_botnet"},
}

#: Web-exploitation signatures matched against the request text itself (the
#: HTTP decoy records each request line as a "command"). The flow classifier is
#: blind to these — they live in the payload, not the flow shape — and the tool
#: table above only catches sqlmap-style strings, so web probes used to leave no
#: category behind. Each maps to one of the engine's category tags, consumed by
#: the analysis pipeline's rule-based category.
WEB_ATTACK_SIGNATURES = {
    "sql_injection": r"(?:union(?:\s|\+|%20)+(?:all(?:\s|\+|%20)+)?select|'\s*or\s*'?1'?\s*=\s*'?1|\bor\s+1=1\b|;\s*drop\s+table|sleep\(\d|benchmark\(|waitfor\s+delay)",
    "xss": r"(?:<script|%3cscript|onerror\s*=|onerror%3d|javascript:|<svg[^>]*onload)",
    "path_traversal": r"(?:\.\./\.\.|\.\.%2f|\.\.\\|/etc/passwd|/etc/shadow|%2fetc%2f|\.\.%252f)",
    "log4shell": r"(?:\$\{jndi:|%24%7bjndi|\$\{\$\{)",
    "command_injection": r"(?:;\s*(?:id|whoami|uname)\b|\|\s*(?:bash|sh)\b|\$\(.*\)|/dev/tcp/|%60|`[^`\n]{1,80}`)",
    "lfi_rfi": r"(?:php://(?:filter|input)|data://text|expect://|/proc/self/environ)",
    "webshell": r"(?:<\?php|eval\(\$_(?:get|post|request|server)|system\(\$_|passthru\(|assert\(\$_|\bcmd=|shell_exec\()",
    "ssrf": r"(?:169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data/)",
}

#: Which of the four stored classes each web signature implies.
WEB_ATTACK_CATEGORY = {
    "sql_injection": "exploitation",
    "xss": "exploitation",
    "command_injection": "exploitation",
    "log4shell": "exploitation",
    "lfi_rfi": "exploitation",
    "webshell": "exploitation",
    "ssrf": "exploitation",
    "path_traversal": "reconnaissance",
}

#: Intent signatures over shell/FTP command text. Every entry is a regex with
#: word boundaries where a bare substring used to fire on ordinary text: the
#: old keyword lists matched "admin" inside a shop URL as privilege escalation,
#: "upload" in /wp-content/uploads/ as exfiltration, "bot" in Googlebot as a
#: botnet, and "rdp" inside "wordpress" as lateral movement — which is how an
#: analyst browsing the decoy shop produced CRITICAL alerts.
ATTACK_INTENTS = {
    "credential_harvesting": [
        r"/etc/shadow", r"\bmimikatz\b", r"\blsass\b", r"\bntds\b", r"\bhashdump\b",
        r"\bid_rsa\b", r"\.ssh/id_", r"\bcredential", r"\bpassword[s]?\.(?:txt|db|lst)\b",
        r"\bkeylog", r"/etc/passwd\s*>", r"\bsekurlsa\b", r"\bgetcreds?\b",
    ],
    "privilege_escalation": [
        r"\bsudo\b", r"\bsu\s+-?\s*root\b", r"\bsu\s*$", r"\bsetuid\b", r"\bsuid\b",
        r"chmod\s+[ug]\+s", r"\bescalat", r"\bpkexec\b", r"\bdirtyc0w\b|\bdirty_?cow\b",
        r"\bpwnkit\b", r"passwd\s+root\b",
    ],
    "reconnaissance": [
        r"\bnmap\b", r"\bmasscan\b", r"\bscan\b", r"\benum\b", r"\bprobe\b", r"\bdiscover",
        r"\bwhoami\b", r"\buname\b", r"/proc/cpuinfo", r"\bnproc\b", r"\blscpu\b",
        r"\bifconfig\b", r"\bip\s+(?:a|addr|route|r)\b", r"\bnetstat\b", r"\bss\s+-", r"\barp\s+-a\b",
        r"cat\s+/etc/(?:passwd|issue|os-release|hostname)", r"\blsb_release\b",
    ],
    "lateral_movement": [
        r"\bpivot", r"\blateral\b", r"\bpsexec\b", r"\bwmic\b", r"\bssh\s+[^\n]{0,100}@",
        r"\brdesktop\b", r"\bxfreerdp\b", r"\bsmbclient\b", r"\bproxychains\b", r"\bchisel\b",
        r"\bsshpass\b",
    ],
    "data_exfiltration": [
        r"\bexfil", r"\bsteal\b", r"\bscp\s+\S+\s+\S+@", r"\brsync\s+[^\n]{0,200}@",
        r"\bcurl\s+[^\n]{0,200}(?:-T\s|--upload-file|-F\s|-d\s*@)",
        r"\btar\s+[^\n]{0,200}\|[^\n]{0,100}\b(?:nc|curl|ncat)\b",
        r"\bbase64\s+[^\n]{0,100}\|[^\n]{0,100}\bcurl\b", r"\bnc\s+[^\n]{0,100}<\s*\S+",
        r"\bmysqldump\b", r"\bpg_dump\b",
    ],
    "persistence": [
        r"\bpersist", r"\bbackdoor\b", r"\bcrontab\b", r"\bcron\b", r"authorized_keys",
        r"\.bashrc\b", r"\.profile\b", r"rc\.local", r"systemctl\s+enable", r"/etc/init\.d/",
        r"\buseradd\b", r"\badduser\b", r"chattr\s+\+i", r"/etc/ld\.so\.preload", r"\bnohup\b",
    ],
    "denial_of_service": [
        r"\bflood\b", r"\bddos\b", r"\bdos\b", r"\bhping3?\b", r"\bslowloris\b", r"\bstress\b",
        r"\bexhaust",
    ],
    "defacement": [
        r"\bdeface", r"\bvandal", r">\s*/var/www/[^\n]*index\.", r"\bhacked\s+by\b",
    ],
    "ransomware": [
        r"\bransom", r"\bencrypt(?:ed|ing|or)?\b", r"\bbitcoin\b", r"\bbtc\b", r"\.locked\b",
        r"openssl\s+enc\b", r"\bgpg\s+-c\b", r"\bdecrypt(?:or|ion)?\s+(?:key|instructions)",
    ],
    "cryptomining": [
        r"\bxmrig\b", r"\bminerd\b", r"\bcpuminer\b", r"stratum\+tcp", r"\bkdevtmpfsi\b",
        r"\bkinsing\b", r"\bxmr\b", r"\bmonero\b", r"\bminexmr\b", r"\bnanopool\b",
        r"\bsupportxmr\b", r"\bhashrate\b", r"\bminer\b",
    ],
    "botnet": [
        r"\bc2\b", r"\bcnc\b", r"\bbeacon\b", r"\bbotnet\b", r"\bmirai\b", r"\bmozi\b",
        r"\bgafgyt\b", r"\bbashlite\b", r"\bcallback\b", r"/bin/busybox\s+\w+",
        r"\bbusybox\s+(?:wget|tftp|ftpget)\b", r"\btftp\s+-g\b", r"\bcheckin\b",
    ],
}

_INTENT_PATTERNS = {
    intent: re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)
    for intent, patterns in ATTACK_INTENTS.items()
}
_TOOL_PATTERNS = {
    name: re.compile(info["pattern"], re.IGNORECASE) for name, info in OFFENSIVE_TOOLS.items()
}
_WEB_PATTERNS = {
    name: re.compile(pattern, re.IGNORECASE) for name, pattern in WEB_ATTACK_SIGNATURES.items()
}

#: Protocols whose "commands" are HTTP request lines plus headers and bodies.
_WEB_PROTOCOLS = {"http", "https"}

#: The decoy appends the user agent to each recorded request as
#: ``  [ua: ...]``; see honeypot/emulators/http.py.
_UA_SUFFIX = re.compile(r"\s+\[ua: [^\]\n]*\]")
_UA_VALUE = re.compile(r"\[ua: ([^\]\n]*)\]")

#: Tools that announce themselves in the User-Agent. Only these names are
#: read from the agent string; a browser or crawler agent is not evidence.
_UA_TOOLS = {
    "sqlmap": ("sqlmap", "sql_injection"),
    "nikto": ("nikto", "vulnerability_scanner"),
    "nuclei": ("nuclei", "vulnerability_scanner"),
    "gobuster": ("gobuster", "directory_enum"),
    "dirbuster": ("dirbuster", "directory_enum"),
    "ffuf": ("ffuf", "directory_enum"),
    "wfuzz": ("wfuzz", "directory_enum"),
    "masscan": ("masscan", "scanner"),
    "zgrab": ("zgrab", "scanner"),
    "nmap": ("nmap", "scanner"),
    "wpscan": ("wpscan", "vulnerability_scanner"),
    "acunetix": ("acunetix", "vulnerability_scanner"),
    "nessus": ("nessus", "vulnerability_scanner"),
    "openvas": ("openvas", "vulnerability_scanner"),
    "hydra": ("hydra", "password_cracker"),
    "metasploit": ("metasploit", "exploitation_framework"),
}
_UA_TOOL_PATTERN = re.compile(r"\b(" + "|".join(map(re.escape, _UA_TOOLS)) + r")\b", re.IGNORECASE)


def _intent_text_for_web(commands: List[str]) -> str:
    """The part of recorded HTTP requests that intent rules may read.

    Request lines and user agents are left out: a path like
    ``/admin/orders`` or a crawler's user agent is not evidence of intent,
    and both were the source of most false alerts. Bodies (form posts, JSON,
    uploaded scripts) are where shell-style intent shows up in web traffic,
    so those stay in. Web-attack signatures still run over the whole text.
    """
    bodies = []
    for command in commands:
        head, sep, body = command.partition("\n")
        if sep and body.strip():
            bodies.append(body)
    return "\n".join(bodies)


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

    def analyze_commands(self, commands: List[str], protocol: Optional[str] = None) -> Dict:
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

        is_web = (protocol or "").lower() in _WEB_PROTOCOLS
        # Tool and intent rules are written for shell text. On web sessions the
        # request line and user agent are stripped first; the web signatures
        # below still see everything.
        if is_web:
            bodies = _intent_text_for_web(commands)
            body_text = (
                deobfuscate_commands([bodies]).combined.lower()[: self.MAX_ANALYSIS_CHARS]
                if bodies else ""
            )
        else:
            body_text = full_text

        if is_web:
            for command in commands:
                for match in _UA_VALUE.finditer(command):
                    hit = _UA_TOOL_PATTERN.search(match.group(1))
                    if hit:
                        name, category = _UA_TOOLS[hit.group(1).lower()]
                        if name not in tool_names:
                            tool_names.add(name)
                            categories.add(category)
                            detected_tools.append(
                                {"name": name, "category": category, "confidence": 0.9}
                            )

        for tool_name, pattern in _TOOL_PATTERNS.items():
            if pattern.search(body_text):
                tool_info = OFFENSIVE_TOOLS[tool_name]
                tool_names.add(tool_name)
                categories.add(tool_info["category"])
                detected_tools.append({
                    "name": tool_name,
                    "category": tool_info["category"],
                    "confidence": 0.85,
                })

        # Web-exploitation signatures over the raw request text.
        web_attacks: Set[str] = set()
        for name, pattern in _WEB_PATTERNS.items():
            if pattern.search(full_text):
                web_attacks.add(name)
                categories.add(name)
                detected_intents.add("web_exploitation")

        for intent, pattern in _INTENT_PATTERNS.items():
            if pattern.search(body_text):
                detected_intents.add(intent)

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
