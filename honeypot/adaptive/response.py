import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from honeypot.core.config import config
from honeypot.core.session import session_manager

logger = logging.getLogger(__name__)


class ThreatActorType(str, Enum):
    AUTOMATED_BOT = "automated_bot"
    SCRIPT_KIDDIE = "script_kiddie"
    SKILLED_ATTACKER = "skilled_attacker"
    APT = "apt"
    UNKNOWN = "unknown"


@dataclass
class ActorProfile:
    ip_address: str
    actor_type: ThreatActorType = ThreatActorType.UNKNOWN
    confidence: float = 0.0
    session_count: int = 0
    total_commands: int = 0
    unique_commands: int = 0
    auth_attempts: int = 0
    attack_techniques: list[str] = field(default_factory=list)
    tools_detected: list[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    session_ids: list[str] = field(default_factory=list)
    risk_score: float = 0.0


class AdaptiveEngine:
    def __init__(self):
        self._profiles: dict[str, ActorProfile] = {}
        self._command_patterns: dict[str, list[str]] = {
            ThreatActorType.AUTOMATED_BOT: [
                "wget", "curl", "python -c", "perl -e", "base64",
                "/bin/sh", "nc -e", "bash -i",
            ],
            ThreatActorType.SCRIPT_KIDDIE: [
                "nmap", "nikto", "sqlmap", "dirb", "gobuster",
                "hydra", "metasploit", "msfconsole",
                "uname -a", "whoami", "id", "cat /etc/passwd",
            ],
            ThreatActorType.SKILLED_ATTACKER: [
                "chmod", "chown", "sudo", "su ",
                "iptables", "netstat", "ss ",
                "find / -perm", "find / -writable",
                "crontab", "systemctl",
            ],
            ThreatActorType.APT: [
                "mimikatz", "secretsdump", "bloodhound",
                "kerberoast", "golden ticket", "dcsync",
                "lateral movement", "pass the hash",
                "cobalt strike", "empire",
            ],
        }
        self._tool_signatures = {
            "nmap": ["nmap", "nse", "nmap scripting"],
            "metasploit": ["metasploit", "msf", "meterpreter", "payload"],
            "nikto": ["nikto", "nikto scan"],
            "sqlmap": ["sqlmap", "sql injection"],
            "burp": ["burp", "intruder", "repeater"],
            "hydra": ["hydra", "brute force"],
            "mimikatz": ["mimikatz", "sekurlsa", "lsadump"],
            # Named, not guessed at. This list used to end with "c2": two
            # characters that occur in base64, hex, hostnames and file names,
            # so an ordinary dropper session was labelled Cobalt Strike and,
            # from that, APT.
            "cobalt_strike": ["cobalt strike", "cobaltstrike"],
            "masscan": ["masscan"],
            "gobuster": ["gobuster", "dirbuster"],
            "dirb": ["dirb", "dirbuster"],
        }

    async def profile_actor(self, session_id: str, ip: str, indicators: dict):
        """Update a source's profile and label the session with it.

        Governed by ``HONEYPOT_ADAPTIVE_RESPONSE``. The switch used to change
        nothing: profiling ran either way and its result went nowhere. Now,
        on, the label reaches the backend as the session's
        ``threat_profile``; off, no profile is kept and none is sent. It is
        a keyword heuristic and is reported as one — it does not alter what
        the decoy answers.
        """
        if not config.adaptive_response:
            return
        profile = await self._get_or_create_profile(ip)
        profile.last_seen = time.time()

        if session_id not in profile.session_ids:
            profile.session_ids.append(session_id)
            profile.session_count += 1

        if "command" in indicators:
            cmd = indicators["command"].lower()
            profile.total_commands += 1
            self._analyze_command(profile, cmd)

        if "auth_attempts" in indicators:
            profile.auth_attempts += indicators["auth_attempts"]

        if "attack_type" in indicators:
            attack = indicators["attack_type"]
            if attack not in profile.attack_techniques:
                profile.attack_techniques.append(attack)

        if "http_path" in indicators:
            path = indicators["http_path"].lower()
            self._analyze_http_path(profile, path)

        if "ftp_command" in indicators:
            cmd = indicators["ftp_command"].upper()
            if cmd in ("STOR", "PUT"):
                profile.attack_techniques.append("file_upload")

        await self._classify_actor(profile)
        await session_manager.set_threat_profile(
            session_id, profile.actor_type.value
        )

        # Per command, so at debug: at info this was a log line a keystroke.
        logger.debug(
            "Actor profile update: %s -> %s (confidence: %.2f)",
            ip, profile.actor_type.value, profile.confidence,
        )

    def _analyze_command(self, profile: ActorProfile, cmd: str):
        for actor_type, patterns in self._command_patterns.items():
            for pattern in patterns:
                if pattern in cmd:
                    if actor_type.value not in profile.attack_techniques:
                        profile.attack_techniques.append(actor_type.value)
                    break

        for tool, signatures in self._tool_signatures.items():
            for sig in signatures:
                if sig in cmd:
                    if tool not in profile.tools_detected:
                        profile.tools_detected.append(tool)
                    break

    def _analyze_http_path(self, profile: ActorProfile, path: str):
        recon_paths = [
            "/admin", "/login", "/wp-admin", "/phpmyadmin",
            "/.env", "/config", "/backup", "/.git",
            "/robots.txt", "/sitemap.xml",
        ]
        exploit_paths = [
            "/shell", "/cmd", "/eval", "/exec",
            "/wp-content/uploads/",
            "/cgi-bin/",
        ]
        traversal_paths = [
            "../", "/etc/passwd", "/etc/shadow",
            "/proc/", "/var/log",
        ]

        for p in recon_paths:
            if p in path:
                if "reconnaissance" not in profile.attack_techniques:
                    profile.attack_techniques.append("reconnaissance")
                break

        for p in exploit_paths:
            if p in path:
                if "exploitation" not in profile.attack_techniques:
                    profile.attack_techniques.append("exploitation")
                break

        for p in traversal_paths:
            if p in path:
                if "lfi" not in profile.attack_techniques:
                    profile.attack_techniques.append("lfi")
                break

    async def _classify_actor(self, profile: ActorProfile):
        score = 0.0
        classifications = []

        if profile.total_commands == 0 and profile.auth_attempts <= 2:
            classifications.append((ThreatActorType.AUTOMATED_BOT, 0.3))

        if profile.auth_attempts > 10:
            score += 0.4
            classifications.append((ThreatActorType.AUTOMATED_BOT, 0.6))

        if len(profile.tools_detected) > 0:
            score += 0.3
            if any(
                t in ("nmap", "nikto", "sqlmap", "hydra", "gobuster", "dirb")
                for t in profile.tools_detected
            ):
                classifications.append((ThreatActorType.SCRIPT_KIDDIE, 0.7))

        if "exploitation" in profile.attack_techniques:
            score += 0.3
            classifications.append((ThreatActorType.SKILLED_ATTACKER, 0.6))

        if any(
            t in profile.attack_techniques
            for t in ("lfi", "rce", "privilege_escalation")
        ):
            score += 0.4
            classifications.append((ThreatActorType.SKILLED_ATTACKER, 0.8))

        if any(
            t in profile.tools_detected
            for t in ("mimikatz", "cobalt_strike", "bloodhound")
        ):
            score += 0.5
            classifications.append((ThreatActorType.APT, 0.9))

        if any(
            t in profile.attack_techniques
            for t in ("lateral_movement", "persistence", "defense_evasion")
        ):
            score += 0.5
            classifications.append((ThreatActorType.APT, 0.85))

        if profile.unique_commands > 20:
            score += 0.2

        if profile.session_count > 3:
            score += 0.2

        if classifications:
            best = max(classifications, key=lambda x: x[1])
            if best[1] > profile.confidence:
                profile.actor_type = best[0]
                profile.confidence = best[1]

        profile.risk_score = min(score, 1.0)

    async def get_profile(self, ip: str) -> Optional[ActorProfile]:
        return self._profiles.get(ip)

    MAX_PROFILES = 5000

    def _evict_stale_profiles(self):
        if len(self._profiles) <= self.MAX_PROFILES:
            return
        stale = sorted(self._profiles.values(), key=lambda p: p.last_seen)
        for profile in stale[: len(self._profiles) - self.MAX_PROFILES]:
            self._profiles.pop(profile.ip_address, None)

    async def _get_or_create_profile(self, ip: str) -> ActorProfile:
        if ip not in self._profiles:
            self._profiles[ip] = ActorProfile(ip_address=ip)
            self._evict_stale_profiles()
        return self._profiles[ip]

    async def get_all_profiles(self) -> list[ActorProfile]:
        return list(self._profiles.values())

    async def serialize_profiles(self) -> list[dict]:
        """JSON-safe view of every profile, worst risk first.

        The cross-session actor model was reachable only from inside the
        process: the control API advertised /threat-actors but called a
        method that did not exist, so the endpoint raised on every request.
        Sorting by risk means the response leads with the actors an operator
        would want to see rather than with dictionary insertion order.
        """
        profiles = sorted(
            self._profiles.values(), key=lambda p: p.risk_score, reverse=True
        )
        return [
            {
                "ip_address": p.ip_address,
                "actor_type": p.actor_type.value,
                "confidence": round(p.confidence, 3),
                "risk_score": round(p.risk_score, 3),
                "session_count": p.session_count,
                "total_commands": p.total_commands,
                "unique_commands": p.unique_commands,
                "auth_attempts": p.auth_attempts,
                "attack_techniques": list(p.attack_techniques),
                "tools_detected": list(p.tools_detected),
                "first_seen": datetime.fromtimestamp(
                    p.first_seen, tz=timezone.utc
                ).isoformat(),
                "last_seen": datetime.fromtimestamp(
                    p.last_seen, tz=timezone.utc
                ).isoformat(),
                "session_ids": list(p.session_ids),
            }
            for p in profiles
        ]

    async def get_high_risk_actors(self, threshold: float = 0.5) -> list[ActorProfile]:
        return [p for p in self._profiles.values() if p.risk_score >= threshold]


adaptive_engine = AdaptiveEngine()
