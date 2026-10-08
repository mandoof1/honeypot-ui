"""Decision-model client — fast triage and technique checks.

Stage 2 has two models. The language model (Wolfram) reads a transcript and
writes an analysis, which takes minutes on the server's CPU. This one is a
decision model in the style of TypeSafe's Jev — Kev-4B in production, served
by llama.cpp's ``/v1/systemone`` endpoint. It never generates text: it reads
the transcript once and returns a probability for each option of each
question the backend asks, in seconds. That makes it useful for two jobs the
language model is bad at:

* triage, before the language model: what kind of session is this, how
  serious, a bot or a person? The answers decide whether the session is
  worth minutes of language-model time, and give the rules a second opinion
  that reads the commands themselves rather than flow features;
* checking, after the language model: for each ATT&CK technique it named,
  how likely is it that the transcript actually shows it?

The options are fixed by this module, so a transcript can move a probability
but cannot introduce an answer. Like the language model it is called from
the backend only, against the operator's own server, so nothing leaves the
deployment and the engine keeps its zero-egress property.
"""

from __future__ import annotations

import logging
import time
from typing import Iterable, Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

#: The pipeline's own categories, described the way the rule layer uses them,
#: so the two verdicts can be compared directly.
CATEGORY_CRITERIA = {
    "benign": "Ordinary use with no hostile intent, such as browsing pages or a login with no follow-up",
    "reconnaissance": "Only gathers information about the host, its users or its network, without changing anything",
    "exploitation": (
        "Tries to gain, extend or keep control: downloads or runs programs, creates users or keys, "
        "edits scheduled tasks, disables defences, reads credentials, or exploits a web application"
    ),
    "exfiltration": "Collects data and sends it to another system",
}

#: Ordered, lowest first. Levels 0-1 are what triage may leave to the rules;
#: 2-3 are what the language model is for.
SEVERITY_LEVELS = [
    "Nothing harmful was attempted",
    "Information gathering only",
    "An attempted compromise: running or installing something, or changing accounts or settings",
    "High impact: stealing credentials or data, destroying data, mining cryptocurrency, or attacking other hosts",
]

OPERATOR_CRITERIA = {
    "automated": "A bot or script sending a fixed sequence of commands",
    "human": "A person typing interactively and reacting to what the host returned",
}

#: Most techniques one check will ask about.
MAX_TECHNIQUES = 20

#: What each technique looks like in a transcript. The check asks about the
#: behaviour, not the id: the model knows little ATT&CK by number, and on the
#: held-out set the described questions separated real from wrong techniques
#: far better (AUC 0.982 against 0.957; docs/evaluation/decider-README.md).
#: Looked up by id, then by parent id; a technique with no entry is asked
#: about by name alone.
TECHNIQUE_HINTS = {
    "T1003": "dumps account credentials or password hashes from the operating system",
    "T1003.001": "dumps credentials from the memory of the Windows LSASS process",
    "T1003.008": "reads the passwd or shadow files to obtain account password hashes",
    "T1005": "collects files or data stored on the host",
    "T1016": "looks up the host's network interfaces, addresses or routes",
    "T1018": "looks for other hosts on the network, e.g. ping sweeps or reading the ARP table",
    "T1021": "logs in to another host through a remote service",
    "T1021.004": "connects to another host over SSH",
    "T1027": "hides a command or file by encoding or obfuscating it",
    "T1033": "checks which user it is running as or who is logged in",
    "T1036": "names or places a file so that it looks legitimate",
    "T1041": "sends collected data out over its command-and-control channel",
    "T1046": "scans for network services or open ports",
    "T1049": "lists the host's open or active network connections, e.g. with netstat or ss",
    "T1048": "sends data out over a protocol other than its control channel",
    "T1053": "creates or changes a scheduled task to run something later or repeatedly",
    "T1053.003": "adds or changes a cron job to run something on a schedule",
    "T1057": "lists the running processes",
    "T1069": "lists permission groups or their members",
    "T1087": "lists the accounts on the host, e.g. by reading /etc/passwd",
    "T1059": "runs commands or scripts through an interpreter",
    "T1059.004": "runs commands or a script through a Unix shell such as sh or bash",
    "T1068": "exploits a software flaw to gain higher privileges",
    "T1070": "deletes or alters logs, history or other traces of its activity",
    "T1070.006": "changes file timestamps to hide when files were modified",
    "T1071": "talks to its controller over a common application protocol such as HTTP",
    "T1078": "logs in with an existing account's valid credentials",
    "T1082": "looks up the operating system, kernel, CPU, memory or hardware",
    "T1083": "lists or searches directories and files",
    "T1007": "lists the system services",
    "T1095": "communicates over a raw or non-application protocol",
    "T1098": "changes an existing account, its password or its permissions",
    "T1098.004": "adds a key to an authorized_keys file to keep SSH access",
    "T1105": "copies a tool or file onto the host from an outside system, e.g. with wget, curl or tftp",
    "T1110": "tries many passwords or credentials to log in",
    "T1136": "creates a new account",
    "T1136.001": "creates a new local user account",
    "T1140": "decodes or decompresses hidden content before using it",
    "T1190": "exploits a flaw in an internet-facing application or web page",
    "T1222": "changes file or directory permissions, e.g. with chmod or chattr",
    "T1485": "deletes or overwrites data to destroy it",
    "T1486": "encrypts files so that their owner cannot use them",
    "T1489": "stops or disables services",
    "T1490": "deletes backups or disables recovery features",
    "T1496": "uses the host's resources for its own ends, typically cryptocurrency mining",
    "T1498": "floods another network or host with traffic",
    "T1499": "exhausts the host's resources to make it unavailable",
    "T1505": "installs a component in server software, such as a web shell",
    "T1543": "creates or changes a system service or daemon",
    "T1548": "abuses a mechanism such as sudo or setuid to raise its privileges",
    "T1552": "searches for stored credentials in files or configuration",
    "T1552.004": "searches for or reads private key files such as SSH keys",
    "T1555": "takes credentials from a password store or browser",
    "T1562": "weakens or turns off the host's defences",
    "T1562.001": "stops or removes security or logging tools",
    "T1562.004": "turns off or changes the firewall, e.g. iptables or ufw",
    "T1564": "hides files, processes or users",
    "T1570": "copies tools to other hosts inside the network",
    "T1571": "communicates on a non-standard port",
    "T1572": "tunnels traffic inside another protocol",
    "T1595": "actively scans or probes systems for weaknesses",
}


class DeciderUnavailable(Exception):
    """The endpoint could not be reached or did not answer in time."""


class DeciderClient:
    """Optional decision-model stage. Absent by default."""

    def __init__(self) -> None:
        self._settings = get_settings()

    @property
    def enabled(self) -> bool:
        return bool(self._settings.DECIDER_URL)

    @property
    def model_name(self) -> str:
        return self._settings.DECIDER_MODEL

    def _url(self, path: str) -> str:
        return self._settings.DECIDER_URL.rstrip("/") + path

    async def healthy(self) -> bool:
        if not self.enabled:
            return False
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(self._url("/health"))
                return response.status_code < 500
        except Exception:
            return False

    def build_state(self, commands: list[str], protocol: str, facts: Optional[dict] = None) -> str:
        """The text the model reads: a short header, then the commands.

        Long transcripts keep their beginning and end, where the download and
        the execution usually are, and say how much was left out.
        """
        limit = self._settings.DECIDER_MAX_TRANSCRIPT_CHARS
        transcript = "\n".join(commands)
        if len(transcript) > limit:
            head = transcript[: limit * 2 // 3]
            tail = transcript[-(limit - len(head)):]
            omitted = len(transcript) - len(head) - len(tail)
            transcript = f"{head}\n[... {omitted} characters omitted ...]\n{tail}"
        lines = [
            f"Honeypot session over {(protocol or 'ssh').upper()}. "
            "The honeypot emulated the host; nothing ran on a real system."
        ]
        for label, value in (facts or {}).items():
            if value is not None:
                lines.append(f"{label}: {value}")
        lines.append("Commands the client sent, in order:")
        lines.append(transcript)
        return "\n".join(lines)

    async def ask(self, state: str, questions: dict) -> Optional[dict]:
        """POST /v1/systemone. Returns {answers, input_tokens}, or None for a bad answer.

        Raises DeciderUnavailable when the server cannot be reached, times
        out or reports a server-side failure, so the caller can retry later.
        """
        payload = {"state": state, "questions": questions}
        timeout = httpx.Timeout(self._settings.DECIDER_TIMEOUT, connect=10.0)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(self._url("/v1/systemone"), json=payload)
        except httpx.TimeoutException as exc:
            raise DeciderUnavailable(f"timed out after {self._settings.DECIDER_TIMEOUT:.0f}s") from exc
        except httpx.HTTPError as exc:
            raise DeciderUnavailable(str(exc) or exc.__class__.__name__) from exc

        if response.status_code >= 500 or response.status_code == 429:
            raise DeciderUnavailable(f"HTTP {response.status_code}")
        if response.status_code >= 400:
            logger.warning("Decision model rejected the request: HTTP %s %s",
                           response.status_code, response.text[:200])
            return None
        try:
            body = response.json()
            answers = body["answers"]
        except (ValueError, KeyError, TypeError):
            logger.warning("Decision model returned an unexpected response shape")
            return None
        if not isinstance(answers, dict):
            return None
        usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
        return {"answers": answers, "input_tokens": usage.get("input_tokens")}

    async def triage(
        self,
        commands: list[str],
        protocol: str = "ssh",
        duration_seconds: Optional[float] = None,
        keystrokes: Optional[int] = None,
    ) -> Optional[dict]:
        """Category, severity and operator for one session, or None."""
        if not self.enabled or not commands:
            return None
        facts = {
            "Duration": f"{duration_seconds:.0f} seconds" if duration_seconds is not None else None,
            "Commands": len(commands),
            # Interactive shells report keystrokes; exec requests and replayed
            # scripts mostly do not, which is evidence for the operator question.
            "Keystrokes typed": keystrokes if keystrokes is not None else None,
        }
        questions = {
            "category": {
                "type": "choice",
                "instructions": "Which best describes what the client did in this session?",
                "criteria": CATEGORY_CRITERIA,
            },
            "severity": {
                "type": "score",
                "instructions": "How serious is the most serious thing the client attempted?",
                "criteria": SEVERITY_LEVELS,
            },
            "operator": {
                "type": "choice",
                "instructions": "Who drove this session?",
                "criteria": OPERATOR_CRITERIA,
            },
        }
        started = time.perf_counter()
        reply = await self.ask(self.build_state(commands, protocol, facts), questions)
        if reply is None:
            return None
        return self.parse_triage(reply, elapsed_ms=(time.perf_counter() - started) * 1000.0)

    def parse_triage(self, reply: dict, elapsed_ms: Optional[float] = None) -> Optional[dict]:
        answers = reply.get("answers") or {}
        category = _distribution(answers.get("category"), CATEGORY_CRITERIA.keys())
        severity = _distribution(answers.get("severity"), (str(i) for i in range(len(SEVERITY_LEVELS))))
        operator = _distribution(answers.get("operator"), OPERATOR_CRITERIA.keys())
        if category is None or severity is None or operator is None:
            logger.warning("Decision model answer is missing a triage question")
            return None
        levels = [severity[str(i)] for i in range(len(SEVERITY_LEVELS))]
        top_category = max(category, key=category.get)
        top_operator = max(operator, key=operator.get)
        return {
            "category": top_category,
            "category_probabilities": _rounded(category),
            "severity": round(sum(i * p for i, p in enumerate(levels)), 3),
            "severity_probabilities": _rounded(severity),
            # The two numbers routing reads: how sure the model is that the
            # session is harmless or reconnaissance, and that it went further.
            "p_low": round(levels[0] + levels[1], 4),
            "p_compromise": round(levels[2] + levels[3], 4),
            "operator": top_operator,
            "operator_probability": round(operator[top_operator], 4),
            "model": self.model_name,
            "input_tokens": reply.get("input_tokens"),
            "ms": round(elapsed_ms, 1) if elapsed_ms is not None else None,
        }

    async def check_techniques(
        self,
        commands: list[str],
        protocol: str,
        techniques: Iterable[dict],
    ) -> Optional[dict]:
        """{technique id: probability the transcript shows it}, or None."""
        from app.ai.mitre_mapper import mitre_mapper

        if not self.enabled or not commands:
            return None
        questions = {}
        for technique in techniques:
            tid = str(technique.get("id") or "")
            if not tid or tid in questions:
                continue
            questions[tid] = technique_question(tid, mitre_mapper.technique_name(tid) or technique.get("name") or "")
            if len(questions) >= MAX_TECHNIQUES:
                break
        if not questions:
            return {}
        reply = await self.ask(self.build_state(commands, protocol), questions)
        if reply is None:
            return None
        support = {}
        for tid, answer in (reply.get("answers") or {}).items():
            value = answer.get("noul") if isinstance(answer, dict) else None
            if isinstance(value, (int, float)) and tid in questions:
                support[tid] = round(max(0.0, min(1.0, float(value))), 4)
        return support


def technique_question(tid: str, name: str) -> dict:
    """The yes/no question for one technique, as measured in the evaluation."""
    hint = TECHNIQUE_HINTS.get(tid) or TECHNIQUE_HINTS.get(tid.split(".")[0])
    if hint is None:
        label = f"{tid} ({name})" if name else tid
        return {"type": "noul", "instructions": f"Do the commands show MITRE ATT&CK technique {label}?"}
    return {
        "type": "noul",
        "instructions": f"Do the commands themselves show the attacker doing this: {name or tid} ({tid}), which {hint}?",
        "criteria": {"true": "The commands clearly do this", "false": "None of the commands do this"},
    }


def _distribution(answer, keys: Iterable[str]) -> Optional[dict]:
    """The probabilities of a choice or score answer, over exactly ``keys``."""
    if not isinstance(answer, dict):
        return None
    probabilities = answer.get("probabilities")
    if not isinstance(probabilities, dict):
        return None
    out = {}
    for key in keys:
        value = probabilities.get(key)
        if not isinstance(value, (int, float)):
            return None
        out[key] = max(0.0, min(1.0, float(value)))
    total = sum(out.values())
    if total <= 0:
        return None
    return {k: v / total for k, v in out.items()}


def _rounded(values: dict) -> dict:
    return {k: round(v, 4) for k, v in values.items()}


decider = DeciderClient()
