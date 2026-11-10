"""The rule layer: what the recorded commands and requests are evidence of.

Shell sessions are read command by command (``shell_parse``) and each command
is judged by what it does (``rules``). Web sessions are matched against
attack signatures after the request has been normalised, and a body that is a
script is read as one. Encoded payloads are unwrapped first (``deobfuscate``)
and what they contain is judged the same way.

Everything here runs inside the ingest request on text an attacker chose, so
the work is bounded and linear: a fixed budget of characters per session, a
bounded window per pattern, and no pattern that rescans its input from every
position. A session too long for the budget is read at its start and end, and
the result says it was truncated so nothing downstream mistakes silence for
a clean bill.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import logging
import math
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from app.ai import rules
from app.ai.config import get_analysis_settings
from app.ai.deobfuscate import Result as DecodeResult
from app.ai.deobfuscate import deobfuscate
from app.ai.rules import BENIGN, EXPLOIT, RECON, STAGE_RANK, Finding
from app.ai.shell_parse import Command, ShellSession, parse_line, select_lines
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

#: Web-exploitation signatures, matched against each request after it has
#: been normalised (see ``_signature_text``). The flow classifier is blind to
#: these — they live in the payload, not the flow shape. Every quantifier
#: over attacker text is bounded: ``<svg[^>]*onload`` and ``\\$\\(.*\\)`` used
#: to rescan the rest of the request from each ``<svg`` or ``$(``.
WEB_ATTACK_SIGNATURES = {
    "sql_injection": (
        r"(?:union(?:\s|\+|%20)+(?:all(?:\s|\+|%20)+)?select|'\s?or\s?'?1'?\s?=\s?'?1|\bor\s1=1\b"
        r"|;\s?drop\stable|sleep\(\d|benchmark\(|waitfor\sdelay|pg_sleep\(|information_schema\.)"
    ),
    "xss": r"(?:<script|%3cscript|onerror\s?=|onerror%3d|javascript:|<svg[^>]{0,200}onload)",
    "path_traversal": r"(?:\.\./\.\.|\.\.%2f|\.\.\\|/etc/passwd|/etc/shadow|%2fetc%2f|\.\.%252f)",
    "log4shell": r"(?:\$\{jndi:|%24%7bjndi|\$\{\$\{|\$\{(?:lower|upper|env|sys|date):)",
    "command_injection": (
        r"(?:;\s?(?:id|whoami|uname)\b|\|\s?(?:bash|sh)\b|\$\([^)\n]{1,200}\)|/dev/tcp/|%60|`[^`\n]{1,80}`)"
    ),
    "lfi_rfi": r"(?:php://(?:filter|input)|data://text|expect://|/proc/self/environ)",
    "webshell": r"(?:<\?php|eval\(\$_(?:get|post|request|server)|system\(\$_|passthru\(|assert\(\$_|\bcmd=|shell_exec\()",
    "ssrf": r"(?:169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data/)",
    # A shell function definition where a header or a path should be: the
    # Shellshock prefix. It arrives in the User-Agent as often as anywhere.
    "shellshock": r"\(\)\s{0,4}\{\s{0,4}[:;]",
    # Paths nobody browses to: exposed secrets, version-control directories,
    # backups and management consoles. One request for any of them is a probe.
    # Ordinary application paths such as /admin or /login are deliberately
    # absent: behind the decoys there may be a real site whose owner uses them.
    "sensitive_path_probe": (
        r"(?:/\.env\b|/\.git/|/\.aws/|/\.ssh/|/\.ds_store\b|/server-status\b|/manager/html\b"
        r"|/phpmyadmin\b|/wp-login\.php\b|/xmlrpc\.php\b|/actuator(?:/|\b)"
        r"|\.(?:bak|old|swp)(?:\s|\?|$)|/backup\.(?:zip|sql|tar|tgz)\b|/cgi-bin/)"
    ),
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
    "shellshock": "exploitation",
    "path_traversal": "reconnaissance",
    "sensitive_path_probe": "reconnaissance",
}

_WEB_PATTERNS = {
    name: re.compile(pattern, re.IGNORECASE) for name, pattern in WEB_ATTACK_SIGNATURES.items()
}

#: Protocols whose "commands" are HTTP request lines plus headers and bodies.
_WEB_PROTOCOLS = {"http", "https"}
#: Protocols whose commands are typed at a shell or an FTP prompt.
_SHELL_PROTOCOLS = {"ssh", "telnet", "ftp"}
_HTTP_METHODS = (
    "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "PROPFIND ",
)

#: The decoy appends the user agent to each recorded request line as
#: ``  [ua: ...]``; see honeypot/emulators/http.py.
_UA_MARKER = " [ua: "
_UA_MAX_CHARS = 400

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
#: Tool categories that only look: an inbound scan of the decoy.
_UA_RECON_CATEGORIES = {"scanner", "directory_enum", "vulnerability_scanner"}

#: Characters that make a web parameter value worth reading as a command. A
#: bare word is not: ``?sort=id`` is a column name, not ``id`` being run.
_SHELL_METACHARACTERS = frozenset(";|`&<>\n")

_URL_PATTERN = re.compile(r"(?:https?|ftp|tftp)://[^\s'\"<>`\\]{1,2000}", re.IGNORECASE)
#: A dotted quad that stands on its own. Not one glued to a word or another
#: number, and not the version of a product token (``Chrome/154.0.0.0``).
_IP_PATTERN = re.compile(r"(?<![\w.])(?<![A-Za-z]/)(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
_VERSION_WORDS = frozenset({"version", "ver", "release", "build"})


@dataclass
class Evidence:
    """One finding, with where it came from."""

    finding: Finding
    #: Index of the recorded command or request it was found in, or -1.
    line: int
    #: The command or request text that showed it, shortened.
    detail: str = ""
    #: How the command came to run, when not typed directly.
    via: str = ""

    def as_dict(self) -> Dict:
        return {
            "key": self.finding.key,
            "stage": self.finding.stage,
            "line": self.line,
            "detail": self.detail[:200],
            "via": self.via,
        }


def split_user_agent(first_line: str) -> Tuple[str, str]:
    """The request line without the decoy's ``[ua: ...]`` suffix, and the agent.

    Done with string searches: the regular expressions this replaces
    (``\\s+\\[ua: [^\\]\\n]*\\]``) were retried from every space and every
    ``[ua:`` of a request built to make them slow.
    """
    if not first_line.endswith("]"):
        return first_line, ""
    marker = first_line.rfind(_UA_MARKER)
    if marker < 0:
        return first_line, ""
    agent = first_line[marker + len(_UA_MARKER) : -1]
    return first_line[:marker].rstrip(), agent[:_UA_MAX_CHARS]


def _is_request(text: str) -> bool:
    return text.startswith(_HTTP_METHODS)


def _collapse_sql(text: str) -> str:
    """Comments out, whitespace runs down to one space.

    ``union/**/select`` and ``union%0a%09select`` are the same query as
    ``union select``. Found with ``str.find`` rather than a lazy pattern, so
    an unterminated ``/*`` costs one scan and not one per opener.
    """
    parts: List[str] = []
    position = 0
    while True:
        start = text.find("/*", position)
        if start < 0:
            break
        end = text.find("*/", start + 2)
        if end < 0:
            break
        parts.append(text[position:start])
        # MySQL runs the body of a "/*! ... */" comment, so it is kept.
        body = text[start + 2 : end]
        parts.append(" " + body.lstrip("!0123456789") + " " if body.startswith("!") else " ")
        position = end + 2
    parts.append(text[position:])
    return " ".join("".join(parts).replace("+", " ").split())


def _signature_text(text: str) -> str:
    """Every form of a request the signatures should see.

    The raw text, the text percent-decoded once and twice (``%27`` and
    ``%2527`` are both a quote to something downstream), and the decoded text
    with SQL comments and whitespace collapsed. One pass each.
    """
    raw = text.lower()
    variants = [raw]
    once = urllib.parse.unquote(raw)
    if once != raw:
        variants.append(once)
        twice = urllib.parse.unquote(once)
        if twice != once:
            variants.append(twice)
    collapsed = _collapse_sql(variants[-1])
    if collapsed not in variants:
        variants.append(collapsed)
    return "\n".join(variants)


def _form_values(text: str) -> Optional[List[str]]:
    """Decoded values of ``a=b&c=d``, or None when the text is not a form."""
    if not text or " " in text or "\n" in text:
        return None
    pairs = text.split("&")
    if not all("=" in pair for pair in pairs[:200]):
        return None
    return [urllib.parse.unquote_plus(pair.split("=", 1)[1]) for pair in pairs[:200]]


def _json_strings(value, out: List[str], budget: int = 200) -> None:
    if len(out) >= budget:
        return
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            _json_strings(item, out, budget)
    elif isinstance(value, list):
        for item in value:
            _json_strings(item, out, budget)


def _command_fragments(request_line: str, body: str) -> List[str]:
    """The parts of a request worth reading as shell commands.

    A body that is a script is read whole. Parameter values (query string,
    form body, JSON strings) are read only when they carry a shell
    metacharacter: ``?q=free shipping`` must not run ``free``.
    """
    fragments: List[str] = []
    values: List[str] = []

    path = request_line.split(" ", 2)[1] if request_line.count(" ") >= 1 else ""
    query = path.partition("?")[2]
    if query:
        values.extend(_form_values(query) or [])

    stripped = body.strip()
    if stripped:
        if "content-disposition: form-data" in stripped[:2048].lower() or stripped[0] == "<":
            # An upload or a document: signatures read it, the shell reader
            # does not.
            pass
        elif stripped[0] in "{[":
            try:
                _json_strings(json.loads(stripped), values)
            except ValueError:
                pass
        else:
            form = _form_values(stripped)
            if form is None:
                fragments.append(stripped)
            else:
                values.extend(form)

    fragments.extend(v for v in values if _SHELL_METACHARACTERS.intersection(v))
    return fragments


#: Characters a browser's own requests do not put in a parameter value.
_UNUSUAL_VALUE_CHARS = frozenset("'\"<>\\`;|{}$")
_ORDINARY_METHODS = ("GET ", "HEAD ", "OPTIONS ", "POST ")
_LONG_REQUEST_CHARS = 2048


def web_input_is_unusual(text: str) -> bool:
    """Whether a request carries input worth a model's reading.

    Not a verdict. The signatures are a fixed list, and a request they do
    not match used to be neither triaged nor read. This marks the requests
    that are not plain browsing — an unusual method, a body that is not a
    form or JSON, a parameter value with quoting, markup or shell
    characters in it, a traversal, or sheer length — so they are queued.
    """
    text = text[:NLPEngine.MAX_REQUEST_CHARS]
    if not text.startswith(_ORDINARY_METHODS) or len(text) > _LONG_REQUEST_CHARS:
        return True
    first_line, _, body = text.partition("\n")
    request_line, _ = split_user_agent(first_line)
    path = request_line.split(" ", 2)[1] if request_line.count(" ") >= 1 else ""
    query = path.partition("?")[2]

    values: List[str] = [urllib.parse.unquote(path.partition("?")[0])]
    if query:
        form = _form_values(query)
        if form is None:
            return True
        values.extend(form)
    stripped = body.strip()
    if stripped:
        if stripped[0] in "{[":
            try:
                _json_strings(json.loads(stripped), values)
            except ValueError:
                return True
        else:
            form = _form_values(stripped)
            if form is None:
                return True
            values.extend(form)
    return any(
        _UNUSUAL_VALUE_CHARS.intersection(value) or "../" in value or "\x00" in value
        for value in values
    )


def _trim_url(url: str) -> str:
    """Drop punctuation that closed the sentence or bracket around a URL."""
    while url:
        last = url[-1]
        if last in ".,;:!?'\"":
            url = url[:-1]
        elif last in ")]}" and url.count(last) > url.count({")": "(", "]": "[", "}": "{"}[last]):
            # A closing bracket with no opener inside the URL belongs to the
            # text around it: "$(curl http://x/a)" or "[ua: … http://x/a]".
            url = url[:-1]
        else:
            break
    return url


def extract_urls(text: str) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for match in _URL_PATTERN.finditer(text):
        url = _trim_url(match.group())
        if len(url) > 10 and url not in seen:
            seen.add(url)
            out.append(url)
            if len(out) >= 100:
                break
    return out


def extract_ips(text: str) -> List[str]:
    """IPv4 addresses that are addresses.

    Checked with ``ipaddress`` (so 999.1.1.1 and 1.02.3.4 are out), and never
    taken from a version context: a browser's ``Chrome/154.0.0.0`` used to be
    stored as an indicator.
    """
    seen: Set[str] = set()
    out: List[str] = []
    for match in _IP_PATTERN.finditer(text):
        candidate = match.group()
        if candidate in seen:
            continue
        # "version 1.2.3.4" is a version; "nameserver 1.2.3.4" is not.
        before = text[max(0, match.start() - 12) : match.start()].lower().rstrip(" :=").split()
        if before and before[-1] in _VERSION_WORDS:
            continue
        try:
            address = ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        if address.is_unspecified or address.is_multicast or address.is_loopback or candidate.startswith("255."):
            continue
        seen.add(candidate)
        out.append(candidate)
        if len(out) >= 100:
            break
    return out


class NLPEngine:
    #: Characters of a session that the rules read. Past this the start and
    #: the end are read and the result is marked truncated.
    MAX_ANALYSIS_CHARS = 65_536
    #: Characters of one web request that the signatures read.
    MAX_REQUEST_CHARS = 8_192
    #: Characters of a standalone payload that are analysed.
    MAX_PAYLOAD_CHARS = 16_384
    #: Evidence items returned per session.
    MAX_EVIDENCE = 200

    def __init__(self):
        self.nlp = None
        self._loaded = False

    # -- optional named-entity pass ----------------------------------------

    def _ensure_loaded(self):
        """Load the spaCy model once, tolerating its absence.

        Only when NLP_ENTITIES_ENABLED is set: nothing in the pipeline reads
        the entities, and running the model over every session was the
        largest single cost in the ingest budget. spaCy itself is imported
        here rather than at module load for the same reason.
        """
        if self._loaded:
            return
        self._loaded = True
        if not get_analysis_settings().NLP_ENTITIES_ENABLED:
            return
        try:
            import spacy

            self.nlp = spacy.load(settings.SPACY_MODEL)
        except (ImportError, OSError, IOError):
            logger.warning(
                "spaCy model %r unavailable; named-entity extraction disabled. "
                "Install it with: python -m spacy download %s",
                settings.SPACY_MODEL,
                settings.SPACY_MODEL,
            )
            self.nlp = None

    def _entities(self, text: str) -> List[tuple]:
        self._ensure_loaded()
        if self.nlp is None or not text:
            return []
        return [(ent.text, ent.label_) for ent in self.nlp(text[:10_000]).ents]

    # -- the analysis -------------------------------------------------------

    def analyze_commands(
        self,
        commands: List[str],
        protocol: Optional[str] = None,
        headers: Optional[Sequence[Optional[Dict]]] = None,
    ) -> Dict:
        """Judge a session's recorded commands or requests.

        ``headers`` is optional and parallel to ``commands``: the request
        headers of each web request, when the engine recorded them.
        """
        commands = [str(c) for c in (commands or [])]
        kind = (protocol or "").lower()
        is_web = kind in _WEB_PROTOCOLS
        # With no protocol given each line decides for itself.
        sniff = not is_web and kind not in _SHELL_PROTOCOLS

        selected, truncated = select_lines(commands, self.MAX_ANALYSIS_CHARS)
        evidence: List[Evidence] = []
        web_attacks: Set[str] = set()
        shell_lines: List[Tuple[int, str]] = []
        # What indicators are extracted from: requests without their user
        # agent and headers, shell lines as typed.
        indicator_text: List[str] = []

        for index, text in selected:
            if is_web or (sniff and _is_request(text)):
                header_map = headers[index] if headers and index < len(headers) else None
                fragments, clean = self._web_request(index, text, header_map, evidence, web_attacks)
                shell_lines.extend((index, fragment) for fragment in fragments)
                indicator_text.append(clean)
            else:
                shell_lines.append((index, text))
                indicator_text.append(text)

        session = ShellSession()
        parsed: List[Command] = []
        for index, text in shell_lines:
            parsed.extend(parse_line(text, index, session))

        # Decode nested encodings, then judge what was inside them exactly
        # like a typed command. The expert interviews in section V.B.2 asked
        # for this: the outer command is deliberately unremarkable.
        self._shell_evidence(parsed, evidence)

        document = "\n".join(text for _, text in selected)
        decoded = deobfuscate(document)
        starts = self._line_starts(selected)
        obfuscated = False
        for layer in decoded.layers:
            # Percent-encoding of a web request is transport, already handled
            # by the signature normaliser; its values are not typed commands.
            if is_web and layer.encoding == "url":
                obfuscated = obfuscated or layer.depth > 1
                continue
            origin = self._line_at(starts, selected, layer.root_offset)
            inner = parse_line(layer.decoded, origin, session)
            for command in inner:
                command.via = command.via or f"decoded {layer.encoding}"
            before = len(evidence)
            self._shell_evidence(inner, evidence)
            parsed.extend(inner)
            indicator_text.append(layer.decoded)
            # A web request carries base64 for ordinary reasons (tokens,
            # cookies); it is obfuscation when what was inside is a command.
            productive = any(STAGE_RANK[e.finding.stage] > STAGE_RANK[BENIGN] for e in evidence[before:])
            obfuscated = obfuscated or productive or not is_web

        return self._result(
            commands, evidence, web_attacks, decoded, parsed, indicator_text,
            truncated=truncated or decoded.truncated, is_web=is_web, obfuscated=obfuscated,
        )

    def _web_request(
        self,
        index: int,
        text: str,
        header_map: Optional[Dict],
        evidence: List[Evidence],
        web_attacks: Set[str],
    ) -> Tuple[List[str], str]:
        """Judge one request. Returns its shell-like fragments and the text
        indicators may be taken from."""
        text = text[: self.MAX_REQUEST_CHARS]
        first_line, _, body = text.partition("\n")
        request_line, agent = split_user_agent(first_line)

        if agent:
            hit = _UA_TOOL_PATTERN.search(agent)
            if hit:
                name, category = _UA_TOOLS[hit.group(1).lower()]
                stage = RECON if category in _UA_RECON_CATEGORIES else EXPLOIT
                finding = Finding(f"ua:{name}", stage, name, category)
                evidence.append(Evidence(finding, index, f"user agent {agent[:80]}"))

        header_text = ""
        if isinstance(header_map, dict):
            header_text = "\n".join(
                f"{str(k)[:64]}: {str(v)[:512]}" for k, v in list(header_map.items())[:40]
            )
        haystack = _signature_text(
            "\n".join(part for part in (request_line, agent, header_text, body) if part)[: self.MAX_REQUEST_CHARS]
        )
        for name, pattern in _WEB_PATTERNS.items():
            if pattern.search(haystack):
                web_attacks.add(name)
                finding = Finding(f"web:{name}", WEB_ATTACK_CATEGORY[name], "", name, "web_exploitation")
                evidence.append(Evidence(finding, index, request_line[:160]))

        return _command_fragments(request_line, body), f"{request_line}\n{body}"

    @staticmethod
    def _line_starts(selected: List[Tuple[int, str]]) -> List[int]:
        starts, offset = [], 0
        for _, text in selected:
            starts.append(offset)
            offset += len(text) + 1
        return starts

    @staticmethod
    def _line_at(starts: List[int], selected: List[Tuple[int, str]], offset: int) -> int:
        if offset < 0 or not starts:
            return -1
        return selected[max(0, bisect.bisect_right(starts, offset) - 1)][0]

    @staticmethod
    def _shell_evidence(parsed: List[Command], evidence: List[Evidence]) -> None:
        for position, command in enumerate(parsed):
            upstream = None
            if command.pipe_in:
                # The writing end of the pipe: the nearest earlier command of
                # the same line and nesting that pipes out.
                for earlier in reversed(parsed[max(0, position - 8) : position]):
                    if earlier.line == command.line and earlier.depth == command.depth and earlier.pipe_out:
                        upstream = earlier
                        break
            for finding in rules.findings_for(command, upstream):
                evidence.append(Evidence(finding, command.line, command.raw, command.via))

    def _result(
        self,
        commands: List[str],
        evidence: List[Evidence],
        web_attacks: Set[str],
        decoded: DecodeResult,
        parsed: List[Command],
        indicator_text: List[str],
        truncated: bool,
        is_web: bool,
        obfuscated: bool,
    ) -> Dict:
        detected_tools: List[Dict] = []
        tool_names: List[str] = []
        categories: List[str] = []
        intents: List[str] = []
        critical: List[str] = []

        for item in evidence:
            finding = item.finding
            if finding.tool and finding.tool not in tool_names:
                tool_names.append(finding.tool)
                detected_tools.append({
                    "name": finding.tool,
                    "category": finding.tool_category,
                    "confidence": 0.9 if finding.key.startswith("ua:") else 0.85,
                })
            if finding.tool_category and finding.tool_category not in categories:
                categories.append(finding.tool_category)
            if finding.intent and finding.intent not in intents:
                intents.append(finding.intent)
            if finding.critical and finding.tool not in critical:
                critical.append(finding.tool)

        text = "\n".join(indicator_text)
        files = self._files(parsed, commands if is_web else [])

        return {
            "detected_tools": detected_tools,
            "tool_names": tool_names,
            "detected_intents": intents,
            "categories": categories,
            "web_attacks": sorted(web_attacks),
            "entities": self._entities(text),
            "extracted_ips": extract_ips(text),
            "extracted_urls": extract_urls(text),
            "extracted_files": files,
            "complexity_score": self._calculate_complexity(commands),
            "command_count": len(commands),
            # Surfaced so an analyst can see the decode chain rather than
            # having to trust that something was unwrapped.
            "deobfuscation": decoded.as_dict(),
            "is_obfuscated": obfuscated,
            # What the verdict rests on, one entry per finding, and the
            # recorded lines they came from (for the model stages' window).
            "evidence": [item.as_dict() for item in evidence[: self.MAX_EVIDENCE]],
            "flagged_lines": sorted({item.line for item in evidence if item.line >= 0}),
            "critical_tools": critical,
            # True when the session was longer than the rules read: silence
            # from a truncated read is not the same as a clean session.
            "truncated": truncated,
        }

    @staticmethod
    def _files(parsed: List[Command], requests: List[str]) -> List[str]:
        """Paths named as arguments, and the paths web requests asked for."""
        seen: List[str] = []
        for command in parsed:
            for word in command.args + command.writes + command.reads:
                if word.startswith(("/", "./", "~/")) and 1 < len(word) <= 255 and word not in seen:
                    seen.append(word)
                    if len(seen) >= 20:
                        return seen
        for request in requests[:200]:
            parts = request.split(" ", 2)
            if len(parts) >= 2 and parts[1].startswith("/"):
                path = parts[1].partition("?")[0][:255]
                if len(path) > 1 and path not in seen:
                    seen.append(path)
                    if len(seen) >= 20:
                        break
        return seen

    def flagged_lines(self, commands: List[str], protocol: Optional[str] = None) -> List[int]:
        """Indexes of the commands the rules found something in."""
        return self.analyze_commands(commands, protocol)["flagged_lines"]

    def analyze_payload(self, payload: str) -> Dict:
        """Score a standalone payload string. Bounded like everything else."""
        payload = str(payload or "")[: self.MAX_PAYLOAD_CHARS]
        results = {
            "is_suspicious": False,
            "suspicion_score": 0.0,
            "detected_patterns": [],
            "language_indicators": [],
        }
        if not payload:
            return results

        haystack = _signature_text(payload)
        for name, pattern in _WEB_PATTERNS.items():
            if pattern.search(haystack):
                results["detected_patterns"].append({"signature": name})
                results["suspicion_score"] += 0.3
        for command in parse_line(payload, 0):
            for finding in rules.findings_for(command):
                if STAGE_RANK[finding.stage] > STAGE_RANK[BENIGN]:
                    results["detected_patterns"].append({"finding": finding.key})
                    results["suspicion_score"] += 0.3

        if len(payload) > 1000:
            results["suspicion_score"] += 0.1
        if self._shannon_entropy(payload) > 4.5:
            results["suspicion_score"] += 0.15
            results["language_indicators"].append("high_entropy")

        results["detected_patterns"] = results["detected_patterns"][:50]
        results["suspicion_score"] = min(results["suspicion_score"], 1.0)
        results["is_suspicious"] = results["suspicion_score"] > 0.3
        return results

    def _calculate_complexity(self, commands: List[str]) -> float:
        if not commands:
            return 0.0
        # On a bounded sample: the counts below were taken character by
        # character over the whole session, however long it was.
        sample = commands[:500]
        text = " ".join(sample)[: self.MAX_ANALYSIS_CHARS]
        unique_ratio = len(set(sample)) / len(sample)
        avg_length = len(text) / len(sample)
        pipe_count = text.count("|")
        redirect_count = text.count(">")
        special_chars = sum(text.count(c) for c in "&;`$(){}[]")

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
