"""A malware-family *hint*, with the evidence that suggested it.

This is deliberately not antivirus. It is a small set of rules over the facts
the other analysers already produced — behaviours, imports, architecture,
strings — that names the well-known commodity families a honeypot sees most,
so an analyst starts from "this looks like Mirai, here is why" rather than
from raw bytes. Every result carries its evidence and a confidence, and the
absence of a match means nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Rule:
    family: str
    kind: str  # botnet, miner, ransomware, webshell, ...
    #: Substrings looked for across the sample's recovered strings, lowercased.
    strings: tuple[str, ...] = ()
    #: Behaviour ids (from script.py) that must all be present.
    behaviours: tuple[str, ...] = ()
    #: How many string hits are needed to fire.
    min_string_hits: int = 2


RULES = [
    Rule("Mirai", "botnet",
         strings=("/bin/busybox", "mirai", "/dev/watchdog", "gtfo", "listeningtord",
                  "hax7654", "\\x7f\\x45\\x4c\\x46", "80808080", "table_init"),
         min_string_hits=2),
    Rule("Gafgyt/Bashlite", "botnet",
         strings=("gafgyt", "bashlite", "lolnogtfo", "telnet.arm", "ohshit",
                  "rm -rf /tmp/*", "\\x1f\\x1f", "PONG", "getlocalip"),
         min_string_hits=2),
    Rule("Tsunami/Kaiten", "botnet",
         strings=("tsunami", "kaiten", "nickconstruct", "privmsg", "getspoofs",
                  "\\x01version", "std <ip> <port>"),
         min_string_hits=2),
    Rule("XMRig", "miner",
         strings=("xmrig", "stratum+tcp", "--donate-level", "randomx", "cryptonight",
                  "cpu.huge-pages", "supportxmr", "nanopool"),
         min_string_hits=2),
    Rule("Kinsing", "botnet",
         strings=("kinsing", "kdevtmpfsi", "/etc/kinsing", "spre.sh", "libsystem.so"),
         min_string_hits=1),
    Rule("Sysrv-hello", "miner",
         strings=("sysrv", "ldr.sh", "network03", "xmrig", "cp.php"),
         min_string_hits=2),
    Rule("China Chopper", "webshell",
         strings=("eval(request", "z0=", "z1=", "@eval", "caidao"),
         min_string_hits=1),
    Rule("Generic PHP webshell", "webshell",
         strings=("c99shell", "r57shell", "wso shell", "b374k", "filesman",
                  "eval(base64_decode", "eval(gzinflate", "assert($_", "system($_"),
         min_string_hits=1),
]

_WEBSHELL_KIND = {"webshell"}


def classify(sample: dict) -> dict | None:
    """Return the strongest family hint for an analysed sample, or None.

    ``sample`` is the assembled analysis dict: file kind, strings, behaviours.
    """
    strings_blob = "\n".join(sample.get("strings", [])).lower()
    # Script bodies are the most reliable place to see a family's own strings.
    script = sample.get("script") or {}
    behaviour_ids = {b["id"] for b in script.get("behaviours", [])}
    file_kind = sample.get("file_type", {}).get("kind", "")

    best = None
    for rule in RULES:
        if rule.kind in _WEBSHELL_KIND and file_kind not in ("script", "text", "data"):
            continue
        hits = [s for s in rule.strings if s in strings_blob]
        if len(hits) < rule.min_string_hits:
            continue
        if rule.behaviours and not set(rule.behaviours) <= behaviour_ids:
            continue
        # Confidence grows with corroborating hits but is capped: this is a
        # hint, and a hint should never present as certainty.
        confidence = min(0.85, 0.4 + 0.15 * len(hits))
        candidate = {
            "family": rule.family,
            "kind": rule.kind,
            "confidence": round(confidence, 2),
            "evidence": hits[:8],
            "basis": "string and behaviour heuristics",
        }
        if best is None or candidate["confidence"] > best["confidence"]:
            best = candidate
    return best


#: A coarse kind, independent of any named family, from behaviour alone.
def infer_kind(sample: dict) -> str | None:
    script = sample.get("script") or {}
    behaviour_ids = {b["id"] for b in script.get("behaviours", [])}
    if "mining" in behaviour_ids:
        return "miner"
    if {"download", "execute"} <= behaviour_ids and ("multi_arch" in behaviour_ids or "kill_competitors" in behaviour_ids):
        return "botnet loader"
    caps = {c for c in sample.get("elf", {}).get("capabilities", [])}
    if "network" in caps and "process" in caps:
        return "network-capable binary"
    return None
