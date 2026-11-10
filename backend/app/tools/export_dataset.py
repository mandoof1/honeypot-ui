"""Anonymised research export of captured sessions.

Writes two files: a JSONL of sessions that can leave the deployment, and a
data card describing every field, the counts, the collection window and
exactly what was done to anonymise it.

    EXPORT_PSEUDONYM_KEY=$(openssl rand -hex 32) \\
    python -m app.tools.export_dataset --out sessions.jsonl --card datacard.json \\
        --since 2026-11-01 --until 2026-12-01

What is changed on the way out:

* **Source addresses** become keyed pseudonyms: ``src-<hex>`` is an
  HMAC-SHA256 of the address under the export key, and ``net-<hex>`` the
  same of its /24 (IPv4) or /48 (IPv6), so sessions from one address or one
  network can still be grouped. Without the key a pseudonym cannot be
  turned back into an address or tested against a guess. The same key gives
  the same pseudonyms, so two exports can be joined; a new key unlinks them.
  The session's own address is also replaced wherever it appears in its
  commands.
* **Passwords** are replaced by a keyed hash and a length class. Reuse of a
  password across sessions stays visible; the password does not. Usernames
  are kept, except ones that are e-mail addresses.
* **Payload bytes** are not exported. Uploaded files appear as their SHA-256
  and name.
* **Free text** (commands and their output) has secrets masked: credentials
  in URLs and in ``password=``-style parameters, password arguments, private
  keys, cloud access keys, e-mail addresses, and any password the session
  itself tried at login.
* **Location** is reduced to the country.

What is kept as captured: timestamps, durations, the commands, the hosts and
URLs attackers reached for (their infrastructure is what the data is for),
client fingerprints, and the pipeline's verdicts. Read the card before
sharing: command text is free text, and masking by pattern is not proof that
nothing identifying remains.

Run inside the backend container, where the encryption key is available.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import select

from app.tools.session_io import write_jsonl

MIN_KEY_BYTES = 16
MASK = "[masked]"

#: Patterns for secrets in command text. Every quantifier is bounded: the
#: text is attacker-written.
_URL_CREDENTIALS = re.compile(r"(?i)\b((?:https?|ftp|sftp|ssh)://)[^\s/:@]{1,128}:[^\s/@]{1,256}@")
_ASSIGNED_SECRET = re.compile(
    r"(?i)\b((?:password|passwd|pass|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|auth)"
    r"[\w-]{0,16}\s{0,3}[=:]\s{0,3})(\"[^\"\n]{1,256}\"|'[^'\n]{1,256}'|[^\s&;'\"]{1,256})"
)
_PASSWORD_ARGUMENT = re.compile(r"(?i)((?:^|\s)(?:--password|--pass|-p|sshpass\s{1,4}-p)[= ]\s{0,3})([^\s]{1,256})")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]{0,8192}?-----END [A-Z ]{0,40}PRIVATE KEY-----")
_CLOUD_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_EMAIL = re.compile(r"\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,4}\b")
_CHPASSWD = re.compile(r"(?i)(echo\s{1,4}['\"]?[\w.-]{1,64}:)([^\s'\"|]{1,256})(['\"]?\s{0,4}\|\s{0,4}chpasswd)")


def load_key(args) -> bytes:
    raw = None
    if args.key_file:
        with open(args.key_file, "rb") as handle:
            raw = handle.read().strip()
    elif os.environ.get("EXPORT_PSEUDONYM_KEY"):
        raw = os.environ["EXPORT_PSEUDONYM_KEY"].strip().encode()
    if not raw or len(raw) < MIN_KEY_BYTES:
        raise SystemExit(
            "A pseudonymisation key of at least 16 bytes is required: set EXPORT_PSEUDONYM_KEY or pass "
            "--key-file. Generate one with `openssl rand -hex 32` and keep it: the same key reproduces "
            "the same pseudonyms, and without it they cannot be reversed."
        )
    return raw


class Anonymiser:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def _tag(self, purpose: str, value: str, length: int = 16) -> str:
        # The purpose is part of the message, so a password and an address
        # that happen to be the same string do not share a pseudonym.
        digest = hmac.new(self._key, f"{purpose}\x00{value}".encode("utf-8", "replace"), hashlib.sha256)
        return digest.hexdigest()[:length]

    @property
    def key_id(self) -> str:
        """Identifies the key in the data card without revealing it."""
        return self._tag("key-id", "export", 12)

    def address(self, value: str) -> Dict:
        """A source address as pseudonyms for the address and its network."""
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return {"source": f"src-{self._tag('address', value)}", "network": None, "family": "unknown"}
        prefix = 24 if address.version == 4 else 48
        network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        return {
            "source": f"src-{self._tag('address', address.compressed)}",
            "network": f"net-{self._tag('network', network.compressed)}",
            "family": f"ipv{address.version}",
        }

    def password(self, value: str) -> Dict:
        return {"hash": self._tag("password", value), "length_class": length_class(len(value))}

    def username(self, value: str) -> str:
        return f"user-{self._tag('username', value, 12)}" if _EMAIL.fullmatch(value or "") else value

    def text(self, value: str, own_address: str = "", tried_passwords: Optional[List[str]] = None) -> str:
        """Command or output text with secrets masked."""
        text = str(value or "")
        text = _PRIVATE_KEY.sub("[masked private key]", text)
        text = _URL_CREDENTIALS.sub(rf"\1{MASK}:{MASK}@", text)
        text = _CHPASSWD.sub(rf"\1{MASK}\3", text)
        text = _ASSIGNED_SECRET.sub(rf"\1{MASK}", text)
        text = _PASSWORD_ARGUMENT.sub(rf"\1{MASK}", text)
        text = _CLOUD_KEY.sub("[masked access key]", text)
        text = _EMAIL.sub("[masked email]", text)
        # A password tried at login and then typed again in the shell.
        for password in tried_passwords or []:
            if len(password) >= 6 and password in text:
                text = text.replace(password, MASK)
        if own_address and own_address in text:
            text = text.replace(own_address, self.address(own_address)["source"])
        return text


def length_class(length: int) -> str:
    for upper, name in ((0, "0"), (5, "1-5"), (8, "6-8"), (12, "9-12"), (20, "13-20")):
        if length <= upper:
            return name
    return "21+"


def anonymise_session(session, data: Dict, file_hashes: List[str], anonymiser: Anonymiser) -> Dict:
    """One stored session, as it may leave the deployment."""
    own = str(session.attacker_ip or "")
    tried = [str(c.get("password") or "") for c in data["credentials"]]
    transcript = {
        index: entry for index, entry in enumerate(data["transcript"])
    } if len(data["transcript"]) == len(data["commands"]) else {}

    commands = []
    for index, command in enumerate(data["commands"]):
        entry = transcript.get(index, {})
        commands.append({
            "command": anonymiser.text(command, own, tried),
            "output": anonymiser.text(entry.get("output") or "", own, tried),
            "exit_code": entry.get("exit_code"),
            "timestamp": entry.get("timestamp"),
        })

    events = []
    for event in data["events"]:
        if not isinstance(event, dict):
            continue
        kept = {
            key: value for key, value in event.items()
            if key in ("event_type", "url", "host", "port", "filename", "path", "piped_to_shell", "bytes",
                       "reason", "at", "dest_host", "dest_port", "canary", "channel", "token_id", "kind",
                       "count", "interpreter")
        }
        for key in ("url", "path", "reason"):
            if isinstance(kept.get(key), str):
                kept[key] = anonymiser.text(kept[key], own, tried)
        events.append(kept)

    signals = session.signals if isinstance(session.signals, dict) else {}
    return {
        "session_id": session.session_uuid,
        **anonymiser.address(own),
        "protocol": session.protocol,
        "country": session.geo_country,
        "started_at": session.started_at.isoformat() if session.started_at else None,
        "duration_seconds": session.duration_seconds,
        "commands": commands,
        "credentials": [
            {
                "username": anonymiser.username(str(c.get("username") or "")),
                "password": anonymiser.password(str(c.get("password") or "")),
                "success": bool(c.get("success")),
                "timestamp": c.get("timestamp"),
            }
            for c in data["credentials"]
        ],
        "failed_logins": data["failed_logins"],
        "keystroke_count": data["keystroke_count"],
        "events": events,
        # Files as names and hashes; their bytes stay behind.
        "uploaded_files": [anonymiser.text(str(name), own, tried) for name in (session.uploaded_files or [])],
        "file_hashes": sorted(set(file_hashes)),
        "fingerprints": session.fingerprints,
        "verdict": {
            "category": session.attack_category.value if session.attack_category else None,
            "source": session.model_source,
            "tools": list(session.detected_tools or []),
            "intents": list(session.detected_intents or []),
            "techniques": [
                {"id": t.get("id"), "name": t.get("name"), "source": t.get("source")}
                for t in (session.mitre_techniques or []) if isinstance(t, dict)
            ],
            "severity": signals.get("severity"),
            "scanner_operator": session.scanner_operator,
            "label": (signals.get("label") or {}).get("category") if isinstance(signals.get("label"), dict) else None,
            "ai_agent": {k: (signals.get("ai_agent") or {}).get(k) for k in ("score", "canary", "basis")}
            if isinstance(signals.get("ai_agent"), dict) else None,
        },
    }


FIELDS = {
    "session_id": "The session's id in the source deployment (random UUID).",
    "source": "Keyed pseudonym of the source address (HMAC-SHA256, truncated). Stable under one key.",
    "network": "Keyed pseudonym of the source's /24 (IPv4) or /48 (IPv6).",
    "family": "ipv4, ipv6 or unknown.",
    "protocol": "ssh, telnet, ftp, http or https: the decoy service the session reached.",
    "country": "ISO country code of the source from GeoIP at capture time, when available.",
    "started_at": "Start of the session, UTC, as captured.",
    "duration_seconds": "Length of the session.",
    "commands": "Each command or web request in order, with the decoy's reply, exit code and time. "
                "Secrets are masked by pattern.",
    "credentials": "Login attempts: username, a keyed hash and length class of the password, and "
                   "whether the decoy accepted it.",
    "failed_logins": "Count of attempts the decoy refused.",
    "keystroke_count": "Keystrokes the engine counted in an interactive shell.",
    "events": "What the decoy observed beyond commands: retrievals a dropper asked for (never "
              "performed), forwards, canary and honeytoken triggers.",
    "uploaded_files": "Names of files the session uploaded.",
    "file_hashes": "SHA-256 of those files. Their bytes are not in the export.",
    "fingerprints": "Client handshake fingerprints the engine measured (SSH version, HASSH, JA3/JA4, ...).",
    "verdict": "The pipeline's own analysis at export time: category, tools, intents, ATT&CK techniques "
               "(validated against the catalog), severity, and a human label where one was recorded. "
               "A verdict is the system's output, not ground truth.",
}


async def export(args) -> int:
    from app.ai.provenance import run_metadata
    from app.ai.session_view import rebuild_session_data
    from app.core.database import async_session_factory
    from app.models import HoneypotSession, IndicatorOfCompromise

    anonymiser = Anonymiser(load_key(args))

    def parse(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    since, until = parse(args.since), parse(args.until)
    query = select(HoneypotSession).order_by(HoneypotSession.started_at, HoneypotSession.id)
    if since:
        query = query.where(HoneypotSession.started_at >= since)
    if until:
        query = query.where(HoneypotSession.started_at < until)
    if args.exclude_scanners:
        query = query.where(HoneypotSession.scanner_operator.is_(None))

    records: List[Dict] = []
    async with async_session_factory() as db:
        rows = (await db.execute(query)).scalars().all()
        hash_rows = (
            await db.execute(
                select(IndicatorOfCompromise.session_id, IndicatorOfCompromise.value)
                .where(IndicatorOfCompromise.ioc_type == "file_hash")
            )
        ).all()
        hashes: Dict[int, List[str]] = {}
        for session_id, value in hash_rows:
            hashes.setdefault(session_id, []).append(value)
        for row in rows:
            # A refused connection is not a session.
            if isinstance(row.signals, dict) and row.signals.get("refusal"):
                continue
            records.append(anonymise_session(row, rebuild_session_data(row), hashes.get(row.id, []), anonymiser))

    write_jsonl(args.out, records)
    starts = sorted(r["started_at"] for r in records if r["started_at"])
    card = {
        **run_metadata("app.tools.export_dataset", argv=[]),
        # Where the key came from is nobody else's business.
        "arguments": {name: value for name, value in vars(args).items() if name != "key_file"},
        "title": args.title or "HoneySentinel session export",
        "description": args.description or "not described",
        "sessions": len(records),
        "collection_window": {"first": starts[0] if starts else None, "last": starts[-1] if starts else None,
                              "requested_since": args.since, "requested_until": args.until},
        "counts": {
            "by_protocol": dict(Counter(r["protocol"] for r in records)),
            "by_category": dict(Counter((r["verdict"]["category"] or "unknown") for r in records)),
            "unique_sources": len({r["source"] for r in records}),
            "unique_networks": len({r["network"] for r in records if r["network"]}),
            "sessions_with_commands": sum(1 for r in records if r["commands"]),
            "sessions_with_a_human_label": sum(1 for r in records if r["verdict"]["label"]),
            "research_scanners_excluded": bool(args.exclude_scanners),
        },
        "fields": FIELDS,
        "anonymisation": {
            "key_id": anonymiser.key_id,
            "source_addresses": "HMAC-SHA256 under the export key, truncated to 64 bits; the /24 or /48 "
                                "likewise. The session's own address is replaced in its command text too.",
            "passwords": "HMAC-SHA256 under the export key, truncated to 64 bits, plus a length class "
                         "(0, 1-5, 6-8, 9-12, 13-20, 21+).",
            "usernames": "Kept, except e-mail addresses, which are pseudonymised.",
            "payloads": "File bytes excluded; SHA-256 and names kept.",
            "free_text": "Masked by pattern: credentials in URLs, password/token/key assignments, "
                         "password arguments, private key blocks, cloud access keys, e-mail addresses, "
                         "and any password the session tried at login.",
            "location": "Country only.",
            "not_changed": "Timestamps, durations, attacker-referenced hosts and URLs, fingerprints.",
        },
        "limitations": [
            "Masking is by pattern over free text; it reduces, and does not prove the absence of, "
            "identifying or secret material in commands and outputs.",
            "Exact timestamps and behaviour can identify a session to someone who also observed it.",
            "Verdicts are the pipeline's output at export time, not labels, unless 'label' is set.",
            "Sessions are what reached this deployment's decoys; they are not a sample of any wider population.",
        ],
    }
    with open(args.card, "w", encoding="utf-8") as handle:
        json.dump(card, handle, indent=2)
        handle.write("\n")
    print(f"{len(records)} session(s) -> {args.out}; data card -> {args.card}", file=sys.stderr)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, help="JSONL of anonymised sessions to write")
    parser.add_argument("--card", required=True, help="data card (JSON) to write")
    parser.add_argument("--since", help="ISO date/time; sessions started at or after")
    parser.add_argument("--until", help="ISO date/time; sessions started before")
    parser.add_argument("--exclude-scanners", action="store_true",
                        help="leave out sessions attributed to research scanners")
    parser.add_argument("--key-file", help="file holding the pseudonymisation key (else EXPORT_PSEUDONYM_KEY)")
    parser.add_argument("--title", help="title for the data card")
    parser.add_argument("--description", help="what the collection is: decoys, placement, purpose")
    args = parser.parse_args(argv)
    return asyncio.run(export(args))


if __name__ == "__main__":
    raise SystemExit(main())
