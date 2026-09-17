"""Indicators an attacker left inside a payload.

Network indicators (addresses, domains, URLs), where the money goes (wallets,
mining pools), how the operator is contacted (Telegram bots, Discord webhooks,
IRC), and keys that give the operator their way back in.

Everything here is pattern extraction over text the analyser has already
recovered. None of it is resolved, fetched or contacted: a URL found in a
sample is recorded, never visited, because visiting it would tell the operator
their payload is being analysed and would be exactly the egress the honeypot
exists to avoid.

Binaries are full of byte runs that look like things. Every extractor here
leans towards precision: wallet addresses are checksum-validated, domains must
end in a real TLD and not look like a filename, and private addresses are kept
out of the indicator feed.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from typing import Iterable

MAX_PER_TYPE = 200

# --------------------------------------------------------------------------
# Domains
# --------------------------------------------------------------------------

#: Generic TLDs worth recognising. Two-letter country codes are accepted
#: generically below.
_GENERIC_TLDS = frozenset("""
com net org info biz xyz top online site club live store tech app dev pro
cloud host space website fun icu vip shop buzz link click work life world
network email digital today tk ml ga cf gq name mobi asia tel travel jobs
edu gov mil int onion bit lol pw cam monster rest bar win bid men loan
download stream racing review trade date party science cricket accountant
faith webcam gdn kim ooo sbs cfd skin quest hair beauty makeup autos boats
homes motorcycles yachts wiki one best ninja rocks systems services company
agency solutions center support network media news blog group team tools
""".split())

#: Country codes that are also common file extensions. "libc.so", "run.sh",
#: "setup.py" and "readme.md" all end in real TLDs; a name under one of these
#: is only accepted with at least three labels (e.g. "cdn.example.sh").
_AMBIGUOUS_TLDS = frozenset(
    "so sh py pl md rs pm cc am in ac mk la ps ai ms as st sy id js hh mm cs sc".split()
)

_DOMAIN = re.compile(
    r"(?<![\w.@/-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,8}([a-z]{2,24}))(?![\w-])",
    re.IGNORECASE,
)

#: Names that satisfy the grammar but are never indicators.
_BENIGN_DOMAINS = frozenset({
    "example.com", "example.net", "example.org", "localhost.localdomain",
    "schemas.xmlsoap.org", "www.w3.org", "schemas.microsoft.com",
    "ns.adobe.com", "purl.org", "xmlns.com", "gnu.org", "www.gnu.org",
    "sourceware.org", "json-schema.org", "ocsp.digicert.com",
    "crl.microsoft.com", "www.microsoft.com", "go.microsoft.com",
})


def valid_domain(name: str) -> bool:
    name = name.lower().rstrip(".")
    labels = name.split(".")
    if len(labels) < 2 or len(name) > 253:
        return False
    tld = labels[-1]
    if not (tld in _GENERIC_TLDS or (len(tld) == 2 and tld.isalpha())):
        return False
    if tld in _AMBIGUOUS_TLDS and len(labels) < 3:
        return False
    if all(label.isdigit() for label in labels[:-1]):
        return False
    return name not in _BENIGN_DOMAINS


# --------------------------------------------------------------------------
# Addresses and URLs
# --------------------------------------------------------------------------

_IPV4 = re.compile(
    r"(?<![\d.])((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))(?::(\d{1,5}))?(?![\d.])"
)
_URL = re.compile(
    r"\b((?:https?|ftp|tftp|stratum\+(?:tcp|ssl|tls)|wss?|irc)://[^\s'\"<>`\\\x00-\x1f]{3,2000})",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]{1,64}@((?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}))\b")

#: Private and special-use space is kept in the report but never exported as
#: an indicator: blocking 10.0.0.1 because a payload mentions it helps nobody.
#: Documentation ranges (RFC 5737) are not excluded; they never occur in real
#: payloads, and excluding them would only make synthetic tests lie.
_NON_ROUTABLE = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
)]


def ip_scope(address: str) -> str:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "invalid"
    return "private" if any(ip in net for net in _NON_ROUTABLE) else "public"


def _clean_url(url: str) -> str:
    return url.rstrip(").,;:'\"]}>")


# --------------------------------------------------------------------------
# Wallets
# --------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}

_BTC_LEGACY = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])([13][1-9A-HJ-NP-Za-km-z]{25,34})(?![1-9A-HJ-NP-Za-km-z])")
_BTC_BECH32 = re.compile(r"(?<![a-z0-9])(bc1[ac-hj-np-z02-9]{11,71})(?![a-z0-9])", re.IGNORECASE)
_ETH = re.compile(r"(?<![0-9a-fA-Fx])(0x[a-fA-F0-9]{40})(?![0-9a-fA-F])")
#: Monero standard (95) and integrated (106) addresses. Monero's checksum is
#: Keccak-256, which hashlib does not provide (its sha3 pads differently), so
#: these are matched on shape: the prefix and length are distinctive enough.
_XMR = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])([48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?)(?![1-9A-HJ-NP-Za-km-z])")


def _base58check(value: str) -> bool:
    number = 0
    for char in value:
        if char not in _B58_INDEX:
            return False
        number = number * 58 + _B58_INDEX[char]
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(value) - len(value.lstrip("1"))) + raw
    if len(raw) != 25:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum


def _bech32(value: str) -> bool:
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    value = value.lower()
    hrp, _, data = value.rpartition("1")
    if hrp != "bc" or len(data) < 6 or any(c not in charset for c in data):
        return False
    values = [charset.index(c) for c in data]
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    checksum = 1
    for v in [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            checksum ^= generator[i] if (top >> i) & 1 else 0
    return checksum in (1, 0x2BC830A3)  # bech32 and bech32m


# --------------------------------------------------------------------------
# Operator channels and keys
# --------------------------------------------------------------------------

_TELEGRAM = re.compile(r"(?:api\.telegram\.org/bot|bot_?token\W{0,4})?(\d{8,10}):([A-Za-z0-9_-]{35})\b")
_TELEGRAM_HANDLE = re.compile(r"\bt\.me/([A-Za-z0-9_]{4,32})\b")
_DISCORD = re.compile(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,22}/[\w-]{20,100})")
_IRC_VARIABLE = re.compile(
    r"\$(server|servidor|channel|canal|chan|nick|nickname|admin|port|porta)\s*=\s*['\"]([^'\"\r\n]{1,120})['\"]",
    re.IGNORECASE,
)
_IRC_COMMAND = re.compile(r"\b(?:JOIN|PRIVMSG|NOTICE)\s+(#[\w-]{2,50})")
_SSH_PUBKEY = re.compile(
    r"(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com)\s+([A-Za-z0-9+/]{40,}={0,3})(?:[ \t]+([^\r\n\x00]{1,200}))?"
)
_USER_AGENT = re.compile(r"(Mozilla/[45]\.0 \([^)\r\n]{5,160}\)[^\"'\r\n\x00]{0,160})")
_POOL_ARG = re.compile(r"(?:-o|--url|\"url\"\s*:)\s*\"?([A-Za-z0-9.-]+\.[A-Za-z]{2,24}:\d{2,5})")


def ssh_key(key_type: str, blob_b64: str, comment: str | None) -> dict | None:
    """Fingerprint a public key the way ssh-keygen -l does, if it is one."""
    try:
        blob = base64.b64decode(blob_b64 + "=" * (-len(blob_b64) % 4), validate=True)
    except ValueError:
        return None
    if len(blob) < 8:
        return None
    length = int.from_bytes(blob[:4], "big")
    if blob[4:4 + length].decode("latin-1", errors="replace") != key_type:
        return None
    fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return {
        "type": key_type,
        "fingerprint": f"SHA256:{fingerprint}",
        "comment": (comment or "").strip()[:200] or None,
    }


def _add(bucket: list, seen: set, key, item) -> None:
    if key in seen or len(bucket) >= MAX_PER_TYPE:
        return
    seen.add(key)
    bucket.append(item)


def extract(texts: Iterable[tuple[str, str]]) -> dict:
    """Extract indicators from (text, origin) pairs.

    ``origin`` says where the text came from — ``strings``, ``xor:0x22``,
    ``script``, ``base64 layer`` — and travels with each indicator, because an
    address recovered from an XOR-encoded table is a stronger finding than one
    that happens to sit in a string table.
    """
    found = {
        "ips": [], "domains": [], "urls": [], "emails": [], "wallets": [],
        "ssh_keys": [], "c2_channels": [], "mining_pools": [], "user_agents": [],
        "irc": [],
    }
    seen = {key: set() for key in found}

    for text, origin in texts:
        if not text:
            continue
        lowered = text.lower()
        mentions_bot = "telegram" in lowered or "bot" in lowered

        for match in _URL.finditer(text):
            url = _clean_url(match.group(1))
            host = re.sub(r"^[a-z+]+://", "", url, flags=re.IGNORECASE).split("/", 1)[0].split("@")[-1].split(":")[0]
            if host.lower() in _BENIGN_DOMAINS:
                continue
            kind = "mining_pools" if url.lower().startswith("stratum") else "urls"
            _add(found[kind], seen[kind], url.lower() if kind == "mining_pools" else url,
                 {"value": url, "origin": origin})

        for match in _IPV4.finditer(text):
            address, port = match.group(1), match.group(2)
            if address in ("0.0.0.0", "255.255.255.255"):
                continue
            value = f"{address}:{port}" if port else address
            _add(found["ips"], seen["ips"], value, {
                "value": address, "port": int(port) if port else None,
                "scope": ip_scope(address), "origin": origin,
            })

        for match in _EMAIL.finditer(text):
            if valid_domain(match.group(2)):
                _add(found["emails"], seen["emails"], match.group(1).lower(),
                     {"value": match.group(1), "origin": origin})

        for match in _DOMAIN.finditer(text):
            name = match.group(1).rstrip(".")
            if not valid_domain(name):
                continue
            # A domain that is really the host part of an email is reported as
            # the email; keeping both double-counts one indicator.
            if text[max(0, match.start() - 1):match.start()] == "@":
                continue
            _add(found["domains"], seen["domains"], name.lower(), {"value": name.lower(), "origin": origin})

        for match in _BTC_LEGACY.finditer(text):
            if _base58check(match.group(1)):
                _add(found["wallets"], seen["wallets"], match.group(1),
                     {"currency": "BTC", "value": match.group(1), "origin": origin})
        for match in _BTC_BECH32.finditer(text):
            if _bech32(match.group(1)):
                _add(found["wallets"], seen["wallets"], match.group(1).lower(),
                     {"currency": "BTC", "value": match.group(1).lower(), "origin": origin})
        for match in _ETH.finditer(text):
            _add(found["wallets"], seen["wallets"], match.group(1).lower(),
                 {"currency": "ETH", "value": match.group(1), "origin": origin})
        for match in _XMR.finditer(text):
            _add(found["wallets"], seen["wallets"], match.group(1),
                 {"currency": "XMR", "value": match.group(1), "origin": origin})

        for match in _SSH_PUBKEY.finditer(text):
            key = ssh_key(match.group(1), match.group(2), match.group(3))
            if key:
                _add(found["ssh_keys"], seen["ssh_keys"], key["fingerprint"], {**key, "origin": origin})

        for match in _TELEGRAM.finditer(text):
            if not mentions_bot:
                continue
            _add(found["c2_channels"], seen["c2_channels"], f"telegram:{match.group(1)}", {
                "kind": "telegram_bot", "value": f"{match.group(1)}:{match.group(2)}",
                "indicator": f"telegram-bot:{match.group(1)}", "origin": origin,
            })
        for match in _TELEGRAM_HANDLE.finditer(text):
            _add(found["c2_channels"], seen["c2_channels"], f"t.me:{match.group(1).lower()}", {
                "kind": "telegram_handle", "value": f"t.me/{match.group(1)}",
                "indicator": f"t.me/{match.group(1)}", "origin": origin,
            })
        for match in _DISCORD.finditer(text):
            _add(found["c2_channels"], seen["c2_channels"], match.group(1), {
                "kind": "discord_webhook", "value": match.group(1),
                "indicator": match.group(1), "origin": origin,
            })

        for match in _IRC_VARIABLE.finditer(text):
            role = match.group(1).lower()
            role = {"servidor": "server", "canal": "channel", "chan": "channel",
                    "nickname": "nick", "porta": "port"}.get(role, role)
            _add(found["irc"], seen["irc"], f"{role}={match.group(2)}", {
                "role": role, "value": match.group(2), "origin": origin,
            })
        for match in _IRC_COMMAND.finditer(text):
            _add(found["irc"], seen["irc"], f"channel={match.group(1)}", {
                "role": "channel", "value": match.group(1), "origin": origin,
            })

        for match in _POOL_ARG.finditer(text):
            _add(found["mining_pools"], seen["mining_pools"], match.group(1).lower(),
                 {"value": match.group(1), "origin": origin})

        for match in _USER_AGENT.finditer(text):
            _add(found["user_agents"], seen["user_agents"], match.group(1),
                 {"value": match.group(1).strip()[:300], "origin": origin})

    # Hosts already reported as part of a URL or pool are still worth a
    # domain row — a blocklist wants the host — so nothing is removed here.
    return found


def count(indicators: dict) -> int:
    return sum(len(v) for v in indicators.values())
