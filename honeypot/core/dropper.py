"""Emulated file retrieval — wget, curl, tftp and ftpget.

The SSH emulator answered every ``wget`` and ``curl`` with ``command not
found``. Almost every real Linux host has at least one of them, so that reply
is both a fingerprint and, more importantly, the point at which every dropper
gives up. A loader that fetches its payload gets one line into its script and
stops, and the C2 URL it was about to reveal, the payload name, the
architecture it selected and everything it would have run afterwards are never
observed. That is the single most valuable moment in an SSH honeypot session
and the emulator was throwing it away.

So the download is emulated as *succeeding*. Nothing is fetched: the URL is
parsed, recorded as an indicator, and a plausible transcript is printed. The
honeypot makes no outbound connection of any kind here, which is what keeps
the egress guarantee intact while still letting the attack chain continue.

Parsing works on the argument vector the shell lexer produced, with a table
of which options take a value. The earlier version took the first token that
did not start with a dash and split the raw line on ``|;&``: ``curl -m 30
URL`` recorded the host ``30``, ``curl -O URL`` recorded nothing because
``-O`` swallowed the URL as its value, and a quoted URL with ``?a=1&b=2`` was
cut at the ampersand.
"""

from __future__ import annotations

import hashlib
import posixpath
import random
import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

#: Bounded so a pathological command line cannot be used to build a huge reply.
MAX_URL_LENGTH = 2048
#: URLs taken from one command (``wget a b c``).
MAX_URLS = 8

#: Options that consume the next argument, per tool. Anything not listed is a
#: switch. Getting this table right is the whole of "which token is the URL".
_WGET_SHORT_VALUES = set("OoatTwPUeiQlDARIXB")
_WGET_LONG_VALUES = {
    "output-document", "output-file", "append-output", "tries", "timeout", "wait",
    "directory-prefix", "user-agent", "execute", "input-file", "header", "post-data",
    "post-file", "user", "password", "quota", "limit-rate", "level", "domains",
    "accept", "reject", "bind-address", "dns-timeout", "connect-timeout",
    "read-timeout", "referer", "load-cookies", "save-cookies", "method",
    "body-data", "ca-certificate", "certificate", "secure-protocol", "base",
    "waitretry", "http-user", "http-password", "proxy-user", "proxy-password",
}
#: wget's two-letter short switches, which must not be read as a cluster.
_WGET_PAIRS = {"-nc", "-nd", "-nv", "-nH", "-np"}
_CURL_SHORT_VALUES = set("omAHdXeuxbcTFwEKryYzCUDtQP")
_CURL_LONG_VALUES = {
    "output", "max-time", "user-agent", "header", "data", "data-binary", "data-raw",
    "data-urlencode", "request", "referer", "user", "proxy", "cookie", "cookie-jar",
    "upload-file", "form", "connect-timeout", "retry", "retry-delay",
    "retry-max-time", "write-out", "cert", "cacert", "config", "range",
    "continue-at", "interface", "resolve", "proxy-user", "limit-rate",
    "max-filesize", "dump-header", "socks5", "socks5-hostname", "key", "pass",
    "ciphers", "stderr", "trace", "trace-ascii", "max-redirs", "connect-to",
    "dns-servers", "speed-limit", "speed-time", "output-dir",
}


@dataclass
class Download:
    tool: str
    url: str
    host: str
    port: int
    filename: str
    #: Where the attacker asked for it to land, as written on the command
    #: line. Kept separate from ``filename`` so ``-O /tmp/x86`` drops the file
    #: in /tmp while the transcript still names it ``x86``.
    target: str
    #: True when the fetched content is piped straight into a shell
    #: (``curl … | sh``) — nothing is written to disk in that case.
    piped: bool
    #: True when the tool was asked to save rather than print.
    saves: bool
    #: Run as a busybox applet, whose output differs from the full tool's.
    busybox: bool = False


def _build(tool: str, url: str, output: Optional[str], saves: bool, piped: bool,
           busybox: bool, default_scheme: str = "http", directory: str = "") -> Optional[Download]:
    url = url.strip()[:MAX_URL_LENGTH]
    if not url:
        return None
    if "://" not in url:
        url = f"{default_scheme}://" + url
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return None
    if not host:
        return None
    if port is None:
        port = {"https": 443, "ftp": 21, "tftp": 69}.get(parsed.scheme, 80)
    if output is None:
        output = posixpath.basename(parsed.path) or "index.html"
        if directory:
            output = posixpath.join(directory, output)
    return Download(
        tool=tool,
        url=url,
        host=host,
        port=port,
        # Never let a crafted URL escape into a path the emulator prints back.
        filename=posixpath.basename(output) or "index.html",
        target=output,
        piped=piped,
        saves=saves and not piped,
        busybox=busybox,
    )


def _options(args: list[str], short_values: set[str], long_values: set[str],
             pairs: frozenset[str] = frozenset()) -> tuple[list[tuple[str, Optional[str]]], list[str]]:
    """Split arguments into (option, value) pairs and operands."""
    options: list[tuple[str, Optional[str]]] = []
    operands: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            operands.extend(args[i + 1:])
            break
        if arg.startswith("--") and len(arg) > 2:
            name, equals, value = arg[2:].partition("=")
            if equals:
                options.append((name, value))
            elif name in long_values and i + 1 < len(args):
                options.append((name, args[i + 1]))
                i += 1
            else:
                options.append((name, None))
        elif arg in pairs:
            options.append((arg[1:], None))
        elif arg.startswith("-") and len(arg) > 1:
            cluster = arg[1:]
            for position, flag in enumerate(cluster):
                if flag in short_values:
                    rest = cluster[position + 1:]
                    if rest:
                        options.append((flag, rest))
                    elif i + 1 < len(args):
                        options.append((flag, args[i + 1]))
                        i += 1
                    else:
                        options.append((flag, None))
                    break
                options.append((flag, None))
        else:
            operands.append(arg)
        i += 1
    return options, operands


def _parse_wget(args: list[str], piped: bool, busybox: bool) -> list[Download]:
    options, operands = _options(args, _WGET_SHORT_VALUES, _WGET_LONG_VALUES, frozenset(_WGET_PAIRS))
    output = None
    directory = ""
    saves = True
    for name, value in options:
        if name in ("O", "output-document"):
            if value == "-":
                saves = False
            elif value:
                output = value
        elif name in ("P", "directory-prefix") and value:
            directory = value
    downloads = []
    for url in operands[:MAX_URLS]:
        built = _build("wget", url, output, saves, piped, busybox, directory=directory)
        if built:
            downloads.append(built)
    return downloads


def _parse_curl(args: list[str], piped: bool) -> list[Download]:
    options, operands = _options(args, _CURL_SHORT_VALUES, _CURL_LONG_VALUES)
    urls = list(operands)
    output = None
    remote_name = False
    for name, value in options:
        if name in ("o", "output"):
            output = value if value and value != "-" else None
        elif name in ("O", "remote-name", "J", "remote-header-name"):
            remote_name = True
        elif name == "url" and value:
            urls.append(value)
    downloads = []
    for url in urls[:MAX_URLS]:
        built = _build("curl", url, output, output is not None or remote_name, piped, False)
        if built:
            downloads.append(built)
    return downloads


def _parse_tftp(args: list[str], piped: bool, busybox: bool) -> list[Download]:
    """``tftp -g -r REMOTE [-l LOCAL] HOST [PORT]`` and ``tftp HOST -c get FILE``."""
    options, operands = _options(args, set("rlbc"), set())
    remote = local = None
    getting = False
    for name, value in options:
        if name == "r":
            remote = value
        elif name == "l":
            local = value
        elif name == "g":
            getting = True
        elif name == "c" and value == "get":
            getting = True
            if len(operands) >= 2:
                remote = operands.pop(1)
    if not operands or not remote or not getting:
        return []
    host = operands[0]
    port = operands[1] if len(operands) > 1 and operands[1].isdigit() else "69"
    built = _build("tftp", f"tftp://{host}:{port}/{remote.lstrip('/')}", local or posixpath.basename(remote),
                   True, piped, busybox, default_scheme="tftp")
    return [built] if built else []


def _parse_ftpget(args: list[str], piped: bool, busybox: bool) -> list[Download]:
    """``ftpget [-u USER] [-p PASS] [-P PORT] HOST LOCAL [REMOTE]``."""
    options, operands = _options(args, set("upP"), {"username", "password", "port"})
    port = "21"
    for name, value in options:
        if name in ("P", "port") and value and value.isdigit():
            port = value
    if len(operands) < 2:
        return []
    host, local = operands[0], operands[1]
    remote = operands[2] if len(operands) > 2 else local
    built = _build("ftpget", f"ftp://{host}:{port}/{remote.lstrip('/')}", local, True, piped, busybox,
                   default_scheme="ftp")
    return [built] if built else []


def parse_argv(argv: list[str], piped: bool = False, busybox: bool = False) -> list[Download]:
    """Every retrieval one command asks for, from its argument vector.

    ``argv`` is what the shell lexer produced, so quoting is already
    resolved: a quoted URL arrives whole, ampersands and all. Returns an
    empty list when the command is not a fetch that can be read.
    """
    if not argv:
        return []
    tool = posixpath.basename(argv[0])
    args = [a[:MAX_URL_LENGTH] for a in argv[1:256]]
    if tool == "wget":
        return _parse_wget(args, piped, busybox)
    if tool == "curl":
        return _parse_curl(args, piped)
    if tool == "tftp":
        return _parse_tftp(args, piped, busybox)
    if tool == "ftpget":
        return _parse_ftpget(args, piped, busybox)
    return []


def parse(command: str) -> Download | None:
    """Pull the retrieval intent out of a command line given as text.

    Returns ``None`` when the command is not a fetch we can emulate, so the
    caller can fall through to its normal handling.
    """
    # Imported here: the capture package imports core modules at load time.
    from honeypot.capture.shell_writes import INTERPRETERS, TRANSPARENT_PREFIXES, _Lexer

    try:
        statements = _Lexer(command).run()
    except Exception:
        return None
    if not statements:
        return None
    pipeline = statements[0][1]
    words = list(pipeline[0].words)
    while words and words[0] in TRANSPARENT_PREFIXES:
        words.pop(0)
    busybox = bool(words) and posixpath.basename(words[0]) == "busybox"
    if busybox:
        words.pop(0)
    piped = any(
        stage.words and posixpath.basename(stage.words[0]) in INTERPRETERS
        for stage in pipeline[1:]
    )
    downloads = parse_argv(words, piped=piped, busybox=busybox)
    return downloads[0] if downloads else None


def usage_error(tool: str, busybox: bool = False) -> str:
    """What the tool prints when it is given nothing it can fetch."""
    if tool == "wget":
        if busybox:
            return ("BusyBox v1.30.1 (Ubuntu 1:1.30.1-4ubuntu6.4) multi-call binary.\n\n"
                    "Usage: wget [-c|--continue] [--spider] [-q|--quiet] [-O|--output-document FILE]\n"
                    "\t[--header 'header: value'] [-Y|--proxy on/off] [-P DIR]\n"
                    "\t[-S|--server-response] [-U|--user-agent AGENT] [-T SEC] URL...\n")
        return (
            "wget: missing URL\n"
            "Usage: wget [OPTION]... [URL]...\n\n"
            "Try `wget --help' for more options.\n"
        )
    if tool == "curl":
        return "curl: try 'curl --help' or 'curl --manual' for more information\n"
    if tool == "tftp":
        return ("BusyBox v1.30.1 (Ubuntu 1:1.30.1-4ubuntu6.4) multi-call binary.\n\n"
                "Usage: tftp [OPTIONS] HOST [PORT]\n")
    return ("BusyBox v1.30.1 (Ubuntu 1:1.30.1-4ubuntu6.4) multi-call binary.\n\n"
            "Usage: ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE\n")


def size_for(download: Download, seed: int = 0) -> int:
    """A plausible size for the file, the same every time it is asked for.

    It used to be drawn afresh on each call, so the size wget reported and
    the size a second fetch of the same URL reported differed.
    """
    rng = random.Random(f"{seed}:size:{download.url}")
    if re.search(r"\.(sh|py|pl|txt)$", download.filename):
        return rng.randint(400, 6_000)
    return rng.randint(20_000, 180_000)


def is_ip_literal(host: str) -> bool:
    return bool(re.fullmatch(r"[0-9.]+", host)) or ":" in host


def resolved_address(host: str, seed: int) -> str:
    """The address this deployment "resolves" a name to.

    Nothing is looked up — the engine makes no outbound request, DNS
    included. The address used to be the literal ``10.0.0.9`` for every name
    on every deployment, which is both a private address no public name
    resolves to and a constant anyone could match. It is now drawn from the
    deployment's seed and the name, so one name always gives one address
    here, in wget, ping and nslookup alike, and a different one elsewhere.
    """
    digest = hashlib.sha256(f"{seed}:resolve:{host.lower()}".encode()).digest()
    # Keep clear of private, loopback, link-local, multicast and reserved
    # ranges: a public name would not resolve into any of them.
    first = [n for n in range(23, 223) if n not in (100, 127, 169, 172, 192, 198, 203)]
    return f"{first[digest[0] % len(first)]}.{digest[1]}.{digest[2]}.{1 + digest[3] % 254}"


def _connect_lines(download: Download, seed: int) -> str:
    """wget's resolve/connect preamble.

    An IP literal is not resolved, and wget does not print a Resolving line
    for one. Getting this wrong is a cheap tell for anyone who has read real
    wget output, which is most people writing droppers.
    """
    if is_ip_literal(download.host):
        return f"Connecting to {download.host}:{download.port}... connected.\n"
    resolved = resolved_address(download.host, seed)
    return (
        f"Resolving {download.host} ({download.host})... {resolved}\n"
        f"Connecting to {download.host} ({download.host})|{resolved}|"
        f":{download.port}... connected.\n"
    )


def transcript(download: Download, size: int, seed: int = 0) -> str:
    """What the tool would have printed on a successful fetch."""
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%d %H:%M:%S")
    # How long the "transfer" took: the same for the same URL here, and not
    # the same constant in every transcript from every deployment.
    elapsed = random.Random(f"{seed}:elapsed:{download.url}").uniform(0.02, 0.4)
    rate = size / elapsed / (1024 * 1024)

    if download.tool in ("tftp", "ftpget"):
        # Both busybox applets are silent on success.
        return ""

    if download.tool == "wget" and download.busybox:
        address = download.host if is_ip_literal(download.host) else resolved_address(download.host, seed)
        if not download.saves:
            return f"Connecting to {download.host} ({address}:{download.port})\n"
        return (
            f"Connecting to {download.host} ({address}:{download.port})\n"
            f"{download.filename[:20]:<20} 100% |********************************| {size:>5}  0:00:00 ETA\n"
        )

    if download.tool == "wget":
        if not download.saves:
            # -O- streams to stdout; wget still logs progress to stderr.
            return (
                f"--{stamp}--  {download.url}\n"
                + _connect_lines(download, seed)
                + "HTTP request sent, awaiting response... 200 OK\n"
                f"Length: {size} ({size // 1024}K) [application/octet-stream]\n"
                "Saving to: 'STDOUT'\n\n"
                f"-                   100%[===================>] "
                f"{size / 1024:6.2f}K  --.-KB/s    in {elapsed:.2g}s\n\n"
                f"{stamp} ({rate:.2f} MB/s) - written to stdout "
                f"[{size}/{size}]\n"
            )
        return (
            f"--{stamp}--  {download.url}\n"
            + _connect_lines(download, seed)
            + "HTTP request sent, awaiting response... 200 OK\n"
            f"Length: {size} ({size // 1024}K) [application/octet-stream]\n"
            f"Saving to: '{download.filename}'\n\n"
            f"{download.filename[:19]:<19} 100%[===================>] "
            f"{size / 1024:6.2f}K  --.-KB/s    in {elapsed:.2g}s\n\n"
            f"{stamp} ({rate:.2f} MB/s) - '{download.filename}' saved "
            f"[{size}/{size}]\n"
        )

    # curl is silent unless it is showing its progress meter, which it does
    # only when output is not a terminal-bound stdout.
    if download.saves:
        return (
            "  % Total    % Received % Xferd  Average Speed   Time    Time"
            "     Time  Current\n"
            "                                 Dload  Upload   Total   Spent"
            "    Left  Speed\n"
            f"100 {size // 1024:5d}  100 {size // 1024:5d}    0     0  "
            f"{size // 1024:5d}      0 --:--:-- --:--:-- --:--:-- {size // 512:5d}\n"
        )
    return ""
