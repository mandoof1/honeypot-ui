import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


logger = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    """An integer setting that falls back instead of crashing the engine.

    A typo in one variable used to raise ValueError at import time and take
    every decoy down with it; a wrong limit is far less damaging than no
    honeypot at all.
    """
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        logger.warning("Ignoring %s=%r: not an integer, using %s", name, raw, default)
        return default


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw.strip())
    except ValueError:
        logger.warning("Ignoring %s=%r: not a number, using %s", name, raw, default)
        return default


def _optional_int_env(name: str) -> Optional[int]:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return None
    try:
        return int(raw.strip())
    except ValueError:
        logger.warning("Ignoring %s=%r: not an integer", name, raw)
        return None


#: The ingest token the code ships with. Everyone who has read the
#: repository knows it, so the engine refuses to start with it.
DEFAULT_INGEST_TOKEN = "honeypot-ingest-token-change-in-production"


class OperationalMode(str, Enum):
    ACTIVE_EMULATION = "active"
    PASSIVE_MONITORING = "passive"


class EmulationProtocol(str, Enum):
    SSH = "ssh"
    FTP = "ftp"
    HTTP = "http"
    HTTPS = "https"
    TELNET = "telnet"


def _mode_from_env() -> OperationalMode:
    raw = os.getenv("HONEYPOT_OPERATIONAL_MODE", "active").strip().lower()
    try:
        return OperationalMode(raw)
    except ValueError:
        return OperationalMode.ACTIVE_EMULATION


def _protocols_from_env() -> list["EmulationProtocol"]:
    raw = os.getenv("HONEYPOT_PROTOCOLS", "ssh,ftp,http")
    protocols = []
    for name in raw.split(","):
        name = name.strip().lower()
        if not name:
            continue
        try:
            protocols.append(EmulationProtocol(name))
        except ValueError:
            continue
    return protocols or [
        EmulationProtocol.SSH,
        EmulationProtocol.FTP,
        EmulationProtocol.HTTP,
    ]


@dataclass
class HoneypotConfig:
    # HONEYPOT_OPERATIONAL_MODE was documented and set in docker-compose but
    # never actually read, so the engine was always in active mode.
    operational_mode: OperationalMode = field(default_factory=_mode_from_env)
    enabled_protocols: list[EmulationProtocol] = field(
        default_factory=_protocols_from_env
    )

    ssh_port: int = _int_env("HONEYPOT_SSH_PORT", 2222)
    ftp_port: int = _int_env("HONEYPOT_FTP_PORT", 2121)
    telnet_port: int = _int_env("HONEYPOT_TELNET_PORT", 2323)
    #: Passive-mode data ports, which must be published alongside the control
    #: port, and the address PASV advertises. Behind NAT or Docker the socket's
    #: own address is unreachable, so set this to the public one.
    ftp_pasv_ports: str = os.getenv("HONEYPOT_FTP_PASV_PORTS", "50000-50019")
    ftp_pasv_address: str = os.getenv("HONEYPOT_FTP_PASV_ADDRESS", "")
    http_port: int = _int_env("HONEYPOT_HTTP_PORT", 8080)
    https_port: int = _int_env("HONEYPOT_HTTPS_PORT", 8443)

    bind_address: str = os.getenv("HONEYPOT_BIND_ADDRESS", "0.0.0.0")

    #: Largest HTTP request body read, and so the largest file an HTTP upload
    #: can deliver.
    http_max_body_bytes: int = _int_env("HONEYPOT_HTTP_MAX_BODY_BYTES", 8 * 1024 * 1024)
    #: A real web application to put behind the HTTP/HTTPS decoys, as
    #: http://host:port on a network the engine can reach. Every request is
    #: recorded exactly as before and then answered by the application, except
    #: the bait paths (fake .env, WordPress, phpMyAdmin...), which the decoy
    #: keeps answering itself. Empty: the decoy's built-in pages only.
    http_upstream: str = os.getenv("HONEYPOT_HTTP_UPSTREAM", "")
    #: Bait paths the application serves itself and so should receive,
    #: comma-separated: a shop has its own /login and /admin.
    http_upstream_owns: str = os.getenv("HONEYPOT_HTTP_UPSTREAM_OWNS", "")
    #: A decoy copy of that application, as http://host:port: same public
    #: pages, invented private data. Set, a client that gives itself away as
    #: an attacker is answered by the decoy copy from then on, while everyone
    #: else keeps reaching the live one. See honeypot/security/diversion.py.
    http_decoy_upstream: str = os.getenv("HONEYPOT_HTTP_DECOY_UPSTREAM", "")
    #: Seconds a diverted client stays diverted after its last request.
    http_divert_ttl: int = _int_env("HONEYPOT_HTTP_DIVERT_TTL", 6 * 3600)
    #: Failed logins within ten minutes that divert a client; 0 never does.
    http_divert_failed_logins: int = _int_env("HONEYPOT_HTTP_DIVERT_FAILED_LOGINS", 10)
    #: The application's session cookie, so a diverted session stays diverted
    #: when its address changes. Empty: clients are told apart by address and
    #: user agent only.
    http_session_cookie: str = os.getenv("HONEYPOT_HTTP_SESSION_COOKIE", "")
    #: Seconds a web session stays open for more requests from the same client
    #: (address, user agent, session cookie) after its connection closes, so a
    #: scanner firing one request per connection, or a browser reconnecting,
    #: is recorded as one session rather than dozens. The session is delivered
    #: to the backend this long after the client's last request. 0 restores
    #: one session per connection.
    http_session_idle: float = _float_env("HONEYPOT_HTTP_SESSION_IDLE", 30.0)

    #: Which OpenSSH release the SSH emulator imitates — banner and transport
    #: proposal together. See honeypot/adaptive/ssh_profile.py; the profile
    #: exists because the two used to be chosen independently, which is
    #: fingerprintable in one packet.
    ssh_profile: str = os.getenv("HONEYPOT_SSH_PROFILE", "openssh-8.2p1-ubuntu")
    #: Concurrent connections one address may hold open across every
    #: protocol, and across all addresses together. Both are enforced at
    #: accept time (security/rate_limiter.py), before any protocol work.
    max_connections_per_ip: int = _int_env("HONEYPOT_MAX_CONN_PER_IP", 5)
    max_connections: int = _int_env("HONEYPOT_MAX_CONNECTIONS", 500)
    #: The same two per-address limits for the HTTP/HTTPS decoys. A browser
    #: opens about six connections to load one page and keeps them alive,
    #: and every tailnet or LAN visitor arrives from one bridge address, so
    #: the shell-sized cap of 5 refused part of every page of the website.
    http_max_connections_per_ip: int = _int_env("HONEYPOT_HTTP_MAX_CONN_PER_IP", 32)
    http_rate_limit_per_minute: int = _int_env("HONEYPOT_HTTP_RATE_LIMIT", 600)
    #: Idle timeout in seconds for every protocol. Unset, each emulator keeps
    #: its own default (SSH 300, FTP 120, HTTP 60).
    connection_timeout: Optional[int] = _optional_int_env("HONEYPOT_CONN_TIMEOUT")
    #: Longest a single connection may live, idle or not.
    max_session_seconds: int = _int_env("HONEYPOT_MAX_SESSION_SECONDS", 1800)
    rate_limit_per_minute: int = _int_env("HONEYPOT_RATE_LIMIT", 60)

    session_capture_dir: str = os.getenv(
        "HONEYPOT_CAPTURE_DIR", "./data/sessions"
    )
    file_capture_dir: str = os.getenv(
        "HONEYPOT_FILE_CAPTURE_DIR", "./data/uploads"
    )
    #: Largest captured file whose bytes are sent to the backend for analysis,
    #: and the most one session may send in total. Larger files still arrive
    #: as hashes and metadata, and remain in the capture directory.
    upload_forward_max_bytes: int = _int_env("HONEYPOT_UPLOAD_FORWARD_MAX_BYTES", 8 * 1024 * 1024)
    upload_forward_session_bytes: int = _int_env("HONEYPOT_UPLOAD_FORWARD_SESSION_BYTES", 24 * 1024 * 1024)
    #: Sessions the backend could not take (down, timing out, 5xx) wait on
    #: disk under <capture dir>/spool and are retried; see core/spool.py.
    spool_max_files: int = _int_env("HONEYPOT_SPOOL_MAX_FILES", 5000)
    spool_max_bytes: int = _int_env("HONEYPOT_SPOOL_MAX_BYTES", 512 * 1024 * 1024)
    #: Local copies of ingested sessions and captured uploads are pruned
    #: after this many days; the backend holds the record of them.
    capture_retention_days: int = _int_env("HONEYPOT_CAPTURE_RETENTION_DAYS", 7)
    upload_retention_days: int = _int_env("HONEYPOT_UPLOAD_RETENTION_DAYS", 30)
    #: Seconds between heartbeats to the backend.
    heartbeat_interval: int = _int_env("HONEYPOT_HEARTBEAT_INTERVAL", 60)

    enable_anti_fingerprinting: bool = os.getenv(
        "HONEYPOT_ANTI_FINGERPRINT", "true"
    ).lower() == "true"
    banner_rotation_interval: int = _int_env("HONEYPOT_BANNER_ROTATION", 3600)
    #: Random delay before each HTTP and FTP reply, in seconds. A few
    #: milliseconds, the scale of a server doing real work; the old 50-500 ms
    #: capped throughput and was slower than any server it imitated.
    response_delay_min: float = _float_env("HONEYPOT_RESPONSE_DELAY_MIN", 0.001)
    response_delay_max: float = _float_env("HONEYPOT_RESPONSE_DELAY_MAX", 0.006)
    #: Seconds each decoy waits before it refuses a wrong password, while
    #: HONEYPOT_ANTI_FINGERPRINT is on. The defaults are what the daemons
    #: they imitate took in the first fingerprint comparison (docs/
    #: evaluation/fingerprint/1-baseline): OpenSSH 8.2p1 2.175 s, login(1)
    #: behind telnetd 2.885 s, vsftpd 3.031 s. ProFTPD refused at once, so
    #: the FTP value applies to the vsftpd identity only. See
    #: honeypot/core/login_delay.py.
    ssh_fail_delay: float = _float_env("HONEYPOT_SSH_FAIL_DELAY", 2.175)
    telnet_fail_delay: float = _float_env("HONEYPOT_TELNET_FAIL_DELAY", 2.885)
    ftp_fail_delay: float = _float_env("HONEYPOT_FTP_FAIL_DELAY", 3.031)
    #: Refusals that may be waiting out that pause at one moment, across all
    #: protocols. Past it a refusal is sent without the pause.
    fail_delay_max_pending: int = _int_env("HONEYPOT_FAIL_DELAY_MAX_PENDING", 256)
    #: Also put the web canary comment (HONEYPOT_AI_CANARY) into HTML pages
    #: relayed from HONEYPOT_HTTP_UPSTREAM. Off: only the decoy's own pages
    #: carry it, and the application's responses pass through untouched.
    http_ai_canary_upstream: bool = os.getenv(
        "HONEYPOT_HTTP_AI_CANARY_UPSTREAM", "false"
    ).lower() == "true"

    enable_isolation: bool = os.getenv(
        "HONEYPOT_ENABLE_ISOLATION", "true"
    ).lower() == "true"
    docker_network: str = os.getenv("HONEYPOT_DOCKER_NETWORK", "honeypot_isolated")

    #: Profile each source address from what it does (tools, techniques,
    #: volume) and send the resulting label to the backend with its sessions
    #: as ``threat_profile``. Off: no profiling, no label. The name is
    #: historical — nothing about the decoy's responses changes with it.
    adaptive_response: bool = os.getenv(
        "HONEYPOT_ADAPTIVE_RESPONSE", "true"
    ).lower() == "true"
    #: Plant a note addressed to automated assistants in each home directory
    #: and raise ``ai_canary_triggered`` when a session acts on it; see
    #: honeypot/core/canary.py.
    ai_canary: bool = os.getenv("HONEYPOT_AI_CANARY", "true").lower() == "true"
    #: Seconds a source that was let in with a guessed password may come
    #: back with the same credential and be let in again.
    accepted_login_ttl: int = _int_env("HONEYPOT_ACCEPTED_LOGIN_TTL", 7 * 86400)
    #: Seconds between isolation checks, so the heartbeat reports the
    #: current state and not the one found at startup. 0 checks only once.
    isolation_check_interval: int = _int_env("HONEYPOT_ISOLATION_CHECK_INTERVAL", 600)
    #: Start even though HONEYPOT_INGEST_TOKEN is still the published
    #: default. For a throwaway local run only.
    allow_default_token: bool = os.getenv(
        "HONEYPOT_ALLOW_DEFAULT_TOKEN", "false"
    ).lower() == "true"

    # Management API. Bound separately from the emulators so it can be kept
    # off the interface attackers reach.
    control_bind_address: str = os.getenv("HONEYPOT_CONTROL_BIND", "0.0.0.0")
    control_port: int = _int_env("HONEYPOT_CONTROL_PORT", 8000)

    node_name: str = os.getenv("HONEYPOT_NODE_NAME", "honeypot-engine-main")

    backend_api_url: str = os.getenv(
        "BACKEND_API_URL", "http://backend:8000/api/v1"
    )
    ingest_token: str = os.getenv(
        "HONEYPOT_INGEST_TOKEN", DEFAULT_INGEST_TOKEN
    )
    #: Token the control API accepts. Unset, it is the ingest token, as it
    #: always was; set, only this one opens the control API, so the secret
    #: that can change the engine's mode is not the one every ingest carries.
    control_token: str = os.getenv("HONEYPOT_CONTROL_TOKEN", "")

    @property
    def effective_control_token(self) -> str:
        return self.control_token or self.ingest_token


config = HoneypotConfig()
