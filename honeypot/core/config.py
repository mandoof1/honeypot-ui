import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class OperationalMode(str, Enum):
    ACTIVE_EMULATION = "active"
    PASSIVE_MONITORING = "passive"


class EmulationProtocol(str, Enum):
    SSH = "ssh"
    FTP = "ftp"
    HTTP = "http"
    HTTPS = "https"


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

    ssh_port: int = int(os.getenv("HONEYPOT_SSH_PORT", "2222"))
    ftp_port: int = int(os.getenv("HONEYPOT_FTP_PORT", "2121"))
    #: Passive-mode data ports, which must be published alongside the control
    #: port, and the address PASV advertises. Behind NAT or Docker the socket's
    #: own address is unreachable, so set this to the public one.
    ftp_pasv_ports: str = os.getenv("HONEYPOT_FTP_PASV_PORTS", "50000-50019")
    ftp_pasv_address: str = os.getenv("HONEYPOT_FTP_PASV_ADDRESS", "")
    http_port: int = int(os.getenv("HONEYPOT_HTTP_PORT", "8080"))
    https_port: int = int(os.getenv("HONEYPOT_HTTPS_PORT", "8443"))

    bind_address: str = os.getenv("HONEYPOT_BIND_ADDRESS", "0.0.0.0")

    #: Largest HTTP request body read, and so the largest file an HTTP upload
    #: can deliver.
    http_max_body_bytes: int = int(
        os.getenv("HONEYPOT_HTTP_MAX_BODY_BYTES", str(8 * 1024 * 1024))
    )

    #: Which OpenSSH release the SSH emulator imitates — banner and transport
    #: proposal together. See honeypot/adaptive/ssh_profile.py; the profile
    #: exists because the two used to be chosen independently, which is
    #: fingerprintable in one packet.
    ssh_profile: str = os.getenv("HONEYPOT_SSH_PROFILE", "openssh-8.2p1-ubuntu")
    max_connections_per_ip: int = int(os.getenv("HONEYPOT_MAX_CONN_PER_IP", "5"))
    connection_timeout: int = int(os.getenv("HONEYPOT_CONN_TIMEOUT", "300"))
    rate_limit_per_minute: int = int(os.getenv("HONEYPOT_RATE_LIMIT", "60"))

    session_capture_dir: str = os.getenv(
        "HONEYPOT_CAPTURE_DIR", "./data/sessions"
    )
    file_capture_dir: str = os.getenv(
        "HONEYPOT_FILE_CAPTURE_DIR", "./data/uploads"
    )
    #: Largest captured file whose bytes are sent to the backend for analysis,
    #: and the most one session may send in total. Larger files still arrive
    #: as hashes and metadata, and remain in the capture directory.
    upload_forward_max_bytes: int = int(
        os.getenv("HONEYPOT_UPLOAD_FORWARD_MAX_BYTES", str(8 * 1024 * 1024))
    )
    upload_forward_session_bytes: int = int(
        os.getenv("HONEYPOT_UPLOAD_FORWARD_SESSION_BYTES", str(24 * 1024 * 1024))
    )
    log_dir: str = os.getenv("HONEYPOT_LOG_DIR", "./data/logs")

    enable_anti_fingerprinting: bool = os.getenv(
        "HONEYPOT_ANTI_FINGERPRINT", "true"
    ).lower() == "true"
    banner_rotation_interval: int = int(
        os.getenv("HONEYPOT_BANNER_ROTATION", "3600")
    )
    response_delay_min: float = float(
        os.getenv("HONEYPOT_RESPONSE_DELAY_MIN", "0.05")
    )
    response_delay_max: float = float(
        os.getenv("HONEYPOT_RESPONSE_DELAY_MAX", "0.5")
    )

    enable_isolation: bool = os.getenv(
        "HONEYPOT_ENABLE_ISOLATION", "true"
    ).lower() == "true"
    allowed_egress_hosts: list[str] = field(
        default_factory=lambda: [
            os.getenv("BACKEND_API_URL", "http://backend:8000")
        ]
    )
    docker_network: str = os.getenv("HONEYPOT_DOCKER_NETWORK", "honeypot_isolated")

    adaptive_response: bool = os.getenv(
        "HONEYPOT_ADAPTIVE_RESPONSE", "true"
    ).lower() == "true"
    profile_update_interval: int = int(
        os.getenv("HONEYPOT_PROFILE_UPDATE", "60")
    )

    # Management API. Bound separately from the emulators so it can be kept
    # off the interface attackers reach.
    control_bind_address: str = os.getenv("HONEYPOT_CONTROL_BIND", "0.0.0.0")
    control_port: int = int(os.getenv("HONEYPOT_CONTROL_PORT", "8000"))

    node_name: str = os.getenv("HONEYPOT_NODE_NAME", "honeypot-engine-main")

    backend_api_url: str = os.getenv(
        "BACKEND_API_URL", "http://backend:8000/api/v1"
    )
    backend_api_key: Optional[str] = os.getenv("HONEYPOT_BACKEND_API_KEY")
    ingest_token: str = os.getenv(
        "HONEYPOT_INGEST_TOKEN", "honeypot-ingest-token-change-in-production"
    )


config = HoneypotConfig()
