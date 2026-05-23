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


@dataclass
class HoneypotConfig:
    operational_mode: OperationalMode = OperationalMode.ACTIVE_EMULATION
    enabled_protocols: list[EmulationProtocol] = field(
        default_factory=lambda: [
            EmulationProtocol.SSH,
            EmulationProtocol.FTP,
            EmulationProtocol.HTTP,
        ]
    )

    ssh_port: int = int(os.getenv("HONEYPOT_SSH_PORT", "2222"))
    ftp_port: int = int(os.getenv("HONEYPOT_FTP_PORT", "2121"))
    http_port: int = int(os.getenv("HONEYPOT_HTTP_PORT", "8080"))
    https_port: int = int(os.getenv("HONEYPOT_HTTPS_PORT", "8443"))

    bind_address: str = os.getenv("HONEYPOT_BIND_ADDRESS", "0.0.0.0")
    max_connections_per_ip: int = int(os.getenv("HONEYPOT_MAX_CONN_PER_IP", "5"))
    connection_timeout: int = int(os.getenv("HONEYPOT_CONN_TIMEOUT", "300"))
    rate_limit_per_minute: int = int(os.getenv("HONEYPOT_RATE_LIMIT", "60"))

    session_capture_dir: str = os.getenv(
        "HONEYPOT_CAPTURE_DIR", "./data/sessions"
    )
    file_capture_dir: str = os.getenv(
        "HONEYPOT_FILE_CAPTURE_DIR", "./data/uploads"
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

    backend_api_url: str = os.getenv(
        "BACKEND_API_URL", "http://backend:8000/api/v1"
    )
    backend_api_key: Optional[str] = os.getenv("HONEYPOT_BACKEND_API_KEY")
    ingest_token: str = os.getenv(
        "HONEYPOT_INGEST_TOKEN", "honeypot-ingest-token-change-in-production"
    )


config = HoneypotConfig()
