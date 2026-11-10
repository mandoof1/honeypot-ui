import json
import os
import secrets
from functools import lru_cache
from typing import Annotated, Dict, List

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode

#: Values shipped in .env.example / docker-compose. Never acceptable in a
#: deployment that is reachable from anywhere but localhost.
PLACEHOLDER_SECRETS = {
    "super-secret-key-change-in-production",
    "change-this-to-a-secure-random-string-in-production",
    "0123456789abcdef0123456789abcdef",
    "honeypot-ingest-token-change-in-production",
    "",
}


class Settings(BaseSettings):
    PROJECT_NAME: str = "HoneySentinel AI"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"

    #: "development" relaxes the secret checks. Anything else is treated as a
    #: real deployment and refuses to start on placeholder credentials.
    ENVIRONMENT: str = "development"

    #: Which routes this process serves. "full" is the dashboard API: every
    #: route, plus the background workers when BACKGROUND_WORKERS is on.
    #: "ingest" is for the multi-worker service the engines talk to: only the
    #: ``-internal`` routes and /health are mounted and no worker is started,
    #: so a process reachable from the engine network exposes no login, no
    #: user route and no export.
    API_ROLE: str = "full"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://honeypot:honeypot@localhost:5432/honeysentinel"
    DATABASE_URL_SYNC: str = "postgresql+psycopg2://honeypot:honeypot@localhost:5432/honeysentinel"

    # JWT
    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Encryption at rest for captured commands/payloads
    ENCRYPTION_KEY: str = ""
    #: Keys this deployment used before the current one, comma-separated,
    #: newest first. Never used to encrypt; they exist so rows written under
    #: them still decrypt until `python -m app.core.rotate_key` has
    #: re-encrypted everything, after which the entry can be removed.
    ENCRYPTION_KEY_PREVIOUS: str = ""
    #: Refuse stored data that is not bound to its row and column where a
    #: binding is expected. Turn on after `python -m app.core.rotate_key` has
    #: re-sealed the rows written before binding existed.
    ENCRYPTION_REQUIRE_CONTEXT: bool = False

    # Shared secret the honeypot engine uses to ingest sessions
    HONEYPOT_INGEST_TOKEN: str = ""
    #: Per-engine secrets, as a JSON object of node name to token, e.g.
    #: {"honeysentinel-debian": "...", "honeysentinel-web": "..."}. A node
    #: named here must use its own token for registration, heartbeat and
    #: ingest, and that token works for no other node; a node not named here
    #: keeps using HONEYPOT_INGEST_TOKEN. With one shared token, an engine
    #: that is compromised can submit sessions and heartbeats as any other.
    HONEYPOT_NODE_TOKENS: str = ""
    #: Sent to the engines' control API (mode changes, blocks) instead of the
    #: ingest token when set, so the secret that lets the backend steer an
    #: engine is not the one every engine holds for writing sessions.
    HONEYPOT_CONTROL_TOKEN: str = ""

    # CORS. Comma-separated in the environment.
    #
    # NoDecode is required: pydantic-settings classifies List[str] as a complex
    # type and runs json.loads on the raw environment value *before* any
    # validator sees it, so a comma-separated string raised
    # SettingsError/JSONDecodeError and the process died at import. NoDecode
    # suppresses that step and hands the raw string to _split_origins below.
    CORS_ORIGINS: Annotated[List[str], NoDecode] = [
        "http://localhost:5173",
        "http://localhost:3000",
    ]

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    #: Largest request body accepted on user-facing routes (413 above it).
    #: The engine's -internal routes have their own limit below.
    MAX_REQUEST_BODY_BYTES: int = 1_048_576
    #: Largest body accepted on the engine's ``-internal`` routes. A session
    #: can forward captured files (the engine's budget is 24 MiB of content
    #: per session, about 32 MiB once base64-encoded) beside its transcript,
    #: so this is generous, but it is a limit: those routes had none.
    MAX_INTERNAL_BODY_BYTES: int = 64 * 1024 * 1024
    #: Enable only when the app really is behind a trusted reverse proxy;
    #: otherwise clients can spoof X-Forwarded-For to dodge rate limits.
    TRUST_PROXY_HEADERS: bool = False

    #: Populate an empty database with the demo dataset on first boot.
    SEED_ON_STARTUP: bool = False

    #: Apply Alembic migrations during startup. Disable when migrations are
    #: run as a separate release step (`alembic upgrade head`), which is the
    #: safer pattern once more than one instance is running.
    RUN_MIGRATIONS_ON_STARTUP: bool = True

    # Email / Webhook
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    ALERT_EMAIL_FROM: str = ""
    ALERT_EMAIL_TO: str = ""
    WEBHOOK_URL: str = ""
    #: Optional HMAC secret so receivers can verify webhook authenticity.
    WEBHOOK_SECRET: str = ""

    # GeoIP
    GEOIP_DB_PATH: str = "./data/GeoLite2-City.mmdb"

    # Honeypot engine control API. Status and lists come from this engine;
    # mode changes and blocks go to it and to every extra one.
    HONEYPOT_CONTROL_URL: str = "http://honeypot:8000"
    #: Comma-separated control URLs of further engines (one per node).
    HONEYPOT_CONTROL_EXTRA_URLS: str = ""

    # AI Model paths
    MODEL_PATH_RF: str = "./models/random_forest_model.pkl"
    MODEL_PATH_IF: str = "./models/isolation_forest_model.pkl"
    SPACY_MODEL: str = "en_core_web_sm"

    # Optional semantic-analysis stage (finding 12). Unset by default, in
    # which case command analysis stays on the regex path. Point this at any
    # OpenAI-compatible endpoint serving chimera-14b-v2 — llama.cpp's server,
    # Ollama or vLLM — e.g. "http://127.0.0.1:8081/v1".
    #
    # Deliberately called from the backend, never the honeypot engine: NFR-1
    # requires zero egress from the engine, and running the user's own weights
    # locally is what keeps that claim true where a third-party API would not.
    CHIMERA_URL: str = ""
    CHIMERA_MODEL: str = "chimera-14b-v2"
    #: Total wall-clock budget for one analysis. The production model runs on
    #: CPU at a few tokens a second, so a full answer takes minutes, not
    #: seconds; this is a detached stage, so that is acceptable.
    CHIMERA_TIMEOUT: float = 300.0
    #: Tokens the model may spend on the answer. The prompt asks for compact
    #: JSON; reasoning is turned off through the chat template.
    CHIMERA_MAX_TOKENS: int = 600
    #: Characters of transcript sent for inference.
    CHIMERA_MAX_TRANSCRIPT_CHARS: int = 6000

    # Optional decision model (Kev, a Jev-style "System One" model) in front
    # of the language model. It never writes text: it reads a transcript once
    # and returns probabilities over options the backend supplies, in seconds
    # rather than minutes. It triages every session (category, severity,
    # automated or human) so the language model only reads the ones worth its
    # time, and checks each ATT&CK technique the language model names against
    # the transcript. Base URL of a llama.cpp server exposing /v1/systemone,
    # e.g. "http://decider:8080". Same egress rule as CHIMERA_URL: local only.
    DECIDER_URL: str = ""
    DECIDER_MODEL: str = "kev-4b"
    DECIDER_TIMEOUT: float = 120.0
    #: Characters of transcript the decision model reads. Its cost is the
    #: length of the transcript (about 25 ms a token on the server's CPU),
    #: not the number of questions, which share one read.
    DECIDER_MAX_TRANSCRIPT_CHARS: int = 3000
    #: Skip the language model when the decision model puts at least this
    #: much probability on "nothing worse than information gathering" and
    #: the rules found nothing worse either. Uncertain sessions still go.
    DECIDER_SKIP_THRESHOLD: float = 0.85
    #: Also triage the sessions the rules would skip (plain web browsing,
    #: short benign FTP), so triage can send one on. Off by default: on the
    #: deployment's captured browsing the model read 30 of 32 benign sessions
    #: as reconnaissance, at about 16 s of CPU each, and escalated none.
    DECIDER_TRIAGE_RULE_SKIPPED: bool = False
    #: Send a session the rules would have skipped when the decision model
    #: puts at least this much probability on an attempted compromise.
    DECIDER_ESCALATE_THRESHOLD: float = 0.6
    #: A technique the language model names is marked unconfirmed when the
    #: decision model's probability that the transcript shows it is below
    #: this. Marked, not removed: see DECIDER_DROP_UNCONFIRMED.
    DECIDER_SUPPORT_THRESHOLD: float = 0.3
    #: Remove unconfirmed techniques instead of marking them.
    DECIDER_DROP_UNCONFIRMED: bool = False
    #: A session waiting on an unreachable decision model goes to the
    #: language model on the rules' verdict alone after this long.
    DECIDER_FALLBACK_SECONDS: int = 900

    # Background workers: the enrichment queue, the notification outbox, node
    # liveness checks and retention. Run them in exactly one process — the
    # `backend` service — never in the multi-worker ingest service.
    BACKGROUND_WORKERS: bool = False
    #: Seconds without a heartbeat before a node is shown as offline, and
    #: before a system alert is raised for it.
    NODE_STALE_SECONDS: int = 180
    NODE_OFFLINE_ALERT_SECONDS: int = 300
    #: Below this fraction of free disk on an engine, raise a system alert.
    NODE_DISK_ALERT_FRACTION: float = 0.10

    # Alert handling.
    #: Repeats of the same address at the same category inside this window
    #: are folded into the open alert instead of raising another one.
    ALERT_DEDUP_WINDOW_MINUTES: int = 60
    #: Do not alert on sessions from known research scanners (Censys, Shodan,
    #: Shadowserver). They are still recorded and still count as sessions.
    ALERT_SUPPRESS_SCANNERS: bool = True
    #: Delivery retries for email/webhook notifications before giving up.
    NOTIFICATION_MAX_ATTEMPTS: int = 6

    # Retention. 0 keeps everything, which is the right default for a
    # research deployment where the captures are the point.
    SESSION_RETENTION_DAYS: int = 0
    AUDIT_RETENTION_DAYS: int = 365
    OUTBOX_RETENTION_DAYS: int = 30

    # Account lockout after repeated wrong passwords or second-factor codes.
    LOGIN_LOCKOUT_THRESHOLD: int = 10
    LOGIN_LOCKOUT_MINUTES: int = 15
    #: Failed sign-ins one source address may make against one account inside
    #: LOGIN_LOCKOUT_MINUTES before further attempts from it are refused
    #: without being checked. This is what stops a password-guessing run from
    #: one address. The account-wide lock above still applies on top of it:
    #: while it lasts, an account WITHOUT two-factor has even its correct
    #: password refused, so failures from several addresses can keep such an
    #: account out for LOGIN_LOCKOUT_MINUTES at a time. An account with
    #: two-factor is not affected (its password and code are still checked),
    #: which is one more reason every administrator should enrol.
    LOGIN_SOURCE_FAILURE_LIMIT: int = 5

    #: One-time codes (signup verification, password reset) issued per
    #: account per hour. Each code allows five guesses, so without a cap a
    #: client could keep requesting fresh codes and guess indefinitely.
    OTP_MAX_CODES_PER_HOUR: int = 5

    #: Optional static token for the plain-text indicator feed, so a firewall
    #: or SIEM can pull it without a user session that expires hourly. Sent
    #: as X-Feed-Token. Empty leaves the feed JWT-only.
    IOC_FEED_TOKEN: str = ""
    #: Addresses and networks (comma-separated, CIDR allowed) that never
    #: appear in the address blocklist feed whatever was captured: the
    #: operator's own egress address, a monitoring service, a partner range.
    IOC_FEED_ALLOWLIST: str = ""

    #: Seconds the dashboard summary may be served from memory. The summary
    #: is a dozen aggregate queries and every open dashboard polls it; a few
    #: seconds of staleness is invisible there. 0 disables the cache.
    DASHBOARD_CACHE_SECONDS: float = 10.0

    #: Addresses treated as reverse proxies when reading X-Forwarded-For:
    #: walked from the right, the first address not in this list is the
    #: client. Loopback and the Docker ranges by default.
    TRUSTED_PROXIES: str = "127.0.0.0/8,::1,172.16.0.0/12,10.0.0.0/8,192.168.0.0/16"

    # Captured payload analysis. Files an attacker uploads are stored
    # encrypted and reverse engineered statically — nothing is executed, and
    # no URL or host found inside a sample is ever contacted.
    PAYLOAD_ANALYSIS_ENABLED: bool = True
    #: Largest sample whose bytes are kept. Larger ones keep their hashes.
    PAYLOAD_MAX_STORE_BYTES: int = 10 * 1024 * 1024
    #: The analyser runs in a separate process under these limits, because
    #: every parser in it is being fed input chosen by an attacker.
    PAYLOAD_ANALYSIS_TIMEOUT: float = 60.0
    #: Virtual address-space cap for the analysis subprocess. numpy and the
    #: parser libraries reserve a lot of it, so this is floored at 1024 MiB in
    #: the worker regardless of what is set here.
    PAYLOAD_ANALYSIS_MEMORY_MB: int = 2048
    #: Times one sample's analysis is started before it is marked failed. A
    #: sample whose result could not be stored used to stay pending and was
    #: re-run every hour for ever.
    PAYLOAD_ANALYSIS_MAX_ATTEMPTS: int = 3

    #: Longest an investigation report waits for the language model while
    #: the background enrichment queue is using it, before failing with a
    #: "try again" message. One enrichment call is bounded by
    #: CHIMERA_TIMEOUT (300 s by default), so this covers one call in
    #: progress and a margin.
    REPORT_MODEL_WAIT_SECONDS: float = 420.0

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_origins(cls, value):
        """Accept a comma-separated list or a JSON array.

        NoDecode suppresses pydantic-settings' own JSON decoding, so a value
        that really is JSON has to be handled here or it would be split on its
        commas into fragments like '["https://a.example"'.
        """
        if not isinstance(value, str):
            return value
        text = value.strip()
        if text.startswith("["):
            import json

            try:
                decoded = json.loads(text)
            except ValueError:
                pass
            else:
                if isinstance(decoded, list):
                    return [str(item).strip() for item in decoded if str(item).strip()]
        return [item.strip() for item in text.split(",") if item.strip()]

    @field_validator("DATABASE_URL", mode="after")
    @classmethod
    def _async_driver(cls, value: str) -> str:
        # Managed Postgres providers hand out bare postgresql:// URLs.
        if value.startswith("postgresql://"):
            return value.replace("postgresql://", "postgresql+asyncpg://", 1)
        return value

    @field_validator("DATABASE_URL_SYNC", mode="after")
    @classmethod
    def _sync_driver(cls, value: str) -> str:
        if value.startswith("postgresql://"):
            return value.replace("postgresql://", "postgresql+psycopg2://", 1)
        return value

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.strip().lower() not in ("development", "dev", "test")

    @property
    def api_role(self) -> str:
        return self.API_ROLE.strip().lower() or "full"

    @property
    def node_tokens(self) -> Dict[str, str]:
        """HONEYPOT_NODE_TOKENS as a mapping of node name to token."""
        return _parse_node_tokens(self.HONEYPOT_NODE_TOKENS)

    @property
    def previous_encryption_keys(self) -> List[str]:
        return [
            item.strip()
            for item in self.ENCRYPTION_KEY_PREVIOUS.split(",")
            if item.strip()
        ]

    def validate_roles_and_tokens(self) -> None:
        """Refuse settings that would quietly weaken engine authentication.

        These fail in every environment, development included: a malformed
        HONEYPOT_NODE_TOKENS that was skipped would leave every engine on the
        shared token while the operator believed otherwise.
        """
        if self.api_role not in ("full", "ingest"):
            raise RuntimeError(
                f"API_ROLE must be 'full' or 'ingest', not {self.API_ROLE!r}"
            )

        tokens = self.node_tokens
        values = list(tokens.values())
        if len(set(values)) != len(values):
            raise RuntimeError(
                "HONEYPOT_NODE_TOKENS gives two nodes the same token; a token "
                "must identify exactly one node"
            )
        if self.HONEYPOT_INGEST_TOKEN and self.HONEYPOT_INGEST_TOKEN in values:
            raise RuntimeError(
                "A token in HONEYPOT_NODE_TOKENS equals HONEYPOT_INGEST_TOKEN; "
                "a node's own token must not also be the shared one"
            )
        if self.is_production:
            weak = sorted(
                name
                for name, token in tokens.items()
                if token in PLACEHOLDER_SECRETS or len(token) < 16
            )
            if weak:
                raise RuntimeError(
                    "HONEYPOT_NODE_TOKENS entries must be random values of at "
                    "least 16 characters: " + ", ".join(weak)
                )

    @property
    def database_ssl_required(self) -> bool:
        """Whether the database connection must be encrypted.

        The captured commands and payloads on that link are the most sensitive
        data the system holds, and the report commits to TLS for it. Enforced
        client-side in production so it is guaranteed rather than incidental:
        managed Postgres providers generally negotiate TLS anyway, but relying
        on the server to insist is not the same as requiring it.

        Left off in development, where Postgres runs in a container with no
        certificate and a hard requirement would simply refuse to start.
        """
        override = os.environ.get("DATABASE_SSL")
        if override:
            return override.strip().lower() in ("1", "true", "require", "required")
        return self.is_production

    def validate_secrets(self) -> None:
        """Refuse to run a real deployment on placeholder credentials.

        Previously these were only printed as warnings at startup, so a
        deployment that forgot to set SECRET_KEY would happily sign tokens
        with a value published in the repository — anyone could mint an admin
        JWT.
        """
        missing = [
            name
            for name in ("SECRET_KEY", "ENCRYPTION_KEY", "HONEYPOT_INGEST_TOKEN")
            if getattr(self, name).strip() in PLACEHOLDER_SECRETS
        ]
        if not missing:
            return

        if self.is_production:
            raise RuntimeError(
                "Refusing to start: "
                + ", ".join(missing)
                + " must be set to unique random values in a non-development "
                "environment. Generate them with: "
                "python -c 'import secrets; print(secrets.token_urlsafe(48))'"
            )

        # Development: generate ephemeral values so nothing is signed with a
        # secret that is public knowledge. Tokens do not survive a restart.
        for name in missing:
            setattr(self, name, secrets.token_urlsafe(48))
        print(
            "[config] Generated ephemeral values for "
            + ", ".join(missing)
            + " (development only; sessions reset on restart).",
            flush=True,
        )

    model_config = {
        "env_file": ".env",
        "case_sensitive": True,
        "extra": "ignore",
    }


@lru_cache(maxsize=8)
def _parse_node_tokens(raw: str) -> Dict[str, str]:
    """Decode HONEYPOT_NODE_TOKENS, rejecting anything but name -> token."""
    text = (raw or "").strip()
    if not text:
        return {}
    try:
        decoded = json.loads(text)
    except ValueError as exc:
        raise RuntimeError(f"HONEYPOT_NODE_TOKENS is not valid JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError(
            "HONEYPOT_NODE_TOKENS must be a JSON object of node name to token"
        )
    tokens: Dict[str, str] = {}
    for name, token in decoded.items():
        if not isinstance(token, str) or not token.strip() or not str(name).strip():
            raise RuntimeError(
                "HONEYPOT_NODE_TOKENS must map each node name to a non-empty "
                "string token"
            )
        tokens[str(name)] = token
    return tokens


@lru_cache()
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_secrets()
    settings.validate_roles_and_tokens()
    return settings
