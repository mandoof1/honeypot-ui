import os
import secrets
from functools import lru_cache
from typing import Annotated, List

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

    # Shared secret the honeypot engine uses to ingest sessions
    HONEYPOT_INGEST_TOKEN: str = ""

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

    # Honeypot engine control API
    HONEYPOT_CONTROL_URL: str = "http://honeypot:8000"

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
    CHIMERA_TIMEOUT: float = 90.0

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


@lru_cache()
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_secrets()
    return settings
