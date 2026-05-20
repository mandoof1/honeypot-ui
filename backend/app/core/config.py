import os
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    PROJECT_NAME: str = "HoneySentinel AI"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://honeypot:honeypot@localhost:5432/honeysentinel"
    DATABASE_URL_SYNC: str = "postgresql+psycopg2://honeypot:honeypot@localhost:5432/honeysentinel"

    # JWT
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-change-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Encryption
    ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef")

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60

    # Email / Webhook
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    ALERT_EMAIL_FROM: str = ""
    ALERT_EMAIL_TO: str = ""
    WEBHOOK_URL: str = ""

    # GeoIP
    GEOIP_DB_PATH: str = "./data/GeoLite2-City.mmdb"

    # Honeypot
    COWRIE_API_URL: str = "http://localhost:9090"
    DIONAEA_API_URL: str = "http://localhost:8080"

    # AI Model paths
    MODEL_PATH_RF: str = "./models/random_forest_model.pkl"
    MODEL_PATH_IF: str = "./models/isolation_forest_model.pkl"
    SPACY_MODEL: str = "en_core_web_sm"

    # Free tier optimization
    LAZY_LOAD_AI: bool = True

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
