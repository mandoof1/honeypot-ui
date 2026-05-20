import base64
from cryptography.fernet import Fernet
from app.core.config import get_settings


def _get_fernet() -> Fernet:
    settings = get_settings()
    key = base64.urlsafe_b64encode(settings.ENCRYPTION_KEY.encode().ljust(32)[:32])
    return Fernet(key)


def encrypt_data(data: str) -> str:
    fernet = _get_fernet()
    return fernet.encrypt(data.encode()).decode()


def decrypt_data(encrypted_data: str) -> str:
    fernet = _get_fernet()
    return fernet.decrypt(encrypted_data.encode()).decode()
