from datetime import datetime, timedelta, timezone
from typing import Optional
import hashlib
import secrets
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.config import get_settings, Settings

security = HTTPBearer()


def _hash_password(password: str, salt: str = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return salt, hashed.hex()


def verify_password(plain_password: str, stored: str) -> bool:
    salt, hash_value = stored.split(":", 1)
    _, new_hash = _hash_password(plain_password, salt)
    return secrets.compare_digest(new_hash, hash_value)


def get_password_hash(password: str) -> str:
    salt, hashed = _hash_password(password)
    return f"{salt}:{hashed}"


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None, settings: Settings = None) -> str:
    settings = settings or get_settings()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(data: dict, settings: Settings = None) -> str:
    settings = settings or get_settings()
    return create_access_token(data, expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS), settings=settings)


def decode_token(token: str, settings: Settings = None) -> dict:
    settings = settings or get_settings()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    payload = decode_token(credentials.credentials)
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication")
    return {"id": int(user_id), "email": payload.get("email"), "role": payload.get("role", "analyst")}


def require_role(required_role: str):
    async def role_checker(current_user: dict = Depends(get_current_user)):
        role_hierarchy = {"viewer": 0, "analyst": 1, "admin": 2}
        if role_hierarchy.get(current_user.get("role", "viewer"), 0) < role_hierarchy.get(required_role, 0):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user
    return role_checker
