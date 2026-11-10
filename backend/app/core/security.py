"""Password hashing, JWT issuance and role enforcement."""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import Settings, get_settings
from app.core.database import get_db

security = HTTPBearer()

#: OWASP's 2023 floor for PBKDF2-HMAC-SHA256.
PBKDF2_ITERATIONS = 600_000

#: Distinguishes an access token from a refresh token. Without it a refresh
#: token was accepted as an API credential and vice versa.
ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"

ROLE_HIERARCHY = {"viewer": 0, "analyst": 1, "admin": 2}

_CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid or expired token",
    headers={"WWW-Authenticate": "Bearer"},
)

#: How long a user's revocation state (token_version, is_active, role) may be
#: served from memory before the database is asked again. Bounds how long a
#: deactivation or demotion can lag; the process that performs the change
#: drops its own cache entry immediately.
USER_STATE_TTL_SECONDS = 30
_user_state_cache: dict[int, tuple[float, dict]] = {}


def _derive(password: str, salt: str, iterations: int) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), iterations
    ).hex()


def get_password_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = _derive(password, salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(plain_password: str, stored: str) -> bool:
    """Verify a password against a stored hash.

    Accepts both the current ``algo$iterations$salt$hash`` format and the
    legacy ``salt:hash`` format so existing accounts keep working. A malformed
    value returns False instead of raising, which previously turned a corrupt
    row into a 500 on the login endpoint.
    """
    if not stored:
        return False

    try:
        if stored.startswith("pbkdf2_sha256$"):
            _, iterations, salt, digest = stored.split("$", 3)
            candidate = _derive(plain_password, salt, int(iterations))
        elif ":" in stored:
            salt, digest = stored.split(":", 1)
            candidate = _derive(plain_password, salt, 100_000)
        else:
            return False
    except (ValueError, TypeError):
        return False

    return secrets.compare_digest(candidate, digest)


def needs_rehash(stored: str) -> bool:
    """True when a stored hash uses weaker parameters than we now issue."""
    return not stored.startswith(f"pbkdf2_sha256${PBKDF2_ITERATIONS}$")


def new_jti() -> str:
    return secrets.token_urlsafe(24)


def _create_token(
    data: dict,
    token_type: str,
    expires_delta: timedelta,
    settings: Optional[Settings] = None,
    jti: Optional[str] = None,
) -> str:
    settings = settings or get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        **data,
        "typ": token_type,
        "iat": now,
        "exp": now + expires_delta,
        "jti": jti or new_jti(),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
    settings: Optional[Settings] = None,
) -> str:
    settings = settings or get_settings()
    return _create_token(
        data,
        ACCESS_TOKEN_TYPE,
        expires_delta
        or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        settings,
    )


def create_refresh_token(
    data: dict, settings: Optional[Settings] = None, jti: Optional[str] = None
) -> str:
    settings = settings or get_settings()
    return _create_token(
        data,
        REFRESH_TOKEN_TYPE,
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        settings,
        jti=jti,
    )


def decode_token(
    token: str,
    expected_type: str = ACCESS_TOKEN_TYPE,
    settings: Optional[Settings] = None,
) -> dict:
    settings = settings or get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
    except jwt.PyJWTError:
        raise _CREDENTIALS_ERROR

    if payload.get("typ") != expected_type:
        raise _CREDENTIALS_ERROR
    return payload


def invalidate_user_state(user_id: int) -> None:
    """Forget the cached revocation state after changing it."""
    _user_state_cache.pop(int(user_id), None)


async def _user_state(user_id: int, db) -> Optional[dict]:
    """token_version, is_active and role for a user, briefly cached.

    Access tokens used to be trusted on their signature alone for their whole
    lifetime, so a demoted or deactivated user kept working for up to an
    hour. One indexed lookup every thirty seconds per user, on the request's
    own session, is cheap enough to close that.
    """
    now = time.monotonic()
    cached = _user_state_cache.get(user_id)
    if cached and cached[0] > now:
        return cached[1]

    from sqlalchemy import select

    from app.models import User

    row = (
        await db.execute(
            select(User.token_version, User.is_active, User.role).where(User.id == user_id)
        )
    ).first()
    if row is None:
        # Not cached: a missing row is refused outright by the caller, and
        # remembering "missing" would outlive the account being created.
        return None
    state = {
        "token_version": int(row.token_version or 0),
        "is_active": bool(row.is_active),
        "role": row.role.value if hasattr(row.role, "value") else str(row.role),
    }
    _user_state_cache[user_id] = (now + USER_STATE_TTL_SECONDS, state)
    return state


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db=Depends(get_db),
) -> dict:
    payload = decode_token(credentials.credentials, ACCESS_TOKEN_TYPE)

    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError):
        raise _CREDENTIALS_ERROR

    role = payload.get("role", "viewer")
    if role not in ROLE_HIERARCHY:
        raise _CREDENTIALS_ERROR

    state = await _user_state(user_id, db)
    if state is None:
        # The account behind the token no longer exists. A missing row used
        # to be waved through with whatever role the token claimed, so a
        # deleted administrator kept administrator access until expiry.
        raise _CREDENTIALS_ERROR
    # The row is authoritative for revocation, deactivation and the current
    # role; the role claim inside the token is only a hint.
    if not state["is_active"]:
        raise _CREDENTIALS_ERROR
    if int(payload.get("ver", 0)) != state["token_version"]:
        raise _CREDENTIALS_ERROR
    role = state["role"]

    return {"id": user_id, "email": payload.get("email"), "role": role}


# --------------------------------------------------------------------------
# Engine (service-to-service) authentication


@dataclass(frozen=True)
class EngineCredential:
    """Which engine secret a request presented.

    ``node_name`` is the node the token is bound to in HONEYPOT_NODE_TOKENS,
    or None when the request used the shared HONEYPOT_INGEST_TOKEN.
    """

    node_name: Optional[str] = None


def _same_secret(supplied: str, expected: str) -> bool:
    """Constant-time comparison that never treats an empty secret as a match.

    A plain ``!=`` on a shared secret leaks it through response timing one
    byte at a time. An unset token compared with a missing header would be
    ``"" == ""``, so both sides must be non-empty.
    """
    if not supplied or not expected:
        return False
    try:
        return secrets.compare_digest(supplied, expected)
    except TypeError:
        # A non-ASCII header value used to raise here and surface as a 500.
        return False


def match_engine_token(supplied: str) -> Optional[EngineCredential]:
    """The credential ``supplied`` corresponds to, or None for no match.

    Every configured token is compared, whether or not an earlier one
    matched, so the time taken does not say which node a guess came close to.
    """
    settings = get_settings()
    matched: Optional[EngineCredential] = None
    for name, token in settings.node_tokens.items():
        if _same_secret(supplied, token):
            matched = EngineCredential(node_name=name)
    shared = _same_secret(supplied, settings.HONEYPOT_INGEST_TOKEN)
    if matched is None and shared:
        matched = EngineCredential(node_name=None)
    return matched


def engine_token_in_headers(headers) -> bool:
    """Whether raw ASGI headers carry any valid engine token.

    Used by the body-size middleware to refuse an unauthenticated request to
    an ``-internal`` route before its body is read. The per-node binding is
    still enforced by the route, which is the only place the node is known.
    """
    for name, value in headers or ():
        if name == b"x-honeypot-token":
            try:
                supplied = value.decode("latin-1")
            except (AttributeError, UnicodeDecodeError):
                return False
            return match_engine_token(supplied) is not None
    return False


async def verify_honeypot_token(request: Request) -> EngineCredential:
    """Authenticate the honeypot engine on service-to-service routes.

    Returns which credential was used; routes then call
    ``authorize_engine_for_node`` with the node the request is about.
    """
    credential = match_engine_token(request.headers.get("X-Honeypot-Token", ""))
    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid honeypot token",
        )
    return credential


def authorize_engine_for_node(credential: EngineCredential, node_name: str) -> None:
    """Refuse an engine token used for a node it does not belong to.

    * A node listed in HONEYPOT_NODE_TOKENS accepts only its own token; the
      shared token and every other node's token are refused for it.
    * A node not listed there accepts only the shared token; a token bound to
      some other node is refused for it.
    """
    settings = get_settings()
    has_own_token = node_name in settings.node_tokens
    if has_own_token and credential.node_name == node_name:
        return
    if not has_own_token and credential.node_name is None:
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="This engine token is not valid for that node",
    )


def engine_control_token() -> str:
    """The secret sent to an engine's control API."""
    settings = get_settings()
    return settings.HONEYPOT_CONTROL_TOKEN or settings.HONEYPOT_INGEST_TOKEN


def require_role(required_role: str):
    """Dependency enforcing a minimum role."""

    async def _check(current_user: dict = Depends(get_current_user)) -> dict:
        user_level = ROLE_HIERARCHY.get(current_user.get("role", "viewer"), 0)
        required_level = ROLE_HIERARCHY.get(required_role, 0)
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return _check
