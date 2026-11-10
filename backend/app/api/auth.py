"""Authentication, email verification and password reset."""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.rate_limit import limiter
from app.core.throttle import sign_in_failures
from app.core.security import (
    REFRESH_TOKEN_TYPE,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    get_password_hash,
    invalidate_user_state,
    needs_rehash,
    new_jti,
    require_role,
    verify_password,
)
from app.models import AuditLog, RefreshToken, User, UserRole
from app.schemas import (
    AdminPasswordReset,
    PasswordChange,
    UserAdminUpdate,
    AdminUserCreate,
    MFACodeRequest,
    OTPResendRequest,
    OTPVerifyRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterResponse,
    Token,
    UserCreate,
    UserLogin,
    UserResponse,
    UserRoleUpdate,
)
from app.core import totp
from app.core.encryption import decrypt_data, encrypt_data, totp_context
from app.schemas.operations import AuthCapabilities
from app.services.otp import INVALID_CODE, otp_service

logger = logging.getLogger(__name__)
router = APIRouter()

#: Returned for every reset/resend request so the endpoint cannot be used to
#: discover which addresses have accounts.
_GENERIC_OTP_RESPONSE = {
    "message": "If an account exists for that address, a code has been sent."
}

#: Hashing a throwaway password keeps the failed-login path as slow as the
#: successful one, so response timing does not reveal whether a user exists.
_TIMING_DECOY = get_password_hash("timing-equalisation-decoy")

#: The one answer to a sign-in that did not succeed, whatever the reason:
#: no such account, wrong password, or an account that is locked. A locked
#: account used to answer 423, which told anyone the address was registered.
_INVALID_SIGN_IN = "Invalid email or password"
_INVALID_SECOND_FACTOR = "Invalid authenticator code"
_TOO_MANY_ATTEMPTS = "Too many failed attempts from this address. Try again later."

#: What a recovery code looks like (see totp.generate_recovery_codes). Input
#: of any other shape is not compared against the stored hashes at all.
_RECOVERY_CODE = re.compile(r"^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$")

_NO_EMAIL = (
    "This deployment cannot send email, so sign-up and password reset by "
    "emailed code are unavailable. Ask an administrator to create the "
    "account or set a new password."
)


def _client_ip(request: Request) -> str | None:
    from app.core.clientip import client_ip

    return client_ip(request)


def _require_email_delivery() -> None:
    """Refuse an emailed-code flow outright when no mail can be sent.

    Without a mail provider these flows could never finish: a sign-up left a
    dead account behind and a reset request issued a code nobody received,
    which was nonetheless valid. The answer is the same for every address,
    so it reveals nothing about any account.
    """
    if not otp_service.delivery_available:
        raise HTTPException(status_code=503, detail=_NO_EMAIL)


def _failure_window_seconds() -> float:
    return max(1, get_settings().LOGIN_LOCKOUT_MINUTES) * 60.0


def _source_key(purpose: str, request: Request, account: str) -> tuple:
    """Identify one source's attempts against one account."""
    return (purpose, _client_ip(request) or "unknown", account.strip().lower())


def _refuse_if_source_exhausted(key: tuple) -> None:
    """429 once a source has used up its failed attempts on an account.

    Applied before anything about the account is looked at, and identically
    whether or not the account exists, so being refused says nothing about
    it. This, not the account-wide lock, is what ends a guessing run.
    """
    settings = get_settings()
    if sign_in_failures.blocked(
        key, settings.LOGIN_SOURCE_FAILURE_LIMIT, _failure_window_seconds()
    ):
        raise HTTPException(status_code=429, detail=_TOO_MANY_ATTEMPTS)


async def _record_failed_sign_in(
    db: AsyncSession, user: User, request: Request, action: str
) -> None:
    """Count one failed password or second factor against the account.

    The increment is done by the database, not read-then-written here: two
    wrong guesses arriving together would otherwise both read the same count
    and be recorded as one.
    """
    settings = get_settings()
    await db.execute(
        update(User)
        .where(User.id == user.id)
        .values(failed_login_count=func.coalesce(User.failed_login_count, 0) + 1)
    )
    await db.refresh(user, attribute_names=["failed_login_count"])

    locked = False
    if (user.failed_login_count or 0) >= settings.LOGIN_LOCKOUT_THRESHOLD:
        user.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=settings.LOGIN_LOCKOUT_MINUTES
        )
        user.failed_login_count = 0
        locked = True
    db.add(
        AuditLog(
            user_id=user.id,
            action=action,
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
            details={"locked": locked},
        )
    )
    await db.commit()


def _is_locked(user: User, now: datetime) -> bool:
    locked_until = user.locked_until
    if locked_until is not None and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return bool(locked_until and locked_until > now)


def _claims(user: User) -> dict:
    return {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role.value,
        "ver": int(user.token_version or 0),
    }


async def _issue_tokens(
    db: AsyncSession, user: User, request: Request | None, family: str | None = None
) -> dict:
    """Mint an access/refresh pair and record the refresh token.

    The row is what makes sign-out, rotation and reuse detection possible;
    a refresh token with no row (minted before this existed) is refused.
    """
    cfg = get_settings()
    jti = new_jti()
    db.add(
        RefreshToken(
            user_id=user.id,
            jti=jti,
            family=family or jti,
            expires_at=datetime.now(timezone.utc) + timedelta(days=cfg.REFRESH_TOKEN_EXPIRE_DAYS),
            ip_address=_client_ip(request) if request is not None else None,
        )
    )
    await db.commit()
    claims = _claims(user)
    return {
        "access_token": create_access_token(claims),
        "refresh_token": create_refresh_token(claims, jti=jti),
        "token_type": "bearer",
    }


async def _sign_out_everywhere(db: AsyncSession, user: User, reason: str) -> None:
    """Revoke the user's refresh tokens and invalidate their access tokens."""
    now = datetime.now(timezone.utc)
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now, replaced_by=reason[:64])
    )
    user.token_version = int(user.token_version or 0) + 1
    invalidate_user_state(user.id)


@router.get("/capabilities", response_model=AuthCapabilities)
async def auth_capabilities():
    """What the sign-in pages can offer here. Public, and says nothing secret.

    The console asks this before anyone is signed in, to decide whether to
    show "Create account" and "Forgot password": both end in a code sent by
    email, and on a deployment with no mail provider that code never arrives.
    """
    email_delivery = otp_service.delivery_available
    return AuthCapabilities(
        email_delivery=email_delivery,
        self_registration=email_delivery,
        password_reset=email_delivery,
        mfa=True,
    )


async def _send_code_later(
    background: BackgroundTasks,
    db: AsyncSession,
    user: User,
    purpose: str,
    request: Request,
) -> None:
    """Issue a code now and send it after the response has gone.

    Sending takes seconds and only ever happens for an address that has an
    account, so waiting for it in the request made the response time say
    which addresses those were. The code is retired if the send then fails.
    """
    issued = await otp_service.issue(db, user, purpose, _client_ip(request))
    if issued is None:
        return
    record_id, otp_code = issued
    background.add_task(
        otp_service.deliver, db, record_id, user.email, user.name or "", otp_code, purpose
    )


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("5/minute")
async def register(
    request: Request,
    user_data: UserCreate,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Self-service registration.

    New accounts are always created as viewers. The payload schema has no
    `role` field: it previously did, which let anyone register as an admin.
    """
    _require_email_delivery()
    received = RegisterResponse(
        message="Registration received. Check your email for a verification code.",
        email=user_data.email,
        requires_verification=True,
    )

    existing = await db.execute(
        select(User).where(User.email == user_data.email)
    )
    # Hashed in both branches, off the event loop: the hash is the slow part
    # of a registration, and skipping it for an address that is already
    # taken made the two cases easy to tell apart by timing.
    hashed_password = await asyncio.to_thread(get_password_hash, user_data.password)
    if existing.scalar_one_or_none():
        # Do not confirm the address is taken; a duplicate registration gets
        # the same response as a fresh one.
        return received

    user = User(
        email=user_data.email,
        hashed_password=hashed_password,
        name=user_data.name,
        role=UserRole.VIEWER,
        is_active=False,
        is_verified=False,
    )
    db.add(user)
    await db.flush()

    db.add(
        AuditLog(
            user_id=user.id,
            action="user_registered",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
            details={"requires_verification": True},
        )
    )
    await db.commit()

    await _send_code_later(background, db, user, "email_verification", request)
    return received


@router.post("/verify-otp")
@limiter.limit("10/minute")
async def verify_otp(
    request: Request,
    data: OTPVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    _require_email_delivery()
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    # One answer for every failure: no such account, already verified, no
    # live code, wrong code, too many guesses. The service's own messages
    # ("2 attempt(s) remaining") only ever appeared for a real account.
    invalid = HTTPException(status_code=400, detail=INVALID_CODE)
    if not user or user.is_verified:
        raise invalid

    verification = await otp_service.verify(
        db, user.id, data.otp_code, "email_verification"
    )
    if not verification["valid"]:
        raise invalid

    user.is_verified = True
    user.is_active = True
    db.add(
        AuditLog(
            user_id=user.id,
            action="email_verified",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
        )
    )
    await db.commit()

    return {"message": "Email verified successfully. You can now log in."}


@router.post("/resend-otp")
@limiter.limit("3/minute")
async def resend_otp(
    request: Request,
    data: OTPResendRequest,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    _require_email_delivery()
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if user and not user.is_verified:
        await _send_code_later(background, db, user, "email_verification", request)

    return _GENERIC_OTP_RESPONSE


@router.post("/request-password-reset")
@limiter.limit("3/minute")
async def request_password_reset(
    request: Request,
    data: PasswordResetRequest,
    background: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    _require_email_delivery()
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if user and user.is_active:
        await _send_code_later(background, db, user, "password_reset", request)

    return _GENERIC_OTP_RESPONSE


@router.post("/reset-password")
@limiter.limit("5/minute")
async def reset_password(
    request: Request,
    data: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
):
    _require_email_delivery()
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    # A missing user previously returned 404 while a bad code returned 400,
    # which turned this endpoint into an account-existence oracle; then the
    # wording of the 400 did the same. One status, one message.
    invalid = HTTPException(status_code=400, detail=INVALID_CODE)
    if not user or not user.is_active:
        raise invalid

    verification = await otp_service.verify(
        db, user.id, data.otp_code, "password_reset"
    )
    if not verification["valid"]:
        raise invalid

    user.hashed_password = await asyncio.to_thread(get_password_hash, data.new_password)
    # A reset proves control of the mailbox, which is what an administrator
    # would have asked for before unlocking the account by hand.
    user.failed_login_count = 0
    user.locked_until = None
    await _sign_out_everywhere(db, user, "password-reset")
    db.add(
        AuditLog(
            user_id=user.id,
            action="password_reset",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
        )
    )
    await db.commit()

    return {"message": "Password reset successfully. You can now log in."}


@router.post("/login", response_model=Token)
@limiter.limit("10/minute")
async def login(
    request: Request,
    credentials: UserLogin,
    db: AsyncSession = Depends(get_db),
):
    """Sign in. How failures are limited, since the answers are all alike:

    * One source address gets LOGIN_SOURCE_FAILURE_LIMIT failed attempts at
      one account per LOGIN_LOCKOUT_MINUTES, then 429 without being checked,
      whether or not the account exists.
    * An account that collects LOGIN_LOCKOUT_THRESHOLD failures from any
      sources is locked for that long. While it is, a password alone is not
      evaluated; an account with an authenticator can still sign in with the
      right password and code, so nobody can keep its owner out by failing
      on purpose.
    * Wrong authenticator codes count like wrong passwords, and an account
      that has had LOGIN_LOCKOUT_THRESHOLD of them in the window has its
      second factor refused until the window passes. Only someone who
      already has the password can cause that.
    """
    source_key = _source_key("login", request, credentials.email)
    _refuse_if_source_exhausted(source_key)
    window = _failure_window_seconds()
    invalid = HTTPException(status_code=401, detail=_INVALID_SIGN_IN)

    result = await db.execute(
        select(User).where(User.email == credentials.email)
    )
    user = result.scalar_one_or_none()

    if user is None:
        await asyncio.to_thread(verify_password, credentials.password, _TIMING_DECOY)
        sign_in_failures.record(source_key, window)
        raise invalid

    now = datetime.now(timezone.utc)
    if _is_locked(user, now) and not user.totp_enabled:
        # Locked, and nothing but a password to go on: the password is not
        # evaluated, so guessing stops, and the answer is the ordinary one,
        # so the lock cannot be observed. The decoy keeps the timing alike.
        await asyncio.to_thread(verify_password, credentials.password, _TIMING_DECOY)
        sign_in_failures.record(source_key, window)
        raise invalid

    # PBKDF2 at 600,000 rounds is a few hundred milliseconds of CPU; in a
    # thread, so it does not hold up every other request meanwhile.
    password_ok = await asyncio.to_thread(
        verify_password, credentials.password, user.hashed_password
    )
    if not password_ok:
        sign_in_failures.record(source_key, window)
        await _record_failed_sign_in(db, user, request, "login_failed")
        raise invalid

    if not user.is_verified:
        raise HTTPException(
            status_code=403,
            detail="Email not verified. Please verify your email before logging in.",
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Second factor, when enrolled. Checked after the password so an attacker
    # cannot use this response to discover which accounts have MFA on.
    if user.totp_enabled:
        if not credentials.totp_code:
            raise HTTPException(
                status_code=401,
                detail="Authenticator code required",
                headers={"X-MFA-Required": "totp"},
            )
        if not await _verify_second_factor(db, user, credentials.totp_code):
            sign_in_failures.record(source_key, window)
            await _record_failed_sign_in(db, user, request, "mfa_failed")
            raise HTTPException(status_code=401, detail=_INVALID_SECOND_FACTOR)

    # Only now, with every factor checked. The counter used to be cleared
    # as soon as the password matched, so wrong authenticator codes never
    # accumulated and could be tried without limit.
    user.failed_login_count = 0
    user.locked_until = None
    sign_in_failures.reset(source_key)

    # Transparently upgrade hashes stored with weaker parameters.
    if needs_rehash(user.hashed_password):
        user.hashed_password = await asyncio.to_thread(
            get_password_hash, credentials.password
        )

    user.last_login = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            user_id=user.id,
            action="user_login",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
        )
    )
    await db.commit()

    return await _issue_tokens(db, user, request)


async def _second_factor_exhausted(db: AsyncSession, user: User) -> bool:
    """Whether this account has used up its wrong second-factor attempts."""
    settings = get_settings()
    since = datetime.now(timezone.utc) - timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
    failures = (
        await db.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.user_id == user.id,
                AuditLog.action == "mfa_failed",
                AuditLog.created_at >= since,
            )
        )
    ).scalar() or 0
    return failures >= settings.LOGIN_LOCKOUT_THRESHOLD


async def _consume_totp(db: AsyncSession, user: User, code: str) -> bool:
    """Accept an authenticator code once.

    The code must be valid now, and for a later time step than the last one
    accepted for this account. That second condition is the replay guard: a
    code stays valid for about ninety seconds, and without it one that was
    watched being typed could be used again straight away. The check and the
    update are one statement, so two requests carrying the same code cannot
    both pass.
    """
    if not user.totp_secret_encrypted:
        return False
    try:
        secret = decrypt_data(user.totp_secret_encrypted, totp_context(user.id))
    except ValueError:
        logger.error("TOTP secret for user %s could not be decrypted", user.id)
        return False

    step = totp.matching_step(secret, code)
    if step is None:
        return False
    claimed = await db.execute(
        update(User)
        .where(
            User.id == user.id,
            or_(User.totp_last_step.is_(None), User.totp_last_step < step),
        )
        .values(totp_last_step=step)
    )
    return bool(claimed.rowcount)


def _matching_recovery_hash(code: str, stored_hashes: list) -> str | None:
    """The stored hash ``code`` matches, if any. CPU-heavy: run in a thread."""
    for stored in stored_hashes:
        if isinstance(stored, str) and verify_password(code, stored):
            return stored
    return None


async def _consume_recovery_code(db: AsyncSession, user: User, code: str) -> bool:
    """Burn a single-use recovery code.

    Recovery codes are consumed on use: a reusable one is a permanent
    password-equivalent credential sitting in the user's notes app. The row
    is locked while the code is checked and removed, so the same code sent
    twice at once is accepted once.
    """
    if not _RECOVERY_CODE.fullmatch(code):
        return False
    stored_hashes = (
        await db.execute(
            select(User.totp_recovery_hashes).where(User.id == user.id).with_for_update()
        )
    ).scalar_one_or_none()
    if not stored_hashes:
        return False
    # Up to eight 600,000-round derivations. They used to run on the event
    # loop, for every wrong authenticator code as well.
    matched = await asyncio.to_thread(_matching_recovery_hash, code, list(stored_hashes))
    if matched is None:
        return False
    user.totp_recovery_hashes = [h for h in stored_hashes if h != matched]
    await db.flush()
    return True


async def _verify_second_factor(db: AsyncSession, user: User, code: str) -> bool:
    """Accept an authenticator code, or burn a single-use recovery code.

    The authenticator code is checked first and is cheap (one HMAC per time
    step). The recovery codes are only compared when the input has the shape
    of one, so six wrong digits no longer cost eight password hashes.
    """
    if await _second_factor_exhausted(db, user):
        return False
    code = (code or "").strip()
    digits = code.replace(" ", "")
    if digits.isdigit() and len(digits) == totp.DIGITS:
        return await _consume_totp(db, user, digits)
    return await _consume_recovery_code(db, user, code.lower().replace(" ", ""))


@router.post("/mfa/enroll")
@limiter.limit("5/minute")
async def enroll_mfa(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Begin enrolment: issue a secret and the QR payload for it.

    Not enabled yet — the user must prove they can generate a code first, or
    a mistyped setup would lock them out of their own account.
    """
    user = (
        await db.execute(select(User).where(User.id == int(current_user["id"])))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.totp_enabled:
        raise HTTPException(status_code=409, detail="Authenticator already enrolled")

    secret = totp.generate_secret()
    # Bound to this user: the blob does not decrypt as anyone else's secret.
    user.totp_secret_encrypted = encrypt_data(secret, totp_context(user.id))
    user.totp_last_step = None
    await db.commit()

    return {
        "secret": secret,
        "otpauth_uri": totp.provisioning_uri(secret, user.email),
        "next": "Scan this in an authenticator app, then POST the code to /auth/mfa/confirm",
    }


@router.post("/mfa/confirm")
@limiter.limit("10/minute")
async def confirm_mfa(
    request: Request,
    data: MFACodeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Turn MFA on, once a working code proves the app is set up."""
    user = (
        await db.execute(select(User).where(User.id == int(current_user["id"])))
    ).scalar_one_or_none()
    if user is None or not user.totp_secret_encrypted:
        raise HTTPException(status_code=400, detail="Start enrolment first")

    # Consumed like a sign-in code, so the code that proved the setup cannot
    # be used again to sign in during the rest of its ninety seconds.
    if not await _consume_totp(db, user, data.code.strip().replace(" ", "")):
        await db.commit()
        raise HTTPException(status_code=401, detail="That code did not match")

    codes = totp.generate_recovery_codes()
    user.totp_recovery_hashes = await asyncio.to_thread(
        lambda: [get_password_hash(c) for c in codes]
    )
    user.totp_enabled = True
    user.totp_enrolled_at = datetime.now(timezone.utc)
    db.add(
        AuditLog(user_id=user.id, action="mfa_enabled", resource_type="user",
                 resource_id=user.id, ip_address=_client_ip(request))
    )
    await db.commit()

    # Shown exactly once. Password reset depends on email, and email is not
    # configured here, so losing both the app and these codes means losing
    # the account.
    return {
        "enabled": True,
        "recovery_codes": codes,
        "warning": "Store these now. They are shown once and each works only once.",
    }


@router.post("/mfa/disable")
@limiter.limit("5/minute")
async def disable_mfa(
    request: Request,
    data: MFACodeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Turn MFA off. Requires a current code, not just a session."""
    user = (
        await db.execute(select(User).where(User.id == int(current_user["id"])))
    ).scalar_one_or_none()
    if user is None or not user.totp_enabled:
        raise HTTPException(status_code=400, detail="Authenticator is not enabled")

    if not await _verify_second_factor(db, user, data.code):
        # Counted with the sign-in failures, so a stolen session cannot be
        # used to guess the code here without limit.
        await _record_failed_sign_in(db, user, request, "mfa_failed")
        raise HTTPException(status_code=401, detail="That code did not match")

    user.totp_enabled = False
    user.totp_secret_encrypted = None
    user.totp_recovery_hashes = None
    user.totp_enrolled_at = None
    user.totp_last_step = None
    db.add(
        AuditLog(user_id=user.id, action="mfa_disabled", resource_type="user",
                 resource_id=user.id, ip_address=_client_ip(request))
    )
    await db.commit()
    return {"enabled": False}


@router.post("/refresh", response_model=Token)
@limiter.limit("20/minute")
async def refresh_token(
    request: Request,
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """Exchange a refresh token for a new token pair.

    The body is a typed model rather than a bare dict, and the token must
    carry the refresh type claim — an access token used to work here, and a
    refresh token used to work as an API credential.
    """
    claims = decode_token(payload.refresh_token, REFRESH_TOKEN_TYPE)

    try:
        user_id = int(claims["sub"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # Locked for the exchange. Two requests presenting the same token at the
    # same moment both used to read it as unspent and both got a successor,
    # which is exactly the reuse that rotation exists to detect. The second
    # now waits, sees the token spent, and takes the reuse path below.
    row = (
        await db.execute(
            select(RefreshToken)
            .where(RefreshToken.jti == str(claims.get("jti", "")))
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None or row.user_id != user_id:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active or not user.is_verified:
        raise HTTPException(
            status_code=401, detail="User not found or disabled"
        )

    now = datetime.now(timezone.utc)
    if row.revoked_at is not None:
        # A token that was already exchanged is being presented again. One
        # of the two holders is not the user; neither can keep the family.
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.family == row.family, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now, replaced_by="reuse")
        )
        db.add(
            AuditLog(
                user_id=user.id,
                action="refresh_token_reuse",
                resource_type="user",
                resource_id=user.id,
                ip_address=_client_ip(request),
                details={"family": row.family},
            )
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Refresh token has been revoked")

    # Rotate: the presented token is spent, its successor continues the family.
    row.revoked_at = now
    tokens = await _issue_tokens(db, user, request, family=row.family)
    row.replaced_by = decode_token(tokens["refresh_token"], REFRESH_TOKEN_TYPE)["jti"]
    await db.commit()
    return tokens


@router.post("/logout")
async def logout(
    request: Request,
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """Revoke a refresh token (and its family). Idempotent; no session needed."""
    try:
        claims = decode_token(payload.refresh_token, REFRESH_TOKEN_TYPE)
    except HTTPException:
        return {"message": "Signed out"}
    row = (
        await db.execute(select(RefreshToken).where(RefreshToken.jti == str(claims.get("jti", ""))))
    ).scalar_one_or_none()
    if row is not None:
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.family == row.family, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=datetime.now(timezone.utc), replaced_by="logout")
        )
        db.add(
            AuditLog(user_id=row.user_id, action="user_logout", resource_type="user",
                     resource_id=row.user_id, ip_address=_client_ip(request))
        )
        await db.commit()
    return {"message": "Signed out"}


@router.post("/logout-all")
async def logout_everywhere(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Sign out of every device: every refresh token revoked, every access
    token invalidated. The caller must sign in again too."""
    user = (await db.execute(select(User).where(User.id == current_user["id"]))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    await _sign_out_everywhere(db, user, "logout-all")
    db.add(
        AuditLog(user_id=user.id, action="user_logout_all", resource_type="user",
                 resource_id=user.id, ip_address=_client_ip(request))
    )
    await db.commit()
    return {"message": "Signed out everywhere"}


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(User).where(User.id == current_user["id"])
    )
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    result = await db.execute(select(User).order_by(User.email))
    return result.scalars().all()


@router.post(
    "/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def create_user(
    request: Request,
    user_data: AdminUserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    """Admin-only account creation, including role assignment."""
    existing = await db.execute(
        select(User).where(User.email == user_data.email)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        name=user_data.name,
        role=UserRole(user_data.role.value),
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    await db.flush()

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="user_created",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
            details={"role": user.role.value},
        )
    )
    await db.commit()
    await db.refresh(user)
    return user


@router.patch("/users/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: int,
    request: Request,
    payload: UserRoleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user["id"] and payload.role.value != "admin":
        # Prevent an admin locking every administrator out of the system.
        raise HTTPException(
            status_code=400, detail="Cannot remove your own admin role"
        )

    user.role = UserRole(payload.role.value)
    invalidate_user_state(user.id)
    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="user_role_changed",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
            details={"role": user.role.value},
        )
    )
    await db.commit()
    await db.refresh(user)
    return user


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    request: Request,
    payload: UserAdminUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    """Deactivate, reactivate or rename an account."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="Nothing to update")
    if changes.get("is_active") is False and user.id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    for key, value in changes.items():
        setattr(user, key, value)
    if changes.get("is_active"):
        user.failed_login_count = 0
        user.locked_until = None
    if changes.get("is_active") is False:
        await _sign_out_everywhere(db, user, "deactivated")
    invalidate_user_state(user.id)
    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="user_updated",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
            details=changes,
        )
    )
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/users/{user_id}/reset-mfa", response_model=UserResponse)
async def admin_reset_mfa(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    """Remove a user's authenticator so they can sign in and enrol again."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.totp_enabled = False
    user.totp_secret_encrypted = None
    user.totp_recovery_hashes = None
    user.totp_enrolled_at = None
    user.totp_last_step = None
    await _sign_out_everywhere(db, user, "mfa-reset")
    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="mfa_reset_by_admin",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
        )
    )
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/users/{user_id}/reset-password", response_model=UserResponse)
async def admin_reset_password(
    user_id: int,
    request: Request,
    payload: AdminPasswordReset,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    """Set a temporary password for a user, on a deployment without email."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = get_password_hash(payload.new_password)
    user.failed_login_count = 0
    user.locked_until = None
    await _sign_out_everywhere(db, user, "admin-reset")
    db.add(
        AuditLog(
            user_id=current_user["id"],
            action="password_reset_by_admin",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
        )
    )
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/change-password")
@limiter.limit("5/minute")
async def change_password(
    request: Request,
    payload: PasswordChange,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Change your own password; requires the current one."""
    # Limited per address above and per account here. With neither, a stolen
    # access token was an unlimited oracle for the account's password.
    failures_key = ("change-password", current_user["id"])
    window = _failure_window_seconds()
    if sign_in_failures.blocked(
        failures_key, get_settings().LOGIN_SOURCE_FAILURE_LIMIT, window
    ):
        raise HTTPException(status_code=429, detail=_TOO_MANY_ATTEMPTS)

    result = await db.execute(select(User).where(User.id == current_user["id"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not await asyncio.to_thread(
        verify_password, payload.current_password, user.hashed_password
    ):
        sign_in_failures.record(failures_key, window)
        db.add(
            AuditLog(
                user_id=user.id,
                action="password_change_failed",
                resource_type="user",
                resource_id=user.id,
                ip_address=_client_ip(request),
            )
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current one")
    sign_in_failures.reset(failures_key)
    user.hashed_password = await asyncio.to_thread(get_password_hash, payload.new_password)
    await _sign_out_everywhere(db, user, "password-change")
    db.add(
        AuditLog(
            user_id=user.id,
            action="password_changed",
            resource_type="user",
            resource_id=user.id,
            ip_address=_client_ip(request),
        )
    )
    await db.commit()
    return {"message": "Password changed"}
