"""Authentication, email verification and password reset."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.rate_limit import limiter
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
from app.core.encryption import decrypt_data, encrypt_data
from app.services.otp import otp_service

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


def _client_ip(request: Request) -> str | None:
    from app.core.clientip import client_ip

    return client_ip(request)


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


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("5/minute")
async def register(
    request: Request,
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    """Self-service registration.

    New accounts are always created as viewers. The payload schema has no
    `role` field: it previously did, which let anyone register as an admin.
    """
    existing = await db.execute(
        select(User).where(User.email == user_data.email)
    )
    if existing.scalar_one_or_none():
        # Do not confirm the address is taken; a duplicate registration gets
        # the same response as a fresh one.
        return RegisterResponse(
            message=(
                "Registration received. Check your email for a verification "
                "code."
            ),
            email=user_data.email,
            requires_verification=True,
        )

    user = User(
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        name=user_data.name,
        role=UserRole.VIEWER,
        is_active=False,
        is_verified=False,
    )
    db.add(user)
    await db.flush()

    client_ip = _client_ip(request)
    db.add(
        AuditLog(
            user_id=user.id,
            action="user_registered",
            resource_type="user",
            resource_id=user.id,
            ip_address=client_ip,
            details={"requires_verification": True},
        )
    )
    await db.commit()

    await otp_service.generate_and_send(
        db, user, "email_verification", client_ip
    )

    return RegisterResponse(
        message=(
            "Registration received. Check your email for a verification code."
        ),
        email=user.email,
        requires_verification=True,
    )


@router.post("/verify-otp")
@limiter.limit("10/minute")
async def verify_otp(
    request: Request,
    data: OTPVerifyRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    # Same response shape whether or not the account exists.
    invalid = HTTPException(
        status_code=400, detail="Invalid or expired verification code."
    )
    if not user or user.is_verified:
        raise invalid

    verification = await otp_service.verify(
        db, user.id, data.otp_code, "email_verification"
    )
    if not verification["valid"]:
        raise HTTPException(status_code=400, detail=verification["reason"])

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
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if user and not user.is_verified:
        await otp_service.generate_and_send(
            db, user, "email_verification", _client_ip(request)
        )

    return _GENERIC_OTP_RESPONSE


@router.post("/request-password-reset")
@limiter.limit("3/minute")
async def request_password_reset(
    request: Request,
    data: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if user and user.is_active:
        await otp_service.generate_and_send(
            db, user, "password_reset", _client_ip(request)
        )

    return _GENERIC_OTP_RESPONSE


@router.post("/reset-password")
@limiter.limit("5/minute")
async def reset_password(
    request: Request,
    data: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    # A missing user previously returned 404 while a bad code returned 400,
    # which turned this endpoint into an account-existence oracle.
    invalid = HTTPException(
        status_code=400, detail="Invalid or expired reset code."
    )
    if not user:
        raise invalid

    verification = await otp_service.verify(
        db, user.id, data.otp_code, "password_reset"
    )
    if not verification["valid"]:
        raise HTTPException(status_code=400, detail=verification["reason"])

    user.hashed_password = get_password_hash(data.new_password)
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
    result = await db.execute(
        select(User).where(User.email == credentials.email)
    )
    user = result.scalar_one_or_none()

    if user is None:
        verify_password(credentials.password, _TIMING_DECOY)
        raise HTTPException(
            status_code=401, detail="Invalid email or password"
        )

    now = datetime.now(timezone.utc)
    locked_until = user.locked_until
    if locked_until is not None and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    if locked_until and locked_until > now:
        remaining = int((locked_until - now).total_seconds() // 60) + 1
        raise HTTPException(
            status_code=423,
            detail=f"Account temporarily locked after repeated failed sign-ins. Try again in {remaining} minute(s).",
        )

    if not verify_password(credentials.password, user.hashed_password):
        # Per-account lockout, in addition to the per-address rate limit: a
        # distributed guess at one account used to be unlimited.
        cfg = get_settings()
        user.failed_login_count = (user.failed_login_count or 0) + 1
        locked = False
        if user.failed_login_count >= cfg.LOGIN_LOCKOUT_THRESHOLD:
            user.locked_until = now + timedelta(minutes=cfg.LOGIN_LOCKOUT_MINUTES)
            user.failed_login_count = 0
            locked = True
        db.add(
            AuditLog(
                user_id=user.id,
                action="login_failed",
                resource_type="user",
                resource_id=user.id,
                ip_address=_client_ip(request),
                details={"locked": locked},
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=401, detail="Invalid email or password"
        )

    if user.failed_login_count or user.locked_until:
        user.failed_login_count = 0
        user.locked_until = None

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
        if not _verify_second_factor(user, credentials.totp_code):
            db.add(
                AuditLog(
                    user_id=user.id,
                    action="mfa_failed",
                    resource_type="user",
                    resource_id=user.id,
                    ip_address=_client_ip(request),
                )
            )
            await db.commit()
            raise HTTPException(status_code=401, detail="Invalid authenticator code")

    # Transparently upgrade hashes stored with weaker parameters.
    if needs_rehash(user.hashed_password):
        user.hashed_password = get_password_hash(credentials.password)

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


def _verify_second_factor(user: User, code: str) -> bool:
    """Accept a TOTP code, or burn a single-use recovery code.

    Recovery codes are consumed on use: a reusable one is a permanent
    password-equivalent credential sitting in the user's notes app.
    """
    code = (code or "").strip()

    if user.totp_secret_encrypted:
        try:
            secret = decrypt_data(user.totp_secret_encrypted)
        except ValueError:
            logger.error("TOTP secret for user %s could not be decrypted", user.id)
            secret = ""
        if secret and totp.verify(secret, code):
            return True

    remaining = list(user.totp_recovery_hashes or [])
    normalised = code.lower().replace(" ", "")
    for stored in remaining:
        if verify_password(normalised, stored):
            remaining.remove(stored)
            user.totp_recovery_hashes = remaining
            return True
    return False


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
    user.totp_secret_encrypted = encrypt_data(secret)
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

    if not totp.verify(decrypt_data(user.totp_secret_encrypted), data.code):
        raise HTTPException(status_code=401, detail="That code did not match")

    codes = totp.generate_recovery_codes()
    user.totp_recovery_hashes = [get_password_hash(c) for c in codes]
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

    if not _verify_second_factor(user, data.code):
        raise HTTPException(status_code=401, detail="That code did not match")

    user.totp_enabled = False
    user.totp_secret_encrypted = None
    user.totp_recovery_hashes = None
    user.totp_enrolled_at = None
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

    row = (
        await db.execute(select(RefreshToken).where(RefreshToken.jti == str(claims.get("jti", ""))))
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
async def change_password(
    request: Request,
    payload: PasswordChange,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Change your own password; requires the current one."""
    result = await db.execute(select(User).where(User.id == current_user["id"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if payload.current_password == payload.new_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current one")
    user.hashed_password = get_password_hash(payload.new_password)
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
