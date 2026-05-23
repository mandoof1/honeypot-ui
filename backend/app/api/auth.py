from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.security import get_password_hash, verify_password, create_access_token, create_refresh_token, get_current_user
from app.models import User, AuditLog
from app.schemas import (
    UserCreate, UserLogin, Token, UserResponse,
    OTPVerifyRequest, OTPResendRequest, RegisterResponse,
    PasswordResetRequest, PasswordResetConfirm,
)
from app.services.otp import otp_service

router = APIRouter()


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    existing = await db.execute(select(User).where(User.email == user_data.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        name=user_data.name,
        role=user_data.role,
        is_active=False,
        is_verified=False,
    )
    db.add(user)
    await db.flush()

    client_ip = request.client.host if request.client else None
    await otp_service.generate_and_send(db, user, "email_verification", client_ip)

    audit = AuditLog(
        user_id=user.id,
        action="user_registered",
        resource_type="user",
        resource_id=user.id,
        ip_address=client_ip,
        details={"requires_verification": True},
    )
    db.add(audit)
    await db.commit()

    return RegisterResponse(
        message="Registration successful. Please check your email for the verification code.",
        email=user.email,
        requires_verification=True,
    )


@router.post("/verify-otp")
async def verify_otp(
    data: OTPVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_verified:
        raise HTTPException(status_code=400, detail="Email already verified")

    client_ip = request.client.host if request.client else None
    verification = await otp_service.verify(db, user.id, data.otp_code, data.purpose)

    if not verification["valid"]:
        raise HTTPException(status_code=400, detail=verification["reason"])

    audit = AuditLog(
        user_id=user.id,
        action="email_verified",
        resource_type="user",
        resource_id=user.id,
        ip_address=client_ip,
    )
    db.add(audit)
    await db.commit()

    return {
        "message": "Email verified successfully. You can now log in.",
        "email": verification["email"],
    }


@router.post("/resend-otp")
async def resend_otp(
    data: OTPResendRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_verified:
        raise HTTPException(status_code=400, detail="Email already verified")

    client_ip = request.client.host if request.client else None
    sent = await otp_service.resend(db, user.id, data.purpose, client_ip)

    if not sent:
        raise HTTPException(status_code=500, detail="Failed to send verification code")

    return {"message": "Verification code resent. Please check your email."}


@router.post("/request-password-reset")
async def request_password_reset(
    data: PasswordResetRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()
    if not user:
        return {"message": "If the email exists, a reset code has been sent."}

    client_ip = request.client.host if request.client else None
    await otp_service.generate_and_send(db, user, "password_reset", client_ip)

    return {"message": "If the email exists, a reset code has been sent."}


@router.post("/reset-password")
async def reset_password(
    data: PasswordResetConfirm,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    verification = await otp_service.verify(db, user.id, data.otp_code, "password_reset")
    if not verification["valid"]:
        raise HTTPException(status_code=400, detail=verification["reason"])

    user.hashed_password = get_password_hash(data.new_password)

    client_ip = request.client.host if request.client else None
    audit = AuditLog(
        user_id=user.id,
        action="password_reset",
        resource_type="user",
        resource_id=user.id,
        ip_address=client_ip,
    )
    db.add(audit)
    await db.commit()

    return {"message": "Password reset successfully. You can now log in with your new password."}


@router.post("/login", response_model=Token)
async def login(credentials: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == credentials.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    if not user.is_verified:
        raise HTTPException(
            status_code=403,
            detail="Email not verified. Please verify your email before logging in.",
        )

    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    audit = AuditLog(
        user_id=user.id,
        action="user_login",
        resource_type="user",
        resource_id=user.id,
    )
    db.add(audit)
    await db.commit()

    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role.value}
    )
    refresh_token = create_refresh_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role.value}
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh", response_model=Token)
async def refresh_token(token_data: dict, db: AsyncSession = Depends(get_db)):
    from jose import JWTError
    from app.core.config import get_settings
    settings = get_settings()

    try:
        from jose import jwt
        payload = jwt.decode(token_data.get("refresh_token", ""), settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or disabled")

    access_token = create_access_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role.value}
    )
    refresh_token = create_refresh_token(
        data={"sub": str(user.id), "email": user.email, "role": user.role.value}
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.id == current_user["id"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
