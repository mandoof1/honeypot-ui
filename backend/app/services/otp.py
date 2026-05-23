import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import OTPVerification, User
from app.services.email import email_service

logger = logging.getLogger(__name__)

OTP_EXPIRY_MINUTES = 10
OTP_MAX_ATTEMPTS = 5


class OTPService:
    async def generate_and_send(
        self,
        db: AsyncSession,
        user: User,
        purpose: str = "email_verification",
        ip_address: Optional[str] = None,
    ) -> bool:
        await self._invalidate_existing(db, user.id, purpose)

        otp_code = self._generate_code()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES)

        otp_record = OTPVerification(
            user_id=user.id,
            email=user.email,
            otp_code=otp_code,
            purpose=purpose,
            expires_at=expires_at,
            ip_address=ip_address,
        )
        db.add(otp_record)
        await db.commit()

        if purpose == "email_verification":
            sent = email_service.send_otp_email(user.email, otp_code, user.name or "")
        elif purpose == "password_reset":
            sent = email_service.send_password_reset_email(user.email, otp_code, user.name or "")
        else:
            sent = email_service.send_otp_email(user.email, otp_code, user.name or "")

        if not sent:
            logger.error(f"Failed to send OTP for user {user.id}")

        return sent

    async def verify(
        self,
        db: AsyncSession,
        user_id: int,
        otp_code: str,
        purpose: str = "email_verification",
    ) -> dict:
        result = await db.execute(
            select(OTPVerification).where(
                OTPVerification.user_id == user_id,
                OTPVerification.purpose == purpose,
                OTPVerification.is_used == False,
                OTPVerification.expires_at > datetime.now(timezone.utc),
            ).order_by(OTPVerification.created_at.desc())
        )
        otp_record = result.scalar_one_or_none()

        if not otp_record:
            return {"valid": False, "reason": "No active OTP found. Please request a new code."}

        if otp_record.otp_code != otp_code:
            return {"valid": False, "reason": "Invalid verification code."}

        otp_record.is_used = True
        otp_record.used_at = datetime.now(timezone.utc)
        await db.commit()

        if purpose == "email_verification":
            user_result = await db.execute(select(User).where(User.id == user_id))
            user = user_result.scalar_one()
            user.is_verified = True
            user.is_active = True
            await db.commit()

        return {"valid": True, "email": otp_record.email}

    async def resend(
        self,
        db: AsyncSession,
        user_id: int,
        purpose: str = "email_verification",
        ip_address: Optional[str] = None,
    ) -> bool:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            return False

        return await self.generate_and_send(db, user, purpose, ip_address)

    async def cleanup_expired(self, db: AsyncSession):
        await db.execute(
            delete(OTPVerification).where(
                OTPVerification.expires_at < datetime.now(timezone.utc)
            )
        )
        await db.commit()

    async def _invalidate_existing(
        self, db: AsyncSession, user_id: int, purpose: str
    ):
        result = await db.execute(
            select(OTPVerification).where(
                OTPVerification.user_id == user_id,
                OTPVerification.purpose == purpose,
                OTPVerification.is_used == False,
            )
        )
        for record in result.scalars().all():
            record.is_used = True

    def _generate_code(self) -> str:
        return f"{random.randint(100000, 999999)}"


otp_service = OTPService()
