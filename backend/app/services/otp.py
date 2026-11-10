"""One-time passcode issuance and verification."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import OTPVerification, User
from app.services.email import email_service

logger = logging.getLogger(__name__)

OTP_EXPIRY_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
OTP_LENGTH = 6

#: How long a code's row is kept after it expires. The per-account hourly
#: cap counts rows, so they have to outlive the hour they are counted in.
OTP_RETENTION = timedelta(hours=2)

#: One message for every way a code can fail to verify. The old ones ("No
#: active code found", "2 attempt(s) remaining") were only ever produced for
#: an address that had an account, so they told a caller which addresses did.
INVALID_CODE = "Invalid or expired code."


def _hash_code(code: str) -> str:
    """Hash an OTP for storage.

    Codes were previously stored in plaintext, so anyone with read access to
    the database (a backup, a SQL injection, a shared dev dump) could complete
    another user's verification or password reset.
    """
    settings = get_settings()
    return hmac.new(
        settings.SECRET_KEY.encode(), code.encode(), hashlib.sha256
    ).hexdigest()


class OTPService:
    @property
    def delivery_available(self) -> bool:
        """Whether a code could reach anyone on this deployment."""
        return email_service.configured

    async def issue(
        self,
        db: AsyncSession,
        user: User,
        purpose: str = "email_verification",
        ip_address: Optional[str] = None,
    ) -> Optional[tuple[int, str]]:
        """Create a code for ``user``. Returns (row id, code), or None.

        None means no code was created: mail cannot be sent at all, or the
        account has had its codes for the hour. Either way the caller answers
        exactly as it would have otherwise, so the response says nothing
        about the account.

        A code allows five guesses out of a million. Unlimited fresh codes
        made that unlimited guesses, so issuing is capped per account, and
        each new code retires the ones before it.
        """
        if not self.delivery_available:
            logger.warning(
                "No mail provider is configured; not issuing a %s code", purpose
            )
            return None

        since = datetime.now(timezone.utc) - timedelta(hours=1)
        issued = (
            await db.execute(
                select(func.count(OTPVerification.id)).where(
                    OTPVerification.user_id == user.id,
                    OTPVerification.created_at >= since,
                )
            )
        ).scalar() or 0
        if issued >= max(1, get_settings().OTP_MAX_CODES_PER_HOUR):
            logger.warning(
                "Code request for user id %s refused: %s issued in the last hour",
                user.id, issued,
            )
            return None

        await self._invalidate_existing(db, user.id, purpose)

        otp_code = self._generate_code()
        otp_record = OTPVerification(
            user_id=user.id,
            email=user.email,
            otp_code=_hash_code(otp_code),
            purpose=purpose,
            expires_at=datetime.now(timezone.utc)
            + timedelta(minutes=OTP_EXPIRY_MINUTES),
            ip_address=ip_address,
        )
        db.add(otp_record)
        await db.commit()
        return otp_record.id, otp_code

    async def deliver(
        self,
        db: AsyncSession,
        record_id: int,
        email: str,
        name: str,
        otp_code: str,
        purpose: str,
    ) -> bool:
        """Send a code that ``issue`` created, and retire it if sending fails.

        A code nobody received must not stay usable: until it expired it was
        five free guesses at the account for anyone who knew the address.
        """
        sender = (
            email_service.send_password_reset_email
            if purpose == "password_reset"
            else email_service.send_otp_email
        )
        # smtplib and urllib block; running them inline stalled the whole
        # event loop for the duration of the send.
        try:
            sent = await asyncio.to_thread(sender, email, otp_code, name or "")
        except Exception:
            logger.exception("Sending a %s code raised", purpose)
            sent = False

        if not sent:
            # Never log the code itself: application logs are routinely shipped
            # to third parties and would hand over every account.
            logger.error("Failed to deliver %s code (record %s)", purpose, record_id)
            record = (
                await db.execute(
                    select(OTPVerification).where(OTPVerification.id == record_id)
                )
            ).scalar_one_or_none()
            if record is not None and not record.is_used:
                record.is_used = True
                await db.commit()
        return bool(sent)

    async def generate_and_send(
        self,
        db: AsyncSession,
        user: User,
        purpose: str = "email_verification",
        ip_address: Optional[str] = None,
    ) -> bool:
        """Issue a code and send it, waiting for the send. True if delivered."""
        issued = await self.issue(db, user, purpose, ip_address)
        if issued is None:
            return False
        record_id, otp_code = issued
        return await self.deliver(
            db, record_id, user.email, user.name or "", otp_code, purpose
        )

    async def verify(
        self,
        db: AsyncSession,
        user_id: int,
        otp_code: str,
        purpose: str = "email_verification",
    ) -> dict:
        """Check a code. ``reason`` is the same for every kind of failure."""
        failed = {"valid": False, "reason": INVALID_CODE}
        result = await db.execute(
            select(OTPVerification)
            .where(
                OTPVerification.user_id == user_id,
                OTPVerification.purpose == purpose,
                OTPVerification.is_used.is_(False),
                OTPVerification.expires_at > datetime.now(timezone.utc),
            )
            .order_by(OTPVerification.created_at.desc(), OTPVerification.id.desc())
            .limit(1)  # more than one live row raised MultipleResultsFound
            # Two guesses arriving together must not both read "4 attempts
            # used" and both be allowed a fifth.
            .with_for_update()
        )
        otp_record = result.scalar_one_or_none()

        if not otp_record:
            return failed

        if otp_record.attempts >= OTP_MAX_ATTEMPTS:
            otp_record.is_used = True
            await db.commit()
            return failed

        # Constant-time comparison; a plain != leaks the code byte by byte.
        if not hmac.compare_digest(otp_record.otp_code, _hash_code(otp_code)):
            otp_record.attempts += 1
            if otp_record.attempts >= OTP_MAX_ATTEMPTS:
                otp_record.is_used = True
            await db.commit()
            return failed

        otp_record.is_used = True
        otp_record.used_at = datetime.now(timezone.utc)
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
                OTPVerification.expires_at < datetime.now(timezone.utc) - OTP_RETENTION
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
                OTPVerification.is_used.is_(False),
            )
        )
        for record in result.scalars().all():
            record.is_used = True

    @staticmethod
    def _generate_code() -> str:
        # random.randint is a Mersenne Twister: observing a handful of codes
        # lets an attacker predict the rest. secrets uses the OS CSPRNG.
        return f"{secrets.randbelow(10 ** OTP_LENGTH):0{OTP_LENGTH}d}"


otp_service = OTPService()
