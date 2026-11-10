"""Create the first administrator and the default alert threshold.

Run inside the backend container, reading the password from the environment:

    docker compose exec -T -e ADMIN_EMAIL=... -e ADMIN_PASSWORD=... \
        backend python - < create_admin.py

This is what `app.seed` does for an empty database minus everything
synthetic: the seed also inserts 150 generated attack sessions, which must
never sit beside captured traffic.

The last line printed is the outcome, for install.sh to read:

    RESULT=created   the account did not exist and now has ADMIN_PASSWORD
    RESULT=exists    it already existed; nothing about it was changed
    RESULT=reset     ADMIN_RESET=1 was given and an existing account now has
                     ADMIN_PASSWORD (lockout cleared, sessions signed out)

install.sh shows the password only after `created` or `reset`. It used to
write the password to a file after this script returned, whatever had
happened: when the account already existed, the file recorded a password
that had never been set.
"""

import asyncio
import os

from sqlalchemy import select

from app.core.database import async_session_factory
from app.core.security import get_password_hash
from app.models import AlertThreshold, AttackSeverity, AuditLog, User, UserRole


async def main() -> None:
    email = os.environ["ADMIN_EMAIL"]
    password = os.environ["ADMIN_PASSWORD"]
    reset = os.environ.get("ADMIN_RESET") == "1"

    async with async_session_factory() as db:
        user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if user is None and reset:
            raise SystemExit(f"no account {email} to reset")
        if user is None:
            db.add(
                User(
                    email=email,
                    hashed_password=get_password_hash(password),
                    name="Security Admin",
                    role=UserRole.ADMIN,
                    is_active=True,
                    # No SMTP on this host, so email verification cannot
                    # complete; the operator is verified by creating it here.
                    is_verified=True,
                )
            )
            result = "created"
        elif reset:
            user.hashed_password = get_password_hash(password)
            user.failed_login_count = 0
            user.locked_until = None
            # Every token issued under the old password stops working.
            user.token_version = int(user.token_version or 0) + 1
            db.add(
                AuditLog(
                    user_id=user.id,
                    action="password_reset_from_host",
                    resource_type="user",
                    resource_id=user.id,
                    details={"by": "install.sh --reset-admin-password"},
                )
            )
            result = "reset"
        else:
            result = "exists"

        name = "Default High Severity"
        if not (
            await db.execute(select(AlertThreshold).where(AlertThreshold.name == name))
        ).scalar_one_or_none():
            db.add(
                AlertThreshold(
                    name=name,
                    min_severity=AttackSeverity.MEDIUM,
                    anomaly_score_threshold=0.6,
                    email_enabled=True,
                    webhook_enabled=False,
                )
            )

        # One transaction: the account and its outcome are reported together
        # or not at all.
        await db.commit()
    print(f"RESULT={result}")


asyncio.run(main())
