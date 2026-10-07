"""Create the first administrator and the default alert threshold.

Run inside the backend container, reading the password from the environment:

    docker compose exec -T -e ADMIN_EMAIL=... -e ADMIN_PASSWORD=... \
        backend python - < create_admin.py

This is what `app.seed` does for an empty database minus everything
synthetic: the seed also inserts 150 generated attack sessions, which must
never sit beside captured traffic. Idempotent: an existing account with the
same email is left untouched.
"""

import asyncio
import os

from sqlalchemy import select

from app.core.database import async_session_factory
from app.core.security import get_password_hash
from app.models import AlertThreshold, AttackSeverity, User, UserRole


async def main() -> None:
    email = os.environ["ADMIN_EMAIL"]
    password = os.environ["ADMIN_PASSWORD"]

    async with async_session_factory() as db:
        if (await db.execute(select(User).where(User.email == email))).scalar_one_or_none():
            print(f"admin {email} already exists; left unchanged")
        else:
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
            print(f"admin {email} created")

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
            print("default alert threshold created")

        await db.commit()


asyncio.run(main())
