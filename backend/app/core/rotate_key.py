"""Re-encrypt everything stored at rest under the current ENCRYPTION_KEY.

    python -m app.core.rotate_key            # re-encrypt
    python -m app.core.rotate_key --dry-run  # only count what would change

Rotating the key:

1. Generate a new key. Put the old value in ENCRYPTION_KEY_PREVIOUS (comma-
   separated, newest first, if there are several) and the new one in
   ENCRYPTION_KEY. Restart the backend and ingest services. From here on new
   rows are written under the new key and old rows still open.
2. Run this command (inside the backend container, so it sees the same
   settings). It walks every encrypted column in batches and rewrites each
   blob that is not already under the current key, in the current format and
   bound to its own row and column.
3. When it reports nothing left and nothing failed, remove the old key from
   ENCRYPTION_KEY_PREVIOUS and restart.

It is safe to stop and run again: a blob already in its final form is
skipped, and each batch is its own transaction. A blob that cannot be opened
(its key is in neither setting) is left exactly as it is and counted as
failed; the exit status is then 1.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, List

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import encryption
from app.models import HoneypotSession, PayloadSample, User

logger = logging.getLogger("rotate_key")

DEFAULT_BATCH_SIZE = 200


@dataclass
class _Target:
    """One table with encrypted columns, and how each blob is labelled."""

    model: type
    #: column name -> True when the column holds raw bytes, False for text.
    columns: Dict[str, bool]
    #: (row, column name) -> the context label that binds a blob to its place.
    context: Callable[[object, str], str]
    #: Extra columns the context needs besides the primary key.
    extra: List[str] = field(default_factory=list)
    #: Upper bound on rows held in memory at once, whatever --batch-size says.
    max_batch: int = DEFAULT_BATCH_SIZE


_TARGETS = [
    _Target(
        model=HoneypotSession,
        columns={
            "raw_commands_encrypted": False,
            "raw_payloads_encrypted": False,
            "transcript_encrypted": False,
            "credentials_encrypted": False,
        },
        context=lambda row, column: encryption.session_context(row.id, column),
    ),
    _Target(
        model=PayloadSample,
        columns={"content_encrypted": True},
        context=lambda row, column: encryption.payload_context(row.sha256),
        extra=["sha256"],
        # A stored sample can be 10 MiB, about 13 MB once sealed and encoded.
        max_batch=8,
    ),
    _Target(
        model=User,
        columns={"totp_secret_encrypted": False},
        context=lambda row, column: encryption.totp_context(row.id),
    ),
]


def _reseal(blob: str, context: str, binary: bool) -> str:
    """Open ``blob`` with whichever key fits and seal it again, bound."""
    if binary:
        return encryption.encrypt_bytes(encryption.decrypt_bytes(blob, context), context)
    return encryption.encrypt_data(encryption.decrypt_data(blob, context), context)


async def rotate(
    db: AsyncSession, dry_run: bool = False, batch_size: int = DEFAULT_BATCH_SIZE
) -> Dict[str, int]:
    """Walk every encrypted column. Returns counts for the summary line."""
    totals = {"examined": 0, "rotated": 0, "current": 0, "failed": 0}

    for target in _TARGETS:
        model = target.model
        wanted = [model.id] + [getattr(model, name) for name in target.extra]
        wanted += [getattr(model, name) for name in target.columns]
        last_id = 0

        while True:
            # Keyset paging on the primary key: an OFFSET would rescan the
            # rows already done, and these rows carry multi-megabyte blobs.
            query = (
                select(*wanted)
                .where(model.id > last_id)
                .order_by(model.id)
                .limit(min(batch_size, target.max_batch))
            )
            if not dry_run:
                # Hold the rows for the length of the batch, so a write that
                # lands in between (a new authenticator, a late upload) is
                # not overwritten with a re-encryption of the old value.
                query = query.with_for_update()
            rows = (await db.execute(query)).all()
            if not rows:
                break
            last_id = rows[-1].id

            for row in rows:
                changes = {}
                for column, binary in target.columns.items():
                    blob = getattr(row, column)
                    if not blob:
                        continue
                    totals["examined"] += 1
                    context = target.context(row, column)
                    try:
                        if not encryption.needs_rotation(blob, context):
                            totals["current"] += 1
                            continue
                        changes[column] = _reseal(blob, context, binary)
                    except ValueError as exc:
                        totals["failed"] += 1
                        logger.error(
                            "%s id=%s %s could not be re-encrypted: %s",
                            model.__tablename__, row.id, column, exc,
                        )
                        continue
                    totals["rotated"] += 1
                if changes and not dry_run:
                    await db.execute(
                        update(model).where(model.id == row.id).values(**changes)
                    )

            if dry_run:
                await db.rollback()
            else:
                await db.commit()

    return totals


async def _main(dry_run: bool, batch_size: int) -> int:
    from app.core.database import async_session_factory, engine

    try:
        async with async_session_factory() as db:
            totals = await rotate(db, dry_run=dry_run, batch_size=batch_size)
    finally:
        await engine.dispose()

    verb = "would be re-encrypted" if dry_run else "re-encrypted"
    print(
        f"key {encryption.current_key_id()}: {totals['examined']} blob(s) examined, "
        f"{totals['rotated']} {verb}, {totals['current']} already current, "
        f"{totals['failed']} failed"
    )
    return 1 if totals["failed"] else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.core.rotate_key",
        description="Re-encrypt stored data under the current ENCRYPTION_KEY.",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="count what would change; write nothing"
    )
    parser.add_argument(
        "--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="rows per transaction"
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    return asyncio.run(_main(args.dry_run, max(1, args.batch_size)))


if __name__ == "__main__":
    sys.exit(main())
