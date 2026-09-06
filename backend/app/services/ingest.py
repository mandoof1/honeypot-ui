"""Idempotent capture receipts, backed by the session UUID unique index."""

import hashlib
import json
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.models import HoneypotSession
from app.services.analysis import analysis_pipeline


async def ingest_once(db, data, node_id):
    dropped = data.get("capture_dropped")
    if dropped is not None and (
        not isinstance(dropped, dict) or len(dropped) > 32 or any(
            len(k) > 64 or type(v) is not int or not 0 <= v < 2**31
            for k, v in dropped.items()
        )
    ):
        raise HTTPException(422, "capture_dropped must contain bounded nonnegative integer counters")
    capture_id = data.get("capture_id")
    digest = None
    if capture_id is not None:
        try:
            capture_id = str(UUID(str(capture_id)))
            data = {**data, "capture_id": capture_id}
            digest = hashlib.sha256(json.dumps(
                data, sort_keys=True, separators=(",", ":"), allow_nan=False,
            ).encode()).hexdigest()
        except (ValueError, TypeError):
            raise HTTPException(422, "capture_id must be a UUID and the payload must be valid JSON")

    async def existing_receipt():
        if capture_id is None:
            return None
        existing = (await db.execute(select(HoneypotSession).where(
            HoneypotSession.session_uuid == capture_id,
        ))).scalar_one_or_none()
        if existing is None:
            return None
        if existing.node_id != node_id or existing.ingest_digest != digest:
            raise HTTPException(409, "Capture UUID already exists with different evidence or node")
        return {
            "session_id": existing.id, "session_uuid": existing.session_uuid,
            "duplicate": True,
            "ai_classification": {
                "category": existing.attack_category.value,
                "confidence": existing.attack_confidence,
                "model_source": existing.model_source,
            },
        }

    receipt = await existing_receipt()
    if receipt is not None:
        return receipt
    try:
        result = await analysis_pipeline.process_session(
            db, data, node_id, capture_uuid=capture_id, ingest_digest=digest,
        )
    except IntegrityError:
        # Two workers may both miss the lookup. The unique UUID is the
        # arbiter; the losing transaction must not create IOCs or alerts.
        await db.rollback()
        receipt = await existing_receipt()
        if receipt is not None:
            return receipt
        raise
    return {**result, "duplicate": False}
