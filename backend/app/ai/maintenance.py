"""Fitting the unsupervised models on stored sessions, and backfilling rows.

The cluster model and the anomaly detector are fitted on the deployment's
own sessions. Both used to exist only as a manual command, and neither
touched the rows already stored: clustering stayed "not fitted" on every
deployment where nobody ran it, and a fit, once run, described only the
sessions that arrived after it.

These are the operations themselves — fit when there is enough data, refit
on a schedule, re-assign the stored rows after each fit — used by the
backend's scheduler (services/scheduler.py), by ``ml.fit_clusters`` and
``ml.fit_anomaly``, and by the reanalysis tool. The feature work runs on a
thread: it is CPU-bound and the scheduler shares the API's event loop.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import numpy as np
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.anomaly_detector import SOURCE_SESSIONS, anomaly_detector, features_from_session
from app.ai.clustering import MIN_SESSIONS_TO_FIT, clusterer, default_features, extract
from app.ai.config import get_analysis_settings
from app.ai.session_view import is_refusal, rebuild_session_data, run_rules
from app.models import HoneypotSession

logger = logging.getLogger(__name__)

#: Most recent sessions a fit reads. Fitting is quadratic in nothing, but
#: every row is decrypted and re-read by the rules.
MAX_FIT_SESSIONS = 20_000
BACKFILL_BATCH = 200


async def session_count(db: AsyncSession) -> int:
    return (await db.execute(select(func.count(HoneypotSession.id)))).scalar() or 0


async def _recent_sessions(db: AsyncSession, limit: int) -> List[HoneypotSession]:
    rows = (
        await db.execute(select(HoneypotSession).order_by(HoneypotSession.id.desc()).limit(limit))
    ).scalars().all()
    return list(reversed(rows))


def _views(rows: List[HoneypotSession]) -> List[Dict]:
    """Session data rebuilt from rows, without the refused connections."""
    views = []
    for row in rows:
        data = rebuild_session_data(row)
        if not is_refusal({**data, "attacker_port": row.attacker_port}):
            views.append(data)
    return views


def _age(fitted_at: Optional[str]) -> Optional[timedelta]:
    if not fitted_at:
        return None
    try:
        return datetime.now(timezone.utc) - datetime.fromisoformat(fitted_at)
    except ValueError:
        return None


# -- clustering ---------------------------------------------------------------

def _cluster_vectors(views: List[Dict], names: List[str]) -> np.ndarray:
    return np.vstack([extract(view, run_rules(view), names) for view in views])


async def fit_clusters(db: AsyncSession) -> Dict:
    """Fit the cluster model on stored sessions. Raises ValueError if too few."""
    rows = await _recent_sessions(db, MAX_FIT_SESSIONS)
    names = default_features()

    def work() -> Dict:
        views = _views(rows)
        if len(views) < MIN_SESSIONS_TO_FIT:
            raise ValueError(
                f"Only {len(views)} session(s) captured; {MIN_SESSIONS_TO_FIT} are needed. "
                "Fitting on fewer would produce assignments that look like findings but are noise."
            )
        return clusterer.fit(_cluster_vectors(views, names), names)

    return await asyncio.to_thread(work)


async def backfill_clusters(db: AsyncSession, batch: int = BACKFILL_BATCH) -> int:
    """Assign every stored session with the current model. Returns how many.

    Cluster numbers mean nothing across fits, so after a refit every row is
    re-assigned, not only the ones that had no cluster.
    """
    if not clusterer.is_fitted:
        return 0
    updated = 0
    last_id = 0
    while True:
        rows = (
            await db.execute(
                select(HoneypotSession)
                .where(HoneypotSession.id > last_id)
                .order_by(HoneypotSession.id)
                .limit(batch)
            )
        ).scalars().all()
        if not rows:
            break

        def work(chunk=rows) -> List[Dict]:
            out = []
            for row in chunk:
                view = rebuild_session_data(row)
                out.append(clusterer.assign_session(view, run_rules(view)))
            return out

        for row, assignment in zip(rows, await asyncio.to_thread(work)):
            row.cluster_id = assignment.get("cluster")
            row.cluster_distance = assignment.get("distance")
            row.cluster_is_outlier = assignment.get("is_outlier")
            updated += 1
        last_id = rows[-1].id
        await db.commit()
    return updated


async def maintain_clusters(db: AsyncSession) -> Optional[Dict]:
    """Fit when enough sessions exist and none is fitted; refit when due.

    Returns the fit's record when one was made, else None.
    """
    count = await session_count(db)
    if count < MIN_SESSIONS_TO_FIT:
        return None
    clusterer.preload()
    if clusterer.is_fitted:
        age = _age(clusterer.metadata.get("fitted_at"))
        due = age is None or age >= timedelta(hours=get_analysis_settings().CLUSTER_REFIT_HOURS)
        if not due or clusterer.metadata.get("n") == min(count, MAX_FIT_SESSIONS):
            return None
    try:
        record = await fit_clusters(db)
    except ValueError as exc:
        logger.info("Cluster model not fitted: %s", exc)
        return None
    record["backfilled"] = await backfill_clusters(db)
    logger.info(
        "Cluster model fitted: k=%s, silhouette %s over %s sessions; %s rows re-assigned",
        record["k"], record["silhouette"], record["n"], record["backfilled"],
    )
    return record


# -- anomaly detector ---------------------------------------------------------

async def fit_anomaly(db: AsyncSession, contamination: Optional[float] = None,
                      min_sessions: Optional[int] = None) -> Dict:
    """Fit the anomaly detector on stored sessions. Raises ValueError if too few."""
    rows = await _recent_sessions(db, MAX_FIT_SESSIONS)

    def work() -> Dict:
        features = [features_from_session(view) for view in _views(rows)]
        return anomaly_detector.fit(features, contamination=contamination, min_sessions=min_sessions)

    return await asyncio.to_thread(work)


async def backfill_anomaly(db: AsyncSession, batch: int = BACKFILL_BATCH) -> int:
    """Re-score every stored session with the fitted detector.

    Only with a detector fitted on real sessions: re-scoring with the
    bootstrap would overwrite one meaningless number with another. Each
    row's ``signals.anomaly`` then says the score is calibrated.
    """
    anomaly_detector.preload()
    if not anomaly_detector.calibrated:
        return 0
    updated = 0
    last_id = 0
    while True:
        rows = (
            await db.execute(
                select(HoneypotSession)
                .where(HoneypotSession.id > last_id)
                .order_by(HoneypotSession.id)
                .limit(batch)
            )
        ).scalars().all()
        if not rows:
            break

        def work(chunk=rows) -> List[Dict]:
            return [anomaly_detector.detect(features_from_session(rebuild_session_data(row))) for row in chunk]

        for row, result in zip(rows, await asyncio.to_thread(work)):
            row.anomaly_score = result["anomaly_score"]
            row.is_anomalous = result["is_anomalous"]
            signals = dict(row.signals) if isinstance(row.signals, dict) else {}
            signals["anomaly"] = {
                "calibrated": True,
                "model_source": result["model_source"],
                "fitted_at": result.get("fitted_at"),
                "fitted_on": result.get("fitted_on"),
            }
            row.signals = signals
            updated += 1
        last_id = rows[-1].id
        await db.commit()
    return updated


async def mark_anomaly_uncalibrated(db: AsyncSession, batch: int = BACKFILL_BATCH) -> int:
    """Clear ``is_anomalous`` on rows flagged by the synthetic bootstrap.

    Rows stored before the detector was made honest carry flags that mean
    nothing (70 of 109 on the first deployment). The score is left as it is;
    the flag is cleared and the row says the score is uncalibrated.
    """
    anomaly_detector.preload()
    if anomaly_detector.calibrated:
        return 0
    updated = 0
    while True:
        # Only the flagged rows: after the first pass there are none, and
        # this runs every hour until a real fit exists.
        rows = (
            await db.execute(
                select(HoneypotSession)
                .where(HoneypotSession.is_anomalous.is_(True))
                .order_by(HoneypotSession.id)
                .limit(batch)
            )
        ).scalars().all()
        if not rows:
            break
        for row in rows:
            signals = dict(row.signals) if isinstance(row.signals, dict) else {}
            row.is_anomalous = False
            signals["anomaly"] = {"calibrated": False, "model_source": "synthetic"}
            row.signals = signals
            updated += 1
        await db.commit()
    return updated


async def maintain_anomaly(db: AsyncSession) -> Optional[Dict]:
    """Fit the detector once enough sessions exist; refit when due."""
    settings = get_analysis_settings()
    count = await session_count(db)
    if count < settings.ANOMALY_MIN_SESSIONS:
        return None
    anomaly_detector.preload()
    if anomaly_detector.metadata.get("source") == SOURCE_SESSIONS:
        age = _age(anomaly_detector.metadata.get("fitted_at"))
        due = age is None or age >= timedelta(hours=settings.ANOMALY_REFIT_HOURS)
        if not due or anomaly_detector.metadata.get("n") == min(count, MAX_FIT_SESSIONS):
            return None
    try:
        record = await fit_anomaly(db)
    except ValueError as exc:
        logger.info("Anomaly detector not fitted: %s", exc)
        return None
    record["backfilled"] = await backfill_anomaly(db)
    logger.info(
        "Anomaly detector fitted on %s sessions (contamination %s); %s rows re-scored",
        record["n"], record["contamination"], record["backfilled"],
    )
    return record
