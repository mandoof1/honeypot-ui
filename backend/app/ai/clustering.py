"""Behavioural clustering of attacker sessions.

Finding 14: section VI.B states the logic layer "performs behavioural
clustering for attacker profiling". It did not. ``attacker_profiler.py``
defines a dict named ``CLUSTER_RULES``, but the contents are hand-tuned
weighted thresholds — a scorecard. There was no clustering algorithm of any
kind: no k-means, no DBSCAN, nothing unsupervised.

The scorecard is genuinely useful and is kept: it is interpretable, it works
on the very first session, and an analyst can read why a verdict was reached.
Clustering cannot do either of those things. What clustering adds is the thing
thresholds cannot — grouping sessions that *behave alike* without anyone
deciding in advance what alike means, which is how campaigns reusing one
toolkit become visible across many sessions.

So the two run together and are reported separately, rather than one being
dressed up as the other.

MiniBatchKMeans over DBSCAN: it accepts new points without refitting, which
matters when sessions arrive continuously, and it does not need an epsilon
tuned per deployment.
"""

from __future__ import annotations

import logging
import os
import pickle
from typing import Dict, List, Optional

import numpy as np
from sklearn.cluster import MiniBatchKMeans
from sklearn.preprocessing import StandardScaler

from app.core.config import get_settings

logger = logging.getLogger(__name__)

#: Behavioural axes. Deliberately not the flow features the Random Forest
#: uses — clustering here is about *how the attacker acted*, not how the
#: packets looked, so the two models see genuinely different views.
FEATURES = [
    "duration_seconds",
    "command_count",
    "unique_command_ratio",
    "command_rate_per_min",
    "tool_count",
    "intent_count",
    "complexity_score",
    "failed_logins",
    "upload_count",
    "obfuscation_depth",
]

#: Enough groups to separate the broad behaviours a honeypot sees (a scanner
#: that connects and leaves, a dictionary attack, a hands-on session, a
#: dropper) without splitting into clusters too small to mean anything.
N_CLUSTERS = 6

#: Sessions required before a fit is meaningful. Below this the assignment
#: would be noise presented as a finding.
MIN_SESSIONS_TO_FIT = 50


def extract(session_data: Dict, nlp_result: Dict) -> np.ndarray:
    """Behavioural vector for one session."""
    commands: List[str] = session_data.get("commands") or []
    duration = float(session_data.get("duration_seconds") or 0.0)
    count = len(commands)
    unique = len(set(commands))

    deobf = nlp_result.get("deobfuscation") or {}

    return np.array([
        duration,
        count,
        (unique / count) if count else 0.0,
        count / max(duration / 60.0, 0.001),
        len(nlp_result.get("tool_names") or []),
        len(nlp_result.get("detected_intents") or []),
        float(nlp_result.get("complexity_score") or 0.0),
        # The ingest payload's own names. This read failed_login_attempts and
        # uploaded_files, which nothing sends, so both were always zero.
        float(session_data.get("failed_logins") or 0),
        len(session_data.get("uploads") or []),
        float(deobf.get("max_depth") or 0),
    ], dtype=float)


class BehaviouralClusterer:
    """Groups sessions by behaviour. Reports honestly when it cannot."""

    def __init__(self) -> None:
        self._model: Optional[MiniBatchKMeans] = None
        self._scaler: Optional[StandardScaler] = None
        self._loaded = False

    @property
    def _path(self) -> str:
        settings = get_settings()
        return os.path.join(
            os.path.dirname(settings.MODEL_PATH_RF) or ".", "cluster_model.pkl"
        )

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if os.path.exists(self._path):
            try:
                with open(self._path, "rb") as fh:
                    data = pickle.load(fh)
                self._model, self._scaler = data["model"], data["scaler"]
                logger.info("Loaded behavioural cluster model")
            except Exception as exc:
                logger.warning("Cluster model unreadable (%s); clustering disabled", exc)

    @property
    def is_fitted(self) -> bool:
        self._ensure_loaded()
        return self._model is not None and self._scaler is not None

    def fit(self, vectors: np.ndarray) -> Dict:
        """Fit on a corpus of behavioural vectors and persist the result."""
        if len(vectors) < MIN_SESSIONS_TO_FIT:
            raise ValueError(
                f"Need at least {MIN_SESSIONS_TO_FIT} sessions to cluster; "
                f"got {len(vectors)}. Fitting on fewer would produce "
                f"assignments that look like findings but are noise."
            )

        scaler = StandardScaler().fit(vectors)
        scaled = scaler.transform(vectors)

        n_clusters = min(N_CLUSTERS, len(vectors) // 10) or 2
        model = MiniBatchKMeans(
            n_clusters=n_clusters, random_state=42, n_init=10, batch_size=256
        ).fit(scaled)

        self._model, self._scaler, self._loaded = model, scaler, True
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "wb") as fh:
            pickle.dump({"model": model, "scaler": scaler}, fh)

        labels, counts = np.unique(model.labels_, return_counts=True)
        return {
            "n_clusters": int(n_clusters),
            "n_sessions": int(len(vectors)),
            "sizes": {int(k): int(v) for k, v in zip(labels, counts)},
            "inertia": float(model.inertia_),
        }

    def assign(self, vector: np.ndarray) -> Dict:
        """Place one session in a cluster, with its distance to the centroid.

        Returns ``fitted: False`` rather than a made-up cluster when no model
        exists — an unfitted clusterer reporting cluster 0 for everything is
        exactly the kind of confident nonsense this project already has too
        much of.
        """
        self._ensure_loaded()
        if not self.is_fitted:
            return {"fitted": False, "cluster": None, "distance": None}

        scaled = self._scaler.transform(vector.reshape(1, -1))
        cluster = int(self._model.predict(scaled)[0])
        distance = float(
            np.linalg.norm(scaled[0] - self._model.cluster_centers_[cluster])
        )
        return {
            "fitted": True,
            "cluster": cluster,
            "distance": round(distance, 4),
            # A point far from every centroid belongs to no established
            # behaviour — which is itself worth surfacing.
            "is_outlier": distance > 3.0,
        }


clusterer = BehaviouralClusterer()
