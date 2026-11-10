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

The model is fitted by the backend process (on a schedule, see
services/scheduler.py) and read by the ingest workers, which notice a new
file by its modification time. The fit records how good it is: the number of
clusters chosen, the silhouette score, and how many sessions it saw.
"""

from __future__ import annotations

import hashlib
import logging
import os
import pickle
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence

import numpy as np
from sklearn.cluster import MiniBatchKMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

from app.ai.config import get_analysis_settings
from app.ai.provenance import dump_pickle, file_stamp, git_revision
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

#: Optional: the client fingerprint as a categorical, one column per bucket.
#: A hash has no order, so it cannot be one numeric column in a distance.
FINGERPRINT_BUCKETS = 8
FINGERPRINT_FEATURES = [f"fingerprint_bucket_{i}" for i in range(FINGERPRINT_BUCKETS)]

#: Most groups considered. Enough to separate the broad behaviours a honeypot
#: sees (a scanner that connects and leaves, a dictionary attack, a hands-on
#: session, a dropper) without splitting into clusters too small to mean
#: anything. The fit picks the number in 2..N_CLUSTERS with the best
#: silhouette.
N_CLUSTERS = 6

#: Sessions required before a fit is meaningful. Below this the assignment
#: would be noise presented as a finding.
MIN_SESSIONS_TO_FIT = 50

_SILHOUETTE_SAMPLE = 2000


def _fingerprint_bucket(session_data: Dict) -> Optional[int]:
    fingerprints = session_data.get("fingerprints")
    if not isinstance(fingerprints, dict):
        return None
    value = next(
        (str(fingerprints[k]) for k in ("hassh", "ja4", "ja3", "ssh_client_version") if fingerprints.get(k)),
        None,
    )
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8", "replace")).digest()[0] % FINGERPRINT_BUCKETS


def extract(session_data: Dict, nlp_result: Dict, feature_names: Optional[Sequence[str]] = None) -> np.ndarray:
    """Behavioural vector for one session.

    The one place the vector is built, for the fit and for assignment at
    ingest. ``nlp_result`` must come from ``session_view.run_rules`` on the
    same session data in both, or the two see different sessions: the fit
    used to re-run the rules without the protocol, which changed the tool
    and intent counts of every web session.
    """
    commands: List[str] = session_data.get("commands") or []
    duration = float(session_data.get("duration_seconds") or 0.0)
    count = len(commands)
    unique = len(set(commands))

    deobf = nlp_result.get("deobfuscation") or {}

    values = {
        "duration_seconds": duration,
        "command_count": count,
        "unique_command_ratio": (unique / count) if count else 0.0,
        "command_rate_per_min": count / max(duration / 60.0, 0.001),
        "tool_count": len(nlp_result.get("tool_names") or []),
        "intent_count": len(nlp_result.get("detected_intents") or []),
        "complexity_score": float(nlp_result.get("complexity_score") or 0.0),
        # The ingest payload's own names. This read failed_login_attempts and
        # uploaded_files, which nothing sends, so both were always zero.
        "failed_logins": float(session_data.get("failed_logins") or 0),
        "upload_count": len(session_data.get("uploads") or []),
        "obfuscation_depth": float(deobf.get("max_depth") or 0),
    }
    names = list(feature_names) if feature_names else default_features()
    if any(name in FINGERPRINT_FEATURES for name in names):
        bucket = _fingerprint_bucket(session_data)
        for index, name in enumerate(FINGERPRINT_FEATURES):
            values[name] = 1.0 if bucket == index else 0.0
    return np.array([float(values.get(name, 0.0)) for name in names], dtype=float)


def default_features() -> List[str]:
    """The feature list a new fit uses."""
    if get_analysis_settings().CLUSTER_USE_FINGERPRINTS:
        return FEATURES + FINGERPRINT_FEATURES
    return list(FEATURES)


class BehaviouralClusterer:
    """Groups sessions by behaviour. Reports honestly when it cannot."""

    def __init__(self, path: Optional[str] = None) -> None:
        self._explicit_path = path
        self._model: Optional[MiniBatchKMeans] = None
        self._scaler: Optional[StandardScaler] = None
        self.metadata: Dict = {}
        self._loaded = False
        self._stamp = None
        self._lock = threading.Lock()

    @property
    def _path(self) -> str:
        if self._explicit_path:
            return self._explicit_path
        settings = get_settings()
        return os.path.join(
            os.path.dirname(settings.MODEL_PATH_RF) or ".", "cluster_model.pkl"
        )

    @property
    def feature_names(self) -> List[str]:
        """The features the loaded model was fitted on."""
        return list(self.metadata.get("features") or FEATURES)

    def _ensure_loaded(self) -> None:
        """Load the model, or load it again when its file has changed.

        Workers used to latch ``_loaded`` on their first call. One started
        before the first fit therefore never assigned a cluster, and one
        started before a refit kept using cluster numbers that no longer
        meant what the stored rows said.
        """
        stamp = file_stamp(self._path)
        if self._loaded and stamp == self._stamp:
            return
        with self._lock:
            if self._loaded and stamp == self._stamp:
                return
            self._loaded, self._stamp = True, stamp
            if stamp is None:
                self._model = self._scaler = None
                self.metadata = {}
                return
            try:
                with open(self._path, "rb") as fh:
                    data = pickle.load(fh)
                self._model, self._scaler = data["model"], data["scaler"]
                self.metadata = dict(data.get("metadata") or {})
                logger.info("Loaded behavioural cluster model (%s)", self.metadata.get("fitted_at") or "no record")
            except Exception as exc:
                self._model = self._scaler = None
                self.metadata = {}
                logger.warning("Cluster model unreadable (%s); clustering disabled", exc)

    def preload(self) -> None:
        self._ensure_loaded()

    @property
    def is_fitted(self) -> bool:
        self._ensure_loaded()
        return self._model is not None and self._scaler is not None

    def fit(self, vectors: np.ndarray, feature_names: Optional[Sequence[str]] = None) -> Dict:
        """Fit on a corpus of behavioural vectors and persist the result."""
        if len(vectors) < MIN_SESSIONS_TO_FIT:
            raise ValueError(
                f"Need at least {MIN_SESSIONS_TO_FIT} sessions to cluster; "
                f"got {len(vectors)}. Fitting on fewer would produce "
                f"assignments that look like findings but are noise."
            )

        scaler = StandardScaler().fit(vectors)
        scaled = scaler.transform(vectors)

        # The number of clusters with the best silhouette, so the fit says
        # how well separated its groups are instead of assuming six.
        largest = max(2, min(N_CLUSTERS, len(vectors) // 10))
        best = None
        for k in range(2, largest + 1):
            candidate = MiniBatchKMeans(n_clusters=k, random_state=42, n_init=10, batch_size=256).fit(scaled)
            if len(set(candidate.labels_)) < 2:
                continue
            quality = float(silhouette_score(
                scaled, candidate.labels_,
                sample_size=min(len(scaled), _SILHOUETTE_SAMPLE), random_state=42,
            ))
            if best is None or quality > best[1]:
                best = (candidate, quality)
        if best is None:
            # Every session identical: one group, and nothing to separate.
            raise ValueError("The sessions do not separate into more than one cluster.")
        model, quality = best

        labels, counts = np.unique(model.labels_, return_counts=True)
        metadata = {
            "fitted_at": datetime.now(timezone.utc).isoformat(),
            "k": int(model.n_clusters),
            "silhouette": round(quality, 4),
            "n": int(len(vectors)),
            "sizes": {int(k): int(v) for k, v in zip(labels, counts)},
            "inertia": float(model.inertia_),
            "features": list(feature_names) if feature_names else list(FEATURES),
            "git_revision": git_revision(),
        }
        dump_pickle(self._path, {"model": model, "scaler": scaler, "metadata": metadata})
        with self._lock:
            self._model, self._scaler, self.metadata = model, scaler, metadata
            self._loaded, self._stamp = True, file_stamp(self._path)

        return {
            **metadata,
            # The names the first version of this returned.
            "n_clusters": metadata["k"],
            "n_sessions": metadata["n"],
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

    def assign_session(self, session_data: Dict, nlp_result: Dict) -> Dict:
        """Assign from session data, with the features the model was fitted on."""
        self._ensure_loaded()
        if not self.is_fitted:
            return {"fitted": False, "cluster": None, "distance": None}
        return self.assign(extract(session_data, nlp_result, self.feature_names))


clusterer = BehaviouralClusterer()
