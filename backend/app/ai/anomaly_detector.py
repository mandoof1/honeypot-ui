"""Isolation Forest over session behaviour, and how far to trust it.

The detector that shipped was fitted only on invented data: 5,000 rows drawn
from N(0.3, 0.2) and 1,000 from N(0.7, 0.25). Three of its eleven inputs were
read from keys the engine never sends, so they were always zero, and a fourth
was the hour of the *server's* clock at ingest. On the deployment's stored
sessions it scored benign sessions higher than exploitation and flagged 70 of
109. It was also reloaded from disk labelled "pretrained".

What it is now:

* Until it has been fitted on the deployment's own sessions
  (``ml.fit_anomaly``, or the scheduled fit once enough exist) it is
  **uncalibrated**. A score is still produced from the synthetic bootstrap,
  so the column is not empty, but ``is_anomalous`` is never set from it and
  the pipeline does not let it reach severity or alerts.
* Every input is computed from what the engine does send.
* A fitted model carries when it was fitted, on how many sessions, and with
  what contamination, and is labelled by what it was fitted on.
"""

from __future__ import annotations

import logging
import math
import os
import threading
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional

import numpy as np
from sklearn.ensemble import IsolationForest

from app.ai.config import get_analysis_settings
from app.ai.provenance import dump_pickle, file_stamp, git_revision, load_pickle
from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

#: Inputs, each scaled to 0..1 (see ``features_from_session``).
#:
#: ``command_rate``, ``probe_count`` and ``error_rate`` replace
#: ``connection_rate``, ``port_scan_count`` and an ``error_rate`` that were
#: read from payload keys nothing sends. ``keystrokes_per_command`` replaces
#: ``off_hours``: the attacker's local time is not known, and the server's
#: clock at ingest says nothing about the session.
ANOMALY_FEATURES = [
    "session_duration", "command_count", "unique_commands",
    "failed_login_attempts", "file_upload_count",
    "command_rate", "payload_size_avg", "payload_entropy",
    "probe_count", "error_rate", "keystrokes_per_command",
]

#: What a model fitted on stored sessions records as its source.
SOURCE_SESSIONS = "sessions"
SOURCE_SYNTHETIC = "synthetic"

_ENTROPY_SAMPLE_CHARS = 8192


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def features_from_session(session_data: Dict) -> Dict[str, float]:
    """The detector's inputs for one session, from the ingest payload.

    One definition, used at ingest and when fitting on stored sessions, so a
    position in the vector means the same thing in both.
    """
    session_data = session_data or {}
    commands = [str(c) for c in (session_data.get("commands") or [])]
    count = len(commands)
    duration = max(float(session_data.get("duration_seconds") or 0.0), 0.0)
    text = "\n".join(commands)[:_ENTROPY_SAMPLE_CHARS]

    transcript = [e for e in (session_data.get("transcript") or []) if isinstance(e, dict)]
    failed_commands = sum(1 for e in transcript if e.get("exit_code") not in (0, None))
    probes = sum(
        1 for p in (session_data.get("packets") or [])
        if isinstance(p, dict) and p.get("type") == "attack_detected"
    )
    keystrokes = float(session_data.get("keystroke_count") or 0)

    return {
        "session_duration": min(duration / 600, 1),
        "command_count": min(count / 50, 1),
        "unique_commands": min(len(set(commands)) / 30, 1),
        "failed_login_attempts": min(float(session_data.get("failed_logins") or 0) / 20, 1),
        "file_upload_count": min(len(session_data.get("uploads") or []) / 5, 1),
        # Commands a minute, against one a second.
        "command_rate": min(count / max(duration / 60, 1 / 60) / 60, 1) if count else 0.0,
        "payload_size_avg": min(sum(len(c) for c in commands) / count / 200, 1) if count else 0.0,
        # Shannon entropy of the command text, in bits per character out of 8.
        "payload_entropy": min(_entropy(text) / 8, 1),
        "probe_count": min(probes / 20, 1),
        "error_rate": failed_commands / len(transcript) if transcript else 0.0,
        "keystrokes_per_command": min(keystrokes / count / 40, 1) if count else 0.0,
    }


def _vector(features: Dict) -> List[float]:
    return [float(features.get(name, 0.0) or 0.0) for name in ANOMALY_FEATURES]


class AnomalyDetector:
    def __init__(self, path: Optional[str] = None):
        self._explicit_path = path
        self.model: Optional[IsolationForest] = None
        self.model_source = "unloaded"
        self.metadata: Dict = {}
        self._loaded = False
        self._stamp = None
        self._lock = threading.Lock()

    @property
    def path(self) -> str:
        return self._explicit_path or settings.MODEL_PATH_IF

    @property
    def calibrated(self) -> bool:
        """Whether the model was fitted on real sessions."""
        return self.model_source == SOURCE_SESSIONS

    def _ensure_loaded(self):
        """Load the fitted model, or reload it when its file changed.

        The file is fitted by the backend process and read by the ingest
        workers; a worker that latched the first thing it loaded would keep
        scoring with the bootstrap after a real model existed.
        """
        stamp = file_stamp(self.path)
        if self._loaded and stamp == self._stamp:
            return
        with self._lock:
            if self._loaded and stamp == self._stamp:
                return
            self._stamp = stamp
            if stamp is not None and self._load_file():
                self._loaded = True
                return
            self._train_default_model()
            self._loaded = True

    def _load_file(self) -> bool:
        try:
            # pickle executes arbitrary code on load, so only ever read the
            # operator-controlled path from configuration, never user input.
            data = load_pickle(self.path)
        except Exception as exc:
            logger.warning("Anomaly model at %s is unreadable (%s); using the bootstrap", self.path, exc)
            return False
        if not isinstance(data, dict):
            # Older versions pickled the bare bootstrap model here and then
            # reloaded it labelled "pretrained". The only thing that ever
            # wrote that file was the synthetic fit.
            logger.info("Anomaly model at %s is the old synthetic bootstrap; ignoring it", self.path)
            return False
        if data.get("features") != ANOMALY_FEATURES:
            logger.warning(
                "Anomaly model at %s was fitted on a different feature set; "
                "using the bootstrap. Refit with ml.fit_anomaly.", self.path,
            )
            return False
        self.model = data["model"]
        self.model_source = str(data.get("source") or SOURCE_SYNTHETIC)
        self.metadata = {
            key: data.get(key) for key in ("fitted_at", "n", "contamination", "source", "git_revision")
        }
        return True

    def _train_default_model(self):
        """Fit the bootstrap detector on synthetic feature vectors.

        Not trained on real captures, and not written to disk: a file there
        is how the synthetic model came to be reloaded under another name.
        Results carry ``model_source: synthetic`` and ``calibrated: false``.
        """
        rng = np.random.default_rng(42)
        n_normal = 5000
        n_features = len(ANOMALY_FEATURES)

        X_normal = rng.normal(0.3, 0.2, (n_normal, n_features)).clip(0, 1)
        X_anomalous = rng.normal(0.7, 0.25, (n_normal // 5, n_features)).clip(0, 1)

        self.model = IsolationForest(
            n_estimators=50,
            contamination=0.1,
            max_samples="auto",
            random_state=42,
            n_jobs=1,
        )
        self.model.fit(np.vstack([X_normal, X_anomalous]))
        self.model_source = SOURCE_SYNTHETIC
        self.metadata = {"source": SOURCE_SYNTHETIC, "fitted_at": None, "n": None, "contamination": 0.1}

    def preload(self) -> None:
        self._ensure_loaded()

    def fit(self, feature_rows: List[Dict], contamination: Optional[float] = None,
            min_sessions: Optional[int] = None) -> Dict:
        """Fit on real sessions' features and persist the model with its record."""
        analysis = get_analysis_settings()
        minimum = analysis.ANOMALY_MIN_SESSIONS if min_sessions is None else min_sessions
        if len(feature_rows) < minimum:
            raise ValueError(
                f"Need at least {minimum} sessions to fit the anomaly detector; got "
                f"{len(feature_rows)}. A detector fitted on fewer calls ordinary variation unusual."
            )
        contamination = analysis.ANOMALY_CONTAMINATION if contamination is None else contamination
        matrix = np.array([_vector(row) for row in feature_rows], dtype=float)

        model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            max_samples="auto",
            random_state=42,
            n_jobs=1,
        )
        model.fit(matrix)
        flagged = int((model.predict(matrix) == -1).sum())
        record = {
            "source": SOURCE_SESSIONS,
            "fitted_at": datetime.now(timezone.utc).isoformat(),
            "n": int(len(matrix)),
            # An assumption, not a measurement: the share of the fitted
            # sessions the model is told to call anomalous.
            "contamination": float(contamination),
            "flagged_in_fit": flagged,
            "features": list(ANOMALY_FEATURES),
            "git_revision": git_revision(),
        }
        dump_pickle(self.path, {"model": model, **record})
        with self._lock:
            self.model, self.model_source = model, SOURCE_SESSIONS
            self.metadata = {k: record[k] for k in ("fitted_at", "n", "contamination", "source", "git_revision")}
            self._stamp, self._loaded = file_stamp(self.path), True
        return record

    def detect(self, session_features: Dict) -> Dict:
        self._ensure_loaded()
        feature_vector = np.array(_vector(session_features)).reshape(1, -1)

        # predict() is score_samples() - offset_ thresholded at zero; one
        # pass over the trees instead of two.
        score = self.model.score_samples(feature_vector)[0]
        beyond_boundary = bool(score - self.model.offset_ < 0)

        # score_samples returns the negated average path-length score, in
        # (-1, 0): closer to -1 is more isolated. Negating it gives a 0..1
        # anomaly score directly.
        normalized_score = min(max(float(-score), 0.0), 1.0)
        # The model's own decision boundary, on the same scale, so a threshold
        # an operator sets can be compared with where "anomalous" begins.
        boundary = min(max(float(-self.model.offset_), 0.0), 1.0)

        return {
            # Only a detector fitted on real sessions may call one anomalous.
            "is_anomalous": beyond_boundary and self.calibrated,
            "anomaly_score": round(normalized_score, 4),
            "raw_score": round(float(score), 4),
            "threshold": round(boundary, 4),
            "model_source": self.model_source,
            "calibrated": self.calibrated,
            "fitted_at": self.metadata.get("fitted_at"),
            "fitted_on": self.metadata.get("n"),
        }

    def detect_batch(self, sessions_features: List[Dict]) -> List[Dict]:
        return [self.detect(features) for features in sessions_features]


anomaly_detector = AnomalyDetector()
