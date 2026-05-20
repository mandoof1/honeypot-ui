from __future__ import annotations
import os
import pickle
import numpy as np
from typing import Dict, List, Optional
from sklearn.ensemble import IsolationForest
from app.core.config import get_settings

settings = get_settings()

ANOMALY_FEATURES = [
    "session_duration", "command_count", "unique_commands",
    "failed_login_attempts", "file_upload_count",
    "connection_rate", "payload_size_avg", "payload_entropy",
    "port_scan_count", "error_rate", "off_hours",
]


class AnomalyDetector:
    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self._loaded = False

    def _ensure_loaded(self):
        if self._loaded:
            return
        model_path = settings.MODEL_PATH_IF
        if os.path.exists(model_path):
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
        else:
            self._train_default_model()
        self._loaded = True

    def _train_default_model(self):
        np.random.seed(42)
        n_normal = 5000
        n_features = len(ANOMALY_FEATURES)

        X_normal = np.random.normal(0.3, 0.2, (n_normal, n_features)).clip(0, 1)
        X_anomalous = np.random.normal(0.7, 0.25, (n_normal // 5, n_features)).clip(0, 1)
        X_anomalous[:, 3] = np.random.normal(0.9, 0.1, n_normal // 5).clip(0, 1)
        X_anomalous[:, 5] = np.random.normal(0.85, 0.1, n_normal // 5).clip(0, 1)

        X = np.vstack([X_normal, X_anomalous])

        self.model = IsolationForest(
            n_estimators=50,
            contamination=0.1,
            max_samples="auto",
            random_state=42,
            n_jobs=1,
        )
        self.model.fit(X)

        os.makedirs(os.path.dirname(settings.MODEL_PATH_IF) or ".", exist_ok=True)
        with open(settings.MODEL_PATH_IF, "wb") as f:
            pickle.dump(self.model, f)

    def detect(self, session_features: Dict) -> Dict:
        self._ensure_loaded()
        feature_vector = np.array([
            session_features.get(feat, 0.0)
            for feat in ANOMALY_FEATURES
        ]).reshape(1, -1)

        prediction = self.model.predict(feature_vector)[0]
        score = self.model.score_samples(feature_vector)[0]

        anomaly_score = float(-score)
        normalized_score = min(max(anomaly_score / 1.5, 0), 1)

        return {
            "is_anomalous": prediction == -1,
            "anomaly_score": round(normalized_score, 4),
            "raw_score": round(float(score), 4),
            "threshold": 0.6,
        }

    def detect_batch(self, sessions_features: List[Dict]) -> List[Dict]:
        self._ensure_loaded()
        if not sessions_features:
            return []

        feature_matrix = np.array([
            [sf.get(feat, 0.0) for feat in ANOMALY_FEATURES]
            for sf in sessions_features
        ])

        predictions = self.model.predict(feature_matrix)
        scores = self.model.score_samples(feature_matrix)

        results = []
        for pred, score in zip(predictions, scores):
            anomaly_score = float(-score)
            normalized_score = min(max(anomaly_score / 1.5, 0), 1)
            results.append({
                "is_anomalous": pred == -1,
                "anomaly_score": round(normalized_score, 4),
                "raw_score": round(float(score), 4),
            })
        return results


anomaly_detector = AnomalyDetector()
