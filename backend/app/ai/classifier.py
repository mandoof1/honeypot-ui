from __future__ import annotations
import logging
import os
import pickle
import numpy as np
from typing import Dict, Optional
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

ATTACK_LABELS = ["benign", "reconnaissance", "exploitation", "exfiltration"]


#: The service each emulator stands in for. CIC-IDS2017's Destination Port is
#: the service a flow was aimed at; the engine listens on high ports behind a
#: redirect, so the protocol it emulates is the meaningful equivalent.
SERVICE_PORTS = {"ssh": 22, "ftp": 21, "http": 80, "https": 443, "telnet": 23}


class FeatureExtractor:
    """One definition of the model's input, used by training and inference.

    The previous 36-feature vector copied CICFlowMeter's columns, most of which
    (TCP flag counts, header lengths, bulk rates) the engine cannot observe, and
    the engine reported nothing it could: in production nearly every position
    was zero. These twelve are the features both sides measure with the same
    meaning — the engine at its sockets (honeypot/capture/flow.py), the
    dataset in CICFlowMeter's columns (ml/cicids.py) — and ``derive`` is the
    single place the derived ones are computed, for both.

    Values are left in their natural units (seconds, bytes). A Random Forest
    is insensitive to scale, and the old clip-to-[0, 1] normalisation threw
    away everything above each cap: every CIC-IDS2017 flow longer than 600
    microseconds had the same duration.
    """

    FEATURES = [
        "destination_port",
        "flow_duration",           # seconds
        "fwd_data_packets",        # client segments carrying data
        "fwd_bytes",
        "bwd_bytes",
        "fwd_packet_length_max",
        "bwd_packet_length_max",
        "flow_bytes_per_second",
        "bwd_fwd_byte_ratio",
        "fwd_iat_mean",            # seconds
        "fwd_iat_max",             # seconds
        "flow_iat_max",            # seconds
    ]

    @staticmethod
    def derive(port, duration, fwd_packets, fwd_bytes, bwd_bytes,
               fwd_max, bwd_max, fwd_iat_mean, fwd_iat_max, flow_iat_max):
        """Assemble the feature columns. Accepts scalars or numpy arrays."""
        duration = np.maximum(duration, 0.0)
        return [
            port, duration, fwd_packets, fwd_bytes, bwd_bytes, fwd_max, bwd_max,
            (fwd_bytes + bwd_bytes) / np.maximum(duration, 1e-3),
            bwd_bytes / np.maximum(fwd_bytes, 1),
            fwd_iat_mean, fwd_iat_max, flow_iat_max,
        ]

    @classmethod
    def extract_from_flow(cls, flow: Optional[Dict], protocol: str) -> np.ndarray:
        """Build the vector from the engine's flow summary.

        A session ingested without one (an engine predating flow telemetry)
        gets zeros for everything but the port: the verdict then rests on the
        service alone, which is all that is known about it.
        """
        f = flow or {}

        def num(key: str) -> float:
            try:
                return max(float(f.get(key) or 0.0), 0.0)
            except (TypeError, ValueError):
                return 0.0

        row = cls.derive(
            float(SERVICE_PORTS.get((protocol or "").lower(), 0)),
            num("duration"), num("fwd_packets"), num("fwd_bytes"), num("bwd_bytes"),
            num("fwd_max"), num("bwd_max"),
            num("fwd_iat_mean"), num("fwd_iat_max"), num("flow_iat_max"),
        )
        return np.array([float(v) for v in row]).reshape(1, -1)


class AttackClassifier:
    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.label_encoder: Optional[LabelEncoder] = None
        self.feature_extractor = FeatureExtractor()
        self.model_source = "unloaded"
        self._loaded = False

    def _ensure_loaded(self):
        if self._loaded:
            return
        model_path = settings.MODEL_PATH_RF
        if os.path.exists(model_path):
            # pickle executes arbitrary code on load, so only ever read the
            # operator-controlled path from configuration, never user input.
            with open(model_path, "rb") as f:
                data = pickle.load(f)
            if data.get("features") == FeatureExtractor.FEATURES:
                self.model = data["model"]
                self.label_encoder = data["label_encoder"]
                self.model_source = data.get("source", "pretrained")
                # One sample at a time: a thread pool per prediction costs
                # more than the trees themselves.
                self.model.n_jobs = 1
                self._loaded = True
                return
            # An artefact built for another feature layout would accept the
            # vector only if the lengths happened to match, and then answer
            # about the wrong features.
            logger.warning(
                "Model at %s was built for a different feature set; "
                "falling back to the synthetic bootstrap. Retrain with ml.train.",
                model_path,
            )
        self._train_default_model()
        self.model_source = "synthetic"
        self._loaded = True

    def _train_default_model(self):
        """Fit a bootstrap model on synthetic traffic.

        This exists so a fresh deployment has *something* to classify with;
        it is not trained on real capture data and its confidence scores are
        not calibrated. Responses are tagged ``model_source: synthetic``
        so the UI never presents them as ground truth. Replace by training on
        a labelled corpus (e.g. CIC-IDS2017) and dropping the artefact at
        MODEL_PATH_RF.
        """
        rng = np.random.default_rng(42)
        n = 2000

        def flows(count, port, duration, fwd, size, ratio, gap):
            durations = rng.lognormal(np.log(duration), 1.0, count)
            packets = rng.poisson(fwd, count) + 1
            fwd_bytes = packets * rng.lognormal(np.log(size), 0.6, count)
            bwd_bytes = fwd_bytes * rng.lognormal(np.log(ratio), 0.7, count)
            return np.column_stack(FeatureExtractor.derive(
                np.full(count, float(port)) if port else rng.choice([22.0, 21.0, 80.0, 443.0], count),
                durations, packets, fwd_bytes, bwd_bytes,
                fwd_bytes / packets * 1.5, bwd_bytes / packets * 1.5,
                durations / packets, durations / packets * 2, gap * durations,
            ))

        X = np.vstack([
            flows(n, None, 30.0, 20, 300, 3.0, 0.5),            # benign
            flows(n // 2, None, 0.05, 1, 40, 0.5, 0.9),         # reconnaissance
            flows(n // 2, 22, 4.0, 12, 120, 1.2, 0.3),          # exploitation
            flows(n // 2, 443, 120.0, 400, 900, 0.1, 0.2),      # exfiltration
        ])
        y = (["benign"] * n + ["reconnaissance"] * (n // 2)
             + ["exploitation"] * (n // 2) + ["exfiltration"] * (n // 2))

        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)

        self.model = RandomForestClassifier(
            n_estimators=50,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=1,
        )
        self.model.fit(X, y_encoded)

        os.makedirs(os.path.dirname(settings.MODEL_PATH_RF) or ".", exist_ok=True)
        with open(settings.MODEL_PATH_RF, "wb") as f:
            pickle.dump(
                {
                    "model": self.model,
                    "label_encoder": self.label_encoder,
                    "source": "synthetic",
                    "features": FeatureExtractor.FEATURES,
                },
                f,
            )

    def _predict(self, features: np.ndarray) -> Dict:
        # One pass over the forest: predict() is the argmax of predict_proba(),
        # and calling both walked all 200 trees twice per session.
        probabilities = self.model.predict_proba(features)[0]
        prediction = self.model.classes_[int(np.argmax(probabilities))]
        return {
            "category": str(self.label_encoder.inverse_transform([prediction])[0]),
            "confidence": float(max(probabilities)),
            "probabilities": {
                str(label): float(prob)
                for label, prob in zip(
                    self.label_encoder.inverse_transform(self.model.classes_), probabilities
                )
            },
            # Consumers must be able to tell a bootstrap verdict from one
            # produced by a model trained on real labelled traffic.
            "model_source": self.model_source,
        }

    def classify_flow(self, flow: Optional[Dict], protocol: str) -> Dict:
        """Classify the measured flow, or decline when there is nothing to measure.

        A session that arrives without flow statistics (older engines, the
        manual ingest route) used to be scored on an all-zero vector, and the
        model happily returned a confident label for it. No measurement means
        no verdict: benign at zero confidence, and model_source says why, so
        the rule layer is the only thing that can raise it.
        """
        if not isinstance(flow, dict) or not any(
            isinstance(v, (int, float)) and v for v in flow.values()
        ):
            return {
                "category": "benign",
                "confidence": 0.0,
                "probabilities": None,
                "model_source": "no_flow",
            }
        self._ensure_loaded()
        return self._predict(self.feature_extractor.extract_from_flow(flow, protocol))


classifier = AttackClassifier()
