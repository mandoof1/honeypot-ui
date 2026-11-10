"""Settings of the analysis layer.

Kept beside the code they tune rather than in ``app.core.config``: they are
read only by the analysis pipeline, its models and its tools. Same mechanism
(environment variables, then ``.env``), so an operator sets them exactly like
any other setting.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


class AnalysisSettings(BaseSettings):
    #: Run spaCy named-entity extraction over the commands. Off: nothing
    #: reads its output, and it was the largest single cost in the 200 ms
    #: ingest budget. The language model is only imported when this is on.
    NLP_ENTITIES_ENABLED: bool = False

    #: Threads the CPU part of the analysis runs on, so one slow session does
    #: not stop the ingest worker's event loop from accepting the next.
    ANALYSIS_EXECUTOR_THREADS: int = 2

    #: Failed logins in one session from which it reads as a brute-force
    #: attempt. Three, the old value, is a person mistyping a password.
    BRUTE_FORCE_MIN_FAILED_LOGINS: int = 5

    # -- anomaly detector ---------------------------------------------------
    #: Stored sessions required before the detector is fitted on them. Below
    #: this it stays on the synthetic bootstrap and is reported uncalibrated.
    ANOMALY_MIN_SESSIONS: int = 200
    #: Share of the fitted sessions the detector is told to treat as
    #: anomalous. This is an assumption, not a measurement: with it, the most
    #: isolated five per cent of what the deployment has seen are flagged, by
    #: construction. It says "unusual here", never "malicious".
    ANOMALY_CONTAMINATION: float = 0.05
    #: Hours between scheduled refits of the anomaly detector.
    ANOMALY_REFIT_HOURS: int = 24

    # -- behavioural clustering ---------------------------------------------
    #: Hours between scheduled refits of the cluster model.
    CLUSTER_REFIT_HOURS: int = 24
    #: Add the client fingerprint (HASSH/JA3/JA4, hashed into a few buckets)
    #: to the clustering features. Off until captured fingerprints exist to
    #: show that it separates campaigns rather than splitting them.
    CLUSTER_USE_FINGERPRINTS: bool = False

    #: Let the backend's scheduler fit and refit the anomaly detector and the
    #: cluster model from stored sessions. The manual commands still work.
    MODEL_REFIT_ENABLED: bool = True

    # -- alerts raised by the model stages ----------------------------------
    #: Probability of an attempted compromise from which a completed triage
    #: may raise or escalate an alert on a session the rules scored lower.
    DECIDER_ALERT_THRESHOLD: float = 0.8

    model_config = {"env_file": ".env", "case_sensitive": True, "extra": "ignore"}


@lru_cache()
def get_analysis_settings() -> AnalysisSettings:
    return AnalysisSettings()
