"""CIC-IDS2017 adapter.

Maps the dataset's CICFlowMeter columns onto the classifier's features
(``FeatureExtractor.FEATURES``), computing the derived ones with the same
``FeatureExtractor.derive`` the API uses at inference, so a position in the
vector means the same thing in both places by construction.

Two corrections over the first version of this adapter, both of which made
the trained model describe something other than what it would be shown:

* **Units.** CICFlowMeter reports durations and inter-arrival times in
  microseconds; inference measures seconds. The old loader divided the raw
  microsecond values by a 600-*second* cap, so every flow longer than 0.6 ms
  had the same (clipped) duration.
* **Observability.** Features the engine cannot measure (TCP flag counts,
  header lengths, bulk rates, the old 36-column layout) are no longer used.
  Training on them taught the model to rely on inputs that are always zero
  in production.

The remaining gap is stated in ml/README.md: the dataset measures packets on
the wire, the engine measures what its sockets deliver.
"""

from __future__ import annotations

import glob
import logging
import os
import re
import sys
from typing import Iterator, Optional

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ai.classifier import FeatureExtractor  # noqa: E402

logger = logging.getLogger(__name__)

FEATURES = FeatureExtractor.FEATURES

#: Raw CICFlowMeter columns the features are built from. Keys are normalised
#: (lowercased, non-alphanumerics collapsed to "_"); each lists the spellings
#: used by the different CICFlowMeter releases.
_RAW_COLUMNS = {
    "port": ["destination_port", "dst_port"],
    "duration_us": ["flow_duration"],
    "fwd_data_packets": ["act_data_pkt_fwd"],
    "fwd_bytes": ["total_length_of_fwd_packets", "totlen_fwd_pkts"],
    "bwd_bytes": ["total_length_of_bwd_packets", "totlen_bwd_pkts"],
    "fwd_max": ["fwd_packet_length_max", "fwd_pkt_len_max"],
    "bwd_max": ["bwd_packet_length_max", "bwd_pkt_len_max"],
    "fwd_iat_mean_us": ["fwd_iat_mean"],
    "fwd_iat_max_us": ["fwd_iat_max"],
    "flow_iat_max_us": ["flow_iat_max"],
}

MICROSECONDS = 1_000_000.0

#: CIC-IDS2017's attack labels folded onto the four classes the system reports.
#: Anything unmatched is dropped rather than guessed at — silently bucketing an
#: unknown label would corrupt the very metrics this exists to produce.
_LABEL_MAP = {
    "benign": "benign",
    "portscan": "reconnaissance",
    "port_scan": "reconnaissance",
    "ftp_patator": "exploitation",
    "ssh_patator": "exploitation",
    "web_attack_brute_force": "exploitation",
    "web_attack_xss": "exploitation",
    "web_attack_sql_injection": "exploitation",
    "heartbleed": "exploitation",
    "dos_hulk": "exploitation",
    "dos_goldeneye": "exploitation",
    "dos_slowloris": "exploitation",
    "dos_slowhttptest": "exploitation",
    "ddos": "exploitation",
    "infiltration": "exfiltration",
    "bot": "exfiltration",
}

def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")


def _resolve_columns(df: pd.DataFrame) -> dict[str, str]:
    """Match the frame's actual columns to the raw inputs above."""
    lookup = {_norm(c): c for c in df.columns}
    resolved: dict[str, str] = {}
    for name, aliases in _RAW_COLUMNS.items():
        for alias in aliases:
            if alias in lookup:
                resolved[name] = lookup[alias]
                break
    return resolved


def features_from_frame(raw: pd.DataFrame) -> pd.DataFrame:
    """Raw CICFlowMeter values (already numeric, clipped at zero) -> features."""
    cols = FeatureExtractor.derive(
        raw["port"].to_numpy(dtype=float),
        raw["duration_us"].to_numpy(dtype=float) / MICROSECONDS,
        raw["fwd_data_packets"].to_numpy(dtype=float),
        raw["fwd_bytes"].to_numpy(dtype=float),
        raw["bwd_bytes"].to_numpy(dtype=float),
        raw["fwd_max"].to_numpy(dtype=float),
        raw["bwd_max"].to_numpy(dtype=float),
        raw["fwd_iat_mean_us"].to_numpy(dtype=float) / MICROSECONDS,
        raw["fwd_iat_max_us"].to_numpy(dtype=float) / MICROSECONDS,
        raw["flow_iat_max_us"].to_numpy(dtype=float) / MICROSECONDS,
    )
    return pd.DataFrame(np.column_stack(cols), columns=FEATURES, index=raw.index)


def _label_column(df: pd.DataFrame) -> Optional[str]:
    for col in df.columns:
        if _norm(col) == "label":
            return col
    return None


def iter_csv_files(path: str) -> Iterator[str]:
    if os.path.isfile(path):
        yield path
        return
    files = sorted(glob.glob(os.path.join(path, "**", "*.csv"), recursive=True))
    if not files:
        raise FileNotFoundError(f"No CSV files found under {path}")
    yield from files


def load(path: str, max_rows_per_class: Optional[int] = None) -> tuple[np.ndarray, np.ndarray]:
    """Load CIC-IDS2017 into (X, y) with the classifier's feature order.

    Applies the preprocessing the report describes: null and infinity
    handling, label folding and duplicate removal. Duplicates are removed in
    the model's own feature space, after the columns it does not use are
    gone: identical vectors on both sides of the train/test split would
    otherwise be scored as generalisation when they are memorisation.
    """
    frames: list[pd.DataFrame] = []

    for csv_path in iter_csv_files(path):
        df = pd.read_csv(csv_path, low_memory=False, skipinitialspace=True,
                         encoding="latin-1")
        label_col = _label_column(df)
        if label_col is None:
            logger.warning("Skipping %s: no Label column", os.path.basename(csv_path))
            continue

        resolved = _resolve_columns(df)
        missing = [name for name in _RAW_COLUMNS if name not in resolved]
        if missing:
            raise ValueError(
                f"{os.path.basename(csv_path)} lacks columns {missing}; "
                "zero-filling them would train on a feature that is not there"
            )

        raw = pd.DataFrame(
            {name: pd.to_numeric(df[col], errors="coerce") for name, col in resolved.items()},
            index=df.index,
        )
        # CICFlowMeter emits inf for rates on zero-duration flows and a few
        # negative durations/IATs from clock skew; neither is a measurement.
        raw = raw.replace([np.inf, -np.inf], np.nan).fillna(0.0).clip(lower=0.0)
        out = features_from_frame(raw)
        out["label"] = df[label_col].astype(str).map(lambda v: _LABEL_MAP.get(_norm(v)))
        frames.append(out)
        logger.info("Loaded %s (%d rows)", os.path.basename(csv_path), len(out))

    if not frames:
        raise ValueError(f"No usable CSV files under {path}")

    data = pd.concat(frames, ignore_index=True)
    before = len(data)
    data = data.dropna(subset=["label"])
    data = data.drop_duplicates()
    logger.info("Preprocessing: %d rows -> %d after label folding and de-duplication",
                before, len(data))

    if max_rows_per_class:
        data = (
            data.groupby("label", group_keys=False)
            .apply(lambda g: g.sample(min(len(g), max_rows_per_class), random_state=42))
            .reset_index(drop=True)
        )
        logger.info("Capped to %d rows per class -> %d rows", max_rows_per_class, len(data))

    X = data[FEATURES].to_numpy(dtype=float)
    y = data["label"].to_numpy()
    return X, y
