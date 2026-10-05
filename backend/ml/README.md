# Classifier training

Section VI.D of the report describes a Random Forest trained on CIC-IDS2017
with an 80/20 split, evaluated on accuracy, precision, recall, F1 and a
confusion matrix. This directory is that pipeline. Results from the run
quoted in the report are in [docs/evaluation/](../../docs/evaluation/README.md).

## Running it

On the deployment host, one command fetches and verifies the dataset,
trains, installs the model and restarts the API:

```bash
sudo bash deploy/server/train-model.sh
```

By hand, from `backend/`:

```bash
python -m ml.train --data /path/to/MachineLearningCVE/ --tune
```

The flags:

- `--tune` selects class weighting and leaf size by macro F1 on a validation
  split of the training data. The test set is not consulted until the final
  evaluation.
- `--max-per-class 50000` gives a faster first pass.
- `--evaluate-only` reprints the saved metrics without retraining.

Two files land beside `MODEL_PATH_RF`: the model, and
`random_forest_model_metrics.json`. The metrics file holds:

- per-class precision, recall and F1
- the confusion matrix
- the tuning table
- the class balance
- single-prediction latency

**Quote the JSON in the report.** Those are measurements; anything else is an
estimate.

The model artefact records its feature list, and the API refuses one built
for a different layout, falling back to the synthetic bootstrap. Otherwise a
stale model would accept the vector and answer about the wrong features.

## Features

Twelve features, defined once in `FeatureExtractor` (app/ai/classifier.py)
and used by both training and inference:

| feature | CIC-IDS2017 column | engine (honeypot/capture/flow.py) |
|---|---|---|
| destination_port | Destination Port | the emulated service's port (22, 21, 80, 443) |
| flow_duration | Flow Duration (µs → s) | accept to close |
| fwd_data_packets | act_data_pkt_fwd | chunks received from the client |
| fwd_bytes / bwd_bytes | Total Length of Fwd / Bwd Packets | payload bytes each way |
| fwd/bwd_packet_length_max | Fwd / Bwd Packet Length Max | largest chunk each way |
| flow_bytes_per_second | derived | derived |
| bwd_fwd_byte_ratio | derived | derived |
| fwd_iat_mean / fwd_iat_max | Fwd IAT Mean / Max (µs → s) | gaps between client chunks |
| flow_iat_max | Flow IAT Max (µs → s) | longest silence either way |

They replace an earlier 36-feature layout that copied CICFlowMeter's
columns. The engine could observe almost none of those (TCP flag counts,
header lengths, bulk rates) and reported none of them, so in production the
classifier received a vector of zeros. That layout also divided microsecond
durations by a 600-second cap, which made every flow longer than 0.6 ms look
identical. Both sides now use natural units; a Random Forest does not need
scaling.

## What the numbers will and will not tell you

Be straight about these in the report, because a reader who knows the
dataset will ask:

**Domain shift.** CIC-IDS2017 measures packets on the wire, and the engine
measures what its sockets deliver. Data packets and payload bytes mean the
same on both sides, which is why those features were chosen, but bare ACKs
are invisible to the engine and HTTPS is measured above TLS. The metrics are
real on CIC-IDS2017; how well they transfer to live honeypot traffic is an
assumption until captured sessions are labelled and measured.

**The classes are folded.** CIC-IDS2017's labels do not line up with the four
this system reports, so `ml/cicids.py` maps them:

- port scans to reconnaissance
- the Patator, DoS and web-attack families to exploitation
- Bot and Infiltration to exfiltration

Labels with no mapping are dropped rather than guessed at. That mapping is a
design decision to defend in the report, not an implementation detail. It
leaves exfiltration with only ~2,000 flows, which is why it is the weakest
class.

Training on captured honeypot sessions avoids both problems and is the better
long-term path, but it needs the engine to have been exposed to real traffic
first.
