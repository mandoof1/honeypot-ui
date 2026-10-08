# Evaluation results

Measurements behind the report's FR-2 and NFR-2 claims, taken on 2026-10-05
on the project's server (8 cores, 31 GB RAM, Debian 13). Each figure below
comes from a JSON file in this directory; quote those, not this summary.

## Stage-1 classifier (FR-2, Section VI.D)

Random Forest, 200 trees, max depth 20, trained on CIC-IDS2017
(MachineLearningCVE CSVs, 2,830,743 flows, SHA-256 verified against the
mirror's published checksums) with an 80/20 stratified split.

Preprocessing: labels folded onto the four reported classes (ml/cicids.py),
then de-duplicated in the model's feature space, leaving 2,391,461 flows:
1,967,257 benign, 331,400 exploitation, 90,819 reconnaissance and 1,985
exfiltration. 1,913,168 were used for training and 478,293 held out.

**Features.** There are twelve, chosen because the honeypot engine can measure
each one the way CICFlowMeter does:

- destination port
- flow duration
- client data packets
- bytes in each direction
- the largest packet in each direction
- bytes per second
- the response/request byte ratio
- forward inter-arrival mean and maximum
- the longest silence in the flow

The engine measures them at its sockets (`honeypot/capture/flow.py`), and
training and inference share one definition (`FeatureExtractor.derive`).

### Hyperparameters: chosen on validation data, not the test set

`--tune` fitted six configurations on 80% of the training data and scored
each on the remaining 20% by macro F1:

| class weighting | min leaf | validation macro F1 |
|---|---|---|
| balanced (inverse frequency) | 2 | 0.823 |
| balanced | 5 | 0.813 |
| **square root of balanced** | **2** | **0.900** |
| square root of balanced | 5 | 0.892 |
| none | 2 | 0.887 |
| none | 5 | 0.881 |

Inverse-frequency weighting multiplies the rare exfiltration class by about
300x and buys its recall with a large number of benign flows called
exfiltration. The selected configuration was refitted on the full training
set and evaluated once on the held-out test set.

### Test-set results (`rf-cicids2017-tuned-metrics.json`)

| | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.9984 | 0.9977 | 0.9980 | 393,452 |
| exploitation | 0.9947 | 0.9916 | 0.9931 | 66,280 |
| reconnaissance | 0.9878 | 0.9986 | 0.9932 | 18,164 |
| exfiltration | 0.4692 | 0.8237 | 0.5978 | 397 |
| **macro** | 0.8625 | 0.9529 | 0.8955 | |

The overall accuracy was **0.9967**, so the >95% target the Capstone A report set is met.
923 of 393,452 benign test flows (0.23%) were flagged as an attack.

For comparison, the untuned model (`rf-cicids2017-balanced-metrics.json`)
reached 0.9939 accuracy but only 0.823 macro F1, with exfiltration precision
of 0.186 and 2,393 benign flows (0.61%) flagged.

### What these numbers do and do not show

- **Exfiltration is the weak class.** It is CIC-IDS2017's Bot and
  Infiltration traffic: 1,985 flows in total. Precision of 0.47 means
  roughly half of what the model calls exfiltration is something else. The
  report should say so rather than lead with accuracy, which the benign
  majority dominates.
- **Domain shift.** These are scores on CIC-IDS2017 flows. The engine
  measures what its sockets deliver rather than packets on the wire: bare
  ACKs are invisible to it, and HTTPS is measured above TLS. Performance on
  captured honeypot traffic is an assumption until it is labelled and
  measured, and the report should say it is an assumption. Training on
  captured sessions removes the shift and is the better long-term path.
- **Observed on the deployment.** The controlled end-to-end test
  (`deploy/server/controlled-test.sh`) produced five sessions:
  - three SSH logins that were refused;
  - an SSH session with `wget`, `/etc/passwd` and a base64 file drop;
  - an HTTP path traversal with an sqlmap user agent.

  The stage-1 model labelled all five **benign**. The stage-2 NLP stage still
  identified `sqlmap`, `wget_curl`, `enum_linux` and `data_exfil`. These are
  short exchanges over a container network, not the long or high-volume
  flows CIC-IDS2017's attacks consist of. That is the domain shift above in
  practice: on honeypot traffic, the flow model's verdict should not be read
  on its own.
- **Class folding is a design decision.** DoS and DDoS count as
  exploitation, PortScan as reconnaissance, and Bot and Infiltration as
  exfiltration. It belongs in the report as a choice to defend.

## NFR-2: classification latency (TC13)

`deploy/server/stress-test.sh` attacks a throwaway engine registered as
`controlled-test-node` with a fixed mix of sessions, every one carrying a
login and commands:

- 50% SSH: login, three commands
- 30% HTTP: a form login
- 20% FTP: login, PWD

It then reads two figures for every session back from the database:

- **analysis_ms:** the span the backend times itself, from feature extraction
  to the verdict committed.
- **turnaround:** session end, as the engine recorded it, to the classified
  row being written. This is NFR-2's "post session termination" wording.

| scenario | captured | analysis p50 / p95 / p99 | within 200 ms | turnaround p50 / p95 / max |
|---|---|---|---|---|
| 50 sessions, one at a time (`nfr2-sequential50.json`) | 50/50 | 27.8 / 31.9 / 32.3 ms | **100%** | 33 / 39 / 43 ms |
| 300 sessions, 10 concurrent (`nfr2-300-c10.json`) | 300/300 | 28.2 / 51.5 / 62.1 ms | **100%** | 38 / 71 / 138 ms |
| 300 sessions, 20 concurrent (`nfr2-300-c20.json`) | 300/300 | 29.8 / 57.9 / 81.9 ms | **100%** | 55 / 125 / 337 ms (p99 184) |
| 500 sessions, 50 concurrent (`nfr2-sustained500-c50.json`) | 500/500 | 85.8 / 265.4 / 327.3 ms | 88.8% | 0.43 / 0.90 / 1.25 s |
| 500 sessions all at once (`nfr2-burst500.json`) | 500/500 | 115.0 / 398.7 / 601.7 ms | 82.2% | 4.2 / 6.1 / 8.0 s |
| as above, before the ingest service existed (`nfr2-burst500-before-ingest-split.json`) | 500/500 | 143.6 / 263.5 / 492.8 ms | 86.4% | 12.0 / 20.6 / 23.2 s |

Reading it:

- **NFR-2 is met up to 10 concurrent sessions**, on both measures and
  including the worst session. That is about 24 sessions per second arriving
  on this host. At 20 concurrent, every analysis is still within budget and
  99% of verdicts are stored within 200 ms of their session ending.
- **At nominal load the margin is wide.** A session is classified and stored
  about 33 ms after it ends. The models take 16 ms of that: 9.6 ms for the
  forest, 2.8 ms for the isolation forest and 3.6 ms for NLP (single-session
  timings inside the ingest service).
- **Past that, sessions queue for CPU and for the database.** In the
  500-at-once burst the system still captured and classified every session
  (TC13's "no service degradation"), but the last verdict landed about 8 s
  after its session ended. The requirement as worded ("must remain below
  200 ms") needs that load condition in the report: "below 200 ms at up to
  10 concurrent sessions", with this table as the evidence.
- **The ingest service is why the burst drains in about 8 s rather than
  23 s.** Analysis moved out of the dashboard's single API process into
  four workers. Making each forest a single pass (predict_proba and
  score_samples alone, rather than predict as well) cut model time per
  session from 28.3 ms to 16.0 ms.

The load generator ran on the same host, so these figures include its own
CPU use, the SSH key exchanges in particular. Real attackers do that work on
their own machines.

## Decision model: triage and technique checks

Kev-4B (Q8_0, Apache-2.0) is a decision model in the style of TypeSafe's Jev.
It never writes text; it returns a probability for each option of each
question. It sits in front of Wolfram and does two jobs:

- **Triage:** pipeline category, severity 0–3, and automated or human, for
  each session the rules queue for Wolfram. This decides whether Wolfram reads
  the session.
- **Technique check:** for each ATT&CK technique Wolfram adds, how likely the
  transcript is to show it.

Measured on 2026-10-08 on the same server, with
`python -m app.tools.eval_decider`, which asks the questions the pipeline
deploys.

### Technique check (`decider-heldout.json`)

The data is the 24 transcripts held out of Wolfram's fine-tune
(`chimera-heldout.jsonl`). For every transcript, all 15 techniques in that set
were asked about:

- the 86 labelled techniques are the positives;
- the other 274 are hard negatives: real techniques from the same domain that
  this transcript does not show.

| | |
|---|---|
| ROC AUC | **0.983** |
| accuracy at 0.5 | 0.928 |
| expected calibration error | 0.085 |
| mean probability, real / wrong technique | 0.73 / 0.11 |
| at the deployed threshold 0.3 | keeps **86/86** real techniques, accepts 24/274 wrong ones |
| at 0.5 | keeps 78/86, accepts 18/274 |
| time, 15 questions on one transcript | 24 s median |

Two choices were settled on this set and are worth stating:

- **The questions describe the behaviour, not just the ID.** For example:
  "copies a tool or file onto the host from an outside system, e.g. with wget,
  curl or tftp". Asking by ID and name alone gave AUC 0.957, and 70 of 274
  wrong techniques passed at 0.3.
- **The first run exposed T1049, which had no description.** Asked as a bare
  ID, it scored backwards (AUC 0.04); with a description it scores 1.0. A
  technique outside `TECHNIQUE_HINTS` is still asked by name, so that failure
  mode remains possible for unusual techniques.

The threshold marks a technique as unconfirmed; it does not delete it
(`DECIDER_DROP_UNCONFIRMED` is off). At 0.3 no real technique on this set
would have been lost.

### Triage on the same transcripts (`decider-heldout.json`)

The set carries no triage labels, so they were derived from the labelled
techniques by a fixed rule, recorded in the JSON:

- 23 transcripts are exploitation;
- 1 is reconnaissance (discovery techniques only).

| | decision model | rule layer |
|---|---|---|
| category accuracy | 0.83 (4 exploitation sessions read as reconnaissance) | **0.96** |
| mean severity at label 1 / 2 / 3 | 0.71 / 1.28 / 1.57 | — |
| time per session | 8.2 s median, 10.2 s max | < 20 ms |

What this shows:

- **The rules are the better categoriser on these transcripts.** That is
  expected: the transcripts came from the same patterns the signatures were
  written for.
- **The model's severity is in the right order but compressed:** it
  under-rates.
- **Neither weakness causes a wrong skip.** The routing only skips Wolfram
  when the model *and* the rules both say "no further than reconnaissance".
  Applied to these 24 sessions, it sent all 23 exploitation sessions to
  Wolfram and skipped the one reconnaissance session. Taken alone, the model
  would have wrongly skipped one exploitation session, but the rules overruled
  it.
- **The skip path has one example.** That is far too few to claim a saving;
  it needs captured shell traffic.
- **Automated or human is not validated:** every answer was "automated", and
  this set has no usable label for it. The dashboard marks it "unvalidated".

### Captured sessions (`decider-server-sessions.json`)

All 34 stored sessions with commands were triaged after the fact. All were
web sessions on the shop, mostly tailnet testing. There are no labels; the
comparison is with the rules.

- The rules call 32 of them benign, and the model called 30 of those
  **reconnaissance**. It reads a list of page requests as enumeration.
- It recommended sending none of them to Wolfram.
- It took 16.4 s per session at the median and 41.8 s at p95. Web request
  lines are long: 1,513 input tokens at the median.

This is why triage is limited by default to the sessions the rules already
queue for Wolfram. Triaging browsing (`DECIDER_TRIAGE_RULE_SKIPPED`) spends
CPU on a label that is mostly wrong, and on this traffic it never escalated
anything. No shell attack sessions were stored, so triage of captured SSH
and Telnet traffic remains unmeasured.

These are synthetic transcripts plus a small amount of test traffic, not
internet attacks. They support how the routing is designed; they do not
measure accuracy on live traffic.
