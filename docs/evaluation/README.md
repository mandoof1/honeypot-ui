# Evaluation results

[Back to the project overview](../../README.md) ·
[Plan for the first real-traffic evaluation](../EVALUATION_PLAN.md)

Measurements taken on 2026-10-05 and 2026-10-08 on the project's server
(8 cores, 31 GB RAM, Debian 13). Each figure below comes from a JSON file in
this directory; quote those, not this summary.

Read these first:

- **None of this is real attack traffic.** The classifier was scored on a
  public dataset, the latency test and the "observed on the deployment"
  notes used the team's own controlled test traffic, and the decision model
  was scored on synthetic transcripts. The deployment has not been exposed.
- **No evidence file records the git revision of the code that produced
  it.** The dates are the only link to a version. Output written by the
  tools from this release on does record it (`git_revision`).
- **Figures that had no evidence file have been removed** from this page: a
  per-stage timing breakdown, a before-and-after figure for one optimisation
  and a sessions-per-second rate. Where a number was removed, the text says
  so.
- Each result is followed by a table of threats to its validity.

## Stage-1 classifier (FR-2, Section VI.D)

Random Forest, 200 trees, max depth 20, trained on CIC-IDS2017 [1]
(MachineLearningCVE CSVs, 2,830,743 flows, SHA-256 verified against the
mirror's published checksums) with an 80/20 stratified split.

Preprocessing: labels folded onto the four reported classes (ml/cicids.py),
then de-duplicated in the model's feature space, leaving 2,391,461 flows:
1,967,257 benign, 331,400 exploitation, 90,819 reconnaissance and 1,985
exfiltration. 1,913,168 were used for training and 478,293 held out.

**Features.** There are twelve, chosen because the engine can measure a
quantity of the same name at its sockets:

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
The dataset's columns were produced by CICFlowMeter from packets on the
wire. **The two measurements have never been compared on the same
traffic**, so it is not established that the engine's values match what
CICFlowMeter would report for the same connection.

### Hyperparameters

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
exfiltration.

**The test set was scored twice, not once.** Two metric files score the same
held-out 478,293 flows: `rf-cicids2017-balanced-metrics.json` (generated
18:42 UTC, inverse-frequency weighting) and
`rf-cicids2017-tuned-metrics.json` (18:59 UTC, 18 minutes later, square-root
weighting). The tuning table above selects on validation data, but the
decision to tune the class weighting was taken after the first model's test
results were known. The second file's figures are therefore not those of a
configuration fixed before the test set was seen, and are somewhat
optimistic as an estimate of performance on new data from the same
distribution.

### Test-set results (`rf-cicids2017-tuned-metrics.json`)

| | precision | recall | F1 | support |
|---|---|---|---|---|
| benign | 0.9984 | 0.9977 | 0.9980 | 393,452 |
| exploitation | 0.9947 | 0.9916 | 0.9931 | 66,280 |
| reconnaissance | 0.9878 | 0.9986 | 0.9932 | 18,164 |
| exfiltration | 0.4692 | 0.8237 | 0.5978 | 397 |
| **macro** | 0.8625 | 0.9529 | 0.8955 | |

Overall accuracy on this test set is **0.9967**; 923 of 393,452 benign test
flows (0.23%) were flagged as an attack. A single prediction takes 9.1 ms at
the median (`inference_latency` in the same file).

What that accuracy is, and is not:

- It is accuracy on a **random per-flow split of the pooled dataset**. Flows
  from the same attack run, the same hosts and the same day are on both
  sides of the split, so the test set is not independent of the training
  set in the way new traffic would be, and a score on such a split
  overstates what a split by day or by attack would give.
- It is dominated by the benign majority (82% of the test set).
- The Capstone A report set a target of more than 95% accuracy. The figure
  exceeds it **on this dataset and this split only**.
- **On the deployment the model produced no attack verdict at all.** The
  controlled end-to-end test produced five sessions (three refused SSH
  logins; an SSH session with `wget`, `/etc/passwd` and a base64 file drop;
  an HTTP path traversal with an sqlmap user agent) and the model labelled
  all five benign. The rule layer identified `sqlmap`, `wget_curl`,
  `enum_linux` and `data_exfil` in them. The dataset's attacks are long or
  high-volume flows; honeypot sessions are short exchanges. The target is
  not met for the system's actual input, and the flow model's verdict
  should not be read on its own there.

For comparison, the first model (`rf-cicids2017-balanced-metrics.json`)
reached 0.9939 accuracy but only 0.823 macro F1, with exfiltration precision
of 0.186 and 2,393 benign flows (0.61%) flagged.

Other points to state with these numbers:

- **Exfiltration is the weak class.** It is CIC-IDS2017's Bot and
  Infiltration traffic: 1,985 flows in total. Precision of 0.47 means
  roughly half of what the model calls exfiltration is something else.
- **Class folding is a design decision.** DoS and DDoS count as
  exploitation, PortScan as reconnaissance, and Bot and Infiltration as
  exfiltration.

| Threat to validity | Effect | What would address it |
|---|---|---|
| Random per-flow split of pooled data | Test flows are near-duplicates of training flows; accuracy is inflated | A split by day or by attack type; evaluation on captured, labelled sessions |
| Test set scored before the final configuration was chosen | Reported figures are optimistic | A fresh held-out set never used for any decision |
| Known labelling and flow-construction errors in CIC-IDS2017 [2] | Some "ground truth" labels are wrong | The corrected release, or captured data |
| Features never compared with CICFlowMeter on the same traffic | The model may receive values on a different scale than it was trained on | Capture traffic with both and compare per feature |
| Domain shift: packets on the wire versus bytes at a socket; bare ACKs invisible; HTTPS measured above TLS | Performance on honeypot traffic is unknown; the five controlled sessions suggest it is poor | Training and testing on captured sessions |
| 397 exfiltration test flows | Wide uncertainty on that class | More data for the class, or reporting it as counts |
| Dataset from 2017, one lab network | Traffic mix unlike today's internet | Captured data |

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
  including the worst session. At 20 concurrent, every analysis is still
  within budget and 99% of verdicts are stored within 200 ms of their
  session ending. (An arrival rate in sessions per second was quoted here
  before; it was not recorded in any file and has been removed.)
- **At nominal load the margin is wide.** A session is classified and stored
  about 33 ms after it ends. (A breakdown of that time by stage was quoted
  here before; it was not saved to an evidence file and has been removed.
  The only per-stage timing on file is the forest's single prediction,
  9.1 ms at the median.)
- **Past that, sessions queue for CPU and for the database.** In the
  500-at-once burst the system still captured and classified every session
  (TC13's "no service degradation"), but the last verdict landed about 8 s
  after its session ended. The requirement as worded ("must remain below
  200 ms") needs that load condition stated: "below 200 ms at up to
  10 concurrent sessions", with this table as the evidence.
- **The ingest service is why the burst drains in about 8 s rather than
  23 s** (the last two rows). Analysis moved out of the dashboard's single
  API process into four workers. (A figure for a further change, scoring
  each forest in a single pass, was quoted here before without an evidence
  file and has been removed.)

| Threat to validity | Effect | What would address it |
|---|---|---|
| The load generator ran on the same host | Its CPU use, the SSH key exchanges in particular, is inside the figures; real attackers do that work elsewhere | Generating load from another machine |
| One run per scenario | No variance; a single slow run would not be noticed | Repeating each scenario and reporting the spread |
| A fixed, simple session mix | Long transcripts and file uploads, which cost more, are not represented | A mix drawn from captured sessions |
| The asynchronous stages are outside the measurement | The 200 ms covers the flow classifier and rules, not triage or the language model | Reported separately (below) |
| Measured before this release | The ingest path has since gained per-node tokens, body limits and fingerprints | Re-running `stress-test.sh` on the release; its output now records the revision |

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

The data is 24 **synthetic** transcripts held out of Wolfram's fine-tune
(`chimera-heldout.jsonl`; the file records `"synthetic": true`). For every
transcript, all 15 techniques in that set were asked about, giving 360
questions:

- the 86 labelled techniques are the positives;
- the other 274 are negatives: real techniques from the same domain that
  this transcript does not show.

| | |
|---|---|
| ROC AUC | 0.983 |
| accuracy at 0.5 | 0.928 |
| expected calibration error | 0.085 |
| mean probability, real / wrong technique | 0.73 / 0.11 |
| at the deployed threshold 0.3 | keeps 86/86 real techniques, accepts 24/274 wrong ones |
| at 0.5 | keeps 78/86, accepts 18/274 |
| time, 15 questions on one transcript | 24 s median |

**How to read 0.983.** It is not an estimate of accuracy on attack traffic,
and it is not a held-out figure in the usual sense:

- The 360 questions are 15 questions about each of 24 transcripts. They are
  **not independent**: the effective sample is 24 transcripts, all written
  by the same generator in the same style.
- **The question wording was chosen on this set.** Asking by technique ID
  and name alone gave AUC 0.957, with 70 of 274 wrong techniques passing at
  0.3; descriptions were then written (for example "copies a tool or file
  onto the host from an outside system, e.g. with wget, curl or tftp") and
  the score on the same 24 transcripts rose to 0.983. One technique (T1049)
  scored backwards (AUC 0.04) until it was given a description.
- **The 0.3 threshold was chosen on this set** as the highest value that
  kept every labelled technique.

So 0.957 is the figure before tuning, 0.983 the figure after tuning on the
data it is reported on, and neither has been confirmed on transcripts the
wording and threshold have not seen. A technique outside `TECHNIQUE_HINTS`
is still asked by name, so the failure seen with T1049 remains possible.

The threshold marks a technique as unconfirmed; it does not delete it
(`DECIDER_DROP_UNCONFIRMED` is off).

### Triage on the same transcripts (`decider-heldout.json`)

The set carries no triage labels, so they were derived from the labelled
techniques by a fixed rule, recorded in the JSON. The result is **23
transcripts labelled exploitation and 1 labelled reconnaissance**, and none
benign.

| | decision model | rule layer |
|---|---|---|
| category accuracy | 0.83 (4 exploitation sessions read as reconnaissance) | 0.96 |
| mean severity at label 1 / 2 / 3 | 0.71 / 1.28 / 1.57 | — |
| time per session | 8.2 s median, 10.2 s max | < 20 ms |

With 23 examples of one class and 1 of the other, "accuracy" says almost
nothing: a model that always answered "exploitation" would score 0.96.
What the table supports is narrower:

- **The rules are the better categoriser on these transcripts**, which is
  expected: the transcripts follow the patterns the signatures were written
  for.
- **The model's severity is in the right order but compressed:** it
  under-rates.
- **The skip path has one example.** The routing skips Wolfram only when
  the model *and* the rules both say "no further than reconnaissance"; on
  these 24 it sent all 23 exploitation sessions on and skipped the one
  reconnaissance session. Taken alone, the model would have wrongly skipped
  one exploitation session. One example is no basis for claiming a saving.
- **Automated or human is not validated:** every answer was "automated", and
  this set has no usable label for it. The dashboard marks it "unvalidated".

### Stored sessions (`decider-server-sessions.json`)

All 34 stored sessions with commands were triaged after the fact. All were
web sessions on the shop, mostly the team's own testing over the tailnet;
**the deployment was not exposed, so none of them is an internet attack**.
There are no labels; the comparison is with the rules.

- The rules call 32 of them benign, and the model called 30 of those
  **reconnaissance**. It reads a list of page requests as enumeration.
- It recommended sending none of them to Wolfram.
- It took 16.4 s per session at the median and 41.8 s at p95. Web request
  lines are long: 1,513 input tokens at the median.

This is why triage is limited by default to the sessions the rules already
queue for Wolfram. No shell attack sessions were stored, so triage of
captured SSH and Telnet traffic is unmeasured.

| Threat to validity | Effect | What would address it |
|---|---|---|
| 24 synthetic transcripts from one generator | Says little about real sessions, which are messier and often trivial | A labelled sample of captured sessions |
| 360 questions are 15 per transcript | Confidence is that of 24 samples, not 360 | Reporting per transcript; more transcripts |
| Wording and threshold tuned on the reporting set | 0.983 is optimistic; 0.957 is the untuned figure | Scoring on transcripts never used for tuning |
| Triage labels derived by rule, 23 to 1, no benign | Category accuracy is uninformative; the skip decision is untested | Human labels on a balanced sample |
| Stored sessions are the team's own, unlabelled | No accuracy claim is possible from them | Labelled captured traffic |
| One run, one quantisation, one CPU | Timings are for this server only | Stated as such |

## Reproducing each result

The server needs the stack installed (`deploy/server/install.sh`).

| Result | Command | Notes |
|---|---|---|
| Classifier | `sudo bash deploy/server/train-model.sh` | Fetches CIC-IDS2017 from the mirror named in the script and verifies each file's SHA-256; trains with tuning in a container with no network; writes `random_forest_model_metrics.json` beside the model. About 40 minutes on 8 cores. The split uses a fixed seed. `--no-tune` reproduces the first model. |
| NFR-2 | `sudo bash deploy/server/stress-test.sh --sessions N --concurrency C` | The six scenarios are N/C = 50/1, 300/10, 300/20, 500/50 and 500/500 (the last also run before the ingest service existed, which cannot be reproduced on this release). Run on an idle host. Writes `state/nfr2-<time>.json`. |
| Controlled end-to-end test | `sudo bash deploy/server/controlled-test.sh` | Prints the five sessions and their verdicts. |
| Decision model, held-out | `docker compose exec backend python -m app.tools.eval_decider --help` | Needs `chimera-heldout.jsonl` from the Kaggle dataset named in the JSON's `data` field, and the decider service running. |
| Decision model, stored sessions | `docker compose exec backend python -m app.tools.eval_decider --db-summary` | Depends on what is stored; not reproducible elsewhere. |

A reproduction will not match to the last digit: the evidence files do not
record the code revision, and timings depend on the host.

## References

[1] I. Sharafaldin, A. H. Lashkari and A. A. Ghorbani, "Toward Generating a
New Intrusion Detection Dataset and Intrusion Traffic Characterization," in
*Proceedings of the 4th International Conference on Information Systems
Security and Privacy (ICISSP)*, 2018, pp. 108–116.
doi:10.5220/0006639801080116.

[2] G. Engelen, V. Rimmer and W. Joosen, "Troubleshooting an Intrusion
Detection Dataset: the CICIDS2017 Case Study," in *2021 IEEE Security and
Privacy Workshops (SPW)*, 2021, pp. 7–12.

## Controlled pipeline check (November 2026)

The first measurement of the pipeline on labelled sessions is in
[controlled/](controlled/README.md): two runs of the team's own controlled
test traffic, about ninety sessions each, labelled by the scenario that
produced them. The rule layer stored 62% of the sessions of the first run
under their label; three rule gaps that run exposed were fixed, and on a
second, freshly generated run it stored 79%. Both figures describe those
scenarios only. No traffic from real attackers has been evaluated.
