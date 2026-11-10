# Evaluation plan: the first real-traffic evaluation

[Back to the project overview](../README.md) ·
[What has been measured so far](evaluation/README.md)

Everything measured to date used a public dataset, synthetic transcripts or
the team's own controlled test traffic. This is the protocol for the first
evaluation on traffic the deployment did not generate itself. **It contains
no results; none of it has been run.** It is written before the data exists
so that the questions, the tools and the reporting are fixed in advance and
cannot be chosen to suit the outcome.

## Rules that apply to every part

- **Period and provenance.** The capture period starts at the moment
  recorded in the [exposure runbook](EXPOSURE_RUNBOOK.md) and its start, end
  and every interruption are reported. Each tool writes a JSON file that
  records the git revision of the code that produced it (the images carry
  it as `GIT_REVISION`), the period, and the inputs' checksums. None of the
  earlier evidence files records a revision; from here on every one does.
- **The team's own traffic is not data.** Set-up connections, the
  fingerprint audit and anything from `controlled-test-node` are listed by
  node and source address and excluded before any count is taken.
  Legitimate visitors of a site behind the decoys are excluded likewise.
- **Report the denominator.** Every rate is given with its counts, and every
  figure with what was excluded and why.
- **Evidence files** go in `docs/evaluation/` unedited; the write-up quotes
  them. A number without a file is not reported.
- **Fixed before looking.** Thresholds, question wording and model settings
  are those deployed at the start of the period. Anything tuned afterwards
  is reported as tuned, on which data, and is re-tested on data it has not
  seen.
- Tool names below are those of the analysis work in this release; each
  prints its options with `--help`. They run in the backend container and
  write under `/app/out` (`deploy/server/state/out` on the host).

## 1. Comparison with a stock Cowrie

| | |
|---|---|
| Question | On comparable traffic, does the engine attract, hold and record more than the reference medium-interaction honeypot, and is it recognised less often? |
| Method | [deploy/cowrie-baseline/README.md](../deploy/cowrie-baseline/README.md): same host, same period, adjacent ports or a second address, same containment, Cowrie in its default configuration, SSH only. |
| Tool | `python -m app.tools.compare_cowrie` |
| Inputs | Cowrie's JSON log for the period (`export-logs.sh`); this deployment's SSH sessions for the same period and node; the list of excluded addresses. |
| Reported | Per side: connections, sessions with a login, sessions with commands, distinct sources and their overlap, session duration and commands per session (median, 90th percentile), share of sessions ending straight after a fingerprinting sequence, distinct credentials, commands and download URLs. Cowrie's image digest and the engine's revision. Which port or address each had. |
| Not claimed | Superiority from one period on one address; anything about protocols Cowrie did not run. |

## 2. Labelled test set and per-layer confusion matrices

| | |
|---|---|
| Question | How accurate is each layer of the pipeline on captured traffic: the flow classifier, the signature rules, the decision model's triage, the language model's technique mapping, and the final verdict? |
| Tools | `python -m app.tools.label_sessions` (draws the sample and records labels), `python -m app.tools.eval_pipeline` (scores each layer against them), `python -m app.tools.build_attack_catalog` and `reanalyze --attack-catalog` (the technique catalogue the mapping is scored against). |
| Sample | Drawn by the tool at random, stratified by protocol and by the final verdict so that rare classes are present, from sessions after the period's start. The size and the strata are fixed before drawing and reported. |
| Labelling | Two team members label each session independently (category, severity, techniques shown, automated or human) from the transcript alone, without seeing any model output. Disagreements are resolved by discussion and counted; agreement before resolution is reported (Cohen's kappa). |
| Inputs | The labelled sample; the stored outputs of each layer for those sessions, as produced at capture time. |
| Reported | For each layer separately: a confusion matrix over the four categories, per-class precision, recall and F1 with counts, and for the technique mapping precision and recall per technique. The same for the final verdict. The share of sessions each layer decided. Triage: how many sessions it would have skipped, and how many of those the labels say mattered. |
| Not claimed | Generalisation beyond this address and period; accuracy for classes with too few labelled examples (reported as counts only). |

The flow classifier is expected to do poorly here: on the controlled test it
called every session benign. That is a result to report, not to tune away.
A classifier trained on captured sessions does not exist yet. Building one,
and refitting the anomaly model (`ml.fit_anomaly`), are separate experiments,
evaluated on a later, untouched part of the period.

## 3. Fingerprint self-audit against the real daemons

| | |
|---|---|
| Question | How does the engine differ, from a client's point of view, from the software it imitates? |
| Method | A real OpenSSH 8.2p1 server, a real telnetd and a real FTP daemon of the imitated versions run in containers on the test bridge. The same scripted client is pointed at each real daemon and at the engine (a throwaway engine registered as `controlled-test-node`), and the responses are compared: banner, key-exchange proposal and HASSH-server, authentication behaviour and timing, error wording for a fixed list of malformed inputs, and the output of a fixed list of shell commands. Published honeypot-detection checks (the Vetterl and Clayton KEXINIT comparison, common Cowrie detectors) are run against both. |
| Tool | The comparison client is part of the audit work; its output is a JSON file with one entry per probe: real response, engine response, same or different. |
| Inputs | The daemon images (pinned by digest), the probe list, the engine revision. |
| Reported | The count and the list of probes that differ, grouped by protocol and by whether a remote attacker could observe the difference before logging in, after logging in, or only with timing. |
| Not claimed | That an engine passing these probes is undetectable; only that these probes do not distinguish it. |

This is the team's own traffic, run on the test bridge, and never enters the
captured data.

## 4. AI-agent canary validation

| | |
|---|---|
| Question | Does the canary (`HONEYPOT_AI_CANARY`) fire for automated assistants and not for ordinary bots or people? |
| Method | Controlled, on the test bridge: (a) LLM-driven agents given a shell on a throwaway engine and a neutral task, several models and several runs each; (b) replayed transcripts of scripted bots from the captured data; (c) team members working by hand. The event `ai_canary_triggered` is the outcome. Then, on captured traffic: every session that raised the event is read by hand. |
| Inputs | The agent configurations and prompts (published with the result), the replay set, the engine revision. |
| Reported | Trigger rate per group with counts: agents (true positives), bots and humans (false positives). For captured traffic: how many sessions triggered, and for each whether the transcript otherwise looks agent-driven, with the reasoning. |
| Not claimed | That an untriggered session was not an agent; prevalence of AI agents among attackers from one address. |

## 5. Injection robustness

| | |
|---|---|
| Question | Can text an attacker types change what the analysis models report about their own session? |
| Tool | `python -m app.tools.eval_injection` |
| Inputs | A fixed set of base transcripts with known labels, each combined with a fixed set of injected payloads (instructions to report the session as benign, to name false techniques or indicators, to emit malformed output), placed in commands, file contents and HTTP fields. The set is fixed and published before the run. |
| Reported | Per model (decision model, language model) and per payload family: the share of runs in which the category, severity, technique list or indicator list changed relative to the same transcript without the payload, with counts; examples of each success. The end-to-end rate after the pipeline's own guards (indicators kept only when present verbatim; technique checks). |
| Not claimed | Robustness against payloads outside the set. |

## 6. Usability study

| | |
|---|---|
| Question | Can an analyst who has not seen the console before complete investigation tasks with it, and how do they rate it? |
| Method | Participants from the target audience (security students or staff), recruited with the organisation's approval and their consent; no captured personal data is shown (the study uses a dataset from the controlled test node). Each performs a fixed list of tasks (find a session by address, read its transcript, identify the techniques, follow an alert to its session, replay a session, export the matches) without help, then fills in the System Usability Scale. |
| Inputs | The task list and the dataset, fixed before the first participant; the console revision. |
| Reported | Number of participants and how they were recruited; per task: completion rate, time, and errors; SUS scores individually and their mean; every problem observed, verbatim where possible. |
| Not claimed | Statistical generalisation from a small sample; the number of participants is stated wherever a figure is quoted. |

## 7. Thirty-day availability

| | |
|---|---|
| Question | Was the deployment up and healthy for the required share of thirty consecutive days? |
| Method | The host heartbeat ([EXPOSURE_RUNBOOK.md](EXPOSURE_RUNBOOK.md#3-the-dead-mans-switch)) checks every five minutes that all containers are healthy, the firewall rules are intact, backups are fresh and one revision is running, and pings an external service only then. The period is thirty consecutive days fixed in advance. |
| Inputs | The external service's check-in log for the period (independent of the deployment); `state/availability.jsonl` from the host (one line per check, with the reason for each failure). |
| Reported | Availability as healthy intervals over all intervals, from the external log; every outage with its start, duration and cause from the host's log; where the two logs disagree, both. Planned maintenance is counted as downtime and listed. |
| Not claimed | Availability of the decoy ports as seen from the internet beyond what the checks cover: a broken port forward with healthy containers is not detected by this method. An outside port check can be added and, if so, is reported separately. |

## Write-up

One section per part, each with: the question, the method as run (and every
deviation from this plan), the evidence file, the result with counts, and a
threats-to-validity table in the form used in
[docs/evaluation/README.md](evaluation/README.md).
