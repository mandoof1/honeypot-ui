# Controlled pipeline check

Two runs of labelled, controlled test traffic through the rule layer and the
flow classifier, made on 10 November 2026 (UTC) with
[`tools/controlled_traffic`](../../../tools/controlled_traffic/README.md) and
`python -m app.tools.eval_pipeline`.

**What this is.** Traffic the team generated against a throwaway engine on
loopback (node `controlled-test-node`), labelled by construction: every
session carries the label of the scripted scenario that produced it. **None
of it is traffic from real attackers**, and it is not the evaluation
described in [EVALUATION_PLAN.md](../../EVALUATION_PLAN.md), which needs
captured sessions labelled independently by two people. It answers a narrower
question: on scenarios whose class is known, what does the pipeline store?

**What was measured.** The rule layer, the flow classifier and the stored
verdict, in-process. The two model stages were not run (their servers were
not available). The flow classifier scored here is the synthetic bootstrap
(`"flow_classifier": "synthetic"` in the result files): the model trained on
CIC-IDS2017 lives on the deployment server, which was offline. Its row
therefore says nothing about the trained model.

## Run 1: before any change

91 sessions (benign 24, exfiltration 6, exploitation 35, reconnaissance 26), code revision `dff68c5`.
Rule layer and stored verdict: accuracy 0.615 (95% interval 0.516–0.725), macro-F1 0.671 (0.589–0.750).

| labelled \ stored as | benign | reconnaissance | exploitation | exfiltration |
|---|---|---|---|---|
| benign | 24 | 0 | 0 | 0 |
| reconnaissance | 18 | 7 | 1 | 0 |
| exploitation | 12 | 4 | 19 | 0 |
| exfiltration | 0 | 0 | 0 | 6 |

Sessions per scenario: ftp-connect-quit 6, http-browse 6, http-injection-requests 10, http-path-enumeration 6, nmap-http-enum 3, nmap-version-scan 11, sqlmap-default-run 1, ssh-download-and-run 6, ssh-enumeration 6, ssh-one-mistyped-login 6, ssh-password-guessing 12, ssh-persistence 6, ssh-read-and-send 6, telnet-connect 6.

What the misses were, by scenario:

- **Password guessing: 12 of 12 stored as benign.** The rule needed five
  failed logins in a session; the decoy lets a client in after two, so a
  guessing run that succeeds could never reach the count.
- **Requests for sensitive paths (`/.env`, `/.git/config`, `/phpmyadmin` and
  the like): 6 of 6 stored as benign.** No rule looked at the path alone.
- **A Shellshock header: 4 stored as reconnaissance** instead of
  exploitation; only the `/etc/passwd` in it was recognised.
- **`nmap` probe connections: 12 of 14 stored as benign** (10 of 11 from
  `-sV`, 2 of 3 from `--script http-enum`). A probe connection carries
  nothing the engine records beyond the connection itself. One `-sV` probe
  session was stored as exploitation, a false alarm.

## Run 2: after fixing the first three

The three rule gaps were fixed (each with a unit test), then the traffic was
generated again with a different random seed, so the sampled commands, paths
and passwords differ. 92 sessions (benign 24, exfiltration 6, exploitation 36, reconnaissance 26), code revision `31ec27a`.
Rule layer and stored verdict: accuracy 0.793 (95% interval 0.717–0.870), macro-F1 0.821 (0.745–0.879).

| labelled \ stored as | benign | reconnaissance | exploitation | exfiltration |
|---|---|---|---|---|
| benign | 24 | 0 | 0 | 0 |
| reconnaissance | 12 | 13 | 1 | 0 |
| exploitation | 5 | 1 | 30 | 0 |
| exfiltration | 0 | 0 | 0 | 6 |

Sessions per scenario: ftp-connect-quit 6, http-browse 6, http-injection-requests 11, http-path-enumeration 6, nmap-http-enum 3, nmap-version-scan 11, sqlmap-default-run 1, ssh-download-and-run 6, ssh-enumeration 6, ssh-one-mistyped-login 6, ssh-password-guessing 12, ssh-persistence 6, ssh-read-and-send 6, telnet-connect 6.

Run 2 is on the same scenario family the fixes were made for. It shows the
three gaps are closed. It does not show how the rules do on traffic nobody
here wrote, and the difference between the two runs is not a measurement of
improvement on real attacks.

What still misses in run 2:

- **Scan probe connections: 12 of 14 stored as benign** (`nmap -sV`, and the
  version-detection part of `nmap --script http-enum`). Judged one session at
  a time, a probe is an empty connection. Recognising a scan needs the source
  to be looked at across sessions, which the alert grouping does and the
  category does not.
- **Password guessing: 5 of 12 stored as benign.** In those sessions the
  first or second password was accepted, because the decoy remembers a
  password it let in before. One such session looks like a login.
- **One injection request stored as reconnaissance** (`;cat /etc/passwd` in a
  parameter). Fixed after this run; the fix is not reflected in the numbers
  above.
- **One `nmap -sV` probe session stored as exploitation**, as in run 1: a
  false alarm, and the only session in either run stored as more serious
  than its label.

## What the engine did not record

`ssh-banner-grab` ran six times in each run and left no session: a client
that connects to the SSH decoy, reads the banner and leaves is not recorded
at all. That was a gap in capture, found by this check. It has since been
closed: such a connection is now recorded as a session with no commands and
no credentials. The two runs above predate that fix.

## Limits

- The scripted shell and web scenarios were written by the people who wrote
  the rules. Only the `nmap` and `sqlmap` traffic is independent of them.
- One source address on loopback; flow timing is not what a remote client
  produces.
- 91 and 92 sessions, six of them exfiltration in each run. The intervals above are
  bootstrap intervals over these sessions and are wide.
- A scenario's label is given to every session in its time window.

The session files have the engine's local file paths for uploads removed
(`collect.py` does this); nothing else was edited.

## Files

`run1/` and `run2/` each hold `pipeline.json` (the tool's full output, with
per-class figures, technique-id validity and rule timing), `dataset.json`
(the set's composition and what was left out), `labels.jsonl`, and
`sessions.jsonl.gz` (the sessions as the engine stored them). To score them
again:

```sh
gunzip -k docs/evaluation/controlled/run2/sessions.jsonl.gz
cd backend && python -m app.tools.eval_pipeline \
    --sessions ../docs/evaluation/controlled/run2/sessions.jsonl \
    --labels ../docs/evaluation/controlled/run2/labels.jsonl
```
