# Controlled, labelled test traffic

The analysis pipeline needs labelled sessions to be measured against. Until
the decoys have captured real attackers and someone has labelled a sample of
them (the protocol in [docs/EVALUATION_PLAN.md](../../docs/EVALUATION_PLAN.md)),
this produces the nearest honest substitute: traffic whose class is known
because of how it was made.

It is test traffic. Every target is `127.0.0.1`; the addresses inside the
commands are from the documentation ranges and are not routed. Results from
it describe how the pipeline handles these scenarios and nothing else.

## What it runs

| Label | Scenarios |
|---|---|
| benign | SSH banner grab, Telnet connect, FTP connect and quit, three ordinary page requests, one mistyped SSH login |
| reconnaissance | system enumeration after an SSH login, requests for common admin paths, `nmap -sV` on every decoy port, `nmap --script http-enum` |
| exploitation | download-and-run sequences, persistence (authorised key, cron), a run of wrong SSH passwords, injection and traversal requests, a default `sqlmap` run |
| exfiltration | reading credential files and sending them to another host |

The label definitions are written into the manifest before any traffic is
sent. `nmap` and `sqlmap` are used when installed (`--fetch-tools` allows
`uvx sqlmap`) and their absence is noted, not hidden.

## Run it

Start an engine on loopback that cannot reach a backend, with the rate
limits lifted (every connection comes from one address) and a short web
idle window (labels are attached by time window, so a scenario's sessions
must close before the next begins):

```sh
RUN=$(mktemp -d)
HONEYPOT_NODE_NAME=controlled-test-node \
HONEYPOT_INGEST_TOKEN=controlled-traffic-local \
BACKEND_API_URL=http://127.0.0.1:9/api/v1 \
HONEYPOT_ENABLE_ISOLATION=false \
HONEYPOT_BIND_ADDRESS=127.0.0.1 HONEYPOT_CONTROL_BIND=127.0.0.1 HONEYPOT_CONTROL_PORT=48000 \
HONEYPOT_PROTOCOLS=ssh,ftp,telnet,http \
HONEYPOT_SSH_PORT=42222 HONEYPOT_FTP_PORT=42121 HONEYPOT_TELNET_PORT=42323 HONEYPOT_HTTP_PORT=48080 \
HONEYPOT_FTP_PASV_PORTS=45000-45009 \
HONEYPOT_CAPTURE_DIR=$RUN/data/sessions HONEYPOT_FILE_CAPTURE_DIR=$RUN/data/uploads \
HONEYPOT_MAX_CONN_PER_IP=400 HONEYPOT_RATE_LIMIT=20000 \
HONEYPOT_HTTP_MAX_CONN_PER_IP=400 HONEYPOT_HTTP_RATE_LIMIT=20000 \
HONEYPOT_HTTP_SESSION_IDLE=2 \
python -m honeypot.main &

python -m tools.controlled_traffic.generate --manifest $RUN/manifest.jsonl \
    --ssh 42222 --telnet 42323 --ftp 42121 --http 48080 --rounds 6

# stop the engine, then:
python -m tools.controlled_traffic.collect --manifest $RUN/manifest.jsonl \
    --captures $RUN/data/sessions --out $RUN

cd backend && python -m app.tools.eval_pipeline \
    --sessions $RUN/sessions.jsonl --labels $RUN/labels.jsonl \
    --dataset-description "controlled test traffic, generated on loopback" \
    --out ../docs/evaluation/pipeline-controlled-<date>.json
```

`collect` also writes `dataset.json`: the size of the set by label, scenario
and protocol, how many stored sessions were left out and why, and the limits
of the set. Keep it beside the result.

## Limits

- The scripted shell and web scenarios were written by the people who wrote
  the rules. The rule layer is therefore being scored on traffic that
  resembles what it was built for; only the `nmap` and `sqlmap` traffic is
  independent of it.
- One source address, on loopback: flow timing is not what a remote client
  produces.
- A scenario's label is given to every session in its time window. Each
  probe connection of a scan carries the scan's label.
