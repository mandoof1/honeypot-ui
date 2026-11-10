# Self-hosted deployment (one machine)

The whole system on a single Linux host: Postgres, the API, the dashboard and
the honeypot engines, with the dashboard reached over Tailscale. This is the
reference deployment on the project's Debian server.

Settings are named here and described once, in
[docs/CONFIGURATION.md](../../docs/CONFIGURATION.md). Before forwarding any
port to this machine, follow
[docs/EXPOSURE_RUNBOOK.md](../../docs/EXPOSURE_RUNBOOK.md).

```
                Tailscale (HTTPS, tailnet only)
                             │
        127.0.0.1:8088 ──► web (Caddy: static build + /api proxy)        hs-edge
                             │ hs-app
                             ▼
   postgres ◄─ hs-db ─── backend (dashboard API, 1 process) ── hs-llm ──► wolfram, decider
       ▲                     │ hs-control (API → engines only)
       │                     ▼
       └── hs-db ── ingest ◄─ hs-engine ── honeypot      (SSH, FTP, Telnet)
            (API_ROLE=ingest, 4 workers)   honeypot-web  (HTTP, HTTPS)
                                              │ hs-decoy
     :2222 :2121 :2323 :8080 :8443 :50000-50009 ◄┘
     host firewall: every container may answer, none may open a connection
```

| Network (bridge) | Internal | Members | What may flow |
|---|---|---|---|
| `decoy` (`hs-decoy`) | no | honeypot, honeypot-web | Inbound to the published ports and the replies. Docker only publishes ports on a network with a gateway. |
| `engine` (`hs-engine`) | yes | ingest, honeypot, honeypot-web | Engines → `ingest:8000`. Nothing else, not even engine to engine. |
| `control` (`hs-control`) | yes | backend, honeypot, honeypot-web | Backend → an engine's control API (`:8000`). Engines cannot open connections here. |
| `app` (`hs-app`) | yes | web, backend | Proxy → API. |
| `db` (`hs-db`) | yes | postgres, backend, ingest | Postgres requires TLS (`postgres/pg_hba.conf`). |
| `llm` (`hs-llm`) | yes | backend, wolfram, decider | API → the two model servers. |
| `edge` (`hs-edge`) | no | web | Publishes the dashboard on loopback. |

The backend is deliberately **not** on `engine`. There an engine could
address the whole dashboard API; now the only thing it can reach is the
`ingest` service, which runs with `API_ROLE=ingest` and serves the three
`*-internal` routes and `/health`. The backend's API listens on its `hs-app`
address only, so it does not answer on `hs-control` either.

The decoys run as two engines from one image, so the dashboard lists two
nodes: `honeypot` (`HONEYPOT_NODE_NAME`, the shell services) and
`honeypot-web` (`HONEYPOT_WEB_NODE_NAME`, the website). Both are seeded with
`HONEYPOT_IDENTITY_SEED` so they describe the same host. Each has its own
ingest token, valid for its node name only.

`backend` and `ingest` are one image from one build. Session analysis is
CPU-bound, so it runs in `ingest` with four workers (`INGEST_WORKERS`); the
dashboard API stays a single process because its rate limits are kept in
memory. [docs/evaluation](../../docs/evaluation/README.md) has the
measurements.

Every service runs without capabilities, with `no-new-privileges`, a
read-only root filesystem and memory, process and log limits; what each may
write is listed as a volume or tmpfs in `docker-compose.yml`.

## Install

Prerequisites, done by hand:

- **BIOS: "After Power Loss" → "Power On".** Without it a power cut ends the
  deployment until someone presses the button.
- Debian or Ubuntu with Docker, the Compose plugin, nftables, git, curl,
  openssl, python3 and Tailscale (the installer lists what is missing).

```bash
sudo git clone https://github.com/mandoof1/honeypot-ui.git /opt/honeysentinel
sudo bash /opt/honeysentinel/deploy/server/install.sh
```

`install.sh` is idempotent. It creates, once:

- `deploy/server/.env` (mode 600) with a random database password, JWT
  secret and encryption key, one ingest token per engine, and a control
  token. **Back this file up** (the backup does). Losing `ENCRYPTION_KEY`
  makes every stored command and payload unreadable.
- `state/pg-tls/` and `state/decoy-tls/`: self-signed certificates for
  Postgres and the HTTPS decoy.
- `state/geoip/city.mmdb`: DB-IP City Lite (CC BY 4.0, credited on the map),
  compared with the SHA-1 DB-IP publishes where that can be read. A MaxMind
  GeoLite2-City file put there by hand works unchanged and is left alone.
- The administrator, created directly and never through `SEED_ON_STARTUP`
  (which would insert 150 synthetic sessions). **Its password is printed
  once and stored nowhere.** Change it and enable two-factor sign-in
  straight away. Lost it: `sudo bash install.sh --reset-admin-password`.

It installs these systemd units:

| Unit | Does |
|---|---|
| `honeysentinel-egress.service` | Loads the egress rules before Docker starts. A drop-in makes Docker `Require` it: no rules, no containers. Updated with `systemctl reload`, never `restart` (a restart would restart Docker). |
| `honeysentinel-egress-check.timer` | Every 5 minutes: verifies the loaded rules and the Docker networks; re-applies and raises a critical system alert if anything was missing. |
| `honeysentinel-heartbeat.timer` | Every 5 minutes: host-level health check; pings `HEARTBEAT_URL` only while everything is healthy. |
| `honeysentinel-backup.timer` | Nightly backup (03:30), 14 days kept. |
| `honeysentinel-geoip.timer` | Weekly GeoIP refresh. |
| `honeysentinel-shop-reset.timer` | Nightly shop reset; only enabled when an override defines `shop`. |
| `honeysentinel-alert@.service` | The `OnFailure=` hook of the jobs above: a failed job becomes a system alert in the dashboard. |

It builds the images labelled with the git revision, starts the stack, and
then verifies it before it finishes: the same revision in every container,
the networks the firewall expects, and a connection test from inside each
engine. It exits non-zero if any of these fails.

Finally it runs `tailscale serve`, so the dashboard is at
`https://<host>.<tailnet>.ts.net`. On a tailnet that has never used Serve,
the first run prints a link that a tailnet admin approves once; re-run
afterwards.

## Updating

```bash
cd /opt/honeysentinel && sudo git pull
sudo bash deploy/server/install.sh
```

Use `install.sh`, not `docker compose up --build`: it passes the revision to
the build, recreates `backend` and `ingest` together, and re-runs the
verification. Nothing running is touched until the images have built.

**The first update to 1.0.0** additionally:

- recreates the container networks (they gain fixed names and subnets), so
  the stack is down for about a minute; volumes are untouched;
- stops at step 1 if `docker-compose.override.yml` predates the fixed
  network names: bring it in line with `docker-compose.override.example.yml`
  and re-run;
- replaces the old iptables chain with the nftables rules;
- gives each engine its own token (sessions spooled meanwhile are delivered
  afterwards);
- prints a reminder if `state/admin-credentials` from an older version still
  holds the first password in plain text.

## Containment: the egress firewall

`honeysentinel-egress.sh` owns two nftables tables. For every bridge named
`hs-*`, and for every source address in `172.30.64.0/19`, IPv4 and IPv6:

- container → the host itself: replies only;
- container → any other network: replies only;
- container → another container on the same bridge: only the pairs in the
  network table above.

```bash
sudo bash honeysentinel-egress.sh check    # rules and networks as expected? (exit 0/1/2)
sudo bash honeysentinel-egress.sh probe    # connect out from inside the engines
sudo bash honeysentinel-egress.sh status   # the rules, with counters
journalctl -k | grep 'hs egress blocked'   # what containers tried to reach
bash tests/egress-netns-test.sh            # the rules against a model network; no Docker needed
```

The names, subnets and addresses in `docker-compose.yml` are the firewall's
address plan; `scripts/check-network-plan.py` (in CI, and at the top of
`install.sh`) fails when the two differ.

**Optional second layer (Docker 28+).** `HS_ISOLATED_GATEWAY=true` in `.env`
makes the internal bridges have no host address at all
(`docker-compose.isolated-gateway.yml`). Not enabled by default and not yet
run on the reference server.

### Alerts leave by the host

No container can open an outbound connection, so the email and webhook
settings do nothing here; that is deliberate (the payload analyser parses
attacker-supplied files in the API's container). What reaches the outside:

- the dashboard's own alerts, for whoever is looking;
- the host heartbeat: set `HEARTBEAT_URL` to a dead man's switch
  (healthchecks.io, an Uptime Kuma push monitor, Better Stack, Cronitor;
  period 5 minutes, grace 10). `host-heartbeat.sh` requests it only when all
  containers are healthy, the firewall is intact, the newest backup is under
  26 hours old, one revision is running and the disk has room. When the
  requests stop, for any reason including the host being off, that service
  alerts. Each run is also logged to `state/availability.jsonl`.

## A real website behind the HTTP decoys

`HONEYPOT_HTTP_UPSTREAM=http://host:port` makes the HTTP and HTTPS decoys front a real application. Each request is recorded exactly as before (transcript, JSON or form logins as credentials, uploads, probe detection), then forwarded to the application, and its response is relayed back. Bait paths (`/.env`, `/wp-login.php`, `/phpmyadmin`, ...) are still answered by the decoy; `HONEYPOT_HTTP_UPSTREAM_OWNS` hands named bait paths to the application instead. Card numbers (Luhn-valid digit runs) and CVC fields are masked in everything the engine stores; the forwarded request is untouched. Client connections are kept alive, so a browser stays under the per-address connection limit.

**Every visitor's requests are recorded, logins included.** Read
[docs/DATA_HANDLING.md](../../docs/DATA_HANDLING.md#when-a-real-website-sits-behind-the-web-decoys)
before putting a site there.

The reference server uses this to serve the Bolt & Batten practice shop, a separate project built from `/opt/bolt-and-batten`. Its setup is `docker-compose.override.example.yml`: copy it to `docker-compose.override.yml` (git ignores that name; Compose merges it automatically), add `SHOP_ADMIN_PASSWORD` and `SHOP_SEED_TIME` (an ISO date) to `.env`, and re-run `install.sh`. To go back to the decoy's own pages, remove the override file and re-run `install.sh`.

### Diverting attackers to a decoy copy

`HONEYPOT_HTTP_DECOY_UPSTREAM=http://host:port` adds a second copy of the application, and the override runs the shop twice: `shop` (live) and `shop-decoy`. Every client starts on the live copy. One that gives itself away is answered by the decoy copy from then on: a request for a bait path (`/.env`, `/wp-login.php`, ...; not `/robots.txt` or `/sitemap.xml`), an attack pattern in the path, query or body, an attack tool's user agent (sqlmap, nikto, nuclei, ...), or `HONEYPOT_HTTP_DIVERT_FAILED_LOGINS` failed logins within ten minutes. A client is its address plus user agent, so other people behind the same address are not diverted with it, and the session cookie named by `HONEYPOT_HTTP_SESSION_COOKIE` follows it if its address changes. The mark lapses after `HONEYPOT_HTTP_DIVERT_TTL` seconds without a request, and an engine restart clears it. Diverted sessions carry an `http_diversion` event with the reason, shown on the dashboard as "Diverted to decoy", and each request the decoy copy answered is marked in the transcript.

The copies come from the same generator (`SHOP_ROLE` in the shop's `server/seed.js`): identical catalog, prices and reviews, dated as of `SHOP_SEED_TIME` so their pages match, but the decoy's customers have different emails, phones and addresses and its orders different shipping details and card digits. The decoy keeps the demo passwords (`admin1234`, `password123`) as bait; on the live copy no account has a known password, and the admin's is `SHOP_ADMIN_PASSWORD` in `.env`. Each copy is on its own internal network with the web engine, and the firewall allows one flow on each: the engine to the shop's port 3000. A compromised decoy cannot reach the live copy, the engine or the host.

What it cannot do: an attack none of those signals recognises reaches the live copy, as does everything an attacker sends before the first request that gives them away. A client signed in on the live copy appears signed out once diverted, since the decoy does not know its session.

`honeysentinel-shop-reset.timer` runs `reset-shop.sh` nightly at about 04:15. It backs up the live copy without stopping it and regenerates the decoy copy, keeping the decoy's database as it stood (both to `/var/backups/honeysentinel/shop/`, 14 days), so nothing an attacker changed survives the night. The decoy copy is down for about 20 seconds meanwhile. With a single shop and no decoy copy, it resets that shop instead. Run `./reset-shop.sh` by hand to do it immediately. A failed run raises a system alert.

## Exposing the honeypot to the internet

The procedure, with its checklists, is
[docs/EXPOSURE_RUNBOOK.md](../../docs/EXPOSURE_RUNBOOK.md). In short, the
upstream firewall forwards the well-known ports (IPv4):

| Public | To this host |
|---|---|
| TCP 22 | 2222 |
| TCP 23 | 2323 |
| TCP 21 | 2121 |
| TCP 80 | 8080 |
| TCP 443 | 8443 |
| TCP 50000-50009 | 50000-50009 (FTP passive data) |

Mapping 22 to 2222 leaves the host's real sshd on port 22 for the LAN and
tailnet. If the public address changes, update `PUBLIC_IP` in `.env` and
re-run `install.sh` so passive FTP advertises the right one.

Only do this on a network whose owner has agreed to it, in writing.

## Remote sensors

A sensor on another machine ([deploy/node](../node/README.md)) delivers to
this server's `ingest` service over a private overlay. To accept one:
follow `docker-compose.remote-sensors.example.yml`, then

```bash
sudo python3 node_tokens.py add <node-name>     # prints the token once
docker compose up -d backend ingest
sudo python3 node_tokens.py list                # names, never tokens
```

## Testing without polluting the data

Traffic you generate yourself must never be recorded as captured, so never
point a scanner or `ssh` at this host's decoy ports. Use `controlled-test.sh`:
it starts a throwaway engine registered as `controlled-test-node` (with that
node's own token), attacks it from another container on a bridge the two
share with nothing else (SSH brute force and login, commands, a base64 file
drop, an HTTP probe), and prints what the pipeline recorded.

```bash
sudo bash controlled-test.sh            # keep the results, e.g. for a report figure
sudo bash controlled-test.sh --purge    # show them, then delete them
sudo bash controlled-test.sh --purge-only
```

Everything it produces belongs to the `controlled-test-node` node, so it can
always be told apart from real traffic and removed. To date this is the only
kind of traffic the deployment has recorded.

## Training the classifier

```bash
sudo bash train-model.sh             # CIC-IDS2017, tuned on a validation split
```

1. Downloads the dataset (885 MB) and verifies its checksums.
2. Trains in a network-less container from this checkout's code.
3. Installs the model into the models volume and restarts `backend` and
   `ingest`.

It takes about 40 minutes with tuning. backend/ml/README.md explains the
features; [docs/evaluation](../../docs/evaluation/README.md) says what the
resulting numbers do and do not show.

## Measuring NFR-2 (TC13)

```bash
sudo bash stress-test.sh                                  # 500 sessions at once
sudo bash stress-test.sh --sessions 300 --concurrency 10
```

Each run writes `state/nfr2-<time>.json`, with per-session analysis time,
session-end-to-verdict turnaround read back from the database, and the git
revision of the running image, then purges its test sessions. Run it on an
idle host.

## Operating

```bash
cd /opt/honeysentinel/deploy/server
docker compose ps
docker compose logs -f honeypot backend
sudo bash controlled-test.sh --purge                 # end-to-end check
sudo systemctl start honeysentinel-backup.service   # backup now
sudo bash host-heartbeat.sh                          # the host checks, now
systemctl list-timers 'honeysentinel-*'
```

### What watches the platform

On the host:

- **Egress check** (5 min): rules and networks; re-applies and alerts.
- **Heartbeat** (5 min): containers, firewall, backup age, revision skew,
  disk; external ping while healthy; `host_health` system alert otherwise.
- **Failed jobs**: backup, shop reset, GeoIP refresh and the egress check
  raise a system alert through `honeysentinel-alert@.service`.

In the `backend` service (one process, on purpose):

- **Engine liveness.** Every engine heartbeats once a minute with its status
  (bound listeners, open connections, spool depth, disk, and its own
  isolation checks, repeated every `HONEYPOT_ISOLATION_CHECK_INTERVAL`
  seconds). After `NODE_OFFLINE_ALERT_SECONDS` without a heartbeat a system
  alert is raised, and resolved when the engine reports again. Low disk and
  a spool that is not draining alert the same way.
- **Alert grouping.** Repeats of one address at the same category inside
  `ALERT_DEDUP_WINDOW_MINUTES` fold into the open alert; known research
  scanners are recorded but never alert.
- **Retention.** `SESSION_RETENTION_DAYS` and `AUDIT_RETENTION_DAYS`,
  applied hourly. The session default keeps everything for ever; set a
  period before exposure.

`GET /health` pings the database (503 when it is down) and reports the
enrichment and outbox queues.

### The analysis model (stage 2)

The project's own fine-tune, **Wolfram**, reads each worthwhile transcript
and answers with the attacker's intent, objectives, ATT&CK techniques and
the indicators it names. It runs as the `wolfram` service (llama.cpp on the
CPU, internal network, no egress) and is enabled when the GGUF is present:

```bash
sudo install -m 0644 /path/to/wolfram-Q4_K_M.gguf state/models/
sudo bash install.sh          # turns on the wolfram profile and CHIMERA_URL
```

No checksum for this file is pinned in the repository. `install.sh` prints
its SHA-256 and says it is unverified until you record the expected value as
`WOLFRAM_SHA256` in `.env`; with that set, a file that does not match keeps
the stage off.

It is a queue, not a request: ingest marks a session `pending` when it is
worth a model call (shell and FTP sessions with commands; web sessions only
when a signature, tool, upload or non-benign category fired; never research
scanners), and the backend's worker drains it one session at a time. A full
answer takes about two minutes on this CPU. Identical transcripts are
analysed once and the answer reused. Any analyst can push a session to the
front of the queue with **Analyse now**. Indicators the model names are kept
only when the text appears in the transcript.

### Triage: the decision model in front of Wolfram

A second, faster model triages each session **the rules queue for Wolfram**
before Wolfram sees it; it does not triage every session. **Kev-4B**
(Apache-2.0) never writes text: it reads the transcript once and returns
probabilities over options the backend supplies, through llama.cpp's
`/v1/systemone`. On this CPU that took a median of about 8 s on the
synthetic shell transcripts and 16 s on stored web sessions
([measurements](../../docs/evaluation/README.md#decision-model-triage-and-technique-checks)).
It runs as the `decider` service, with its own profile:

```bash
sudo bash fetch-decider.sh    # pinned revision, SHA-256 checked, 4.5 GB
sudo bash install.sh          # verifies the file, turns on DECIDER_URL
```

For each such session it answers three questions: which of the pipeline's
four categories, how severe on a 0–3 scale, and automated or human. Then:

- **Skips Wolfram** only when triage puts at least `DECIDER_SKIP_THRESHOLD`
  on "information gathering at most" *and* the rules found nothing past
  reconnaissance. Rule evidence of exploitation always goes through.
- Otherwise the session goes to Wolfram as before. The reason is stored and
  shown in the session view, where **Analyse now** still overrides a skip.

Sessions the rules skip (plain web browsing, short benign FTP) are left
alone unless `DECIDER_TRIAGE_RULE_SKIPPED=true`. It is off because on the
team's own shop browsing the model called 30 of 32 benign sessions
reconnaissance, at about 16 s of CPU each, and escalated none.

After Wolfram answers, the decider checks each technique it named that the
rule map did not. Below `DECIDER_SUPPORT_THRESHOLD` a technique is marked
*unconfirmed*: still listed, but it does not add a tactic to the session.

The two models never run at the same time. If the decider is down, sessions
waiting on it go to Wolfram on the rules' verdict after
`DECIDER_FALLBACK_SECONDS`. To triage sessions captured before it was
enabled:

```bash
docker compose exec backend python -m app.tools.reanalyze --all --queue-triage
```

### Re-running the rules over old sessions

Verdicts are fixed at ingest, so a signature change leaves old rows on the
old rules. The reanalysis tool rebuilds the rule inputs from what each row
stores and rewrites the category, intents, tools, techniques and reason,
without raising alerts or sending anything:

```bash
docker compose exec backend python -m app.tools.reanalyze --all --dry-run
docker compose exec backend python -m app.tools.reanalyze --all
docker compose exec backend python -m app.tools.reanalyze --since 2026-10-01 --queue-llm
```

`--summary-only` rebuilds just the plain command summary kept for search.

Tools that write a file should write under `/app/out`, which is
`state/out` on the host; the rest of the container's filesystem is read-only.

### Accounts

Sign-up and password reset need email, which this deployment cannot send;
the API answers 503 for both and the sign-in page hides them
(`GET /auth/capabilities`). Administrators create accounts in **Settings →
Accounts** (temporary password shown once), change roles, deactivate, reset
a lost authenticator or password. Everyone can change their own password
there. Repeated wrong passwords are limited per source address and per
account.

### Backups and restore

`backup.sh` runs nightly and writes `/var/backups/honeysentinel/<stamp>/`:

| File | Holds |
|---|---|
| `db.sql.gz` | The database. |
| `config.tar.gz` | `.env`, `state/` (keys, certificates, sensor tokens), the compose override. **The encryption key is here; without it the dump is unreadable.** |
| `models.tar.gz` | The trained classifier and the fitted cluster and anomaly models. |
| `engine-data.tar.gz`, `engine-web-data.tar.gz` | Host keys and identity (so a rebuilt machine looks like the same machine), undelivered sessions, local captures. |
| `shop-source.tar.gz` | The shop's source, when an override builds one. |
| `MANIFEST` | Sizes, SHA-256, row counts at dump time, the git revision. |

**Encrypt them.** A set contains every secret of the deployment. Set one of
these in `.env`:

```
BACKUP_AGE_RECIPIENT=age1...            # preferred: needs `apt install age`
BACKUP_GPG_RECIPIENT=backup@example.org # a key in root's GnuPG keyring
BACKUP_PASSPHRASE_FILE=/root/.hs-backup-pass   # symmetric: gpg, or openssl without it
```

With a public key the server writes backups it cannot read: keep the
matching identity (`age-keygen -o key.txt`) off this machine. Without any of
them the set is plain text, uploaded files are left out of it, and every run
says so.

**Copy them off the machine.** `BACKUP_OFFSITE_RSYNC=user@host:/path` or
`BACKUP_OFFSITE_RCLONE=remote:path` copies each finished set; an unencrypted
set is not sent unless `BACKUP_OFFSITE_ALLOW_PLAINTEXT=1`.

```bash
sudo systemctl start honeysentinel-backup.service                 # backup now
sudo bash restore-drill.sh --identity /path/to/key.txt            # rehearse
sudo bash restore.sh /var/backups/honeysentinel/<stamp> --identity /path/to/key.txt
```

`restore-drill.sh` restores the newest set into a throwaway database and
checks the row counts, that a stored transcript decrypts with the key in the
same set, and that the classifier is in it. Nothing live is written. Run it
after the first backup and after any change to the backup settings.

On a fresh machine: clone to `/opt/honeysentinel`, copy a backup directory
over, run `restore.sh` first (it puts `.env`, `state/`, the shop source, the
database and the volumes back; the dump loads in a single transaction), then
`install.sh`. The language-model files are not in the backup: copy Wolfram's
GGUF back and run `fetch-decider.sh`. `install.sh` also takes a backup before
every update.

### Rotating the encryption key

```bash
# 1. In .env: move the current ENCRYPTION_KEY value to ENCRYPTION_KEY_PREVIOUS
#    and put a new one in ENCRYPTION_KEY. Then:
docker compose up -d backend ingest
# 2. Re-encrypt what is stored (safe to stop and run again):
docker compose exec backend python -m app.core.rotate_key --dry-run
docker compose exec backend python -m app.core.rotate_key
# 3. When it reports nothing left and nothing failed, remove
#    ENCRYPTION_KEY_PREVIOUS from .env and:
docker compose up -d backend ingest
```

Backups taken before the rotation need the old key.

### Engine limits and durability

The engine keeps delivering sessions through a backend outage and bounds
what one client can cost it: a retry queue on disk (`HONEYPOT_SPOOL_MAX_*`)
replayed oldest first and de-duplicated on the engine's session id; a
dead-letter directory for sessions the backend refuses for good; connection
limits per address and in total (`HONEYPOT_MAX_CONN_PER_IP`,
`HONEYPOT_MAX_CONNECTIONS`, and larger ones for the web decoys); a session
time limit; and pruning of local copies (`HONEYPOT_CAPTURE_RETENTION_DAYS`,
`HONEYPOT_UPLOAD_RETENTION_DAYS`). All are in the
[engine table](../../docs/CONFIGURATION.md#engine); set them in the engine
services' environment to change them.

HTTP keep-alive connections are limited to 200 requests and 10 minutes, with
30 s for a request line plus headers; the per-session command, event and
credential lists are capped in memory (the payload's `truncated` field says
what was dropped); the container has a health check (`GET /healthz` on the
control API, no token), a 1 GiB memory limit and a 20 s stop grace period so
open sessions are delivered on shutdown.

`GET /api/v1/honeypot/denied-connections` is still served, by the API and by
the engine's control API, and returns an empty list: the in-process "egress
filter" it once reported on never filtered anything and was removed. What
the engine's isolation report says about egress comes from actually trying
to connect out.
