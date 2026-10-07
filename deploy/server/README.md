# Self-hosted deployment (one machine)

The whole system on a single Linux host: Postgres, the API, the dashboard and
the honeypot engine, with the dashboard reached over Tailscale. This is the
reference deployment on the project's Debian server; DEPLOY.md covers the
older split across Render, Vercel and a separate VM.

```
                      Tailscale (HTTPS, tailnet only)
                                   │
              127.0.0.1:8088 ──► web (Caddy: static build + /api proxy)
                                   │  app (internal)
                                   ▼
                     ┌──────── backend (dashboard API, 1 process) ──┐ control
   postgres ◄── db ──┤                                              ├─ engine ──► honeypot
                     └──────── ingest  (session analysis, 4 workers) ┘  (internal)    │
                                                                                       │
              :2222 :2121 :8080 :8443 :50000-50009 ◄── decoy bridge ───────────────────┘
                     (inbound only; host firewall drops egress)
```

| Network | Internal | Members | Why |
|---|---|---|---|
| `decoy` (`hs-decoy`) | no | honeypot | Docker only publishes ports on a network with a gateway. Egress is dropped by `honeysentinel-egress.sh`. |
| `engine` | yes | backend, ingest, honeypot | The engine reports sessions to `ingest`; `backend` reaches its control API, which binds only here. |
| `db` | yes | backend, ingest, postgres | Postgres requires TLS (`postgres/pg_hba.conf`). |
| `app` | yes | web, backend | The API has no route to the internet. |
| `edge` | no | web | Publishes the dashboard on loopback. |

`backend` and `ingest` run the same image. Session analysis is CPU-bound, so
it runs in `ingest` with four workers (`INGEST_WORKERS`). The dashboard API
stays a single process because its per-address rate limits are kept in
memory. docs/evaluation has the before-and-after measurements.

## Install

```bash
sudo git clone https://github.com/mandoof1/honeypot-ui.git /opt/honeysentinel
sudo bash /opt/honeysentinel/deploy/server/install.sh
```

`install.sh` is idempotent. It creates, once:

- `deploy/server/.env` with a random database password, JWT secret,
  encryption key and ingest token (mode 600). **Back this file up.** Losing
  `ENCRYPTION_KEY` makes every stored command and payload unreadable.
- `state/pg-tls/` with a self-signed certificate for Postgres.
- `state/geoip/city.mmdb`: DB-IP City Lite, which needs no account. It is
  CC BY 4.0, so the map credits it. A MaxMind GeoLite2-City file dropped in
  its place works unchanged, and sessions record which one resolved them
  (`source: dbip` or `geolite2`).
- `state/admin-credentials` with the administrator's generated password. The
  account is created directly, never through `SEED_ON_STARTUP`, which would
  insert 150 synthetic sessions.

It also installs three systemd units:

- `honeysentinel-egress.service` runs before Docker. It drops every connection
  the honeypot container starts, while letting replies to inbound connections
  through.
- `honeysentinel-backup.timer` takes a nightly `pg_dump` and keeps 14 days in
  `/var/backups/honeysentinel/`.

Finally it runs `tailscale serve`, so the dashboard is at
`https://<host>.<tailnet>.ts.net`. On a tailnet that has never used Serve,
the first run prints a link that a tailnet admin approves once; re-run
afterwards.

## Updating

```bash
cd /opt/honeysentinel && sudo git pull
sudo bash deploy/server/install.sh
```

## A real website behind the HTTP decoys

`HONEYPOT_HTTP_UPSTREAM=http://host:port` makes the HTTP and HTTPS decoys front a real application. Each request is recorded exactly as before (transcript, JSON or form logins as credentials, uploads, probe detection), then forwarded to the application, and its response is relayed back. Bait paths (`/.env`, `/wp-login.php`, `/phpmyadmin`, ...) are still answered by the decoy; `HONEYPOT_HTTP_UPSTREAM_OWNS` hands named bait paths to the application instead. Card numbers (Luhn-valid digit runs) and CVC fields are masked in everything the engine stores; the forwarded request is untouched. Client connections are kept alive, so a browser stays under the per-address connection limit.

The reference server uses this to serve the Bolt & Batten practice shop, a separate project built from `/opt/bolt-and-batten`. Its setup is `docker-compose.override.example.yml`: copy it to `docker-compose.override.yml` (git ignores that name; Compose merges it automatically), add `SHOP_ADMIN_PASSWORD` and `SHOP_SEED_TIME` (an ISO date) to `.env`, and re-run `install.sh`. Remove the override file and run `docker compose up -d --remove-orphans` to go back to the decoy's own pages.

### Diverting attackers to a decoy copy

`HONEYPOT_HTTP_DECOY_UPSTREAM=http://host:port` adds a second copy of the application, and the override runs the shop twice: `shop` (live) and `shop-decoy`. Every client starts on the live copy. One that gives itself away is answered by the decoy copy from then on: a request for a bait path (`/.env`, `/wp-login.php`, ...; not `/robots.txt` or `/sitemap.xml`), an attack pattern in the path, query or body, an attack tool's user agent (sqlmap, nikto, nuclei, ...), or `HONEYPOT_HTTP_DIVERT_FAILED_LOGINS` (10) failed logins within ten minutes. A client is its address plus user agent, so other people behind the same address are not diverted with it, and the session cookie named by `HONEYPOT_HTTP_SESSION_COOKIE` (`sid`) follows it if its address changes. The mark lapses after `HONEYPOT_HTTP_DIVERT_TTL` seconds (6 h) without a request, and an engine restart clears it. Diverted sessions carry an `http_diversion` event with the reason, shown on the dashboard as "Diverted to decoy", and each request the decoy copy answered is marked in the transcript.

The copies come from the same generator (`SHOP_ROLE` in the shop's `server/seed.js`): identical catalog, prices and reviews, dated as of `SHOP_SEED_TIME` so their pages match, but the decoy's customers have different emails, phones and addresses and its orders different shipping details and card digits. The decoy keeps the demo passwords (`admin1234`, `password123`) as bait; on the live copy no account has a known password, and the admin's is `SHOP_ADMIN_PASSWORD` (in `.env`; also in `state/shop-admin-credentials`, root only). Each copy is on its own internal network with the engine, so a compromised decoy cannot reach the live one.

What it cannot do: an attack none of those signals recognises reaches the live copy, as does everything an attacker sends before the first request that gives them away. A client signed in on the live copy appears signed out once diverted, since the decoy does not know its session.

`honeysentinel-shop-reset.timer` (enabled by `install.sh` when the override defines `shop`) runs `reset-shop.sh` nightly at about 04:15. It backs up the live copy without stopping it and regenerates the decoy copy, keeping the decoy's database as it stood (both to `/var/backups/honeysentinel/shop/`, 14 days), so nothing an attacker changed survives the night. The decoy copy is down for about 20 seconds meanwhile. With a single shop and no decoy copy, it resets that shop instead. Run `./reset-shop.sh` by hand to do it immediately.

## Exposing the honeypot to the internet

The emulators listen on high ports on every interface. To receive real
attacks, the upstream router or firewall must forward the well-known ports:

| Public | To this host |
|---|---|
| TCP 22 | 2222 |
| TCP 21 | 2121 |
| TCP 80 | 8080 |
| TCP 443 | 8443 |
| TCP 50000-50009 | 50000-50009 (FTP passive data) |

Mapping 22 to 2222 at the router leaves the host's real sshd on port 22 for
the LAN and tailnet. If the public address changes, update `PUBLIC_IP` in
`.env` and re-run `install.sh` so passive FTP advertises the right one.

Only do this on a network whose owner has agreed to it.

## Testing without polluting the data

Traffic you generate yourself must never be recorded as captured, so never
point a scanner or `ssh` at this host's decoy ports. Use `controlled-test.sh`:
it starts a throwaway engine registered as `controlled-test-node` on the
internal network, attacks it from another container (SSH brute force and
login, commands, a base64 file drop, an HTTP probe), and prints what the
pipeline recorded.

```bash
sudo bash controlled-test.sh            # keep the results, e.g. for a report figure
sudo bash controlled-test.sh --purge    # show them, then delete them
sudo bash controlled-test.sh --purge-only
```

Everything it produces belongs to the `controlled-test-node` node, so it can
always be told apart from real traffic and removed.

## Training the classifier

```bash
sudo bash train-model.sh             # CIC-IDS2017, tuned on a validation split
```

The script runs the whole procedure:

1. Downloads the dataset (885 MB) and verifies its checksums.
2. Trains in a network-less container from this checkout's code.
3. Installs the model into the backend's volume and restarts the API.

It takes about 40 minutes with tuning. backend/ml/README.md explains the
features and the caveats to state in the report.

## Measuring NFR-2 (TC13)

```bash
sudo bash stress-test.sh                                  # 500 sessions at once
sudo bash stress-test.sh --sessions 300 --concurrency 10
```

Each run writes `state/nfr2-<time>.json`, with per-session analysis time and
session-end-to-verdict turnaround read back from the database, then purges
its test sessions. Run it on an idle host.

## Operating

```bash
cd /opt/honeysentinel/deploy/server
docker compose ps
docker compose logs -f honeypot backend
sudo cat state/admin-credentials
sudo bash controlled-test.sh --purge                 # end-to-end check
sudo systemctl start honeysentinel-backup.service   # backup now
journalctl -k | grep 'hs-decoy egress blocked'      # anything the engine tried to reach
```

The backend has no internet access, so email and webhook alerts stay off
until it is attached to a network with egress. That is deliberate: the payload
analyser runs attacker-supplied files through parsers in that container.

### What watches the platform itself

The `backend` service runs the background workers (one process, on purpose):

- **Engine liveness.** Every engine heartbeats once a minute with its status
  (bound listeners, open connections, spool depth, disk). The Settings page
  shows each engine online or stale; after `NODE_OFFLINE_ALERT_SECONDS`
  (300) without a heartbeat a **system alert** is raised in the dashboard,
  and resolved by itself when the engine reports again. Low disk on the
  engine (<10 % free) and a spool that is not draining raise system alerts
  the same way.
- **Alert grouping.** Repeats of one address at the same category inside
  `ALERT_DEDUP_WINDOW_MINUTES` (60) fold into the open alert as `×N` rather
  than raising another row; only a severity escalation re-notifies. Known
  research scanners (Censys, Shodan, Shadowserver) are recorded but never
  alert (`ALERT_SUPPRESS_SCANNERS=true`).
- **Notification outbox.** Email and webhook sends are queued, delivered by
  a dispatcher with backoff (up to 6 attempts), and keep their last error.
  Nothing network-bound runs inside the ingest request any more.
- **Retention.** `SESSION_RETENTION_DAYS` (0 = keep everything) and
  `AUDIT_RETENTION_DAYS` (365), applied hourly. Alerts, indicators and
  payload links delete with their session.
- **Host failures.** A failed nightly backup raises a system alert through
  `system-alert.sh`, which any script on the host can use.

`GET /health` now pings the database (503 when it is down, so the container
health check means something) and reports the enrichment and outbox queues.

### The analysis model (stage 2)

The project's own fine-tune, **Wolfram**, reads each worthwhile transcript
and answers with the attacker's intent, objectives, ATT&CK techniques and
the indicators it names. It runs as the `wolfram` service (llama.cpp on the
CPU, internal network, no egress) and is enabled when the GGUF is present:

```bash
sudo install -m 0644 /path/to/wolfram-Q4_K_M.gguf state/models/
sudo bash install.sh          # turns on the llm profile and CHIMERA_URL
```

It is a queue, not a request: ingest marks a session `pending` when it is
worth a model call (shell and FTP sessions with commands; web sessions only
when a signature, tool, upload or non-benign category fired; never research
scanners), and the backend's worker drains it one session at a time — a
full answer takes about two minutes on this CPU. Identical transcripts
(bots replaying one script) are analysed once and the answer reused. Any
analyst can push a session to the front of the queue with **Analyse now**
in the session view. Indicators the model names are kept only when the text
appears in the transcript, so a transcript cannot plant indicators by
asking. `CHIMERA_TIMEOUT` (300 s) and `WOLFRAM_THREADS` (6) are the knobs.

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

### Accounts

Sign-up needs email, which this deployment cannot send. Administrators
create accounts in **Settings → Accounts** (temporary password shown once),
change roles, deactivate, reset a lost authenticator or password. Everyone
can change their own password there. Ten wrong passwords lock an account
for fifteen minutes (`LOGIN_LOCKOUT_THRESHOLD`, `LOGIN_LOCKOUT_MINUTES`).

### Backups and restore

`backup.sh` runs nightly (03:30) and writes `/var/backups/honeysentinel/<stamp>/`
with the database dump, `config.tar.gz` (`.env`, `state/`, the compose
override — **the encryption key lives here; without it the dump is
unreadable**), the engine's volume (host keys and identity, so a rebuilt
machine looks like the same machine) and a manifest with checksums. Fourteen
days are kept, on the same disk: copy them off the machine yourself.

```bash
sudo systemctl start honeysentinel-backup.service          # backup now
sudo bash restore.sh /var/backups/honeysentinel/20261007-033307
```

On a fresh machine: clone to `/opt/honeysentinel`, copy a backup directory
over, run `restore.sh` first (it puts `.env` and `state/` back), then
`install.sh`. `install.sh` also takes a backup before every update.

### Engine limits and durability

The engine keeps delivering sessions through a backend outage and bounds
what one client can cost it. All of these have defaults; set them in the
`honeypot` service's environment to change them.

| Variable | Default | What it does |
|---|---|---|
| `HONEYPOT_SPOOL_MAX_FILES` | `5000` | Sessions the backend could not take (down, timing out, 5xx, 429) wait under `<capture dir>/spool` and are resent oldest first, every 30 s (backing off to 5 min). The backend de-duplicates on the engine's session id. Past this many files the oldest are dropped and logged. |
| `HONEYPOT_SPOOL_MAX_BYTES` | `536870912` | Byte bound on the same queue (512 MiB). |
| `HONEYPOT_HEARTBEAT_INTERVAL` | `60` | Seconds between heartbeats to `/nodes/heartbeat-internal`, which carry the engine's status (version, bound listeners, open connections, spool depth, disk). A 404 re-registers the node. |
| `HONEYPOT_MAX_CONN_PER_IP` | `5` | Concurrent connections one address may hold open, across every protocol, enforced at accept (for SSH, before the key exchange). |
| `HONEYPOT_MAX_CONNECTIONS` | `500` | Concurrent connections across all addresses. |
| `HONEYPOT_MAX_SESSION_SECONDS` | `1800` | Longest a single connection may live, idle or not. |
| `HONEYPOT_CONN_TIMEOUT` | unset | Idle timeout for every protocol. Unset, SSH uses 300 s, FTP 120 s, HTTP 60 s. |
| `HONEYPOT_CAPTURE_RETENTION_DAYS` | `7` | Local JSON copies of ingested sessions are pruned after this many days (hourly pass). The spool, `failed/` and the SSH host keys are never touched. |
| `HONEYPOT_UPLOAD_RETENTION_DAYS` | `30` | Captured upload bytes in the engine's own directory are pruned after this many days; the backend keeps its encrypted copy. |

Also fixed in the same round: HTTP keep-alive connections are limited to 200
requests and 10 minutes, with 30 s for a request line plus headers; a heredoc
typed into the SSH shell no longer costs quadratic time per line; the per-
session command, event and credential lists are capped in memory (the
payload's `truncated` field says what was dropped); and the container has a
health check (`GET /healthz` on the control API, no token), a 1 GiB memory
limit and a 20 s stop grace period so open sessions are delivered on
shutdown. `GET /denied-connections` always answered from an in-process
"egress filter" that no socket ever consulted; it is gone, and the isolation
report's `egress_blocked` check now actually tries to connect out.
