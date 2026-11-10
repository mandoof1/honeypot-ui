# Configuration reference

[Back to the project overview](../README.md)

Every setting, in one place. Other documents name a setting and link here
rather than repeat its default, so a renamed or re-defaulted setting is
corrected in this file only.

**Where a value is set.** On the self-hosted deployment, in
`deploy/server/.env`, which `install.sh` writes and Compose reads; settings
marked *compose* are fixed in `deploy/server/docker-compose.yml` and changed
there. In development, in the repository-root `.env` (from `.env.example`).
On a remote sensor, in `deploy/node/.env`.

**Who reads it.** *API* = the backend image (the `backend` and `ingest`
services), defined in `backend/app/core/config.py`. *Engine* = the honeypot
engine, `honeypot/core/config.py`. *Host* = the scripts in `deploy/server/`.

Generate a secret with
`python3 -c "import secrets; print(secrets.token_urlsafe(48))"`.

## Secrets and identity

| Setting | Read by | Default | Purpose |
|---|---|---|---|
| `SECRET_KEY` | API | none; required outside development | Signs access and refresh tokens. |
| `ENCRYPTION_KEY` | API | none; required | Key material for AES-256-GCM over transcripts, credentials, payload bytes and authenticator secrets. Losing it makes them unreadable. |
| `ENCRYPTION_KEY_PREVIOUS` | API | empty | Old key(s), newest first, while rotating; see [rotating the key](../deploy/server/README.md#rotating-the-encryption-key). |
| `HONEYPOT_NODE_TOKENS` | API | empty | JSON object, node name → ingest token. A token is accepted only for its own node (403 otherwise). Assembled by `install.sh` / `node_tokens.py`; do not edit by hand. |
| `HONEYPOT_NODE_TOKEN_SHELL`, `_WEB`, `_TEST` | Host | generated | The local engines' and the test engine's tokens, from which the map above is built. Each engine receives its own as `HONEYPOT_INGEST_TOKEN`. |
| `HONEYPOT_INGEST_TOKEN` | API, Engine | none | Engine side: the engine's own token. The engine exits (code 78) if it is the published default, unless `HONEYPOT_ALLOW_DEFAULT_TOKEN=true`. API side: the single shared token used before per-node tokens; still required at start, and what development uses. |
| `HONEYPOT_CONTROL_TOKEN` | API, Engine | generated | Authenticates the backend's calls to an engine's control API. Must be set whenever node tokens are used. A sensor generates its own. |
| `POSTGRES_PASSWORD` | compose | generated | Database password. |
| `IOC_FEED_TOKEN` | API | empty | Static token (`X-Feed-Token`) for the plain-text indicator feed; empty leaves it session-only. |
| `HONEYPOT_IDENTITY_SEED` | Engine | generated | Both local engines derive hostname, OS and banners from it, so they describe one host. |

## API

| Setting | Default | Purpose |
|---|---|---|
| `ENVIRONMENT` | `development` | Anything else enforces real secrets and TLS to the database. |
| `API_ROLE` | `full` | `ingest` mounts only the engine-facing `*-internal` routes and `/health`. Set on the `ingest` service (*compose*). |
| `DATABASE_URL`, `DATABASE_URL_SYNC` | local Postgres | Runtime (asyncpg) and migration (psycopg2) connections. |
| `DATABASE_SSL` | on outside development | Override for the TLS requirement. |
| `RUN_MIGRATIONS_ON_STARTUP` | `true` | Off on `ingest`; the `backend` service migrates. |
| `BACKGROUND_WORKERS` | `false` | Queue, outbox, liveness, retention and scheduled model fits in this process. On for exactly one process (`backend`). |
| `CORS_ORIGINS` | localhost | Allowed browser origins (`DASHBOARD_ORIGIN` on the server). |
| `TRUST_PROXY_HEADERS` | `false` | Read `X-Forwarded-For`. On for `backend`, off for `ingest` (*compose*). |
| `TRUSTED_PROXIES` | loopback and all private ranges | Proxies whose `X-Forwarded-For` is believed. The server sets it to Caddy's two networks only (*compose*). |
| `RATE_LIMIT_PER_MINUTE` | `60` | Per-address API rate limit. |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | Largest body on user-facing routes (413 above). |
| `MAX_INTERNAL_BODY_BYTES` | `67108864` | Largest body on the engines' `*-internal` routes. |
| `DASHBOARD_CACHE_SECONDS` | `10` | How long the dashboard summary is served from memory; 0 disables. |
| `SEED_ON_STARTUP` | `false` | Insert the demo dataset (150 synthetic sessions) into an empty database. Development only. |
| `GEOIP_DB_PATH` | `./data/GeoLite2-City.mmdb` | MaxMind GeoLite2 or DB-IP City Lite file. |
| `SCANNER_LIST_PATH` | built-in list | A MISP warninglist export of research scanners. |
| `HONEYPOT_CONTROL_URL`, `HONEYPOT_CONTROL_EXTRA_URLS` | `http://honeypot:8000`, empty | Engines' control APIs: status from the first, mode changes and blocks to all. |

## Accounts and sign-in

| Setting | Default | Purpose |
|---|---|---|
| `ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_TOKEN_EXPIRE_DAYS` | `60`, `7` | Token lifetimes. |
| `LOGIN_LOCKOUT_THRESHOLD`, `LOGIN_LOCKOUT_MINUTES` | `10`, `15` | Account-level response to repeated wrong passwords. |
| `LOGIN_SOURCE_FAILURE_LIMIT` | `5` | Failed sign-ins from one address before that address is refused for the lockout period. |
| `OTP_MAX_CODES_PER_HOUR` | `5` | One-time codes issued per account per hour. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `BREVO_API_KEY`, `SENDGRID_API_KEY`, `RESEND_API_KEY` | empty | Mail providers. Without one, sign-up and password reset answer 503 (`GET /auth/capabilities` says which are available) and administrators create accounts. No container on the server can reach a mail provider; see below. |

## Alerts, notifications, retention

| Setting | Default | Purpose |
|---|---|---|
| `ALERT_DEDUP_WINDOW_MINUTES` | `60` | Repeats of one address at one category fold into the open alert. |
| `ALERT_SUPPRESS_SCANNERS` | `true` | Sessions attributed to a research scanner never alert. |
| `ALERT_EMAIL_FROM`, `ALERT_EMAIL_TO`, `WEBHOOK_URL`, `WEBHOOK_SECRET` | empty | Email and signed-webhook delivery. Inert on the server deployment: its containers cannot open outbound connections. Host-level alerting is `HEARTBEAT_URL`. |
| `NOTIFICATION_MAX_ATTEMPTS` | `6` | Delivery attempts before an outbox row is marked failed. |
| `NODE_STALE_SECONDS`, `NODE_OFFLINE_ALERT_SECONDS` | `180`, `300` | When a node shows offline, and when that raises a system alert. |
| `NODE_DISK_ALERT_FRACTION` | `0.10` | Free-disk fraction on an engine below which a system alert is raised. |
| `SESSION_RETENTION_DAYS` | **`0` = keep for ever** | Days captured sessions (with their alerts, indicators and payload links) are kept. Decide a period before exposure: [DATA_HANDLING.md](DATA_HANDLING.md). |
| `AUDIT_RETENTION_DAYS`, `OUTBOX_RETENTION_DAYS` | `365`, `30` | Audit log and delivered-notification retention. |
| `IOC_FEED_ALLOWLIST` | empty | Addresses and networks that never appear in the blocklist feed (your own egress address, a monitoring service). |

## Analysis and models

| Setting | Default | Purpose |
|---|---|---|
| `MODEL_PATH_RF`, `MODEL_PATH_IF` | `./models/...` | Classifier and anomaly model files; the cluster model is stored beside the first. Absent: a synthetic bootstrap, and verdicts say `model_source: "synthetic"`. |
| `SPACY_MODEL` | `en_core_web_sm` | Installed in the image at build time. |
| `CHIMERA_URL`, `CHIMERA_MODEL`, `CHIMERA_TIMEOUT` | empty, `wolfram` on the server, `300` | The language model (stage 2): an OpenAI-compatible endpoint, its name, seconds per call. Empty disables the stage. |
| `CHIMERA_MAX_TOKENS`, `CHIMERA_MAX_TRANSCRIPT_CHARS` | `600`, `6000` | Answer length; transcript sent. |
| `REPORT_MODEL_WAIT_SECONDS` | `420` | How long a report waits for the language model while the queue is using it. |
| `DECIDER_URL`, `DECIDER_MODEL`, `DECIDER_TIMEOUT` | empty, `kev-4b`, `120` | The decision model (triage and technique checks): a llama.cpp server with `/v1/systemone`. Empty disables it. |
| `DECIDER_MAX_TRANSCRIPT_CHARS` | `3000` | Transcript the decision model reads. |
| `DECIDER_SKIP_THRESHOLD`, `DECIDER_ESCALATE_THRESHOLD` | `0.85`, `0.6` | Probability needed to skip the language model (rules must agree), and to send a session the rules skipped. |
| `DECIDER_TRIAGE_RULE_SKIPPED` | `false` | Also triage sessions the rules skip. |
| `DECIDER_SUPPORT_THRESHOLD`, `DECIDER_DROP_UNCONFIRMED` | `0.3`, `false` | Below the first a language-model technique is marked unconfirmed; the second removes it instead. |
| `DECIDER_FALLBACK_SECONDS` | `900` | Wait on an unreachable decision model before the rules route the session. |
| `PAYLOAD_ANALYSIS_ENABLED`, `PAYLOAD_MAX_STORE_BYTES` | `true`, `10485760` | Static analysis of uploaded files; largest sample whose bytes are kept. |
| `PAYLOAD_ANALYSIS_TIMEOUT`, `PAYLOAD_ANALYSIS_MEMORY_MB`, `PAYLOAD_ANALYSIS_MAX_ATTEMPTS` | `60`, `2048`, `3` | Limits on the analysis subprocess, and tries before a sample is marked failed. |

## Engine

| Setting | Default | Purpose |
|---|---|---|
| `HONEYPOT_NODE_NAME` | `honeypot-engine-main` | The node this engine registers as. Unique per engine; its token is bound to it. (`HONEYPOT_WEB_NODE_NAME` names the server's web engine.) |
| `BACKEND_API_URL` | `http://backend:8000/api/v1` | Where sessions are delivered: the `ingest` service, or a sensor's `INGEST_ADDR`. |
| `HONEYPOT_PROTOCOLS` | `ssh,ftp,http` | Any of `ssh,telnet,ftp,http,https`. |
| `HONEYPOT_OPERATIONAL_MODE` | `active` | `active` answers; `passive` records attempts only. A mode saved in Settings wins once the engine registers. |
| `HONEYPOT_SSH_PORT`, `_TELNET_PORT`, `_FTP_PORT`, `_HTTP_PORT`, `_HTTPS_PORT` | `2222`, `2323`, `2121`, `8080`, `8443` | Listener ports inside the container. |
| `HONEYPOT_BIND_ADDRESS` | `0.0.0.0` | Address the decoys bind. |
| `HONEYPOT_CONTROL_BIND`, `HONEYPOT_CONTROL_PORT` | `0.0.0.0`, `8000` | Control API. The server binds it to the engine's `hs-control` address, a sensor to loopback (*compose*). |
| `HONEYPOT_FTP_PASV_PORTS`, `HONEYPOT_FTP_PASV_ADDRESS` | `50000-50019`, empty | Passive FTP range (the compose files publish `50000-50009`) and advertised address (`PUBLIC_IP` on the server). |
| `HONEYPOT_TLS_CERT`, `HONEYPOT_TLS_KEY` | generated at start | HTTPS decoy certificate; the installers create a persistent one. |
| `HONEYPOT_SSH_PROFILE` | `openssh-8.2p1-ubuntu` | The OpenSSH release imitated (banner and key exchange together). |
| `HONEYPOT_MAX_CONN_PER_IP`, `HONEYPOT_RATE_LIMIT`, `HONEYPOT_MAX_CONNECTIONS` | `5`, `60`, `500` | Concurrent connections per address, connections per minute, and total. |
| `HONEYPOT_HTTP_MAX_CONN_PER_IP`, `HONEYPOT_HTTP_RATE_LIMIT` | `32`, `600` | The same limits for the web decoys (a browser opens several connections per page). |
| `HONEYPOT_MAX_SESSION_SECONDS`, `HONEYPOT_CONN_TIMEOUT` | `1800`, per protocol | Longest connection; idle timeout (SSH 300 s, FTP 120 s, HTTP 60 s when unset). |
| `HONEYPOT_HTTP_MAX_BODY_BYTES` | `8388608` | Largest HTTP request body read. |
| `HONEYPOT_HTTP_SESSION_IDLE` | `30` | Seconds a web client's requests coalesce into one session. |
| `HONEYPOT_HTTP_UPSTREAM`, `_UPSTREAM_OWNS`, `_DECOY_UPSTREAM`, `_SESSION_COOKIE` | empty | A real web application behind the decoys, the bait paths it serves itself, its decoy copy, and its session cookie. |
| `HONEYPOT_HTTP_DIVERT_TTL`, `HONEYPOT_HTTP_DIVERT_FAILED_LOGINS` | `21600`, `10` | How long a diverted client stays diverted; failed logins in ten minutes that divert. |
| `HONEYPOT_ANTI_FINGERPRINT`, `HONEYPOT_ADAPTIVE_RESPONSE` | `true`, `true` | Banner consistency and response shaping. |
| `HONEYPOT_AI_CANARY` | `true` | Plants a note addressed to automated assistants; a session acting on it raises `ai_canary_triggered`. |
| `HONEYPOT_ACCEPTED_LOGIN_TTL` | `604800` | Seconds a source let in with a guessed password is let in again with it. |
| `HONEYPOT_ENABLE_ISOLATION`, `HONEYPOT_DOCKER_NETWORK` | `true`, `honeypot_isolated` | The engine's self-checks, and the network they refer to. |
| `HONEYPOT_ISOLATION_CHECK_INTERVAL` | `600` | Seconds between isolation re-checks reported in the heartbeat; 0 checks once. |
| `HONEYPOT_HEARTBEAT_INTERVAL` | `60` | Seconds between heartbeats. |
| `HONEYPOT_CAPTURE_DIR`, `HONEYPOT_FILE_CAPTURE_DIR` | `./data/sessions`, `./data/uploads` | Local copies, host keys, identity, the spool and the dead-letter directory (`spool/`, `failed/` under the first); raw uploads. |
| `HONEYPOT_SPOOL_MAX_FILES`, `HONEYPOT_SPOOL_MAX_BYTES` | `5000`, 512 MiB | Bounds on sessions waiting for the backend. |
| `HONEYPOT_CAPTURE_RETENTION_DAYS`, `HONEYPOT_UPLOAD_RETENTION_DAYS` | `7`, `30` | Pruning of the engine's local session copies and raw uploads. |
| `HONEYPOT_UPLOAD_FORWARD_MAX_BYTES`, `_SESSION_BYTES` | 8 MiB, 24 MiB | Largest file, and most per session, forwarded to the backend. |
| `HONEYPOT_ALLOW_DEFAULT_TOKEN` | `false` | Start despite the published default ingest token. Never outside a throwaway test. |

## Self-hosted deployment (`deploy/server/.env`, read by the host scripts and Compose)

| Setting | Default | Purpose |
|---|---|---|
| `DASHBOARD_ORIGIN`, `WEB_PORT` | tailnet name, `8088` | Dashboard URL (also the CORS origin) and its loopback port. |
| `PUBLIC_IP` | detected | Advertised in passive FTP replies. |
| `COMPOSE_PROFILES` | set by `install.sh` | `wolfram` and/or `decider`, on while that model file is present and verified. |
| `WOLFRAM_MODEL`, `WOLFRAM_THREADS`, `WOLFRAM_CPUS`, `WOLFRAM_MEM_LIMIT` | `wolfram-Q4_K_M.gguf`, `6`, `6`, `10g` | Language-model service. |
| `WOLFRAM_SHA256` | empty | Expected SHA-256 of that file. Empty: used unverified, and `install.sh` says so. |
| `DECIDER_MODEL_FILE`, `DECIDER_THREADS`, `DECIDER_CPUS`, `DECIDER_MEM_LIMIT` | `Kev-4B-Q8_0.gguf`, `6`, `6`, `6g` | Decision-model service; the file's checksum is pinned in `fetch-decider.sh`. |
| `INGEST_WORKERS` | `4` | Worker processes of the `ingest` service. |
| `HS_ISOLATED_GATEWAY` | `false` | Docker 28+: no host address on the internal bridges. |
| `BACKUP_AGE_RECIPIENT`, `BACKUP_GPG_RECIPIENT`, `BACKUP_PASSPHRASE_FILE` | empty | Backup encryption; the first one set is used. |
| `BACKUP_OFFSITE_RSYNC`, `BACKUP_OFFSITE_RCLONE`, `BACKUP_OFFSITE_ALLOW_PLAINTEXT` | empty | Off-host copy of each set; refused for an unencrypted set unless the third is `1`. |
| `BACKUP_DEST`, `BACKUP_KEEP_DAYS`, `BACKUP_ENGINE_CAPTURES` | `/var/backups/honeysentinel`, `14`, unset | Where, how long, and (`1`) include raw uploads even in an unencrypted set. |
| `HEARTBEAT_URL`, `HEARTBEAT_FAIL_URL`, `HEARTBEAT_BACKUP_MAX_AGE_HOURS` | empty, empty, `26` | Dead man's switch pinged while healthy; optional failure URL; backup age that counts as stale. |
| `GEOIP_REQUIRE_CHECKSUM` | `0` | `1` refuses a GeoIP download whose published checksum cannot be read. |
| `SHOP_SOURCE`, `SHOP_ADMIN_PASSWORD`, `SHOP_SEED_TIME` | `/opt/bolt-and-batten`, none, none | Only with the shop override. |
| `SENSOR_INGEST_BIND`, `SENSOR_INGEST_PORT` | none, `8001` | Only with the remote-sensors override: overlay address and port of the ingest endpoint. |
| `VITE_GEOIP_ATTRIBUTION` | DB-IP credit | Map attribution, built into the console. |

`deploy/server/egress.conf` (optional, root-owned): `PROFILE=server|sensor`
and `ALLOW_OUT="bridge:ipv4:port ..."`, the only outbound connections a
container may open. Empty on the server.

## Remote sensor (`deploy/node/.env`)

| Setting | Purpose |
|---|---|
| `HONEYPOT_NODE_NAME`, `HONEYPOT_NODE_TOKEN` | The name and the token issued for it on the server (`node_tokens.py add`). |
| `INGEST_ADDR`, `INGEST_PORT` | The server's ingest endpoint on the private overlay; also the firewall's one permitted destination. |
| `SENSOR_BIND_IPV4`, `SENSOR_PUBLIC_IPV4` | The local address the decoy ports bind, and the public address passive FTP advertises. |
| `HONEYPOT_PROTOCOLS`, `HONEYPOT_OPERATIONAL_MODE` | As for any engine. |

## Console (build time)

| Setting | Purpose |
|---|---|
| `VITE_API_URL` | API base including `/api/v1`. The server image builds with `/api/v1` (same origin). |
| `VITE_GEOIP_ATTRIBUTION` | HTML appended to the map's attribution. |

## Not yet in this file

The evaluation and export tools (`python -m app.tools.*`) take their options
on the command line; see each tool's `--help` and
[EVALUATION_PLAN.md](EVALUATION_PLAN.md). Settings introduced by work merged
after this file was written belong here, in the table of the component that
reads them.
