# Technical reference

[Back to the project overview](../README.md)

## Architecture

```
        Attacker
           │  SSH 2222 / FTP 2121 / Telnet 2323 / HTTP 8080 / HTTPS 8443
           ▼
┌──────────────────────────────────────────────┐
│  Honeypot Engine  (honeypot/)                │
│  · protocol emulators + session capture      │
│  · socket-level flow meter (classifier input)│
│  · anti-fingerprinting banner rotation       │
│  · per-IP rate limiting                      │
│  · control API (token-authenticated)         │
└───────────────┬──────────────────────────────┘
                │ POST /sessions/ingest-internal   (X-Honeypot-Token)
                │ GET  control API                 (X-Honeypot-Token)
                ▼
┌──────────────────────────────────────────────┐
│  Backend API  (backend/)  FastAPI            │
│  · JWT auth + RBAC (viewer/analyst/admin)    │
│  · analysis pipeline (see below); deploy/    │
│    server runs it in a multi-worker `ingest` │
│    service beside the dashboard API          │
│  · alerting: email + signed webhook          │
│  · export: CSV / JSON / CEF / STIX 2.1             │
└───────────────┬──────────────────────────────┘
                │ SQLAlchemy (async)
                ▼
        ┌───────────────┐
        │  PostgreSQL   │
        └───────────────┘
                ▲
                │ REST + JWT
┌───────────────┴──────────────────────────────┐
│  Dashboard  (src/)  React 19 + Vite          │
│  Dashboard │ Live Map │ Sessions │ Settings  │
└──────────────────────────────────────────────┘
```

The engine reaches the backend only over an **internal** Docker network.
Docker refuses to publish ports for a container whose only network is
internal, so the decoy ports sit on a second bridge. On that bridge,
`deploy/server/honeysentinel-egress.sh` (a systemd unit that runs before
Docker) lets replies to inbound connections through and drops every connection
the engine tries to open. A process that escaped an emulator would have no way
out, and the engine's isolation check verifies this by attempting connections
outward rather than reading the routing table.

---

## Analysis pipeline

Each ingested session runs through, in order:

| Stage | Implementation | Output |
|---|---|---|
| Geolocation | MaxMind GeoLite2 or DB-IP City Lite (recorded as the location's `source`) | country / city / lat / lon, or an explicit "unknown" |
| Classification | Random Forest over 12 flow features the engine measures at its sockets, trained on CIC-IDS2017 ([results](evaluation/README.md)) | benign / reconnaissance / exploitation / exfiltration |
| De-obfuscation | Recursive base64 / hex / escape / URL decoding, depth- and size-bounded | decoded layers, merged into the text everything below matches against |
| Command NLP | Regex tool + intent signatures, optional spaCy NER | tool names, intents, extracted IPs/URLs |
| Anomaly detection | Isolation Forest over 11 behavioural features | anomaly score, outlier flag |
| Attacker profiling | Weighted indicator scorecard | automated bot / script kiddie / skilled / APT |
| Behavioural clustering | Mini-batch k-means over 10 behavioural features | cluster id, centroid distance, outlier flag |
| ATT&CK mapping | Tool + intent → technique lookup | tactic IDs and technique objects |
| Severity | Composite score over the above, then matched against the configured alert thresholds | low / medium / high / critical, and whether to alert |

Sessions from known research scanners (Censys, Shodan, Rapid7, Shadowserver)
are **attributed, not discarded**. A honeypot on a public address is scanned
continuously by organisations that are not attacking it, and counting their
probes as attacks makes every figure incomparable. They are labelled with the
operator and can be excluded from any view; they are always recorded, because
a honeypot that silently drops traffic cannot be audited. Point
`SCANNER_LIST_PATH` at a [MISP warninglist](https://github.com/MISP/misp-warninglists)
export to replace the built-in seed list.

Raw commands, the command/output transcript, captured credentials, and any
uploaded files are encrypted with AES-256-GCM before they are stored.

The engine records HTTP requests (request line, user agent, body) and every FTP
command in the transcript, with the reply it gave, so tool detection,
de-obfuscation and NLP read web and FTP sessions the way they read shell
commands. Logins from web forms and HTTP Basic auth join the captured
credentials. An FTP `PASS` argument is masked in the transcript, because
credentials are admin-only and the transcript is not.

The synchronous path takes 16 ms of model time per session (forest 9.6 ms,
isolation forest 2.8 ms, NLP 3.6 ms). The whole span to a stored verdict is
about 33 ms at nominal load and stays within 200 ms up to 10 concurrent
sessions on the reference host; see [evaluation](evaluation/README.md).

**Two stages run asynchronously**, after the response has been returned, for
the same reason: NFR-2 budgets 200 ms for classification, so anything slower
than that runs out of the ingest path, and a slow or absent stage degrades the
depth of analysis, never the capture.

- **Semantic analysis (Chimera).** If `CHIMERA_URL` points at a local endpoint
  serving the project's fine-tuned model, it reads the stored transcript and
  returns intent, objectives, ATT&CK techniques and indicators, merged onto the
  session. A 14B model answers in seconds, two orders of magnitude over the
  budget, which is why it is out of band.

- **Triage (decision model).** If `DECIDER_URL` points at a llama.cpp server
  with a decision model (Kev-4B in production) loaded, every session the rules
  would send to the language model is first triaged by it: a distribution over
  the four categories, an expected severity on a 0–3 scale, and automated
  versus human, read from the commands in one pass of a few seconds. Triage
  decides whether the language model reads the session (it can skip one only
  when it is confident the session went no further than reconnaissance and the
  rules agree; with `DECIDER_TRIAGE_RULE_SKIPPED` it also reads the sessions
  the rules skip and can escalate one), and afterwards checks each
  technique the language model added against the transcript, marking those it
  finds no sign of as unconfirmed. Its answers are probabilities over options
  the backend fixes, so a transcript can shift them but cannot add an answer.

- **Payload analysis.** Files an attacker uploads — through the SSH shell
  (echo/base64/printf loaders and heredocs), a pipe into an interpreter, SFTP,
  SCP, FTP `STOR`, or an HTTP body — are captured *inbound*, so the engine
  makes no outbound connection to obtain them. Each unique file (by SHA-256) is
  then reverse-engineered **statically** in a sandboxed subprocess: file type
  from magic bytes, ELF/PE internals and capabilities, script behaviours,
  archive contents, and the indicators left inside it (C2 addresses, wallets,
  mining pools, operator channels, embedded keys), plus a heuristic
  malware-family hint shown always with its evidence. **Nothing in a sample is
  ever executed, and no host or URL found inside one is ever contacted** —
  doing so would announce the analysis and create exactly the egress the engine
  exists to avoid. Indicators recovered from a payload are attributed back to
  every session that dropped it. Point analysis is on by default and gated by
  `PAYLOAD_ANALYSIS_ENABLED`.

---

## Honest limitations

These matter more than the feature list, so they are stated up front.

**The classifier is trained on CIC-IDS2017; it has not met real traffic.**
`deploy/server/train-model.sh` (or `python -m ml.train --data … --tune`)
produces the model and a metrics report. On the held-out test set it scores
0.9967 accuracy and 0.896 macro F1, but exfiltration precision is only 0.47
([evaluation](evaluation/README.md)).

The artefact is not committed. Without it, the classifier is fitted on
*synthetic* data and every verdict carries `model_source: "synthetic"`. The
API also refuses a model built for a different feature layout. The anomaly
detector is still a synthetic bootstrap.

The [model training guide](../backend/ml/README.md) documents the domain shift
between CIC-IDS2017's packet-level records and what the engine's sockets see.
Read it before quoting any figure.

**Nothing has captured real internet traffic yet.** No honeypot node has
been exposed to the internet, so:

- the behavioural clusters are unfitted;
- no session has passed through the semantic stage;
- no real payload has been captured or analysed.

The classifier's metrics are empirical on its dataset. Everything the API
returns about attacks is structural until a node runs exposed.

**Payload analysis is static and heuristic, not a sandbox and not antivirus.**
It reads a file's bytes and reports what they show; it never runs the sample,
so it sees nothing that only happens at runtime (a packer that unpacks in
memory, a domain built at execution). The family label is a hint from a small
rule set over strings and behaviours, shown with its evidence and a bounded
confidence — it is a starting point for an analyst, and its absence means
nothing. Every parser runs on attacker-chosen input, so it is sandboxed in a
resource-limited subprocess; a sample that trips a limit is marked failed and
the rest of the session is unaffected.

**Isolation is verified, not enforced by this code.** The real controls are
the container runtime's (`cap_drop: ALL`, `read_only`, `no-new-privileges`),
the internal networks, and, for the published decoy bridge, the host firewall.
`honeypot/security/breakout.py` *checks* those controls are in place and
reports honestly when they are not. Where the engine has a default route, it
tries connecting to public addresses and fails the check if any succeed. It
does not claim to sandbox itself from inside the sandbox.

**Geolocation requires a database file.** `GEOIP_DB_PATH` takes MaxMind
GeoLite2 or DB-IP City Lite (CC BY 4.0, credited on the map; the self-hosted
installer fetches it). Without one, sessions are stored with no location: the
map and the country filter show fewer events rather than invented ones.

**Rate limiting is per-process and in-memory.** The dashboard API therefore
runs as one process. The self-hosted `ingest` service has several workers, but
it serves only the engine's token-authenticated calls, which carry no user
rate limits. Scaling the dashboard API itself would need a shared limiter
backend (Redis).

**The SSH disguise is exact for OpenSSH 8.2p1 and nothing else.** Vetterl and
Clayton ([USENIX WOOT '18](https://www.usenix.org/conference/woot18/presentation/vetterl))
fingerprint medium-interaction honeypots with a single packet by comparing the
KEXINIT an off-the-shelf transport library sends against the one the claimed
software sends. This engine speaks SSH through asyncssh, so the banner and the
transport proposal are pinned to one profile and match byte for byte — but only
for 8.2p1, because asyncssh cannot implement `sntrup761x25519-sha512@openssh.com`
and so cannot imitate 8.9 or later exactly. Imitating a version we can match
perfectly is the deliberate trade. The disguise is still only transport-deep:
timing, error-message wording and edge-case command behaviour remain
fingerprintable.

**The emulated shell has a small, bounded filesystem.** `cd` moves, downloads
land where they were asked to land, and `chmod +x` then `./payload` behaves —
enough for a dropper to run its chain to the end. It is not a real filesystem,
and an attacker who explores beyond the emulated commands will notice.

---

## Security model

| Control | Implementation |
|---|---|
| Password hashing | PBKDF2-HMAC-SHA256, 600 000 iterations, per-user salt |
| Sessions | JWT access + refresh tokens, with a `typ` claim so the two are not interchangeable |
| Authorisation | Role hierarchy viewer < analyst < admin, enforced per route |
| Registration | Always creates a **viewer**; roles are assigned only by an admin |
| Email OTP | 6 digits from `secrets`, stored as an HMAC digest, 5-attempt limit, 10-minute expiry |
| Multi-factor auth | TOTP (RFC 6238), enrolled from Settings with a locally drawn QR code; activation requires a valid code, recovery codes are single-use and shown once; sign-in asks for the code when the API answers `X-MFA-Required: totp` |
| Database transport | TLS required outside development (`DATABASE_SSL` to override) |
| Encryption at rest | AES-256-GCM, unique nonce per record, over captured commands, payloads, uploaded files and authenticator secrets |
| Service-to-service | Shared `HONEYPOT_INGEST_TOKEN`, compared in constant time |
| Rate limiting | Per-IP via slowapi; 5/min register, 10/min login, 3/min OTP resend |
| Secrets | The app **refuses to start** in a non-development environment if any secret is still a placeholder |
| Transport | Security headers on every response; CORS restricted to configured origins |
| Payload analysis | Uploaded files are analysed statically in a subprocess under CPU, memory and file-size limits; nothing is executed and no indicator inside a sample is contacted |
| Sample download | Raw captured malware is admin-only, served `application/octet-stream` with `nosniff`, and audit-logged |
| Audit | Every privileged action written to `audit_logs` |

---

## Configuration

Every setting lives in `.env`; see `.env.example` for the annotated list. The
ones that matter most:

| Variable | Purpose |
|---|---|
| `ENVIRONMENT` | Anything other than `development` enforces real secrets |
| `SECRET_KEY` | JWT signing key |
| `ENCRYPTION_KEY` | Key material for encryption at rest |
| `HONEYPOT_INGEST_TOKEN` | Shared between backend and engine — **must match** |
| `CORS_ORIGINS` | Comma-separated allowed browser origins |
| `TRUST_PROXY_HEADERS` | Enable only behind a trusted reverse proxy |
| `GEOIP_DB_PATH` | MaxMind GeoLite2 or DB-IP City Lite database |
| `SEED_ON_STARTUP` | Load the demo dataset into an empty database |
| `RUN_MIGRATIONS_ON_STARTUP` | Disable to run `alembic upgrade head` as a release step |
| `CHIMERA_URL` | Local OpenAI-compatible endpoint for semantic stage-2 analysis; unset disables it |
| `PAYLOAD_ANALYSIS_ENABLED` | Reverse-engineer uploaded files in the detached stage (default on) |

### Operations settings (backend)

| Variable | Default | What it does |
|---|---|---|
| `BACKGROUND_WORKERS` | `false` | Run the enrichment worker, notification outbox, engine-liveness check and retention in this process. Exactly one process per deployment (the `backend` service). |
| `CHIMERA_URL` / `CHIMERA_MODEL` / `CHIMERA_TIMEOUT` | unset / `chimera-14b-v2` / `300` | OpenAI-compatible endpoint for the stage-2 model, its name, and the per-call budget in seconds. Unset disables the stage. |
| `CHIMERA_MAX_TOKENS` / `CHIMERA_MAX_TRANSCRIPT_CHARS` | `600` / `6000` | Answer length and how much transcript is sent. |
| `DECIDER_URL` / `DECIDER_MODEL` / `DECIDER_TIMEOUT` | unset / `kev-4b` / `120` | llama.cpp server with a decision model (`/v1/systemone`), its name, and the per-call budget. Unset disables triage. |
| `DECIDER_MAX_TRANSCRIPT_CHARS` | `3000` | Transcript the decision model reads; longer ones keep their start and end. Cost scales with this, not with the number of questions. |
| `DECIDER_SKIP_THRESHOLD` / `DECIDER_ESCALATE_THRESHOLD` | `0.85` / `0.6` | Probability of "information gathering at most" needed to skip the language model (rules must agree); probability of an attempted compromise needed to send one the rules skipped. |
| `DECIDER_TRIAGE_RULE_SKIPPED` | `false` | Also triage the sessions the rules skip (plain browsing, short benign FTP), so triage can escalate one. |
| `DECIDER_SUPPORT_THRESHOLD` / `DECIDER_DROP_UNCONFIRMED` | `0.3` / `false` | Below this a language-model technique is marked unconfirmed; set the second to remove it instead. |
| `DECIDER_FALLBACK_SECONDS` | `900` | How long a session waits on an unreachable decision model before the rules route it. |
| `NODE_STALE_SECONDS` / `NODE_OFFLINE_ALERT_SECONDS` | `180` / `300` | When a node shows as offline, and when a system alert is raised for it. |
| `NODE_DISK_ALERT_FRACTION` | `0.10` | Free-disk fraction on an engine below which a system alert is raised. |
| `ALERT_DEDUP_WINDOW_MINUTES` | `60` | Repeats of one address at one category inside this window fold into the open alert. |
| `ALERT_SUPPRESS_SCANNERS` | `true` | Sessions attributed to a research scanner never alert. |
| `NOTIFICATION_MAX_ATTEMPTS` | `6` | Email/webhook delivery attempts before an outbox row is marked failed. |
| `SESSION_RETENTION_DAYS` / `AUDIT_RETENTION_DAYS` / `OUTBOX_RETENTION_DAYS` | `0` / `365` / `30` | Hourly deletion of rows older than this; 0 keeps everything. |
| `LOGIN_LOCKOUT_THRESHOLD` / `LOGIN_LOCKOUT_MINUTES` | `10` / `15` | Per-account lockout after repeated wrong passwords. |
| `TRUSTED_PROXIES` | loopback + RFC1918 | Addresses skipped (right to left) when reading `X-Forwarded-For`; the first other address is the client. Only used with `TRUST_PROXY_HEADERS=true`. |

### Telnet decoy

`HONEYPOT_TELNET_PORT` (default `2323`, listed in `HONEYPOT_PROTOCOLS` as `telnet`). Answers option negotiation like telnetd (offers ECHO and SUPPRESS-GO-AHEAD, refuses the rest), runs the SSH decoy's login policy (weak credential or soft accept after three failures, every attempt recorded) and then the same shell dispatcher, so busybox probes, `wget`/`tftp` loaders and shell-written files are captured identically. Sessions carry `protocol: telnet`.

### Engine limits and durability

Set on the honeypot engine's environment. Bad numbers fall back to the default
with a warning instead of stopping the engine.

| Variable | Default | Purpose |
|---|---|---|
| `HONEYPOT_SPOOL_MAX_FILES` / `HONEYPOT_SPOOL_MAX_BYTES` | `5000` / 512 MiB | On-disk retry queue for sessions the backend could not take; replayed oldest first, de-duplicated by the engine's session id |
| `HONEYPOT_HEARTBEAT_INTERVAL` | `60` | Seconds between status heartbeats to the backend |
| `HONEYPOT_MAX_CONN_PER_IP` / `HONEYPOT_MAX_CONNECTIONS` | `5` / `500` | Concurrent connections per address and in total, enforced at accept |
| `HONEYPOT_MAX_SESSION_SECONDS` | `1800` | Hard cap on a connection's lifetime |
| `HONEYPOT_CONN_TIMEOUT` | unset | Idle timeout for all protocols (defaults: SSH 300 s, FTP 120 s, HTTP 60 s) |
| `HONEYPOT_CAPTURE_RETENTION_DAYS` / `HONEYPOT_UPLOAD_RETENTION_DAYS` | `7` / `30` | Pruning of the engine's local session copies and captured upload bytes |

Generate each secret separately:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## API

Interactive documentation at `/docs`. Authentication is `Authorization:
Bearer <access_token>`.

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/register` | — | Register (viewer role, sends OTP) |
| POST | `/api/v1/auth/verify-otp` | — | Verify email |
| POST | `/api/v1/auth/login` | — | Obtain a token pair |
| POST | `/api/v1/auth/refresh` | — | Exchange a refresh token |
| POST | `/api/v1/auth/request-password-reset` | — | Request a reset code |
| POST | `/api/v1/auth/reset-password` | — | Complete a reset |
| GET | `/api/v1/auth/me` | any | Current user, including whether TOTP is enabled |
| POST | `/api/v1/auth/mfa/enroll` | any | Issue an authenticator secret and its `otpauth://` URI |
| POST | `/api/v1/auth/mfa/confirm` | any | Activate it with a valid code; returns recovery codes once |
| POST | `/api/v1/auth/mfa/disable` | any | Turn it off; needs a current or recovery code |
| GET | `/api/v1/auth/users` | admin | List users |
| POST | `/api/v1/auth/users` | admin | Create a user with a role |
| PATCH | `/api/v1/auth/users/{id}/role` | admin | Change a role |
| GET | `/api/v1/dashboard/stats` | any | Aggregate statistics |
| GET | `/api/v1/dashboard/live-events` | any | Recent sessions for the map |
| GET | `/api/v1/sessions/` | any | List sessions (filter + paginate; `exclude_scanners` hides research scanners) |
| GET | `/api/v1/sessions/{id}` | any | Session detail |
| GET | `/api/v1/sessions/{id}/transcript` | any | Commands and what the honeypot appeared to reply |
| GET | `/api/v1/sessions/{id}/credentials` | admin | Credentials tried — audit-logged on read |
| POST | `/api/v1/sessions/{id}/export` | analyst | Export one session |
| POST | `/api/v1/sessions/ingest` | analyst | Manual ingest |
| POST | `/api/v1/sessions/ingest-internal` | token | Engine ingest |
| GET | `/api/v1/alerts/` | any | List alerts |
| GET | `/api/v1/alerts/stats` | any | Alert counts by status/severity |
| PATCH | `/api/v1/alerts/{id}` | analyst | Triage an alert |
| GET | `/api/v1/iocs/` | any | Indicators, grouped by value and ranked by how many sessions saw each |
| GET | `/api/v1/iocs/session/{id}` | any | Indicators from one session |
| GET | `/api/v1/iocs/feed` | any | Plain-text blocklist, one value per line |
| GET | `/api/v1/payloads/` | any | Captured samples, unique by hash, filter + paginate |
| GET | `/api/v1/payloads/stats` | any | Sample counts by kind and family |
| GET | `/api/v1/payloads/{sha256}` | any | One sample's full analysis and the sessions it appeared in |
| GET | `/api/v1/payloads/{sha256}/download` | admin | Raw sample bytes — audit-logged |
| GET | `/api/v1/nodes/` | any | List nodes |
| POST | `/api/v1/nodes/` | admin | Create a node |
| POST | `/api/v1/nodes/register-internal` | token | Engine self-registration |
| DELETE | `/api/v1/nodes/{id}` | admin | Delete a node |
| POST | `/api/v1/export/` | analyst | Bulk export (CSV/JSON/CEF/STIX) |
| GET | `/api/v1/settings/system` | any | Emulation mode and node summary |
| PATCH | `/api/v1/settings/system` | admin | Save the mode and push it to the running engine (`engine_applied` says whether it arrived) |
| GET | `/api/v1/settings/thresholds` | any | Alert thresholds |
| POST/PATCH/DELETE | `/api/v1/settings/thresholds` | admin | Manage thresholds |
| GET | `/api/v1/honeypot/status` | any | Live engine status |
| PATCH | `/api/v1/honeypot/mode` | admin | Switch active/passive |
| POST | `/api/v1/honeypot/block-ip` | analyst | Block an address |

---

## Repository layout

```
backend/          FastAPI application
  app/api/        route handlers
  app/ai/         classifier, de-obfuscation, NLP, clustering, ATT&CK, LLM and decision-model clients
  app/payloads/   static reverse-engineering of uploaded files, sandboxed
  app/core/       config, database, security, encryption, TOTP, rate limiting
  app/services/   analysis pipeline, async enrichment, payload analysis, alerting, artifacts
  alembic/        migrations
  ml/             classifier training, tuning + evaluation, cluster fitting
  tests/          pytest suite
honeypot/         standalone capture engine (minimal dependencies)
  emulators/      SSH (real transport), FTP, HTTP/HTTPS
  capture/        shell-write interpreter, SFTP/SCP endpoint, HTTP upload parsing,
                  socket-level flow meter
  core/           config, session manager, response modes, control API, TLS
  security/       rate limiting, egress filtering, isolation verification
  adaptive/       banner rotation, actor profiling
src/              React dashboard
deploy/server/    the whole stack on one machine: install, egress firewall, backups,
                  training, controlled and load tests
deploy/node/      standalone engine deployment for a remote VM
docs/evaluation/  classifier metrics and NFR-2 load-test results
scripts/          GeoLite2 fetch
```

---

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React 19, Vite 8, Tailwind CSS 4, React Router 7, Leaflet |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2 (async), Pydantic v2 |
| AI/ML | scikit-learn, spaCy, optional local LLM over an OpenAI-compatible endpoint |
| Database | PostgreSQL 16, Alembic migrations |
| Auth | JWT (python-jose), PBKDF2-HMAC-SHA256, slowapi |
| Engine | asyncio — `asyncssh` for the SSH transport, `httpx`, `cryptography` |

---

## License

MIT — see [LICENSE](../LICENSE).

