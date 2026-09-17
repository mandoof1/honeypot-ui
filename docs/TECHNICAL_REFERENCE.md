# Technical reference

[Back to the project overview](../README.md)

## Architecture

```
        Attacker
           │  SSH 2222 / FTP 2121 / HTTP 8080 / HTTPS 8443
           ▼
┌──────────────────────────────────────────────┐
│  Honeypot Engine  (honeypot/)                │
│  · protocol emulators + session capture      │
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
│  · analysis pipeline (see below)             │
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

The engine sits on an **internal-only** Docker network. Only the backend
bridges that network and the outside world, so a process that escapes an
emulator has no route to the internet.

---

## Analysis pipeline

Each ingested session runs through, in order:

| Stage | Implementation | Output |
|---|---|---|
| Geolocation | MaxMind GeoLite2 | country / city / lat / lon, or an explicit "unknown" |
| Classification | Random Forest over 36 CIC-IDS-style flow features | benign / reconnaissance / exploitation / exfiltration |
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

**Two stages run asynchronously**, after the response has been returned, for
the same reason: NFR-2 budgets 200 ms for classification, so anything slower
than that runs out of the ingest path, and a slow or absent stage degrades the
depth of analysis, never the capture.

- **Semantic analysis (Chimera).** If `CHIMERA_URL` points at a local endpoint
  serving the project's fine-tuned model, it reads the stored transcript and
  returns intent, objectives, ATT&CK techniques and indicators, merged onto the
  session. A 14B model answers in seconds, two orders of magnitude over the
  budget, which is why it is out of band.

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

**The shipped models are bootstraps, not trained detectors.** If no model
artefact exists at `MODEL_PATH_RF` / `MODEL_PATH_IF`, both are fitted on
*synthetic* data generated at build time. Their category labels are
structurally plausible but their confidence scores are not calibrated against
real traffic. Every classification response carries
`model_source: "synthetic"` so this is visible in the API, and the pipeline
never presents a synthetic verdict as ground truth. To get real numbers,
train it: `cd backend && python -m ml.train --data /path/to/CIC-IDS2017/`
writes both the model and a metrics artefact, after which the API reports
`model_source: "cicids2017"`. See [model training guide](../backend/ml/README.md), which also documents
the domain shift between CIC-IDS2017's flow records and the session data this
system actually captures — a limitation worth reading before quoting any
figure the trainer produces.

**Nothing has been trained yet, and nothing has captured real traffic yet.**
The pipeline above is implemented and tested end to end, but no honeypot node
has run against the internet, so the behavioural clusters are unfitted, no
session has passed through the semantic stage, and no real payload has been
captured or analysed. Treat every number the API currently returns as
structural, not empirical.

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
the container runtime's (`cap_drop: ALL`, `read_only`, `no-new-privileges`,
an `internal` network). `honeypot/security/breakout.py` *checks* those
controls are actually in place and reports honestly when they are not — it
does not claim to sandbox itself from inside the sandbox.

**Geolocation requires a MaxMind database.** Without `GEOIP_DB_PATH` pointing
at a GeoLite2 file, sessions are stored with no location. The map and the
country filter show fewer events rather than invented ones.

**Rate limiting is per-process and in-memory.** Correct for a single
instance; running multiple workers needs a shared backend (Redis).

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
| Multi-factor auth | TOTP (RFC 6238); enrolment requires a valid code before activation, single-use recovery codes |
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
| `GEOIP_DB_PATH` | MaxMind GeoLite2 database |
| `SEED_ON_STARTUP` | Load the demo dataset into an empty database |
| `RUN_MIGRATIONS_ON_STARTUP` | Disable to run `alembic upgrade head` as a release step |
| `CHIMERA_URL` | Local OpenAI-compatible endpoint for semantic stage-2 analysis; unset disables it |
| `PAYLOAD_ANALYSIS_ENABLED` | Reverse-engineer uploaded files in the detached stage (default on) |

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
| GET | `/api/v1/auth/me` | any | Current user |
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
  app/ai/         classifier, de-obfuscation, NLP, clustering, ATT&CK, LLM client
  app/payloads/   static reverse-engineering of uploaded files, sandboxed
  app/core/       config, database, security, encryption, TOTP, rate limiting
  app/services/   analysis pipeline, async enrichment, payload analysis, alerting, artifacts
  alembic/        migrations
  ml/             classifier training + evaluation, cluster fitting
  tests/          pytest suite
honeypot/         standalone capture engine (minimal dependencies)
  emulators/      SSH (real transport), FTP, HTTP/HTTPS
  capture/        shell-write interpreter, SFTP/SCP endpoint, HTTP upload parsing
  core/           config, session manager, response modes, control API, TLS
  security/       rate limiting, egress filtering, isolation verification
  adaptive/       banner rotation, actor profiling
src/              React dashboard
deploy/node/      standalone engine deployment for a remote VM
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

