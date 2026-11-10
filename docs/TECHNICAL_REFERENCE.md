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

In the self-hosted deployment an engine shares a network with exactly two
things: the `ingest` service (the API image started with `API_ROLE=ingest`,
which serves only the engine-facing `*-internal` routes) and, on a separate
control network, the backend, which can call the engine but cannot be called
by it. Each engine has its own ingest token, valid for its node name only.

Docker refuses to publish ports for a container whose only network is
internal, so the decoy ports sit on a further, ordinary bridge. The host
firewall (`deploy/server/honeysentinel-egress.sh`, loaded before Docker
starts and re-checked every five minutes) covers every bridge of the
deployment: a container may answer connections and may not open one to the
host or to another network, and inside a bridge only the listed pairs may
talk. The engine's isolation check verifies this from the inside by
attempting connections, and repeats it periodically. The
[threat model](THREAT_MODEL.md) goes through what that leaves an attacker.

---

## Analysis pipeline

Each ingested session runs through, in order:

| Stage | Implementation | Output |
|---|---|---|
| Geolocation | MaxMind GeoLite2 or DB-IP City Lite (recorded as the location's `source`) | country / city / lat / lon, or an explicit "unknown" |
| Classification | Random Forest over 12 flow features the engine measures at its sockets, trained on CIC-IDS2017 ([results](evaluation/README.md)) | benign / reconnaissance / exploitation / exfiltration |
| De-obfuscation | Recursive base64 / hex / escape / URL decoding, depth- and size-bounded | decoded layers, merged into the text everything below matches against |
| Command NLP | Regex tool + intent signatures, optional spaCy NER | tool names, intents, extracted IPs/URLs |
| Anomaly detection | Isolation Forest over 11 behavioural features. **A synthetic bootstrap** until it is fitted on captured sessions | anomaly score, outlier flag |
| Attacker profiling | Weighted indicator scorecard | automated bot / script kiddie / skilled / APT |
| Behavioural clustering | Mini-batch k-means over 10 behavioural features. Needs 50 or more captured sessions; **never yet fitted on the deployment** | cluster id, centroid distance, outlier flag |
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

The whole synchronous span, from session end to a stored verdict, was about
33 ms at nominal load and stayed within 200 ms up to 10 concurrent sessions
on the reference host, measured with the team's own test traffic; see
[evaluation](evaluation/README.md). The only per-stage timing with an
evidence file is the forest's single prediction, 9.1 ms at the median.

**Two stages run asynchronously**, after the response has been returned, for
the same reason: NFR-2 budgets 200 ms for classification, so anything slower
than that runs out of the ingest path, and a slow or absent stage degrades the
depth of analysis, never the capture.

- **Semantic analysis (Chimera).** If `CHIMERA_URL` points at a local endpoint
  serving the project's fine-tuned model, it reads the stored transcript and
  returns intent, objectives, ATT&CK techniques and indicators, merged onto the
  session. On the reference server's CPU one answer takes about two
  minutes, several hundred times the budget, which is why it is out of band
  and a queue.

- **Triage (decision model).** If `DECIDER_URL` points at a llama.cpp server
  with a decision model (Kev-4B in production) loaded, every session the rules
  would send to the language model is first triaged by it: a distribution over
  the four categories, an expected severity on a 0–3 scale, and automated
  versus human, read from the commands in one pass (a median of about 8 s on
  shell transcripts and 16 s on long web sessions on the reference server).
  Sessions the rules do not queue are not triaged by default. Triage
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
been exposed to the internet. Everything recorded so far is the team's own
controlled test traffic, so:

- the behavioural clusters are unfitted and the anomaly detector is a
  synthetic bootstrap;
- the language and decision models have only read synthetic transcripts and
  the team's own test sessions;
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
| Service-to-service | One ingest token per engine, bound to its node name (`HONEYPOT_NODE_TOKENS`), and a separate control token for the backend's calls to the engines; compared in constant time. The ingest service mounts only the engine-facing routes (`API_ROLE=ingest`) |
| Rate limiting | Per-IP via slowapi; 5/min register, 10/min login, 3/min OTP resend |
| Secrets | The app **refuses to start** in a non-development environment if any secret is still a placeholder |
| Transport | Security headers on every response; CORS restricted to configured origins |
| Payload analysis | Uploaded files are analysed statically in a subprocess under CPU, memory and file-size limits; nothing is executed and no indicator inside a sample is contacted |
| Sample download | Raw captured malware is admin-only, served `application/octet-stream` with `nosniff`, and audit-logged |
| Audit | Every privileged action written to `audit_logs` |

---

## Configuration

Every setting, with its default and the component that reads it, is in the
[configuration reference](CONFIGURATION.md). It is the only place settings
are described; this document and the deployment guides name a setting and
link there.

Generate each secret separately:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## API

Interactive documentation at `/docs`. Authentication is `Authorization:
Bearer <access_token>`. In the Auth column, *any* is any signed-in user;
*analyst* and *admin* are minimum roles; *engine token* is an engine's
ingest token in `X-Honeypot-Token`.

The `ingest` service (`API_ROLE=ingest`) serves only the routes ending in
`-internal`, and `/health`.

This table is generated from the source by `python3 scripts/list_routes.py`;
regenerate it rather than editing it. Descriptions are the first line of each
handler's docstring, or its name where it has none.

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/alerts/` | any | List alerts |
| POST | `/api/v1/alerts/bulk` | analyst | Move several alerts to one status in a single request |
| GET | `/api/v1/alerts/stats` | any | Alert stats |
| GET | `/api/v1/alerts/{alert_id}` | any | Get alert |
| PATCH | `/api/v1/alerts/{alert_id}` | analyst | Update alert |
| GET | `/api/v1/attack/matrix` | any | Observed techniques by tactic, in kill-chain order, with session counts |
| GET | `/api/v1/attack/navigator-layer` | analyst | An ATT&CK Navigator layer scoring each technique by its session count |
| GET | `/api/v1/audit-logs` | admin | Audit rows, newest first, with the acting user's email where known |
| GET | `/api/v1/audit-logs/` | admin | Audit rows, newest first, with the acting user's email where known |
| GET | `/api/v1/auth/capabilities` | none | What the sign-in pages can offer here. Public, and says nothing secret |
| POST | `/api/v1/auth/change-password` | any | Change your own password; requires the current one |
| POST | `/api/v1/auth/login` | none | Sign in. How failures are limited, since the answers are all alike: |
| POST | `/api/v1/auth/logout` | none | Revoke a refresh token (and its family). Idempotent; no session needed |
| POST | `/api/v1/auth/logout-all` | any | Sign out of every device: every refresh token revoked, every access token invalidated. The caller must sign in again too |
| GET | `/api/v1/auth/me` | any | Get me |
| POST | `/api/v1/auth/mfa/confirm` | any | Turn MFA on, once a working code proves the app is set up |
| POST | `/api/v1/auth/mfa/disable` | any | Turn MFA off. Requires a current code, not just a session |
| POST | `/api/v1/auth/mfa/enroll` | any | Begin enrolment: issue a secret and the QR payload for it |
| POST | `/api/v1/auth/refresh` | none | Exchange a refresh token for a new token pair |
| POST | `/api/v1/auth/register` | none | Self-service registration |
| POST | `/api/v1/auth/request-password-reset` | none | Request password reset |
| POST | `/api/v1/auth/resend-otp` | none | Resend otp |
| POST | `/api/v1/auth/reset-password` | none | Reset password |
| GET | `/api/v1/auth/users` | admin | List users |
| POST | `/api/v1/auth/users` | admin | Admin-only account creation, including role assignment |
| PATCH | `/api/v1/auth/users/{user_id}` | admin | Deactivate, reactivate or rename an account |
| POST | `/api/v1/auth/users/{user_id}/reset-mfa` | admin | Remove a user's authenticator so they can sign in and enrol again |
| POST | `/api/v1/auth/users/{user_id}/reset-password` | admin | Set a temporary password for a user, on a deployment without email |
| PATCH | `/api/v1/auth/users/{user_id}/role` | admin | Update user role |
| POST | `/api/v1/auth/verify-otp` | none | Verify otp |
| GET | `/api/v1/dashboard/live-events` | any | The most recent sessions, as the feed shows them |
| GET | `/api/v1/dashboard/stats` | any | Get dashboard stats |
| GET | `/api/v1/dashboard/trends` | any | Sessions per UTC day over the last 7, 30 or 90 days, by category |
| POST | `/api/v1/export/` | analyst | Export sessions |
| POST | `/api/v1/export/reports` | analyst | Prepare investigation report |
| GET | `/api/v1/export/reports/{report_id}` | analyst | Investigation status |
| GET | `/api/v1/export/reports/{report_id}/download` | analyst | Download investigation report |
| POST | `/api/v1/honeypot/block-ip` | analyst | Block ip |
| GET | `/api/v1/honeypot/blocked-ips` | any | Get blocked ips |
| GET | `/api/v1/honeypot/denied-connections` | any | Get denied connections |
| PATCH | `/api/v1/honeypot/mode` | admin | Update mode |
| GET | `/api/v1/honeypot/security-status` | any | Get security status |
| GET | `/api/v1/honeypot/sessions/active` | any | Get active sessions |
| GET | `/api/v1/honeypot/status` | any | Report live engine state, or say plainly that it is unreachable |
| GET | `/api/v1/honeypot/threat-actors` | any | Get threat actors |
| POST | `/api/v1/honeypot/unblock-ip` | admin | Unblock ip |
| GET | `/api/v1/iocs/` | any | Indicators grouped by value, with how widely each has been seen |
| GET | `/api/v1/iocs/feed` | any or feed token | A plain-text list, one indicator per line |
| GET | `/api/v1/iocs/session/{session_id}` | any | Everything one session produced |
| GET | `/api/v1/nodes/` | any | List nodes |
| POST | `/api/v1/nodes/` | admin | Create node |
| POST | `/api/v1/nodes/heartbeat-internal` | engine token | The engine's periodic liveness report |
| POST | `/api/v1/nodes/register-internal` | engine token | Register (or refresh) the calling honeypot engine as a node |
| GET | `/api/v1/nodes/{node_id}` | any | Get node |
| PATCH | `/api/v1/nodes/{node_id}` | admin | Update node |
| DELETE | `/api/v1/nodes/{node_id}` | admin | Delete node |
| GET | `/api/v1/payloads/` | any | Captured samples, newest first, with how widely each has been seen |
| GET | `/api/v1/payloads/stats` | any | Counts by kind and by family, for the overview strip |
| GET | `/api/v1/payloads/{sha256}` | any | One sample: its full analysis and every session it appeared in |
| GET | `/api/v1/payloads/{sha256}/download` | admin | Download payload |
| GET | `/api/v1/sessions/` | any | List sessions |
| GET | `/api/v1/sessions/attacker/{ip}` | any | Everything recorded about one source address, aggregated |
| POST | `/api/v1/sessions/ingest` | admin | Ingest session |
| POST | `/api/v1/sessions/ingest-internal` | engine token | Ingest a session from the honeypot engine (service-to-service) |
| GET | `/api/v1/sessions/uuid/{session_uuid}` | any | Get session by uuid |
| GET | `/api/v1/sessions/{session_id}` | any | Get session |
| GET | `/api/v1/sessions/{session_id}/credentials` | admin | Username/password pairs tried against the honeypot |
| POST | `/api/v1/sessions/{session_id}/enrich` | analyst | Queue (or re-queue) a session for the language model, ahead of the backlog |
| POST | `/api/v1/sessions/{session_id}/export` | analyst | Export session |
| GET | `/api/v1/sessions/{session_id}/transcript` | analyst | The commands the attacker ran and what the honeypot appeared to reply |
| GET | `/api/v1/settings/system` | any | Get system config |
| PATCH | `/api/v1/settings/system` | admin | Update system config |
| GET | `/api/v1/settings/thresholds` | any | List thresholds |
| POST | `/api/v1/settings/thresholds` | admin | Create threshold |
| PATCH | `/api/v1/settings/thresholds/{threshold_id}` | admin | Update threshold |
| DELETE | `/api/v1/settings/thresholds/{threshold_id}` | admin | Delete threshold |

76 routes.

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
  emulators/      SSH (real transport), Telnet, FTP, HTTP/HTTPS
  capture/        shell-write interpreter, SFTP/SCP endpoint, HTTP upload parsing,
                  socket-level flow meter
  core/           config, session manager, response modes, control API, TLS
  security/       rate limiting, diversion to a decoy site, isolation verification
                  (it checks containment; the host firewall enforces it)
  adaptive/       banner rotation, actor profiling
src/              React dashboard
deploy/server/    the whole stack on one machine: install, egress firewall, backups,
                  host heartbeat, training, controlled and load tests
deploy/node/      hardened sensor kit: one engine on a public VPS
deploy/cowrie-baseline/  a stock Cowrie beside the engine, for comparison
deploy/legacy/    the old Render and Vercel files, unmaintained
docs/             threat model, data handling, exposure runbook, evaluation
                  plan, configuration reference
docs/evaluation/  measurements so far, with the raw JSON
scripts/          lock files, image pinning, address-plan check, route table
```

---

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React 19, Vite 8, Tailwind CSS 4, React Router 7, Leaflet |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2 (async), Pydantic v2 |
| AI/ML | scikit-learn, spaCy, optional local LLM over an OpenAI-compatible endpoint |
| Database | PostgreSQL 16, Alembic migrations |
| Auth | JWT (PyJWT), PBKDF2-HMAC-SHA256, slowapi |
| Engine | asyncio — `asyncssh` for the SSH transport, `httpx`, `cryptography`, `regex` |

---

## License

MIT — see [LICENSE](../LICENSE).

