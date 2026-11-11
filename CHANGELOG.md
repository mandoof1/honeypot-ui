# Changelog

## Unreleased

- 1.0.0 is deployed on the reference server: the installer, the image
  builds, the migrations on the existing data and the firewall probe all
  passed on the first run, and the controlled end-to-end test stores sessions
  through the new ingest path.
- The first fingerprint comparison with the real daemons is recorded in
  `docs/evaluation/fingerprint/`. Checks that match: OpenSSH 26 of 38,
  telnetd 3 of 10, vsftpd 24 of 29, ProFTPD 17 of 29, Apache 58 of 86,
  nginx 82 of 86. The SSH algorithm lists match; the replies to a malformed
  client identification, random padding in unencrypted packets and the
  absence of a delay after a wrong password do not.
- The Telnet reference image lacked `/etc/services` and listened on nothing;
  the controlled test removed its engine before the web session was
  delivered. Both fixed.
- The differences that comparison found are fixed where they are the server's
  behaviour: the SSH decoy pads unencrypted packets with zeros, answers a
  malformed client identification and a bad first packet as OpenSSH does,
  advertises OpenSSH's signature algorithms and pauses after a wrong
  password; the Telnet decoy negotiates options, prints its banner, echoes
  and pauses as telnetd does; the FTP decoy's replies, limits and failed
  logins follow vsftpd and ProFTPD; HTTP/0.9 requests, `POST` to a static
  page and the 501 page follow Apache and nginx. Left as they are, on
  purpose: the decoy still lets a client in after a few wrong passwords, and
  it serves its own page rather than the distribution's default one.
- Backup, restore and key rotation have now been run on the reference
  server: a fresh backup restored into a throwaway database with matching
  row counts, a transcript that decrypts with the key from the same set, and
  the trained models; `rotate_key` re-sealed the 209 blobs written before
  binding existed.

## 1.0.0

The hardening pass before the system's first exposure to the internet. Up to
this release it has recorded only the team's own controlled test traffic.

Released 2026-11-11.

**What was verified, and what was not.** The engine, backend and console
test suites, the PostgreSQL-only tests, the migrations from an empty
database, the compose files and the firewall rules (with real connections in
network namespaces) run in CI on every push. Not verified: `install.sh`, the
image builds, backup and restore have not been run end to end since these
changes, because the reference server was offline when the release was cut;
the fingerprint comparison against real daemons has not been run; and the
system has still seen no traffic from the internet.

### Containment

- The host firewall now covers every bridge of the deployment, not only the
  decoy bridge: a container may answer connections and may not open one to
  the host or to another network, for IPv4 and IPv6. Before, an engine could
  reach every service the host listened on through its internal bridges.
- The rules are two nftables tables loaded in one transaction, checked
  against the Docker networks, re-checked every five minutes with an alert
  when they were missing, and tested with real connections in network
  namespaces (`deploy/server/tests/egress-netns-test.sh`).
- Engines can reach only the ingest service, which serves only the
  engine-facing routes (`API_ROLE=ingest`). The dashboard API is no longer
  on a network an engine shares in a way it can use.
- One ingest token per engine, bound to its node name, and a separate
  control token.
- Every service: no capabilities, `no-new-privileges`, read-only root,
  memory, process and log limits. The API image has no compiler and does not
  own its code. Postgres runs as its own user.

### Deployment and operations

- `install.sh` verifies what it starts: one git revision in every container,
  networks matching the firewall, and a connection test from inside the
  engines. It reloads the firewall instead of restarting Docker.
- `backend` and `ingest` are one build and are recreated together.
- The administrator's password is shown once and no longer stored.
- Backups include the models and the shop's source, can be encrypted and
  copied off the machine, and fail loudly; restore is one transaction;
  `restore-drill.sh` rehearses it.
- A host heartbeat pings an external dead man's switch while everything is
  healthy; failed host jobs raise dashboard alerts.
- Each model service has its own profile and is enabled only when its file
  is present and verified. GeoIP refreshes weekly.
- `deploy/node` rebuilt as a hardened sensor kit for a public VPS;
  `deploy/cowrie-baseline` added for the comparison with a stock Cowrie.
- The development stack binds to loopback and has no built-in token.
- The Render and Vercel files moved to `deploy/legacy`, unmaintained.

### Supply chain and CI

- Base images pinned by digest (Python, Postgres, llama.cpp);
  `scripts/pin-images.sh` for the rest and for updates.
- Python dependencies installed from hashed lock files
  (`scripts/lock-requirements.sh`); the spaCy model by URL and hash; the
  decision model and the GeoIP database checked against published checksums.
- CI: engine and backend tests on the locked dependencies, a Postgres job
  with migrations, the console checks, ruff, shellcheck, compose validation
  against the address plan, and report-only audit, lint and secret-scan jobs.
- `passlib` removed (unused). Version 1.0.0 in the console, API and engine.

### Backend security

- Per-node engine tokens (a token used for another node is refused), a
  control token, an ingest-only API role, and a body limit on the engine
  routes.
- Encryption-key rotation (`ENCRYPTION_KEY_PREVIOUS`,
  `python -m app.core.rotate_key`).
- `X-Forwarded-For` is read only from a trusted proxy.
- Sign-in limits per source address; a cap on one-time codes; sign-up and
  password reset answer 503 where no mail provider exists.
- An allowlist for the blocklist feed; an audit-log route.

### Engine

Safety of the engine itself:

- A pattern an attacker gives to the emulated `grep` is matched with a time
  budget instead of on the event loop without one; one command could freeze
  every decoy.
- What one session may hold in memory is bounded (stored output, transcript,
  uploads), with counters for what was cut; Telnet sessions free their files.
- A finished session is written to the spool before it is sent and removed
  on success. A session the backend refuses goes to a dead-letter directory
  after a few attempts instead of blocking every session behind it.
- Retention deletes captures only; it used to delete the host's identity
  file after seven days.
- The engine refuses to start on the published default token. Isolation
  checks test what they name, repeat, and travel in the heartbeat.

What is captured:

- `sh`, `bash`, pipe-to-shell and commands given by absolute path are run by
  the emulator and recorded as executions; they used to answer "command not
  found". Download URLs are parsed with their options.
- A password that was accepted once is accepted again from the same source,
  so a returning loader gets in. Commands are recorded before they are
  emulated.
- HTTP: refused requests (over-long lines, oversized bodies, bad chunking)
  are recorded, chunked bodies are decoded, and every request keeps its
  headers (credentials in them masked), so header-borne attacks are visible.
- Client fingerprints: SSH client version, HASSH and hasshServer, the Telnet
  option sequence, JA3 and JA4 from the TLS ClientHello, HTTP header order.
- SSH forwarding requests and connections refused by the rate limits are
  recorded.
- Honeytokens: per-deployment fake secrets planted in the decoy's files and
  its `/.env`; a login that uses one raises `honeytoken_used` on any protocol.
- An AI-agent canary in the shell and on the web decoy: bait only an
  automated assistant would act on; acting on it raises
  `ai_canary_triggered`.

How it looks to a client:

- The shell understands variables, command substitution, simple loops and
  the common forms of `awk`, `sed`, `grep`, `top`, `netstat` and `ss`. One
  seeded filesystem is shared by `ls`, `cat`, `cd` and SFTP, so listings are
  stable and listed files can be read. A terminal gets CRLF and control keys;
  a non-interactive command gets no banner or prompt.
- Values that were identical on every deployment now derive from the host
  identity. The SSH host-key algorithm order follows the imitated release.
- FTP speaks the dialect of the daemon its banner claims; listings, sizes
  and downloads agree; a client sees its own changes.
- HTTP answers `HEAD`, write methods and closes as the claimed server does,
  with its header order and stock pages. Reply jitter defaults to 1–6 ms and
  never changes a banner.
- The stock texts were written from knowledge of the real daemons and have
  not yet been compared with them; that comparison is what
  `tools/fingerprint_audit` is for.

### Analysis

- The rule layer sets a session's category. The flow classifier is advisory:
  it produced no attack verdict on any stored session, so its output is kept
  for study and decides nothing.
- Severity and alerts follow the evidence that set the category; they used
  to take the flow classifier's confidence in "benign".
- ATT&CK techniques are checked against a catalog built from the official
  bundle (version 20.1). An id that is not in it is shown as unverified and
  never counted; names and tactics come from the catalog.
- Rules read what a command does, not what it mentions; web signatures see
  URL-decoded input and request headers; matching is linear-time and the
  input is bounded. De-obfuscation covers more encodings.
- Both models read the same window of a transcript: its start, its end and
  every line the rules flagged, with omissions marked and delimiter
  look-alikes neutralised. Their findings can raise or escalate an alert,
  and disagreement with the rules is recorded.
- The anomaly detector flags nothing until it has been fitted on captured
  sessions (`python -m ml.fit_anomaly`, also scheduled); before that the
  console says "not calibrated". Clustering is fitted on a schedule, reloads
  when refitted, and back-fills stored sessions.
- Alerts group by source and category with every contributing session
  listed, and a later, more serious session updates the alert. A scanner's
  address quiets alerts only when the session also behaves like a scan.
- An address that only appears in typed text is stored as `referenced_ip`
  and never reaches the blocklist feed.
- Models load at start-up and the unused language pass is off, so the
  200 ms budget is no longer spent on loading.
- Tools: `eval_pipeline` and `label_sessions` (per-layer confusion matrices
  on labelled sessions), `eval_injection` (robustness of the model stages to
  padding and steering text), `export_dataset` (anonymised research export),
  `compare_cowrie` (comparison with a stock Cowrie log),
  `build_attack_catalog`, and `reanalyze --attack-catalog`. Evaluation
  outputs record the code revision.
- Not built: a classifier trained on the honeypot's own sessions. It needs
  labelled captured sessions, which do not exist yet.

### Console

- Session replay with timing, an ATT&CK matrix with a Navigator-layer
  download, trends over 7, 30 and 90 days, an audit-log viewer, blocking and
  unblocking an address, client fingerprints and signals on sessions and
  attacker profiles, saved searches, a light high-contrast theme, a
  presentation mode that masks secrets, and a UTC/local switch.
- A failed load no longer looks like "nothing there"; the open session
  refreshes; a stale response cannot overwrite a newer page.
- Each verdict is labelled with the layer that produced it, tactics are
  named, and nothing uncalibrated is shown as a probability.
- Sign-up and password reset are offered only where mail can be sent;
  signing out in one tab signs out the others; downloading a captured
  sample asks first.

### Found by an independent review of this release, and fixed in it

- Planted secrets and the canary token were derived from the host identity
  seed, which was 31 bits and could be recovered offline from one value the
  decoy prints. They now derive from a separate 256-bit secret
  (`HONEYPOT_DECOY_SECRET`); new identity seeds are 63 bits.
- The engine's cap on events could discard the canary, honeytoken and
  download events that alerts depend on; they now have their own allowance,
  and a planted login is noticed past the login-attempt cap.
- An engine that had not yet registered, or whose token was refused, sent
  its sessions to the dead-letter directory. They are now kept until it has
  registered again.
- One command line could hold the engine's event loop for seconds. A line
  now has a bounded share of it and yields between pipeline stages.
- Stored commands, transcripts and credentials were not bound to their row
  and column, so a blob moved to another column still opened. They are bound
  at ingest; `ENCRYPTION_REQUIRE_CONTEXT` refuses the unbound ones once
  older rows have been re-sealed.
- Payload analysis ran inside the ingest workers, next to a process holding
  every secret. It now runs only in the single-process dashboard API, which
  polls the queue; ingest mounts the models read-only.
- Model files are unpickled, and the analysis child could have replaced one.
  They are now signed with a key the child does not have and nothing unsigned
  is loaded (`python -m app.ai.provenance sign` for a model trained
  elsewhere).
- Alert folding under concurrent ingest workers could lose a count; list
  fingerprints were dropped at ingest; what the engine truncated was not
  stored; the evaluation tool could print a headline for a layer that
  answered few sessions.

The review did not reach everything: the firewall rules under a live Docker,
backup and restore, key rotation, and the SSH, Telnet and FTP emulators in
depth were not examined.

### Evaluation tools

- `tools/fingerprint_audit`: sends the same probes to a decoy and to the
  real daemon it imitates and reports what differs, for SSH, FTP, HTTP and
  Telnet.
- `tools/controlled_traffic`: produces labelled, controlled test traffic
  against a throwaway engine on loopback, for `eval_pipeline`.
- A first controlled check of the pipeline with it is recorded in
  `docs/evaluation/controlled/`: on about ninety labelled sessions of the
  team's own test traffic the rule layer stored 62% under their label; the
  three gaps that exposed (a guessed login, sensitive-path probes, a
  Shellshock header) were fixed, and a second run with a different seed
  gave 79%. The rest are mostly scan probes, which one session at a time
  cannot be told from an empty connection. It also showed that an SSH banner
  grab leaves no record at all, which is open.

### Documentation

- New: threat model, data handling, exposure runbook, evaluation plan,
  configuration reference, security policy, this changelog.
- Corrected: every claim found not to match the code or the evidence files,
  in the README, the deployment guides, the technical reference and the
  evaluation page. Figures with no evidence file were removed; each
  evaluation result now carries its threats to validity.
