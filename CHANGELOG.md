# Changelog

## 1.0.0

The hardening pass before the system's first exposure to the internet. Up to
this release it has recorded only the team's own controlled test traffic.

> **To complete after the final merge.** This entry was written while the
> pass was still being merged. Before tagging:
>
> - [ ] Engine section: confirm the list against the merged engine work
>       (fingerprints, canary, honeytokens, shell hardening).
> - [ ] Analysis section: add the evaluation, labelling, export and
>       comparison tools and the scheduled model fits once that work is in,
>       with their final command names.
> - [ ] Console section: add session replay, the ATT&CK matrix and Navigator
>       export, trends, the audit-log viewer, the block list and the light
>       theme once that work is in.
> - [ ] Regenerate what is generated: `bash scripts/lock-requirements.sh`,
>       `python3 scripts/list_routes.py` (the table in
>       docs/TECHNICAL_REFERENCE.md), and check docs/CONFIGURATION.md
>       against `backend/app/core/config.py` and `honeypot/core/config.py`.
> - [ ] Run `sudo bash deploy/server/install.sh` on the reference server and
>       record here that its verification passed, with the revision.
> - [ ] Set the release date.

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

- The engine refuses to start on the published default token.
- Isolation checks repeat periodically and travel in the heartbeat; the
  network check passes only if the host drops what the engine sends.
- An AI-agent canary; SSH client fingerprints; a dead-letter directory for
  sessions the backend refuses; bounded pattern matching in the emulated
  text tools.

### Documentation

- New: threat model, data handling, exposure runbook, evaluation plan,
  configuration reference, security policy, this changelog.
- Corrected: every claim found not to match the code or the evidence files,
  in the README, the deployment guides, the technical reference and the
  evaluation page. Figures with no evidence file were removed; each
  evaluation result now carries its threats to validity.
