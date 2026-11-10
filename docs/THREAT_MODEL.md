# Threat model

[Back to the project overview](../README.md)

What this deployment protects, where its trust boundaries are, what an
attacker can do at each one, and what is left over. Written from
`deploy/server/docker-compose.yml`, `deploy/server/honeysentinel-egress.sh`
and `deploy/node/`; where a statement rests on a test rather than on reading
the configuration, the test is named. Statements about a running system that
have not yet been verified on the reference server are marked *not yet
verified*.

The starting assumption is the one a honeypot has to make: **the engine will
be attacked by people who are good at it, continuously, and should be treated
as compromised.** The design question is what that compromise is worth.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Captured evidence: transcripts, credentials typed into decoys, uploaded files, source addresses | Postgres (`pgdata`), sensitive columns encrypted with `ENCRYPTION_KEY`; for a few days also in each engine's data volume | Personal data of third parties and live malware ([DATA_HANDLING.md](DATA_HANDLING.md)); the research data itself |
| `ENCRYPTION_KEY`, `SECRET_KEY`, the database password | `deploy/server/.env` (root, 0600); the environment of `backend` and `ingest` | Reads every stored transcript; mints an administrator session |
| Engine tokens (one per node) and the control token | `.env`; each engine holds only its own | Writes sessions under a node's name; drives an engine's control API |
| Integrity of the record | The database; the audit log | A honeypot whose data can be forged or silently altered is evidence of nothing |
| The host and the network around it | The server sits on an organisation's network behind its firewall | The honeypot must not become the way in |
| The live shop's data (when a site sits behind the decoys) | `shop_data` volume | Real visitors' accounts on the demo shop |
| Backups | `/var/backups/honeysentinel`, and wherever they are copied | Everything above in one directory |

## Components and trust boundaries

```
 internet ─────────────────────────────┐                      tailnet users
   │  B1                               │                            │  B6
   ▼                                   ▼                            ▼
 honeypot (ssh/telnet/ftp)        honeypot-web (http/https)   Tailscale Serve (host)
   │        │                       │      │       │                │
   │ B2     │ B3                    │ B2   │ B3    │ B4             ▼
   ▼        ▼                       ▼      ▼       ▼               web (Caddy)
 ingest ◄───────────────────────────┘   (control) shop / shop-decoy  │ B5
   │ B5        backend ─── B3 ──► engines' control API               ▼
   ▼            │   │                                             backend
 postgres ◄─────┘   └──► wolfram, decider (local models)
 ─────────────────────────── B7: every container │ the host ────────────────
```

| | Boundary | Enforced by |
|---|---|---|
| B1 | Internet → decoy ports | Only the published ports (`hs-decoy`, IPv4). The engine never executes what it receives; the shell is emulated. |
| B2 | Engine → ingest | `hs-engine`: the firewall allows engine → `172.30.67.20:8000` and nothing else on that bridge. `API_ROLE=ingest`: only the three `*-internal` routes and `/health` exist there. Per-node token, bound to the node name. Body limit `MAX_INTERNAL_BODY_BYTES`. |
| B3 | Backend → engine control API | `hs-control`: the firewall allows backend → engine `:8000` and replies; an engine cannot open a connection there. The backend's API does not listen on its control address. `HONEYPOT_CONTROL_TOKEN`. |
| B4 | Web engine → shop copies | `hs-shop`, `hs-shop-decoy`: one allowed flow each, engine → shop `:3000`. The two copies share no network. |
| B5 | Proxy → API → database, models | Internal bridges `hs-app`, `hs-db`, `hs-llm`. Postgres requires TLS and a password. |
| B6 | Operators → dashboard | Reachable only through Tailscale Serve on the tailnet (the port is published on loopback). Accounts, roles, optional TOTP, lockout, audit log. |
| B7 | Any container → the host and beyond | The host firewall: on every `hs-*` bridge and for every address in `172.30.64.0/19`, a container may answer and may not open a connection to the host or to another network. Docker will not start without the rules; a timer re-checks them every five minutes. |

## What an attacker can do at each boundary

### B1. Anyone on the internet, against the decoys

Intended: connect, log in with guessed credentials, run commands in the
emulated shell, upload files, send any HTTP request. All of it is recorded.

Not intended, and what stands in the way:

- **Exhaust the engine.** Per-address and global connection limits, session
  time limits, capped in-memory lists, a 1 GiB memory and 256-process limit
  on the container. A flood degrades capture; it does not reach anything else.
- **Recognise the honeypot** and avoid it or feed it noise. Not prevented.
  The SSH transport imitates one OpenSSH release exactly; timing and the
  bounded filesystem remain tells
  ([limitations](TECHNICAL_REFERENCE.md#honest-limitations)).
- **Poison the record**: flood it with invented sessions, or craft
  transcripts aimed at the analysis models (prompt injection). Sessions are
  attributed and rate-limited, not authenticated; that is inherent. The
  decision model answers only with probabilities over fixed options and the
  language model's indicators are kept only when they appear verbatim in the
  transcript. Robustness to injection is planned to be measured, not yet
  measured ([EVALUATION_PLAN.md](EVALUATION_PLAN.md)).
- **Exploit the engine itself** (a bug in the SSH library, in a parser).
  Assume this succeeds; see the next section.

### A compromised engine (code execution inside `honeypot` or `honeypot-web`)

It runs as uid 10001 with no capabilities, `no-new-privileges`, a read-only
root filesystem, a `noexec` tmpfs, and its data volume.

| It wants to | Result | Why |
|---|---|---|
| Reach the internet (fetch tools, call home, attack others) | Blocked | B7: new connections from `hs-decoy` are dropped; DNS forwards nowhere (`dns: 127.0.0.1`). |
| Reach the host's services (sshd, the Docker socket's TCP port if any, anything on `0.0.0.0`) through a bridge gateway | Blocked | B7 covers every bridge it is on, by interface and by source address. This was open on all but `hs-decoy` before 1.0.0. |
| Reach the organisation's network | Blocked | Same rule: it is "another network". |
| Use the dashboard API (log in, read sessions, export) | Not reachable | The backend is not on `hs-engine`; on `hs-control` it does not listen and the engine cannot connect. `ingest` serves no such route. |
| Read the database or the encryption key | Not reachable | Not on `hs-db`; holds neither secret. |
| Write false sessions | **Possible, under its own node name only** | It holds its own token. A token is refused for any other node. |
| Drive the other engine's control API | Blocked | Engines cannot open connections on `hs-control`, nor to each other on any bridge. It does hold the shared control token; the network is what stops it. |
| Attack the ingest service's three routes (malformed or oversized payloads) | Possible | The remaining attack surface towards the backend. Bodies are size-limited; analysis of uploaded files runs in a resource-limited subprocess. |
| Attack the live shop (web engine only) | **Possible, on port 3000** | It is the shop's reverse proxy by design. |
| Persist | In its data volume only | The image and root filesystem are read-only; the volume is not executable from `/tmp`, but files written to the volume survive a restart. Recreate the volume after a suspected compromise. |
| Read what other attackers typed | Possible for sessions still on its volume | Local copies are kept `HONEYPOT_CAPTURE_RETENTION_DAYS` (7), in plain text. |

Verified by: `deploy/server/tests/egress-netns-test.sh` (44 connection
checks against the real ruleset, in network namespaces),
`honeysentinel-egress.sh probe` at the end of every `install.sh`, and the
engine's own isolation checks in each heartbeat. *Not yet verified on the
reference server:* this release's rules and network layout have not been
installed there.

### A compromised ingest or backend (for example through a parser fed an uploaded file)

These hold every secret. Compromise here is compromise of the data.

- **Contained:** no outbound connection to the host, the internet or the
  organisation's network (B7), so stolen data has no direct way out and the
  process cannot fetch a second stage. No capabilities, read-only root,
  code owned by root, no compiler in the image.
- **Not contained:** everything in the database and the key to it; the
  ability to alter or delete records (the audit log lives in the same
  database); the engines' control API (from `backend`); the model servers.
- **Exfiltration path that remains:** through its own answers. A compromised
  backend can put data into responses to dashboard users; a compromised
  ingest can only answer engines.

### B6. Dashboard users and stolen sessions

A viewer reads sessions; an analyst can export; an administrator can read
captured credentials, download samples and manage accounts. Tokens are kept
in browser storage, so script injection in the console would be session
theft; the proxy sends a strict content-security policy. Lost or stolen
operator devices are handled by the tailnet (remove the device) and by
`logout-all`.

### B7. The host

Whoever has root on the host has everything: `.env`, the volumes, the
firewall. The host runs nothing internet-facing of its own (its sshd is on
the LAN and tailnet; the decoys are the only forwarded ports).

### The remote sensor (deploy/node)

A VPS holding one engine, its own token and nothing else. Compromise of the
engine there is as above with one allowed destination, the server's ingest
port on the overlay. Compromise of the VPS itself (root) yields that token,
the undelivered sessions and overlay membership: restrict the overlay so the
sensor reaches the ingest port only.

## Residual risks

Ordered by how much they should worry an operator.

1. **This release's containment has not run on the reference server.** The
   rules are tested in isolation; the installed combination is verified by
   the installer's probe the first time it runs. Do not expose before that
   passes ([EXPOSURE_RUNBOOK.md](EXPOSURE_RUNBOOK.md)).
2. **A backend or ingest compromise exposes all captured data and the key.**
   Nothing inside the deployment limits that. Mitigations are indirect: the
   attack surface is the ingest routes and file parsers only, and there is
   no way out for the data.
3. **False data.** An engine token writes sessions for its node. A flood of
   plausible fabricated sessions is hard to tell from traffic.
4. **Container escape.** A kernel or runtime vulnerability bypasses every
   control listed here. Mitigated only by dropped capabilities,
   `no-new-privileges` and patching the host. User namespaces and a
   seccomp profile beyond Docker's default are not configured.
5. **Rules removed between checks.** `nft flush ruleset` or a firewall
   reload removes the tables; the timer restores them within five minutes
   and raises an alert, and deletes connections containers opened meanwhile
   where `conntrack` is installed. The gap is up to five minutes.
   `HS_ISOLATED_GATEWAY` narrows it for the internal bridges on Docker 28+.
6. **The live shop is exposed to whatever the diversion rules miss**, and to
   the web engine itself.
7. **Backups.** Unencrypted unless configured, and on the same disk unless
   an off-host copy is configured.
8. **Alerting depends on someone looking**, plus one outbound path: the
   host heartbeat. Email and webhook alerts do not work on this deployment.
9. **The two model servers and the model files are trusted.** The language
   model file has no pinned checksum unless `WOLFRAM_SHA256` is set; images
   for Node and Caddy are still referenced by tag
   (`scripts/pin-images.sh`).
10. **Intra-bridge rules are stateless** (replies are recognised by source
    port and TCP flags). The listed services can answer on those bridges
    but could also send unsolicited non-SYN segments; no listed service is
    an adversary in this model.
11. **IPv6 is not served.** The plan is IPv4 only and the rules drop IPv6
    from every bridge; an IPv6-only attacker is not captured.

## Out of scope

Denial of service against the host's uplink; physical access; compromise of
the tailnet's coordination service or of an operator's device; the security
of the demo shop application itself, which is a separate project.
