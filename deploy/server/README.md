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
