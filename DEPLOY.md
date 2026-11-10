# Deployment guide

Which way to run HoneySentinel, and where each is documented. Settings are
described once, in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

> **Before you expose anything.** A honeypot is deliberately attractive to
> attackers and records personal data (source addresses, the credentials
> people type). Run it only on infrastructure whose owner has agreed in
> writing, and only after the checklists in
> [docs/EXPOSURE_RUNBOOK.md](docs/EXPOSURE_RUNBOOK.md) and the decisions in
> [docs/DATA_HANDLING.md](docs/DATA_HANDLING.md).

| You want | Use | Exposed to the internet? |
|---|---|---|
| To try it, or to develop | The development stack: `./start.sh` | **Never.** Everything is on 127.0.0.1 and the engine is not contained. |
| The system, running for real | [`deploy/server/`](deploy/server/README.md): everything on one Linux machine | The decoy ports only, forwarded by the network's firewall; the dashboard stays on the tailnet |
| A decoy on a separate public address | [`deploy/node/`](deploy/node/README.md): one engine on a small VPS, reporting to the server over a private overlay | The VPS, which holds nothing but the engine |
| A stock Cowrie for comparison | [`deploy/cowrie-baseline/`](deploy/cowrie-baseline/README.md), beside the server's engines | Its SSH port, for the comparison period |

## 1. Development stack

```bash
./start.sh        # writes .env with generated secrets, then docker compose up
./stop.sh
```

PostgreSQL, the API (with reload), the Vite dev server and one engine, all
published on loopback. `SEED_ON_STARTUP=true` here fills an empty database
with 150 synthetic sessions and prints a generated administrator password in
the backend's log (`docker compose logs backend`). That seed is for
development only: never enable it where captured traffic is stored.

## 2. Self-hosted server

```bash
sudo git clone https://github.com/mandoof1/honeypot-ui.git /opt/honeysentinel
sudo bash /opt/honeysentinel/deploy/server/install.sh
```

One script: secrets, certificates, the egress firewall, the images, the
administrator (created directly, with no synthetic data; its password is
shown once), and the dashboard on the tailnet. It verifies what it started
and exits non-zero if the engines are not contained. The guide covers
updating, backups and restore, the models, a website behind the decoys, and
operation: [deploy/server/README.md](deploy/server/README.md).

The engines emulate SSH, Telnet, FTP, HTTP and HTTPS on ports 2222, 2323,
2121, 8080 and 8443 (plus 50000-50009 for passive FTP); the network's
firewall forwards 22, 23, 21, 80 and 443 to them.

Email and webhook alerts do not work on this deployment, by design: no
container can open an outbound connection. Alerts are in the dashboard, and
the host pings an external dead man's switch (`HEARTBEAT_URL`) while
everything is healthy.

## 3. Remote sensor

For when attack traffic should not enter your network at all, or for a
second vantage point. The sensor is an engine and nothing else, with its own
ingest token and exactly one permitted outbound destination: the server's
ingest endpoint on a WireGuard or Tailscale address. Step-by-step runbook and
pre-exposure checklist: [deploy/node/README.md](deploy/node/README.md).

A PaaS web service (Render, Vercel, Railway, Fly's HTTP services) cannot host
an engine: it exposes one HTTP port behind a TLS-terminating proxy, and the
engine needs raw TCP on several ports.

## The old split deployment

The project was first deployed with the API on Render, the console on Vercel
and the engine on a separate VM. Those files are in
[`deploy/legacy/`](deploy/legacy/README.md), unmaintained; that README says
why they are not a supported path.

## Verifying a deployment

```bash
cd /opt/honeysentinel/deploy/server
docker compose ps                                  # every service healthy
sudo bash honeysentinel-egress.sh check            # firewall rules and networks
sudo bash honeysentinel-egress.sh probe            # connect out from inside the engines
sudo bash controlled-test.sh --purge               # end to end, as controlled-test-node
sudo bash host-heartbeat.sh                        # the host-level checks
```

## Troubleshooting

| Symptom | Cause |
|---|---|
| `install.sh` stops with "do not match the address plan" | `docker-compose.override.yml` predates the fixed network names; update it from the example. |
| `install.sh` stops with "requirements.lock is out of date" during the build | A `requirements.txt` changed; run `bash scripts/lock-requirements.sh` and commit. |
| Backend exits with "Refusing to start" | A secret is still a placeholder and `ENVIRONMENT` is not `development`. |
| An engine exits with code 78 | Its ingest token is the published default; set a real one (`install.sh` and `start.sh` do). |
| Ingest returns 401 or 403 | 401: the token is unknown. 403: the token belongs to another node name. |
| `/honeypot/*` returns 502 "rejected the control token" | `HONEYPOT_CONTROL_TOKEN` differs between backend and engine. |
| Rate limits trigger far too early for everyone | The API is not seeing client addresses: check `TRUSTED_PROXIES` covers the proxy and nothing else. |
| Sessions have no country | No GeoIP database yet (`sudo bash fetch-geoip.sh`). Not a failure. |
| Verdicts say `model_source: "synthetic"` | No trained classifier in the models volume: `train-model.sh`, or restore it from a backup. |
| A system alert "Egress rules were missing or altered" | Something removed the firewall tables; they were re-applied. Find out what (`journalctl -u honeysentinel-egress-check`). |
