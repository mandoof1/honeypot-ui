# Deployment Guide

Three pieces deploy independently:

| Component | Where | Why |
|---|---|---|
| Backend API | Render (or any PaaS) | Ordinary HTTP service |
| Frontend | Vercel (or any static host) | Static build output |
| Honeypot engine | A VPS you control | Needs raw TCP ports, not just HTTP |

> **Before you start.** A honeypot is deliberately attractive to attackers.
> Only run it on infrastructure you own or are authorised to use, keep it off
> any network you care about, and confirm your provider's acceptable-use
> policy allows it. Most do; some explicitly do not.

---

## 1. Backend + database on Render

The repository ships a `render.yaml` blueprint that provisions both the API
and its PostgreSQL database.

1. Push the repository to GitHub.
2. In Render: **New +** → **Blueprint** → select the repository.
3. Render reads `render.yaml`, creates `honeysentinel-db` and
   `honeysentinel-api`, and generates `SECRET_KEY`, `ENCRYPTION_KEY` and
   `HONEYPOT_INGEST_TOKEN` automatically.
4. Fill in the variables marked `sync: false` in the dashboard:

   | Variable | Value |
   |---|---|
   | `CORS_ORIGINS` | Your frontend origin, e.g. `https://your-app.vercel.app` |
   | `ALERT_EMAIL_FROM` / `ALERT_EMAIL_TO` | Optional, for email alerts |
   | `BREVO_API_KEY` | Optional; or SendGrid/Resend/SMTP equivalents |
   | `WEBHOOK_URL` / `WEBHOOK_SECRET` | Optional, for webhook alerts |

5. **Copy the generated `HONEYPOT_INGEST_TOKEN`** out of the dashboard. The
   engine needs exactly the same value or every ingest is rejected with 401.

The first boot applies migrations automatically. Once more than one instance
is running, set `RUN_MIGRATIONS_ON_STARTUP=false` and run
`alembic upgrade head` as a release step instead, so two instances cannot
migrate concurrently.

To create the first administrator, set `SEED_ON_STARTUP=true` for one boot —
the generated password is printed once to the service log — then turn it back
off. Alternatively set `ADMIN_SEED_PASSWORD` yourself and nothing is logged.

### Free-tier caveats

Render's free web services sleep after 15 minutes idle and cold-start in
roughly 30–60 seconds. The AI models are fitted at build time, so a cold start
is dominated by process startup rather than training.

---

## 2. Frontend on Vercel

1. **New Project** → import the repository.
2. Vercel detects Vite from `vercel.json`.
3. Set one environment variable:

   ```
   VITE_API_URL = https://your-api.onrender.com/api/v1
   ```

   `VITE_*` variables are read at **build** time, so changing this requires a
   redeploy.
4. Deploy, then add the resulting origin to `CORS_ORIGINS` on the backend.

`vercel.json` sends `X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy` and `Permissions-Policy` on every response, and rewrites all
paths to `index.html` for client-side routing.

---

## 3. Honeypot engine on a free VM

The engine listens on raw TCP ports (2222/2121/8080/8443). PaaS free tiers —
Render, Vercel, Railway, Fly's HTTP services — expose a single HTTP port
behind a TLS-terminating proxy and cannot forward those connections, so the
engine needs a machine where you control the network. That rules out putting
it next to the backend on Render.

Two hosts give you one permanently, with no card charged after a trial:

| Host | Always-free allowance | Notes |
|---|---|---|
| **Oracle Cloud** (recommended) | 2 Ampere ARM OCPUs, 12 GB RAM, 200 GB block storage | Halved from 4/24 in June 2026, still far more than this needs. Card required for identity check only. |
| **Google Cloud** | 1 `e2-micro`, 30 GB disk, in `us-west1`/`us-central1`/`us-east1` | 1 GB/month egress. Tighter, but sufficient — the engine's traffic is almost all inbound. |

Both give a public IPv4 and arbitrary inbound TCP, which is the requirement.
The engine image is `python:3.12-slim` with two pure-Python dependencies, so
it builds unmodified on ARM.

### Before you start

Running a honeypot on a free tier is not free of consequences. It advertises
open services and will be found within hours. Two things follow from that:

- **Read the provider's acceptable-use policy.** A honeypot that only records
  inbound connections is ordinarily fine, but an instance that starts emitting
  traffic will draw abuse reports and free accounts get reclaimed quickly. The
  engine's egress allowlist and the container hardening below exist for this;
  do not disable them.
- **Use a throwaway project, not your main account.** If the instance is
  suspended you want to lose the instance, not the account holding the rest of
  your work.

The emulators never execute attacker input — they return canned protocol
responses — so a shell is never spawned. That is what makes this reasonable to
expose at all.

### Provisioning

Create an Ubuntu 22.04 or 24.04 instance, then open the ports **in the cloud
firewall as well as on the host**. On Oracle these are separate systems and
the cloud one silently drops traffic if you forget:

> Networking → Virtual Cloud Networks → *your VCN* → Security Lists →
> Default Security List → **Add Ingress Rules** — source `0.0.0.0/0`,
> TCP `21`, `22`, `80`, `443`, plus `22022` for your own SSH.

### Installing

```bash
git clone https://github.com/mandoof1/honeypot-ui.git
cd honeypot-ui/deploy/node
sudo bash bootstrap.sh
```

`bootstrap.sh` moves the real SSH daemon to port 22022 and makes you confirm
you can still log in **before** it hands port 22 to the emulator, installs
Docker, and persists the port redirects. Read it before running it; it changes
how you reach the box.

Then point the node at the backend:

```bash
cp .env.example .env
$EDITOR .env          # BACKEND_API_URL and HONEYPOT_INGEST_TOKEN
docker compose up -d --build
docker compose logs -f
```

`HONEYPOT_INGEST_TOKEN` must be byte-identical to the value on the backend —
copy it from the Render dashboard under Environment. A mismatch shows up as
`401` in the node's log and no sessions ever appear.

> Use this `deploy/node/` compose file, not the one at the repository root.
> The root file's honeypot service declares `depends_on: backend`, so running
> it here would start a second backend and Postgres alongside the engine.

On startup the engine verifies its isolation, registers itself with the
backend as a node, binds the enabled emulators, and starts its control API on
loopback.

### Letting the backend reach the control API

`/api/v1/honeypot/*` proxies to the engine, and the compose file binds that
port to `127.0.0.1` only — it is authenticated by the shared token alone and
must never face the internet.

Render's free tier has no static outbound IP, so it cannot be allowlisted.
Either:

- **Leave it closed.** Sessions still ingest normally; the dashboard shows
  "Engine unreachable" and hides live emulation status. Nothing is fabricated.
- **Expose it through a free Cloudflare Tunnel** and set `HONEYPOT_CONTROL_URL`
  on the backend to the tunnel hostname, with Cloudflare Access in front.

## 4. Optional: GeoIP

Without a GeoLite2 database, sessions are recorded with no location and the
map shows fewer markers. To enable geolocation:

1. Create a free MaxMind account and download `GeoLite2-City.mmdb`.
2. Place it where `GEOIP_DB_PATH` points (default `./data/GeoLite2-City.mmdb`).

---

## Verifying the deployment

For the capture-delivery upgrade, deploy the backend and Alembic revision **007**
before the engine and frontend. Preserve the engine's capture volume: its
`sessions/delivery.sqlite3` queue holds completed evidence awaiting a receipt.
See [recovery, limits and rollback](docs/CAPTURE_AND_CORRELATION.md).

```bash
# API is up
curl https://your-api.onrender.com/health

# Emulators answer
nc your-vps-ip 2222              # SSH banner
curl http://your-vps-ip:8080/    # HTTP response

# Engine reports itself through the backend
curl -H "Authorization: Bearer $TOKEN" \
     https://your-api.onrender.com/api/v1/honeypot/status
```

A healthy response has `"reachable": true` and `"running": true`. If
`reachable` is false, the backend cannot see the control API — check
`HONEYPOT_CONTROL_URL` and the network path.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Backend exits with "Refusing to start" | A secret is still a placeholder and `ENVIRONMENT` is not `development`. Set real values. |
| Ingest returns 401 | `HONEYPOT_INGEST_TOKEN` differs between backend and engine. |
| Captures awaiting delivery | Check `delivery.last_error` in engine status; the queue retries automatically. |
| Idempotent ingest unavailable | Upgrade the API through revision 007 and check its URL and ingest token. The engine retains queued captures. |
| Capture storage errors | Check space and permissions on the persistent capture volume; raw archives may need manual recovery. |
| `/honeypot/*` returns 502 "rejected the control token" | Same mismatch, on the control API side. |
| CORS errors in the browser | The frontend origin is missing from `CORS_ORIGINS`. |
| Rate limits trigger far too early | Behind a proxy without `TRUST_PROXY_HEADERS=true`, so every client shares the proxy's IP. |
| Sessions have no country | No GeoLite2 database configured — working as intended, not a failure. |
| Isolation checks report failures | Expected outside Docker. Inside Docker, check `cap_drop`, `read_only` and the `internal` network are all set. |
