# HoneySentinel AI — Full Session Summary

## Project Overview

**HoneySentinel AI** is a comprehensive AI-integrated honeypot monitoring platform with real-time threat analysis, automated attack classification, and structured intelligence reporting.

### Tech Stack
- **Frontend:** React 19, Vite 8, Tailwind CSS 4, React Router 7, Leaflet.js
- **Backend:** Python 3.12, FastAPI, SQLAlchemy (async), Pydantic
- **AI/ML:** scikit-learn (Random Forest, Isolation Forest), SpaCy (NLP)
- **Database:** PostgreSQL 16 (local), Neon/Render PostgreSQL (cloud)
- **Deployment:** Docker Compose (local), ngrok (tunneling), Vercel + Render (cloud)

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (React)                      │
│  Dashboard │ Live Map │ Session Logs │ Settings          │
└──────────────────────┬──────────────────────────────────┘
                       │ REST API
┌──────────────────────▼──────────────────────────────────┐
│                  Backend (FastAPI)                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐ │
│  │  Auth    │ │ Sessions │ │ Alerts   │ │  Export    │ │
│  │  (JWT)   │ │  CRUD    │ │ Mgmt     │ │  SIEM      │ │
│  └──────────┘ └──────────┘ └──────────┘ └────────────┘ │
│                                                         │
│  ┌────────────────── AI Engine ──────────────────────┐  │
│  │  Random Forest │ NLP (SpaCy) │ Isolation Forest   │  │
│  │  Attacker Profiler │ MITRE ATT&CK Mapper          │  │
│  └───────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │  PostgreSQL  │
                    └─────────────┘
```

---

## Features Implemented

### Core Emulation & Data Capture
- **Multi-Protocol Emulation** — SSH (Cowrie adapter), FTP, HTTP/HTTPS (Dionaea adapter)
- **Full Session Recording** — Commands, payloads, uploaded files, network packets
- **Adaptive Response** — Toggle between Active Emulation and Passive Monitoring modes

### AI & Analysis
- **Real-Time Attack Classification** — Random Forest model trained on CICIDS features (benign, reconnaissance, exploitation, exfiltration)
- **Semantic Intent Analysis (NLP)** — SpaCy-based engine detecting 20+ offensive tools (Metasploit, Mimikatz, Nmap, etc.) and attacker objectives
- **Anomaly Detection** — Isolation Forest fallback for unknown attack patterns
- **Attacker Profiling** — Behavioral clustering: APT, Script Kiddie, Automated Bot

### Threat Intelligence
- **MITRE ATT&CK Mapping** — Auto-correlates AI/NLP outputs to TTPs across 10 tactics
- **Structured Reports** — JSON, CEF, STIX/TAXII export formats
- **SIEM Integration** — Direct consumption by external SIEM systems
- **IoC Extraction** — IPs, URLs, file hashes, tool signatures

### Dashboard
- **Live Analyst Dashboard** — Real-time stats, attack distribution, recent alerts
- **Geographical Attack Mapping** — Leaflet.js with threat markers and severity colors
- **Session Management** — Filtering, drill-down, pagination, export
- **Alert Thresholds** — Configurable severity and anomaly score thresholds
- **Automated Alerting** — Email and webhook notifications for high-severity events

### Security
- **JWT Authentication** — With refresh tokens and RBAC (Admin, Analyst, Viewer)
- **AES-256 Encryption** — Raw session data encrypted at rest (Fernet)
- **Rate Limiting** — Per-IP throttling via slowapi
- **Audit Logging** — Full audit trail of all user actions

---

## Backend Structure

```
backend/
├── app/
│   ├── ai/
│   │   ├── classifier.py          # Random Forest attack classifier
│   │   ├── anomaly_detector.py    # Isolation Forest anomaly detection
│   │   ├── nlp_engine.py          # SpaCy NLP for command/payload analysis
│   │   ├── attacker_profiler.py   # Behavioral clustering profiler
│   │   └── mitre_mapper.py        # MITRE ATT&CK TTP mapper
│   ├── api/
│   │   ├── auth.py                # JWT auth, login, register, refresh
│   │   ├── sessions.py            # Session CRUD, filtering, export
│   │   ├── alerts.py              # Alert management, status updates
│   │   ├── dashboard.py           # Dashboard stats, live events
│   │   ├── nodes.py               # Honeypot node management
│   │   ├── settings.py            # Alert thresholds, system config
│   │   └── export.py              # JSON/CEF/STIX export
│   ├── core/
│   │   ├── config.py              # Environment configuration
│   │   ├── database.py            # Async SQLAlchemy engine/session
│   │   ├── encryption.py          # AES-256 Fernet encryption
│   │   └── security.py            # JWT, password hashing, RBAC
│   ├── models/
│   │   └── __init__.py            # User, Session, Alert, Node, IoC, etc.
│   ├── schemas/
│   │   └── __init__.py            # Pydantic request/response models
│   ├── services/
│   │   ├── analysis.py            # Main AI analysis pipeline
│   │   ├── alerting.py            # Email/webhook notifications
│   │   ├── geoip.py               # IP geolocation lookup
│   │   ├── honeypot_adapters.py   # Cowrie/Dionaea API adapters
│   │   └── report_generator.py    # JSON/CEF/STIX report generation
│   ├── seed.py                    # Database seeding script
│   └── main.py                    # FastAPI app entry point
├── requirements.txt
└── Dockerfile
```

---

## Frontend Structure

```
src/
├── context/
│   └── AuthContext.jsx            # JWT auth provider
├── layouts/
│   └── DashboardLayout.jsx        # Sidebar + header shell
├── pages/
│   ├── Dashboard.jsx              # Stats, charts, recent alerts
│   ├── LiveMap.jsx                # Leaflet threat map
│   ├── SessionLogs.jsx            # Session table, filters, detail modal
│   ├── Settings.jsx               # Honeypot mode, alert thresholds
│   ├── Login.jsx                  # Login form
│   └── Signup.jsx                 # Registration form
├── services/
│   └── api.js                     # API client with JWT headers
├── App.jsx                        # Auth-gated routing
└── main.jsx                       # React entry point
```

---

## Deployment Options

### Option 1: Local (Docker Compose)
```bash
cp .env.example .env
docker compose up -d --build
```
- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8000`
- API Docs: `http://localhost:8000/docs`

### Option 2: Local + Public Tunnel (ngrok)
```bash
./start.sh   # Starts Docker + ngrok, prints public URL
./stop.sh    # Stops everything
```
- URL changes each restart (ngrok free tier)
- Works from any device on any network

### Option 3: Cloud (Free)
- **Frontend:** Vercel (free, custom domain, CDN)
- **Backend:** Render (free tier, 512MB RAM)
- **Database:** Render PostgreSQL (free, auto-provisioned)

```bash
git push origin master
# Deploy via Render Blueprint → Vercel import
```

---

## API Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/api/v1/auth/login` | Authenticate | No |
| POST | `/api/v1/auth/register` | Register new user | No |
| POST | `/api/v1/auth/refresh` | Refresh JWT token | No |
| GET | `/api/v1/auth/me` | Get current user | Yes |
| GET | `/api/v1/dashboard/stats` | Dashboard statistics | Yes |
| GET | `/api/v1/dashboard/live-events` | Live threat events | Yes |
| GET | `/api/v1/sessions/` | List sessions (paginated, filterable) | Yes |
| GET | `/api/v1/sessions/{id}` | Session details | Yes |
| POST | `/api/v1/sessions/ingest` | Ingest new session from honeypot | Yes |
| POST | `/api/v1/sessions/{id}/export` | Export session (JSON/CEF/STIX) | Yes |
| GET | `/api/v1/alerts/` | List alerts | Yes |
| GET | `/api/v1/alerts/{id}` | Alert details | Yes |
| PATCH | `/api/v1/alerts/{id}` | Update alert status | Yes |
| GET | `/api/v1/alerts/stats` | Alert statistics | Yes |
| GET | `/api/v1/nodes/` | List honeypot nodes | Yes |
| POST | `/api/v1/nodes/` | Create honeypot node | Admin |
| PATCH | `/api/v1/nodes/{id}` | Update node | Admin |
| DELETE | `/api/v1/nodes/{id}` | Delete node | Admin |
| POST | `/api/v1/export/` | Bulk export sessions | Yes |
| GET | `/api/v1/settings/thresholds` | List alert thresholds | Yes |
| POST | `/api/v1/settings/thresholds` | Create threshold | Admin |
| PATCH | `/api/v1/settings/thresholds/{id}` | Update threshold | Admin |
| DELETE | `/api/v1/settings/thresholds/{id}` | Delete threshold | Admin |
| GET | `/api/v1/settings/system` | System configuration | Yes |
| PATCH | `/api/v1/settings/system` | Update system config | Admin |

---

## Default Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@honeysentinel.io | admin123 |
| Analyst | analyst@soc.internal | analyst123 |
| Viewer | viewer@honeysentinel.io | viewer123 |

---

## Troubleshooting

### "Failed to fetch" on login (phone/other devices)
1. Open the ngrok URL in browser first
2. Click **"Visit Site"** on the ngrok warning page
3. Then try logging in

### ngrok URL changes after restart
This is expected on the free tier. Run `./start.sh` to get the new URL.

### Render build fails with async driver error
Fixed. The app now auto-converts `postgresql://` → `postgresql+asyncpg://`.

### Render free tier sleeps after 15 minutes
Use [UptimeRobot](https://uptimerobot.com) (free) to ping your API every 14 minutes to keep it awake.

### Database not seeded on cloud deploy
Fixed. The database now auto-seeds on first startup.

---

## Files Created During Session

| File | Purpose |
|------|---------|
| `backend/` | Complete FastAPI backend with AI engine |
| `docker-compose.yml` | Full stack orchestration |
| `Dockerfile.frontend` | Frontend container |
| `.env.example` | Environment template |
| `render.yaml` | Render Blueprint config |
| `vercel.json` | Vercel frontend config |
| `DEPLOY.md` | Cloud deployment guide |
| `cloud-deploy.sh` | Deployment helper script |
| `start.sh` | Local start script (Docker + ngrok) |
| `stop.sh` | Local stop script |

---

## Session Timeline

1. **Project understanding** — Analyzed existing React + Vite honeypot UI skeleton
2. **Backend creation** — Built complete FastAPI backend with AI engine, auth, CRUD, export
3. **Frontend integration** — Connected React frontend to real API with live data
4. **Docker setup** — Created docker-compose with PostgreSQL, Elasticsearch, Redis
5. **Local deployment** — Fixed bcrypt/passlib compatibility, timezone issues, SQLAlchemy errors
6. **Public access** — Set up ngrok tunneling for public URLs
7. **Cloud deployment** — Configured Vercel + Render + Neon for free cloud hosting
8. **Auto-seeding** — Fixed database seeding to work without Render shell access
9. **Final deployment** — Successfully deployed to Vercel (frontend) + Render (backend)

---

*Generated from session on May 20-21, 2026*
