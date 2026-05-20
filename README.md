# HoneySentinel AI — AI-Integrated Honeypot System

A comprehensive honeypot monitoring platform with AI-powered attack analysis, real-time threat visualization, and automated intelligence reporting.

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
└───────┬──────────────┬──────────────┬───────────────────┘
        │              │              │
   ┌────▼────┐   ┌─────▼─────┐  ┌────▼────┐
   │PostgreSQL│   │Elastic    │  │ Redis   │
   │          │   │Search     │  │         │
   └─────────┘   └───────────┘  └─────────┘
```

## Features

### Core Emulation & Data Capture
- **Multi-Protocol Emulation** — SSH (Cowrie), FTP, HTTP/HTTPS (Dionaea) adapters
- **Full Session Recording** — Commands, payloads, uploaded files, network packets
- **Adaptive Response** — Toggle between Active Emulation and Passive Monitoring modes

### AI & Analysis
- **Real-Time Attack Classification** — Random Forest model trained on CICIDS features (benign, reconnaissance, exploitation, exfiltration)
- **Semantic Intent Analysis (NLP)** — SpaCy-based engine detecting offensive tools (Metasploit, Mimikatz, Nmap, etc.) and attacker objectives
- **Anomaly Detection** — Isolation Forest fallback for unknown attack patterns
- **Attacker Profiling** — Behavioral clustering: APT, Script Kiddie, Automated Bot

### Threat Intelligence
- **MITRE ATT&CK Mapping** — Auto-correlates AI/NLP outputs to TTPs
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
- **AES-256 Encryption** — Raw session data encrypted at rest
- **Rate Limiting** — Per-IP throttling to prevent abuse
- **Audit Logging** — Full audit trail of all user actions

## Quick Start

### Option 1: Docker Compose (Recommended)

```bash
cp .env.example .env
docker compose up --build
```

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### Option 2: Manual Setup

**Backend:**
```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
# Start PostgreSQL, Elasticsearch, Redis first
python -c "from app.seed import seed_database; import asyncio; asyncio.run(seed_database())"
uvicorn app.main:app --reload
```

**Frontend:**
```bash
npm install
npm run dev
```

## Default Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@honeysentinel.io | admin123 |
| Analyst | analyst@soc.internal | analyst123 |
| Viewer | viewer@honeysentinel.io | viewer123 |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/login` | Authenticate |
| POST | `/api/v1/auth/register` | Register new user |
| GET | `/api/v1/dashboard/stats` | Dashboard statistics |
| GET | `/api/v1/dashboard/live-events` | Live threat events |
| GET | `/api/v1/sessions/` | List sessions (with filters) |
| GET | `/api/v1/sessions/{id}` | Session details |
| POST | `/api/v1/sessions/ingest` | Ingest new session |
| GET | `/api/v1/alerts/` | List alerts |
| PATCH | `/api/v1/alerts/{id}` | Update alert |
| GET | `/api/v1/nodes/` | List honeypot nodes |
| POST | `/api/v1/export/` | Export sessions (JSON/CEF/STIX) |
| GET | `/api/v1/settings/thresholds` | Alert thresholds |
| PATCH | `/api/v1/settings/system` | System configuration |

## Tech Stack

- **Frontend:** React 19, Vite 8, Tailwind CSS 4, React Router 7, Leaflet
- **Backend:** Python 3.12, FastAPI, SQLAlchemy (async), Pydantic
- **AI/ML:** scikit-learn (Random Forest, Isolation Forest), SpaCy (NLP)
- **Database:** PostgreSQL 16, Elasticsearch 8, Redis 7
- **Security:** JWT, bcrypt, AES-256 (Fernet), slowapi rate limiting

## License

MIT
