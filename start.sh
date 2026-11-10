#!/usr/bin/env bash
# Start the local development stack (docker-compose.yml in this directory).
# Everything it publishes is on 127.0.0.1. For a machine that faces a
# network, use deploy/server/install.sh instead.
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -f .env ]; then
    echo "No .env found. Creating one from .env.example with generated secrets..."
    cp .env.example .env
    for key in SECRET_KEY ENCRYPTION_KEY HONEYPOT_INGEST_TOKEN; do
        value=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
        # Portable in-place edit (BSD and GNU sed disagree on -i).
        tmp=$(mktemp)
        sed "s|^${key}=.*|${key}=${value}|" .env > "$tmp" && mv "$tmp" .env
    done
    echo "Generated secrets written to .env"
fi

echo "Starting Docker containers..."
docker compose up -d --build

echo
echo "HoneySentinel is running:"
echo "  Dashboard : http://localhost:5173"
echo "  API docs  : http://localhost:8000/docs"
echo "  Health    : http://localhost:8000/health"
echo
echo "Emulated services (safe to probe):"
echo "  SSH  : localhost:2222"
echo "  FTP  : localhost:2121"
echo "  Telnet : localhost:2323"
echo "  HTTP : localhost:8080"
echo
echo "To stop: ./stop.sh"
