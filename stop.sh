#!/bin/bash
echo "Stopping HoneySentinel..."

pkill -f "ngrok http" 2>/dev/null

cd /home/meowman/Desktop/honeypot-ui
docker compose down

echo "HoneySentinel stopped."
