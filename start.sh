#!/bin/bash
echo "Starting HoneySentinel..."

cd /home/meowman/Desktop/honeypot-ui

echo "Starting Docker containers..."
docker compose up -d

echo "Starting ngrok tunnel..."
setsid ngrok http 5173 --log=stdout > /tmp/ngrok-main.log 2>&1 &
disown

sleep 8
URL=$(grep -o 'https://[^ ]*ngrok-free\.dev' /tmp/ngrok-main.log | head -1)

if [ -z "$URL" ]; then
    URL=$(grep -o 'https://[^ ]*ngrok-free\.app' /tmp/ngrok-main.log | head -1)
fi

echo ""
echo "HoneySentinel is running!"
echo "Dashboard: $URL"
echo "API:       $URL/api/v1/docs"
echo ""
echo "To stop: ./stop.sh"
