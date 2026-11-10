#!/usr/bin/env bash
#
# Host-level health check and dead man's switch. Run every five minutes by
# honeysentinel-heartbeat.timer; safe to run by hand.
#
# Why it exists. This server was once down for five days, and the only alert
# came after it was back: every check lived inside the thing that had
# stopped, and the containers cannot send a notification anyway (they have
# no way out, on purpose). The host does have a way out. So the host checks
# the deployment and, only when everything passes, requests HEARTBEAT_URL.
# The service behind that URL raises the alarm when the requests stop:
# whether the cause is a failed check, a crashed host, a power cut or a
# dead network link.
#
# What must hold for a ping:
#   - every service of the compose project is running and, where it has a
#     health check, healthy
#   - the egress rules are loaded and match the Docker networks
#   - the newest backup is younger than HEARTBEAT_BACKUP_MAX_AGE_HOURS (26)
#   - every application container was built from the same git revision
#   - the disk holding Docker's data is less than 90 % full
#
# Settings, in .env:
#   HEARTBEAT_URL        requested (GET) after a passing run. Any "dead man's
#                        switch" works: healthchecks.io, Uptime Kuma's push
#                        monitor, Better Stack heartbeats, cronitor. Set its
#                        period to 5 minutes and its grace to 10.
#   HEARTBEAT_FAIL_URL   optional; requested (POST, the failed checks as the
#                        body) after a failing run, for services that can be
#                        told about a failure instead of waiting for silence.
#
# Nothing but the request itself leaves the machine, and the failure body
# names checks, never data. A failing run also raises the system alert
# "host_health" in the dashboard and a passing one resolves it. Every run
# appends one line to state/availability.jsonl, which is the local record
# for the 30-day availability figure (docs/EVALUATION_PLAN.md).

set -uo pipefail
cd "$(dirname "$0")" || exit 1
# shellcheck source=deploy/server/backup-lib.sh
. ./backup-lib.sh

APP_SERVICES="backend ingest honeypot honeypot-web web"
problems=()

services=$(docker compose config --services 2>/dev/null)
if [[ -z "$services" ]]; then
  problems+=("compose: the project could not be read")
fi
for service in $services; do
  id=$(docker compose ps -q "$service" 2>/dev/null | head -n 1)
  if [[ -z "$id" ]]; then
    problems+=("$service: no container")
    continue
  fi
  state=$(docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id" 2>/dev/null)
  case "$state" in
    "running healthy"|"running none") ;;
    *) problems+=("$service: ${state:-unknown}") ;;
  esac
done

if ! reason=$(./honeysentinel-egress.sh check 2>&1); then
  problems+=("egress: $reason")
fi

dest=$(setting BACKUP_DEST); dest=${dest:-/var/backups/honeysentinel}
max_age=$(setting HEARTBEAT_BACKUP_MAX_AGE_HOURS); max_age=${max_age:-26}
if [[ -f "$dest/LATEST" ]]; then
  age_hours=$(( ($(date +%s) - $(stat -c %Y "$dest/LATEST")) / 3600 ))
  (( age_hours <= max_age )) || problems+=("backup: newest is ${age_hours} h old")
else
  problems+=("backup: none recorded in $dest")
fi

revisions=""
for service in $APP_SERVICES; do
  id=$(docker compose ps -q "$service" 2>/dev/null | head -n 1)
  [[ -n "$id" ]] || continue
  revisions+="$(docker inspect -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$id" 2>/dev/null)"$'\n'
done
distinct=$(grep -cv '^$' <<<"$(sort -u <<<"$revisions")" || true)
(( distinct <= 1 )) || problems+=("revision: containers were built from $distinct different revisions")

docker_root=$(docker info -f '{{.DockerRootDir}}' 2>/dev/null); docker_root=${docker_root:-/var/lib/docker}
used=$(df --output=pcent "$docker_root" 2>/dev/null | tail -n 1 | tr -dc '0-9')
[[ -z "$used" ]] || (( used < 90 )) || problems+=("disk: $docker_root is ${used}% full")

now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
install -d -m 0700 state
last=$(cat state/heartbeat.last 2>/dev/null || echo unknown)

if [[ ${#problems[@]} -eq 0 ]]; then
  printf '{"at":"%s","ok":true}\n' "$now" >> state/availability.jsonl
  url=$(setting HEARTBEAT_URL)
  if [[ -n "$url" ]]; then
    curl -fsS -m 10 --retry 3 -o /dev/null "$url" || echo "heartbeat: the ping to HEARTBEAT_URL failed" >&2
  fi
  if [[ "$last" == fail ]]; then
    ./system-alert.sh --resolve host_health "All host checks pass again ($now)." >/dev/null 2>&1 || true
  fi
  echo ok > state/heartbeat.last
  echo "healthy"
  exit 0
fi

summary=$(printf '%s; ' "${problems[@]}")
python3 -c 'import json,sys; print(json.dumps({"at": sys.argv[1], "ok": False, "problems": sys.argv[2:]}))' \
  "$now" "${problems[@]}" >> state/availability.jsonl
echo "NOT HEALTHY: $summary" >&2
fail_url=$(setting HEARTBEAT_FAIL_URL)
if [[ -n "$fail_url" ]]; then
  curl -fsS -m 10 --retry 2 -o /dev/null --data-raw "$summary" "$fail_url" || true
fi
./system-alert.sh host_health high "Host health check failing" \
  "$summary No heartbeat is being sent while this lasts." >/dev/null 2>&1 || true
echo fail > state/heartbeat.last
exit 1
