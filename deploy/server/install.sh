#!/usr/bin/env bash
#
# Install or update the self-hosted HoneySentinel stack on this machine.
#
#   sudo bash deploy/server/install.sh
#   sudo bash deploy/server/install.sh --reset-admin-password
#
# Expects the repository at /opt/honeysentinel. Safe to re-run: secrets,
# certificates and the admin account are created once and then left alone;
# images are rebuilt and containers recreated only where something changed.
#
# What it does:
#   1. generates .env (database password, JWT/encryption keys, one ingest
#      token per engine, a control token) and checks the compose files
#      against the firewall's address plan
#   2. issues self-signed TLS certificates for Postgres and the HTTPS decoy
#   3. fetches the DB-IP City Lite geolocation database
#   4. verifies the model files and turns on the services that have one
#   5. backs up, then builds the images, labelled with the git revision
#   6. loads the egress firewall and installs the systemd units
#   7. starts the stack and verifies it: one revision in every container,
#      the networks the firewall expects, and a connection test from inside
#      the engines; then schedules the periodic jobs
#   8. creates the administrator, without any synthetic data
#   9. publishes the dashboard on the tailnet with Tailscale Serve (HTTPS)
#
# Nothing running is touched before step 6, so a failure up to there (a bad
# override file, a failed build) leaves the previous deployment as it was.

set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }

missing=()
for bin in docker python3 curl openssl nft tailscale git sha256sum; do
  command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
done
docker compose version >/dev/null 2>&1 || missing+=("docker-compose-plugin")
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "Missing prerequisites: ${missing[*]}" >&2
  echo "On Debian: apt install docker.io docker-compose-plugin python3 curl openssl nftables git; Tailscale from https://tailscale.com/download" >&2
  exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
STATE="$HERE/state"
ENV_FILE="$HERE/.env"
WEB_PORT=8088
MODEL_FILE=wolfram-Q4_K_M.gguf
DECIDER_FILE=Kev-4B-Q8_0.gguf
ADMIN_EMAIL=admin@honeysentinel.io
# Built here, and expected to carry the revision this run was started from.
APP_SERVICES=(backend ingest honeypot honeypot-web web)

[[ "$HERE" == /opt/honeysentinel/deploy/server ]] || {
  echo "Expected the repository at /opt/honeysentinel (the systemd units point there)." >&2
  exit 1
}

install -d -m 0700 "$STATE"

rand() { python3 -c "import secrets; print(secrets.token_urlsafe(48))"; }

env_get() {  # env_get NAME: the value in .env, without surrounding quotes
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/'
}

env_set() {  # env_set NAME VALUE: replace the line, or add it
  local tmp
  tmp=$(mktemp "$ENV_FILE.XXXXXX")
  grep -v "^$1=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$1" "$2" >> "$tmp"
  chmod 0600 "$tmp"
  mv "$tmp" "$ENV_FILE"
}

env_unset() {
  local tmp
  tmp=$(mktemp "$ENV_FILE.XXXXXX")
  grep -v "^$1=" "$ENV_FILE" > "$tmp" || true
  chmod 0600 "$tmp"
  mv "$tmp" "$ENV_FILE"
}

# A generated secret that an older .env does not have yet.
ensure_secret() {
  grep -q "^$1=" "$ENV_FILE" && return 0
  printf '%s=%s\n' "$1" "$(rand)" >> "$ENV_FILE"
  echo "    generated $1"
}

# The first password, or a new one. Shown once; never written to disk.
set_admin_password() {  # set_admin_password [reset]
  local pass out result
  pass=$(python3 -c "import secrets; print(secrets.token_urlsafe(18))")
  out=$(docker compose exec -T -e ADMIN_EMAIL="$ADMIN_EMAIL" -e ADMIN_PASSWORD="$pass" \
    -e ADMIN_RESET="${1:+1}" backend python - < "$HERE/create_admin.py")
  result=$(sed -n 's/^RESULT=//p' <<<"$out" | tail -n 1)
  case "$result" in
    created|reset)
      cat <<EOF

    ┌────────────────────────────────────────────────────────────────────┐
      Administrator $result. This password is shown once and stored nowhere:

          email     $ADMIN_EMAIL
          password  $pass

      Sign in now, change it (Settings → Accounts) and turn on two-factor
      sign-in (Settings → Security). If it is lost before then:
          sudo bash deploy/server/install.sh --reset-admin-password
    └────────────────────────────────────────────────────────────────────┘

EOF
      date -u +"$result %Y-%m-%dT%H:%M:%SZ $ADMIN_EMAIL" >> "$STATE/admin-created"
      ;;
    exists)
      echo "    $ADMIN_EMAIL already exists; its password was not changed"
      [[ -f "$STATE/admin-created" ]] || date -u +"exists %Y-%m-%dT%H:%M:%SZ $ADMIN_EMAIL" > "$STATE/admin-created"
      ;;
    *)
      echo "    could not create the administrator:" >&2
      printf '%s\n' "$out" >&2
      return 1
      ;;
  esac
}

if [[ "${1:-}" == --reset-admin-password ]]; then
  set_admin_password reset
  exit
fi

echo "==> 1/9  Secrets"
if [[ ! -f "$ENV_FILE" ]]; then
  dns_name=$(tailscale status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))')
  public_ip=$(curl -fsS -m 10 https://api.ipify.org || true)
  umask 077
  cat > "$ENV_FILE" <<EOF
# Generated by install.sh on $(date -u +%Y-%m-%dT%H:%MZ). Keep private.
# Every setting is described in docs/CONFIGURATION.md.
# Changing ENCRYPTION_KEY makes every stored command and payload unreadable;
# to rotate it, see "Rotating the encryption key" in deploy/server/README.md.
POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(32))")
SECRET_KEY=$(rand)
ENCRYPTION_KEY=$(rand)
HONEYPOT_INGEST_TOKEN=$(rand)

DASHBOARD_ORIGIN=https://${dns_name}
WEB_PORT=${WEB_PORT}

# Name this engine registers under. Traffic you generate yourself must come
# from a separate engine named controlled-test-node, never this one.
HONEYPOT_NODE_NAME=honeysentinel-debian
# Advertised in FTP passive replies. Update if the ISP changes the address.
PUBLIC_IP=${public_ip}

VITE_GEOIP_ATTRIBUTION='<a href="https://db-ip.com">IP Geolocation by DB-IP</a>'
EOF
  echo "    wrote $ENV_FILE"
else
  echo "    $ENV_FILE exists; kept"
fi
chmod 0600 "$ENV_FILE"

# One ingest token per engine and one for the throwaway test engine, plus the
# token the backend presents to the engines' control API. An .env written by
# an earlier version gains them here.
ensure_secret HONEYPOT_CONTROL_TOKEN
ensure_secret HONEYPOT_NODE_TOKEN_SHELL
ensure_secret HONEYPOT_NODE_TOKEN_WEB
ensure_secret HONEYPOT_NODE_TOKEN_TEST
# The map itself needs the engines' names, which only Compose can resolve
# (the override renames one); a placeholder lets it parse the files first.
grep -q '^HONEYPOT_NODE_TOKENS=' "$ENV_FILE" || env_set HONEYPOT_NODE_TOKENS "'{}'"

# Settings added by later versions are appended (commented, with their
# defaults) so an operator can find them without diffing the repository.
append_env() {
  grep -q "^#\? \?$1=" "$ENV_FILE" || printf '%s\n' "$2" >> "$ENV_FILE"
}
append_env ALERT_DEDUP_WINDOW_MINUTES "# ALERT_DEDUP_WINDOW_MINUTES=60   # repeats from one address fold into the open alert"
append_env ALERT_SUPPRESS_SCANNERS   "# ALERT_SUPPRESS_SCANNERS=true    # no alerts for Censys/Shodan/Shadowserver"
append_env SESSION_RETENTION_DAYS    "# SESSION_RETENTION_DAYS=0        # 0 keeps every session for ever; decide before exposure (docs/DATA_HANDLING.md)"
append_env AUDIT_RETENTION_DAYS      "# AUDIT_RETENTION_DAYS=365"
append_env WOLFRAM_THREADS           "# WOLFRAM_THREADS=6               # CPU threads for the analysis model"
append_env WOLFRAM_SHA256            "# WOLFRAM_SHA256=                 # expected SHA-256 of the analysis model file; unset = not checked"
append_env DECIDER_THREADS           "# DECIDER_THREADS=6               # CPU threads for the decision model"
append_env DECIDER_SKIP_THRESHOLD    "# DECIDER_SKIP_THRESHOLD=0.85     # triage skips the LLM above this p(information gathering at most)"
append_env DECIDER_DROP_UNCONFIRMED  "# DECIDER_DROP_UNCONFIRMED=false  # remove, not just mark, techniques the transcript does not support"
append_env HEARTBEAT_URL             "# HEARTBEAT_URL=                  # dead man's switch pinged every 5 min while everything is healthy"
append_env BACKUP_AGE_RECIPIENT      "# BACKUP_AGE_RECIPIENT=           # age public key; backups are encrypted to it (see README, Backups)"
append_env BACKUP_PASSPHRASE_FILE    "# BACKUP_PASSPHRASE_FILE=         # or: a root-only file holding a passphrase"
append_env BACKUP_OFFSITE_RSYNC      "# BACKUP_OFFSITE_RSYNC=           # user@host:/path, copied to after every backup"
append_env BACKUP_OFFSITE_RCLONE     "# BACKUP_OFFSITE_RCLONE=          # or: an rclone remote:path"
append_env HS_ISOLATED_GATEWAY       "# HS_ISOLATED_GATEWAY=false       # Docker 28+: no host address on the internal bridges"

# The shell services and the website run as two engines (two nodes in the
# dashboard) on one address, so they must describe one host: a shared seed
# derives the same hostname, OS and server banners for both. An existing
# install keeps the identity its engine already created.
if ! grep -q '^HONEYPOT_IDENTITY_SEED=' "$ENV_FILE"; then
  seed=$(docker compose exec -T honeypot python -c "import json; print(json.load(open('/app/data/sessions/host-identity.json'))['seed'])" < /dev/null 2>/dev/null || true)
  seed=${seed:-$(python3 -c "import secrets; print(secrets.randbelow(2**62) + 2**62)")}
  printf '\n# Both engines describe this one host (hostname, OS, banners).\nHONEYPOT_IDENTITY_SEED=%s\n' "$seed" >> "$ENV_FILE"
  echo "    pinned the host identity seed"
fi

# What the planted secrets (honeytokens) and the AI-agent canary are derived
# from. Separate from the identity seed on purpose: the seed decides public
# facts and can be worked out from them, and a planted password that followed
# from it would prove nothing when it came back. One value for both engines,
# so the shell's files and the website's /.env plant the same secrets.
if ! grep -q '^HONEYPOT_DECOY_SECRET=' "$ENV_FILE"; then
  printf '\n# Planted secrets and the canary token derive from this. Never shown to a client.\nHONEYPOT_DECOY_SECRET=%s\n' \
    "$(python3 -c "import secrets; print(secrets.token_hex(32))")" >> "$ENV_FILE"
  echo "    generated the decoy secret"
fi
WEB_PORT=$(env_get WEB_PORT | tr -d '[:space:]')
WEB_PORT=${WEB_PORT:-8088}

# Docker 28 can leave the internal bridges without a host address. Opt-in:
# the overlay is listed in COMPOSE_FILE, which also stops Compose loading
# docker-compose.override.yml by itself, so the list is rebuilt on every run.
docker_major=$(docker version --format '{{.Server.Version}}' 2>/dev/null | cut -d. -f1)
if [[ "$(env_get HS_ISOLATED_GATEWAY)" == true ]]; then
  if [[ "${docker_major:-0}" -ge 28 ]]; then
    files=docker-compose.yml
    [[ -f docker-compose.override.yml ]] && files+=:docker-compose.override.yml
    env_set COMPOSE_FILE "$files:docker-compose.isolated-gateway.yml"
    echo "    isolated gateway mode on (Docker $docker_major)"
  else
    env_unset COMPOSE_FILE
    echo "    HS_ISOLATED_GATEWAY needs Docker 28 or later (this is ${docker_major:-unknown}); ignored" >&2
  fi
elif grep -q '^COMPOSE_FILE=.*isolated-gateway' "$ENV_FILE"; then
  env_unset COMPOSE_FILE
fi

# The token map, keyed by the names the engines will register under.
compose_json() { docker compose --profile '*' config --format json; }
names=$(compose_json | python3 -c '
import json, sys
services = json.load(sys.stdin)["services"]
print(services["honeypot"]["environment"]["HONEYPOT_NODE_NAME"],
      services["honeypot-web"]["environment"]["HONEYPOT_NODE_NAME"])')
read -r shell_name web_name <<<"$names"
python3 "$HERE/node_tokens.py" sync --local \
  "$shell_name=HONEYPOT_NODE_TOKEN_SHELL" "$web_name=HONEYPOT_NODE_TOKEN_WEB" \
  "controlled-test-node=HONEYPOT_NODE_TOKEN_TEST" | sed 's/^/    /'

# The compose files and the firewall must describe the same networks: bridge
# names, subnets, and the addresses the rules name. Checked on what Compose
# actually resolved (override included), before anything is changed. An
# override file written for an earlier version fails here: its shop networks
# had no fixed names or addresses.
if ! plan_problems=$(compose_json | python3 /opt/honeysentinel/scripts/check-network-plan.py --resolved - 2>&1); then
  echo "    The compose files do not match the address plan in honeysentinel-egress.sh:" >&2
  sed 's/^/      /' <<<"$plan_problems" >&2
  echo "    If you keep a docker-compose.override.yml, bring its networks: section and the" >&2
  echo "    networks: of its services in line with docker-compose.override.example.yml." >&2
  exit 1
fi

# Everything a service is built from must be here. The override builds the
# shop from a directory outside this repository; on a rebuilt machine it is
# absent until restore.sh has put it back, and the build used to fail on it
# half-way through an install.
absent=$(compose_json | python3 -c '
import json, os, sys
for name, service in json.load(sys.stdin)["services"].items():
    context = (service.get("build") or {}).get("context")
    if context and not os.path.isdir(context):
        print(f"{name}: {context}")')
if [[ -n "$absent" ]]; then
  echo "    A service is built from a directory that does not exist:" >&2
  sed 's/^/      /' <<<"$absent" >&2
  echo "    Restore it (restore.sh does, from a backup's shop-source archive), clone it there," >&2
  echo "    or move docker-compose.override.yml aside to run without the shop." >&2
  exit 1
fi

if ! timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes; then
  echo "WARNING: the clock is not NTP-synchronised; authenticator codes and evidence timestamps depend on it (timedatectl set-ntp true)." >&2
fi

echo "==> 2/9  TLS certificates"
tls="$STATE/pg-tls"
if [[ ! -f "$tls/server.key" ]]; then
  install -d -m 0755 "$tls"
  openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -sha256 \
    -subj "/CN=postgres" -addext "subjectAltName=DNS:postgres" \
    -keyout "$tls/server.key" -out "$tls/server.crt" 2>/dev/null
  # uid/gid 70 is postgres in the postgres:16-alpine image.
  chown 70:70 "$tls/server.key" "$tls/server.crt"
  chmod 0600 "$tls/server.key"
  echo "    issued"
else
  echo "    exists; kept"
fi

# The HTTPS decoy otherwise generates a fresh certificate on every restart,
# and a certificate that keeps changing is itself a tell.
decoy_tls="$STATE/decoy-tls"
if [[ ! -f "$decoy_tls/server.key" ]]; then
  install -d -m 0755 "$decoy_tls"
  # A different plausible name per install: one CN on every deployment of
  # this project would let them be grouped from a certificate scan.
  decoy_cn=$(printf '%s\n' web01 web-prod-02 app-node-1 srv-web-03 edge-01 www2 portal-01 | shuf -n1)
  openssl req -x509 -newkey rsa:2048 -nodes -days 1095 -sha256 \
    -subj "/CN=${decoy_cn}" -addext "subjectAltName=DNS:${decoy_cn}" \
    -keyout "$decoy_tls/server.key" -out "$decoy_tls/server.crt" 2>/dev/null
  # uid 10001 is the engine's user in honeypot/Dockerfile.
  chown 10001:10001 "$decoy_tls/server.key" "$decoy_tls/server.crt"
  chmod 0600 "$decoy_tls/server.key"
  echo "    issued the HTTPS decoy's certificate"
fi

# Where the evaluation and export tools write; uid 10001 is the API's user.
install -d -o 10001 -g 10001 -m 0750 "$STATE/out"

echo "==> 3/9  GeoIP database (DB-IP City Lite, CC BY 4.0)"
bash "$HERE/fetch-geoip.sh" || true

echo "==> 4/9  Models"
models="$STATE/models"
install -d -m 0755 "$models"

# SHA-256 of a model file, remembered against its size and modification time
# so a multi-gigabyte file is not re-read on every run.
model_sha256() {
  local file=$1 key sum
  key="$(basename "$file") $(stat -c '%s %Y' "$file")"
  sum=$(grep -F "$key " "$models/.sha256-cache" 2>/dev/null | tail -n 1 | awk '{print $NF}' || true)
  if [[ -z "$sum" ]]; then
    sum=$(sha256sum "$file" | cut -d' ' -f1)
    echo "$key $sum" >> "$models/.sha256-cache"
  fi
  echo "$sum"
}

# Each model service has its own Compose profile, on only while its file is
# there and matches the expected checksum. With the one shared profile used
# before, the service whose model was missing started anyway and crash-looped.
profiles=$(env_get COMPOSE_PROFILES | tr ',' '\n' | grep -vxE 'llm|wolfram|decider|' || true)

if [[ -f "$models/$MODEL_FILE" ]]; then
  have=$(model_sha256 "$models/$MODEL_FILE")
  want=$(env_get WOLFRAM_SHA256)
  if [[ -n "$want" && "$want" != "$have" ]]; then
    echo "    $MODEL_FILE does not match WOLFRAM_SHA256 (it has $have); the LLM stage stays off" >&2
  else
    profiles+=$'\nwolfram'
    grep -q '^CHIMERA_URL=' "$ENV_FILE" || echo "CHIMERA_URL=http://wolfram:8080/v1" >> "$ENV_FILE"
    grep -q '^CHIMERA_MODEL=' "$ENV_FILE" || echo "CHIMERA_MODEL=wolfram" >> "$ENV_FILE"
    if [[ -n "$want" ]]; then
      echo "    $MODEL_FILE verified; the wolfram service and the LLM stage are enabled"
    else
      echo "    $MODEL_FILE present; the wolfram service and the LLM stage are enabled"
      echo "    NOT VERIFIED: no checksum is pinned for this file. Its SHA-256 is"
      echo "      $have"
      echo "    Compare that with the model repository's and record it as WOLFRAM_SHA256 in .env."
    fi
  fi
else
  # Only our own default is withdrawn; an endpoint the operator set stays.
  [[ "$(env_get CHIMERA_URL)" != http://wolfram:8080/v1 ]] || env_unset CHIMERA_URL
  echo "    no $models/$MODEL_FILE; the LLM stage stays off (copy the GGUF there and re-run)"
fi

if [[ -f "$models/$DECIDER_FILE" ]]; then
  if [[ "$(model_sha256 "$models/$DECIDER_FILE")" == "$(bash "$HERE/fetch-decider.sh" --sha256)" ]]; then
    profiles+=$'\ndecider'
    grep -q '^DECIDER_URL=' "$ENV_FILE" || echo "DECIDER_URL=http://decider:8080" >> "$ENV_FILE"
    echo "    $DECIDER_FILE verified; the decider service and triage are enabled"
  else
    echo "    $DECIDER_FILE does not match its pinned SHA-256; triage stays off (bash fetch-decider.sh)" >&2
  fi
else
  [[ "$(env_get DECIDER_URL)" != http://decider:8080 ]] || env_unset DECIDER_URL
  echo "    no $models/$DECIDER_FILE; triage stays off (bash deploy/server/fetch-decider.sh, then re-run)"
fi

profiles=$(grep -v '^$' <<<"$profiles" | sort -u | paste -sd, - || true)
if [[ -n "$profiles" ]]; then env_set COMPOSE_PROFILES "$profiles"; else env_unset COMPOSE_PROFILES; fi

echo "==> 5/9  Build"
# A backup before an update, so a bad migration has something to go back to.
if docker compose ps -q postgres 2>/dev/null | grep -q .; then
  bash "$HERE/backup.sh" || echo "    pre-update backup failed; continuing" >&2
fi

# The revision every image is labelled with. A checkout with local changes
# says so, because then the commit alone does not describe what was built.
GIT_REVISION=$(git -C /opt/honeysentinel rev-parse HEAD 2>/dev/null || echo unknown)
if [[ -n "$(git -C /opt/honeysentinel status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
  GIT_REVISION+=-dirty
fi
export GIT_REVISION
echo "    revision $GIT_REVISION"

# Before anything running is touched, so a failed build leaves the old stack
# as it was. No --pull: base images are pinned by digest, and the two that
# still use a tag (node, caddy) are updated deliberately, with
# scripts/pin-images.sh.
docker compose build

echo "==> 6/9  Egress firewall and host jobs"
# Units this version no longer ships (the failure hook is now a template).
rm -f /etc/systemd/system/honeysentinel-backup-failed.service
install -m 0644 "$HERE/systemd/"honeysentinel-*.service "$HERE/systemd/"honeysentinel-*.timer /etc/systemd/system/
# Docker refuses to start without the egress rules (fail closed).
install -d -m 0755 /etc/systemd/system/docker.service.d
install -m 0644 "$HERE/systemd/docker.service.d-honeysentinel.conf" /etc/systemd/system/docker.service.d/honeysentinel.conf
systemctl daemon-reload
systemctl enable honeysentinel-egress.service >/dev/null 2>&1
# Reload, never restart: Docker Requires= this unit, so restarting it
# restarted dockerd and with it every container, on every update, in the
# middle of the pre-update backup. A reload re-runs the script (one atomic
# swap of the ruleset) and touches nothing else.
if systemctl is-active --quiet honeysentinel-egress.service; then
  systemctl reload honeysentinel-egress.service
else
  systemctl start honeysentinel-egress.service
fi
# Not "does a chain with our name exist" (the script had just created it):
# the loaded ruleset must be, rule for rule, the one this checkout defines.
# Status 2 means the rules are right and a Docker network predates them;
# the next step recreates those.
egress_status=0
egress_reason=$(bash "$HERE/honeysentinel-egress.sh" check 2>&1) || egress_status=$?
if [[ $egress_status -ne 0 && $egress_status -ne 2 ]]; then
  echo "    egress rules not in place ($egress_reason); refusing to start the engines" >&2
  exit 1
fi
echo "    egress rules loaded and verified"

echo "==> 7/9  Start and verify"
# Networks created by an earlier compose file have Docker's random bridge
# names and unplanned subnets; the firewall rules do not recognise those.
# They are recreated once, which takes the stack down for the length of this
# step. Volumes are not touched.
if [[ $egress_status -eq 2 ]]; then
  echo "    recreating the container networks to match the egress rules:"
  sed 's/; /\n/g' <<<"$egress_reason" | sed 's/^/      /'
  docker rm -f hs-test hs-stress >/dev/null 2>&1 || true
  docker compose --profile '*' down --remove-orphans
fi

# Model files are unpickled by the API, so it loads only those signed with
# this deployment's key. Files written before signing existed are signed
# here, once, on the upgrade that introduces it; after that an unsigned model
# is never signed without being asked (python -m app.ai.provenance sign),
# because "unsigned" is also what a replaced file looks like.
if [[ ! -f "$STATE/models-signed" ]]; then
  docker compose run --rm --no-deps -T backend sh -c '
    for f in /app/models/*.pkl; do
      [ -f "$f" ] || continue
      head -c 12 "$f" | grep -q "^hs-model-v1 " || python -m app.ai.provenance sign "$f"
    done' < /dev/null || echo "    WARNING: could not sign the existing model files; the API will use bootstraps until they are signed" >&2
  date -u +%Y-%m-%dT%H:%M:%SZ > "$STATE/models-signed"
fi

docker compose up -d --remove-orphans

# backend and ingest are one image and must be one version. Compose recreates
# a container when its image changed, so after the build above both follow;
# this catches the case where they do not (one of them was recreated by hand
# from an older build), which is how ingest once ran month-old code.
image_of() { docker inspect -f '{{.Image}}' "$(docker compose ps -q "$1")" 2>/dev/null || true; }
if [[ "$(image_of backend)" != "$(image_of ingest)" ]]; then
  echo "    backend and ingest were on different images; recreating both"
  docker compose up -d --force-recreate --no-deps backend ingest
fi
docker image prune -f >/dev/null 2>&1 || true

wait_healthy() {
  local service=$1 tries=${2:-90} status=""
  for _ in $(seq 1 "$tries"); do
    status=$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q "$service")" 2>/dev/null || true)
    [[ "$status" == healthy ]] && return 0
    sleep 2
  done
  echo "    $service did not become healthy" >&2
  docker compose logs --tail 50 "$service" >&2
  return 1
}
echo "    waiting for the API"
wait_healthy backend || exit 1
wait_healthy ingest || exit 1
echo "    waiting for the engines"
wait_healthy honeypot 60 || exit 1
wait_healthy honeypot-web 60 || exit 1

echo "    revision per container:"
skew=0
for service in "${APP_SERVICES[@]}"; do
  revision=$(docker inspect -f '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
    "$(docker compose ps -q "$service")" 2>/dev/null || echo "not running")
  printf '      %-14s %s\n' "$service" "$revision"
  [[ "$revision" == "$GIT_REVISION" ]] || skew=1
done
if [[ $skew -ne 0 ]]; then
  echo "    Not every container runs revision $GIT_REVISION. Do not rely on this deployment" >&2
  echo "    until they do: docker compose up -d --force-recreate ${APP_SERVICES[*]}" >&2
  exit 1
fi

# The firewall again, now against the networks that exist, and then for
# real: from inside each engine, try to connect to the internet, to the host
# on every bridge and to the other containers.
if ! egress_reason=$(bash "$HERE/honeysentinel-egress.sh" check 2>&1); then
  echo "    the container networks do not match the egress rules: $egress_reason" >&2
  exit 1
fi
if ! bash "$HERE/honeysentinel-egress.sh" probe | sed 's/^/    /'; then
  echo "    THE ENGINES ARE NOT CONTAINED. Do not forward any port to this machine." >&2
  exit 1
fi

# Timers last, so the periodic checks first run against a finished install.
systemctl enable --now honeysentinel-egress-check.timer honeysentinel-backup.timer \
  honeysentinel-geoip.timer honeysentinel-heartbeat.timer >/dev/null 2>&1
echo "    scheduled: egress check and host heartbeat (5 min), backup (nightly), GeoIP (weekly)"
# Only when docker-compose.override.yml puts an application behind the decoys.
if docker compose config --services | grep -x shop >/dev/null; then
  systemctl enable --now honeysentinel-shop-reset.timer >/dev/null 2>&1
  echo "    scheduled: shop reset (nightly)"
else
  systemctl disable --now honeysentinel-shop-reset.timer >/dev/null 2>&1 || true
fi

echo "==> 8/9  Administrator"
if [[ ! -f "$STATE/admin-created" ]]; then
  set_admin_password
else
  echo "    created earlier; kept (lost the password? install.sh --reset-admin-password)"
fi
if [[ -f "$STATE/admin-credentials" ]]; then
  cat <<EOF
    NOTE: $STATE/admin-credentials, written by an earlier version, still
    holds the first administrator password in plain text. Once you have signed
    in and changed that password, remove the file:
        sudo shred -u $STATE/admin-credentials
    New backups leave it out; backups taken before this update contain it.
EOF
fi

echo "==> 9/9  Tailscale Serve"
if tailscale serve status 2>/dev/null | grep -q "127.0.0.1:${WEB_PORT}"; then
  echo "    already serving; left as is"
elif timeout 20 tailscale serve --bg --https=443 "http://127.0.0.1:${WEB_PORT}"; then
  echo "    dashboard: $(env_get DASHBOARD_ORIGIN)"
else
  echo "    Serve is not enabled on the tailnet yet: approve the link above, then re-run."
fi

docker compose ps

echo
echo "Before any port is forwarded to this machine, go through docs/EXPOSURE_RUNBOOK.md."
[[ -n "$(env_get HEARTBEAT_URL)" ]] || echo "  - HEARTBEAT_URL is not set: nothing outside this machine will notice if it goes down."
if [[ -z "$(env_get BACKUP_AGE_RECIPIENT)$(env_get BACKUP_GPG_RECIPIENT)$(env_get BACKUP_PASSPHRASE_FILE)" ]]; then
  echo "  - Backups are not encrypted (BACKUP_AGE_RECIPIENT or BACKUP_PASSPHRASE_FILE)."
fi
[[ "$(env_get SESSION_RETENTION_DAYS)" =~ ^[1-9] ]] || echo "  - SESSION_RETENTION_DAYS is 0: captured sessions are kept for ever (docs/DATA_HANDLING.md)."
