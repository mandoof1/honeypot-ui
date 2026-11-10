#!/usr/bin/env bash
#
# Keep every container of this deployment from opening a connection of its own.
#
#   honeysentinel-egress.sh apply     load the rules (atomic; safe to repeat)
#   honeysentinel-egress.sh check     exit 0 only if the rules and the Docker
#                                     networks are exactly what this file expects
#   honeysentinel-egress.sh watch     check; if anything is wrong, re-apply and
#                                     raise a system alert (run by the timer)
#   honeysentinel-egress.sh probe     try to connect out from inside the engine
#                                     containers and report what got through
#   honeysentinel-egress.sh status    print the live rules with their counters
#   honeysentinel-egress.sh render    print the ruleset without loading it
#
# Why the rules exist. An engine has to sit on a normal bridge (hs-decoy) for
# Docker to publish its ports, and a normal bridge routes to the internet. It
# is also attached to internal bridges (hs-engine, hs-control, and with a shop
# behind the decoys hs-shop and hs-shop-decoy). "Internal" only removes the
# route out: Docker still gives each bridge a host address, so a process in
# the container can reach every service the host listens on through it. The
# previous version of this script matched hs-decoy alone and left that open.
#
# What is enforced, for IPv4 and IPv6, on every bridge named hs-* and for
# every source address in the deployment's address plan (so a bridge that
# kept an old name is still covered):
#
#   container -> host              replies only
#   container -> another network   replies only (plus ALLOW_OUT, below)
#   container -> same bridge       only the pairs listed under "Who may talk
#                                  to whom"; everything else is dropped
#
# How. Two nftables tables of our own, `inet honeysentinel` (routed traffic
# and traffic to the host) and `bridge honeysentinel` (frames switched inside
# one bridge, which the routed hooks never see unless br_netfilter is
# loaded). Their chains run at a priority ahead of Docker's and ufw's, a drop
# there is final, and nothing Docker, ufw or `iptables -F` does can remove
# them. Loading is one `nft -f` transaction: the old tables are replaced by
# the new ones in a single commit, so there is never a moment with the rules
# half-loaded (the earlier flush-then-append left the chain empty in between).
#
# Runs before docker.service (honeysentinel-egress.service), and Docker
# Requires= that unit, so no container starts without the rules.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TABLE=honeysentinel
RUN_DIR=${HS_EGRESS_RUN_DIR:-/run/honeysentinel}

# --- Address plan ----------------------------------------------------------
# Must match docker-compose.yml, docker-compose.override.example.yml,
# deploy/node and deploy/cowrie-baseline; scripts/check-network-plan.py
# compares them in CI, and `check` compares them with the live networks.
PLAN=172.30.64.0/19            # every subnet below is inside this block

# bridge          subnet            internal  purpose
NETWORKS=(
  "hs-decoy       172.30.66.0/24    no        published decoy ports"
  "hs-engine      172.30.67.0/24    yes       engines -> ingest"
  "hs-shop        172.30.68.0/24    yes       web engine -> live shop"
  "hs-shop-decoy  172.30.69.0/24    yes       web engine -> decoy shop"
  "hs-app         172.30.70.0/24    yes       dashboard proxy -> API"
  "hs-control     172.30.71.0/24    yes       API -> engine control"
  "hs-edge        172.30.72.0/24    no        dashboard, loopback only"
  "hs-db          172.30.73.0/24    yes       API, ingest -> Postgres"
  "hs-llm         172.30.74.0/24    yes       API -> model servers"
  "hs-test        172.30.75.0/24    yes       controlled-test.sh, stress-test.sh"
  "hs-sensors     172.30.76.0/24    no        remote sensors -> ingest (optional)"
  "hs-cowrie      172.30.77.0/24    no        deploy/cowrie-baseline"
  "hs-sensor      172.30.80.0/24    no        deploy/node (remote sensor)"
)

INGEST_ENGINE=172.30.67.20      # ingest, on hs-engine
BACKEND_CONTROL=172.30.71.2     # backend, on hs-control
ENGINES_CONTROL="172.30.71.10, 172.30.71.11"
WEB_ENGINE_SHOP=172.30.68.11    # honeypot-web, on hs-shop
SHOP=172.30.68.20
WEB_ENGINE_SHOP_DECOY=172.30.69.11
SHOP_DECOY=172.30.69.20
API_PORT=8000
SHOP_PORT=3000

# Bridges whose members may talk to each other freely: none of them holds an
# engine or anything else an attacker reaches directly.
OPEN_BRIDGES=(hs-app hs-db hs-llm hs-test)

# --- Site configuration (optional) -----------------------------------------
# A root-owned file of KEY=VALUE lines. The only connection a container may
# open towards another network is one listed here, as bridge:ipv4:port. The
# remote sensor kit uses it for its single destination, the backend's ingest
# endpoint on the private overlay:
#
#   ALLOW_OUT="hs-sensor:100.64.0.10:8001"
#   PROFILE=sensor          # no dashboard on this machine to alert through
CONF=${HS_EGRESS_CONF:-$HERE/egress.conf}
ALLOW_OUT=""
PROFILE=server

die() { echo "honeysentinel-egress: $*" >&2; exit 1; }

load_conf() {
  [[ -f "$CONF" ]] || return 0
  # The file is sourced by a root process that controls the firewall.
  local owner mode
  owner=$(stat -c %u "$CONF"); mode=$(stat -c %a "$CONF")
  [[ "$owner" == "$(id -u)" || "$owner" == 0 ]] || die "$CONF is not owned by root"
  (( (8#$mode & 8#022) == 0 )) || die "$CONF is writable by group or others"
  # shellcheck disable=SC1090
  . "$CONF"
  case "$PROFILE" in server|sensor) ;; *) die "PROFILE must be server or sensor" ;; esac
  # Validate now, in this shell: inside the ruleset template a failure would
  # only end a subshell and leave the rule out without stopping anything.
  allow_out_rules >/dev/null
}

# Every value that reaches the ruleset is checked against a fixed pattern
# first, so a malformed entry stops the script instead of becoming a rule.
allow_out_rules() {
  local entry bridge addr port octet
  for entry in $ALLOW_OUT; do
    IFS=: read -r bridge addr port <<<"$entry"
    [[ "$bridge" =~ ^hs-[a-z0-9-]{1,12}$ ]] || die "ALLOW_OUT: bad bridge in '$entry'"
    [[ "$addr" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || die "ALLOW_OUT: bad IPv4 address in '$entry'"
    for octet in "${BASH_REMATCH[@]:1}"; do
      (( 10#$octet <= 255 )) || die "ALLOW_OUT: bad IPv4 address in '$entry'"
    done
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || die "ALLOW_OUT: bad port in '$entry'"
    (( 10#$port >= 1 && 10#$port <= 65535 )) || die "ALLOW_OUT: bad port in '$entry'"
    printf '\t\tiifname "%s" oifname != "hs-*" ip daddr %s tcp dport %s accept\n' "$bridge" "$addr" "$((10#$port))"
  done
}

quoted_list() {  # hs-app hs-db -> "hs-app", "hs-db"
  local out="" item
  for item in "$@"; do out+="${out:+, }\"$item\""; done
  printf '%s' "$out"
}

open_pairs() {   # hs-app hs-db -> "hs-app" . "hs-app", "hs-db" . "hs-db"
  local out="" item
  for item in "$@"; do out+="${out:+, }\"$item\" . \"$item\""; done
  printf '%s' "$out"
}

# The ruleset proper, without the header that swaps it in. Its SHA-256 is
# stored in each table's comment, which is how `check` tells rules loaded by
# an older copy of this file from current ones.
render_body() {
  local fingerprint=${1:-}
  cat <<EOF
table inet $TABLE {
	comment "honeysentinel-egress ${fingerprint}"

	chain blocked {
		limit rate 6/minute burst 10 packets log prefix "hs egress blocked: "
		counter drop
	}

	# A container addressing the host: its bridge gateway, or any other
	# address the host owns. Only replies to connections that came in.
	chain to_host {
		ct state established,related accept
		jump blocked
	}

	# A container addressing anything else. With br_netfilter loaded, frames
	# switched inside one bridge pass here too, so the pairs below repeat
	# what table bridge $TABLE allows; without it they never reach this hook.
	chain from_container {
		ct state established,related accept
		iifname "hs-engine" oifname "hs-engine" ip daddr $INGEST_ENGINE tcp dport $API_PORT accept
		iifname "hs-control" oifname "hs-control" ip saddr $BACKEND_CONTROL ip daddr { $ENGINES_CONTROL } tcp dport $API_PORT accept
		iifname "hs-shop" oifname "hs-shop" ip saddr $WEB_ENGINE_SHOP ip daddr $SHOP tcp dport $SHOP_PORT accept
		iifname "hs-shop-decoy" oifname "hs-shop-decoy" ip saddr $WEB_ENGINE_SHOP_DECOY ip daddr $SHOP_DECOY tcp dport $SHOP_PORT accept
		iifname . oifname { $(open_pairs "${OPEN_BRIDGES[@]}") } accept
$(allow_out_rules)
		jump blocked
	}

	chain input {
		type filter hook input priority filter - 10; policy accept;
		iifname "hs-*" jump to_host
		ip saddr $PLAN jump to_host
	}

	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		iifname "hs-*" jump from_container
		ip saddr $PLAN jump from_container
	}
}

table bridge $TABLE {
	comment "honeysentinel-egress ${fingerprint}"

	chain blocked {
		limit rate 6/minute burst 10 packets log prefix "hs bridge blocked: "
		counter drop
	}

	# Who may talk to whom inside one bridge. Stateless on purpose (no
	# dependency on bridge connection tracking): a reply is a TCP segment
	# from the service's port that is not a bare SYN, so the listed service
	# can answer but cannot open a connection back.
	chain engine {
		ip daddr $INGEST_ENGINE tcp dport $API_PORT accept
		ip saddr $INGEST_ENGINE tcp sport $API_PORT tcp flags & (syn | ack) != syn accept
		jump blocked
	}

	chain control {
		ip saddr $BACKEND_CONTROL ip daddr { $ENGINES_CONTROL } tcp dport $API_PORT accept
		ip saddr { $ENGINES_CONTROL } ip daddr $BACKEND_CONTROL tcp sport $API_PORT tcp flags & (syn | ack) != syn accept
		jump blocked
	}

	chain shop {
		ip saddr $WEB_ENGINE_SHOP ip daddr $SHOP tcp dport $SHOP_PORT accept
		ip saddr $SHOP ip daddr $WEB_ENGINE_SHOP tcp sport $SHOP_PORT tcp flags & (syn | ack) != syn accept
		jump blocked
	}

	chain shop_decoy {
		ip saddr $WEB_ENGINE_SHOP_DECOY ip daddr $SHOP_DECOY tcp dport $SHOP_PORT accept
		ip saddr $SHOP_DECOY ip daddr $WEB_ENGINE_SHOP_DECOY tcp sport $SHOP_PORT tcp flags & (syn | ack) != syn accept
		jump blocked
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		meta ibrname != "hs-*" accept
		ether type arp accept
		meta ibrname "hs-engine" jump engine
		meta ibrname "hs-control" jump control
		meta ibrname "hs-shop" jump shop
		meta ibrname "hs-shop-decoy" jump shop_decoy
		meta ibrname { $(quoted_list "${OPEN_BRIDGES[@]}") } accept
		# hs-decoy and every other hs-* bridge: the containers on it have no
		# business with each other.
		jump blocked
	}
}
EOF
}

fingerprint() { render_body | sha256sum | cut -c1-32; }

render() {
  local fp
  fp=$(fingerprint)
  # Declaring a table and deleting it makes the delete succeed whether or not
  # it existed; with the new definition in the same file the whole swap is
  # one transaction.
  cat <<EOF
table inet $TABLE
delete table inet $TABLE
table bridge $TABLE
delete table bridge $TABLE
EOF
  render_body "sha256:$fp"
}

listing_hash() {  # the live rules without counters; empty if a table is absent
  local out
  out=$(nft -s list table inet "$TABLE" 2>/dev/null) || return 1
  out+=$(nft -s list table bridge "$TABLE" 2>/dev/null) || return 1
  printf '%s' "$out" | sha256sum | cut -d' ' -f1
}

# The chain the previous version of this script kept in iptables. Removed
# only after the new rules are in place.
remove_legacy_iptables() {
  local ipt hook
  for ipt in iptables ip6tables; do
    command -v "$ipt" >/dev/null 2>&1 || continue
    "$ipt" -w -S HS-DECOY-EGRESS >/dev/null 2>&1 || continue
    for hook in DOCKER-USER INPUT; do
      while "$ipt" -w -D "$hook" -i hs-decoy -j HS-DECOY-EGRESS 2>/dev/null; do :; done
    done
    "$ipt" -w -F HS-DECOY-EGRESS 2>/dev/null || true
    "$ipt" -w -X HS-DECOY-EGRESS 2>/dev/null || true
  done
}

apply() {
  command -v nft >/dev/null 2>&1 || die "nft not found (apt install nftables)"
  local file
  file=$(mktemp)
  render > "$file"
  if ! nft -c -f "$file"; then
    rm -f "$file"
    die "the ruleset did not validate; nothing was changed"
  fi
  if ! nft -f "$file"; then
    rm -f "$file"
    die "loading the ruleset failed; the previous rules are still in place"
  fi
  rm -f "$file"
  install -d -m 0755 "$RUN_DIR"
  listing_hash > "$RUN_DIR/egress.applied"
  remove_legacy_iptables
  echo "Egress rules loaded (sha256:$(fingerprint)): containers on hs-* bridges may only answer."
}

# --- check -----------------------------------------------------------------

check_rules() {
  local fp live applied family
  fp="sha256:$(fingerprint)"
  for family in inet bridge; do
    if ! nft list table "$family" "$TABLE" >/dev/null 2>&1; then
      echo "table $family $TABLE is not loaded"; return 1
    fi
    if ! nft list table "$family" "$TABLE" | grep -qF "$fp"; then
      echo "table $family $TABLE was loaded from a different version of the rules"; return 1
    fi
  done
  live=$(listing_hash) || { echo "the rules could not be listed"; return 1; }
  if [[ -f "$RUN_DIR/egress.applied" ]]; then
    applied=$(cat "$RUN_DIR/egress.applied")
    [[ "$live" == "$applied" ]] || { echo "the loaded rules were changed after they were applied"; return 1; }
  fi
  return 0
}

# Every Docker network of this project must be one of the planned bridges,
# with the planned subnet. A network created by an older compose file keeps
# its random br-xxxx name until it is recreated, and rules keyed on hs-* do
# not see it; that is the failure this catches.
check_networks() {
  command -v docker >/dev/null 2>&1 || return 0
  docker info >/dev/null 2>&1 || return 0     # Docker not running yet (boot)
  local ids file status=0
  ids=$(docker network ls -q --filter driver=bridge --filter label=com.docker.compose.project)
  [[ -n "$ids" ]] || return 0
  file=$(mktemp)
  # shellcheck disable=SC2086
  docker network inspect $ids > "$file"
  python3 - "$file" "$PLAN" "${NETWORKS[@]}" <<'PY' || status=$?
import ipaddress, json, sys

plan = ipaddress.ip_network(sys.argv[2])
expected = {}
for row in sys.argv[3:]:
    name, subnet, internal = row.split()[:3]
    expected[name] = (ipaddress.ip_network(subnet), internal == "yes")

problems = []
with open(sys.argv[1], encoding="utf-8") as handle:
    networks = json.load(handle)
for net in networks:
    project = (net.get("Labels") or {}).get("com.docker.compose.project", "")
    if not project.startswith("honeysentinel"):
        continue
    label = net["Name"]
    bridge = (net.get("Options") or {}).get("com.docker.network.bridge.name", "")
    config = (net.get("IPAM") or {}).get("Config") or []
    subnets = [ipaddress.ip_network(c["Subnet"]) for c in config if c.get("Subnet")]
    if bridge not in expected:
        problems.append(f"{label}: bridge '{bridge}' is not one of the planned hs-* bridges (the network needs recreating)")
        continue
    want_subnet, want_internal = expected[bridge]
    if subnets != [want_subnet]:
        problems.append(f"{label}: subnet {[str(s) for s in subnets]} is not {want_subnet}")
    if any(not s.subnet_of(plan) for s in subnets if s.version == 4):
        problems.append(f"{label}: subnet outside the address plan {plan}")
    if bool(net.get("Internal")) != want_internal:
        problems.append(f"{label}: internal is {bool(net.get('Internal'))}, the plan says {want_internal}")
    if net.get("EnableIPv6"):
        problems.append(f"{label}: IPv6 is enabled; the address plan is IPv4 only")
print("; ".join(problems))
sys.exit(1 if problems else 0)
PY
  rm -f "$file"
  return "$status"
}

# 0: as expected. 1: the rules are missing, old or altered. 2: the rules are
# fine but a Docker network is not the one they were written for.
check() {
  local reason
  if ! reason=$(check_rules); then echo "$reason"; return 1; fi
  if ! reason=$(check_networks); then echo "$reason"; return 2; fi
  return 0
}

alert() {  # alert <key> <severity> <title> <description>
  logger -t honeysentinel-egress -p auth.crit "$3: $4" 2>/dev/null || true
  [[ "$PROFILE" == server && -x "$HERE/system-alert.sh" ]] || return 0
  "$HERE/system-alert.sh" "$@" >/dev/null 2>&1 \
    || echo "could not raise the dashboard alert (is the backend running?)" >&2
}

watch() {
  local reason status=0
  reason=$(check) || status=$?
  if [[ $status -eq 0 ]]; then
    echo "egress rules and networks as expected"
    return 0
  fi
  echo "PROBLEM: $reason" >&2
  if [[ $status -eq 2 ]]; then
    # The rules are fine; a network is not the one they were written for.
    # That needs the stack recreated, which is not something to do unasked.
    alert egress_network_mismatch critical \
      "Container network does not match the egress rules" \
      "$reason. Run deploy/server/install.sh, which recreates the networks."
    return 1
  fi
  apply
  # Connections a container opened while the rules were absent would
  # otherwise live on as "established".
  if command -v conntrack >/dev/null 2>&1; then
    conntrack -D --orig-src "$PLAN" >/dev/null 2>&1 || true
  fi
  alert egress_rules_missing critical \
    "Egress rules were missing or altered" \
    "$reason. honeysentinel-egress-check.timer re-applied them; find out what removed them (journalctl -u honeysentinel-egress-check)."
  if ! reason=$(check); then
    echo "still failing after re-applying: $reason" >&2
    return 1
  fi
  echo "re-applied"
}

# --- probe -----------------------------------------------------------------
# `check` reads configuration. This one tries: from inside each engine
# container it connects to public addresses, to the host on every bridge and
# to the other containers, and confirms that only the ingest service answers.
# A refused connection is a failure too: the refusal came from the far end,
# so the packet arrived.
probe() {
  local services service gateways="" row failed=0 allowed
  for row in "${NETWORKS[@]}"; do
    # shellcheck disable=SC2086
    set -- $row
    gateways+="${2%.0/24}.1 "
  done
  if [[ "$PROFILE" == sensor ]]; then
    cd "$HERE/../node"
    services=sensor
    allowed=""
    for row in $ALLOW_OUT; do allowed+="${row#*:} "; done
  else
    cd "$HERE"
    services=$(docker compose config --services | grep -E '^honeypot(-web)?$' || true)
    allowed="$INGEST_ENGINE:$API_PORT"
  fi
  [[ -n "$services" ]] || die "no engine service found to probe from"
  for service in $services; do
    echo "==> $service"
    docker compose exec -T \
      -e HS_GATEWAYS="$gateways" \
      -e HS_BLOCKED="1.1.1.1:443 8.8.8.8:53 9.9.9.9:443 $BACKEND_CONTROL:$API_PORT 172.30.67.10:2222 172.30.67.11:8080 172.30.66.2:2222 172.30.66.3:8080" \
      -e HS_ALLOWED="$allowed" \
      "$service" python - <<'PY' || failed=1
import os, socket, sys


def is_local(address):
    """True when the address belongs to this container (bind succeeds)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind((address, 0))
        return True
    except OSError:
        return False


def attempt(host, port, timeout=2.0):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return "connected"
    except ConnectionRefusedError:
        return "refused"
    except OSError:
        return "blocked"


bad = 0
targets = []
for gateway in os.environ["HS_GATEWAYS"].split():
    targets += [(gateway, 22), (gateway, 9)]
for item in os.environ["HS_BLOCKED"].split():
    host, port = item.rsplit(":", 1)
    targets.append((host, int(port)))
for host, port in targets:
    if is_local(host):
        continue
    result = attempt(host, port)
    ok = result == "blocked"
    bad += not ok
    print(f"  {'ok  ' if ok else 'FAIL'} {host}:{port} {result} (must be blocked)")
for item in os.environ["HS_ALLOWED"].split():
    host, port = item.rsplit(":", 1)
    result = attempt(host, int(port), timeout=5.0)
    ok = result == "connected"
    bad += not ok
    print(f"  {'ok  ' if ok else 'FAIL'} {host}:{port} {result} (must connect)")
sys.exit(1 if bad else 0)
PY
  done
  if [[ $failed -ne 0 ]]; then
    echo "PROBE FAILED: an engine reached something it must not, or cannot reach the ingest service." >&2
    return 1
  fi
  echo "Probe passed: the engines reach the ingest service and nothing else."
}

status() {
  nft list table inet "$TABLE"
  nft list table bridge "$TABLE"
}

load_conf
case "${1:-apply}" in
  apply)  apply ;;
  check)
    status=0
    reason=$(check) || status=$?
    if [[ $status -eq 0 ]]; then
      echo "ok (sha256:$(fingerprint))"
    else
      echo "$reason" >&2
      exit "$status"
    fi ;;
  watch)  watch ;;
  probe)  probe ;;
  status) status ;;
  render) render ;;
  *) echo "usage: $0 [apply|check|watch|probe|status|render]" >&2; exit 2 ;;
esac
