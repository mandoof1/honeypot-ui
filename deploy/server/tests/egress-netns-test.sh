#!/usr/bin/env bash
#
# Functional test of honeysentinel-egress.sh: build the deployment's bridges
# and stand-ins for its containers out of network namespaces, load the real
# ruleset, and check with real TCP connections which paths are open.
#
#   bash deploy/server/tests/egress-netns-test.sh
#
# Needs no Docker and touches nothing on the machine it runs on: everything
# happens inside a private network namespace that disappears when the script
# exits. As root it uses `unshare -n`; otherwise an unprivileged user
# namespace (`unshare -Urn`), which some distributions disable, in which case
# run it with sudo.
#
# What it stands in for:
#
#   internet (198.51.100.2) ── wan0 ── HOST ──┬─ hs-decoy   ─ eng1, eng2
#                                             ├─ hs-engine  ─ eng1, eng2, ingest
#                                             ├─ hs-control ─ eng1, eng2, backend
#                                             ├─ hs-shop    ─ eng2, shop
#                                             └─ hs-app     ─ backend, web
#
# The host forwards and masquerades like a Docker host, publishes eng1's port
# 2222 on its outside address, and listens on port 2200 on every address as a
# stand-in for its own services (sshd and the like).

set -euo pipefail

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
HERE="$(dirname "$SELF")"
EGRESS="$HERE/../honeysentinel-egress.sh"

if [[ "${HS_NETNS_TEST:-}" != inside ]]; then
  for bin in unshare nsenter ip nft python3; do
    command -v "$bin" >/dev/null 2>&1 || { echo "missing: $bin" >&2; exit 2; }
  done
  if [[ $EUID -eq 0 ]]; then
    HS_NETNS_TEST=inside exec unshare -n -- bash "$SELF" "$@"
  fi
  HS_NETNS_TEST=inside exec unshare -Urn -- bash "$SELF" "$@"
fi

WORK=$(mktemp -d)
PIDS=()
cleanup() {
  local pid
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

cat > "$WORK/net.py" <<'PY'
"""listen PORT...   accept on 0.0.0.0 and :: and answer "ok"
probe HOST PORT   print connected, refused or blocked"""
import socket, sys, threading

def serve(family, port):
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    server.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", port))
    server.listen(16)
    while True:
        conn, _ = server.accept()
        try:
            conn.sendall(b"ok")
        finally:
            conn.close()

if sys.argv[1] == "listen":
    for port in map(int, sys.argv[2:]):
        for family in (socket.AF_INET, socket.AF_INET6):
            threading.Thread(target=serve, args=(family, port), daemon=True).start()
    threading.Event().wait()
else:
    try:
        with socket.create_connection((sys.argv[2], int(sys.argv[3])), timeout=1.5) as conn:
            conn.settimeout(1.5)
            print("connected" if conn.recv(2) == b"ok" else "blocked")
    except ConnectionRefusedError:
        print("refused")
    except OSError:
        print("blocked")
PY

declare -A NS      # name -> pid of a process holding that namespace open

container() {      # container <name>
  unshare -n -- sleep infinity &
  NS[$1]=$!
  PIDS+=("$!")
  # The namespace exists once the child has unshared.
  local tries=0
  until nsenter -t "${NS[$1]}" -n true 2>/dev/null; do
    tries=$((tries + 1)); [[ $tries -lt 50 ]] || { echo "namespace $1 did not appear" >&2; exit 2; }
    sleep 0.1
  done
  in_ns "$1" ip link set lo up
}

in_ns() { local name=$1; shift; nsenter -t "${NS[$name]}" -n -- "$@"; }

bridge() {         # bridge <name> <host address/len>
  ip link add "$1" type bridge forward_delay 0
  ip addr add "$2" dev "$1"
  ip link set "$1" up
}

attach() {         # attach <container> <bridge> <address/len> [ifname]
  local name=$1 br=$2 addr=$3 ifname=${4:-eth0} host="v${1:0:4}${2#hs-}"
  host=${host:0:15}
  ip link add "$host" type veth peer name "$ifname" netns "${NS[$name]}"
  ip link set "$host" master "$br" up
  in_ns "$name" ip addr add "$addr" dev "$ifname"
  in_ns "$name" ip link set "$ifname" up
}

listen() {         # listen <container|host> <port>...
  local name=$1; shift
  if [[ "$name" == host ]]; then
    python3 "$WORK/net.py" listen "$@" &
  else
    in_ns "$name" python3 "$WORK/net.py" listen "$@" &
  fi
  PIDS+=("$!")
}

probe() {          # probe <container> <host> <port>
  in_ns "$1" python3 "$WORK/net.py" probe "$2" "$3"
}

FAILED=0
PASSED=0
expect() {         # expect <result> <container> <host> <port> <what>
  local want=$1 from=$2 host=$3 port=$4 what=$5 got
  got=$(probe "$from" "$host" "$port")
  if [[ "$got" == "$want" ]]; then
    PASSED=$((PASSED + 1))
    printf '  ok    %-52s %s\n' "$what" "$got"
  else
    FAILED=$((FAILED + 1))
    printf '  FAIL  %-52s %s (wanted %s)\n' "$what" "$got" "$want"
  fi
}

echo "==> Building the test network"
ip link set lo up
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1 2>/dev/null || true

bridge hs-decoy   172.30.66.1/24
bridge hs-engine  172.30.67.1/24
bridge hs-shop    172.30.68.1/24
bridge hs-app     172.30.70.1/24
bridge hs-control 172.30.71.1/24
# An IPv6 address on a bridge the engines share with the host: the plan is
# IPv4 only, and this shows IPv6 is not a way round it.
ip -6 addr add fd00:67::1/64 dev hs-engine nodad

for name in eng1 eng2 ingest backend web shop internet; do container "$name"; done

attach eng1 hs-decoy   172.30.66.2/24  eth0
attach eng1 hs-engine  172.30.67.10/24 eth1
attach eng1 hs-control 172.30.71.10/24 eth2
attach eng2 hs-decoy   172.30.66.3/24  eth0
attach eng2 hs-engine  172.30.67.11/24 eth1
attach eng2 hs-control 172.30.71.11/24 eth2
attach eng2 hs-shop    172.30.68.11/24 eth3
attach ingest  hs-engine  172.30.67.20/24
attach backend hs-control 172.30.71.2/24  eth0
attach backend hs-app     172.30.70.10/24 eth1
attach web     hs-app     172.30.70.20/24
attach shop    hs-shop    172.30.68.20/24
in_ns eng1 ip -6 addr add fd00:67::10/64 dev eth1 nodad
for name in eng1 eng2; do in_ns "$name" ip route add default via 172.30.66.1; done

# The outside world, and the host doing what a Docker host does: masquerade
# what leaves the decoy bridge and publish eng1's port 2222.
ip link add wan0 type veth peer name eth0 netns "${NS[internet]}"
ip addr add 198.51.100.1/24 dev wan0
ip link set wan0 up
in_ns internet ip addr add 198.51.100.2/24 dev eth0
in_ns internet ip link set eth0 up
nft -f - <<'NFT'
table ip testnat {
	chain prerouting {
		type nat hook prerouting priority dstnat;
		iifname "wan0" tcp dport 2222 dnat to 172.30.66.2:2222
	}
	chain postrouting {
		type nat hook postrouting priority srcnat;
		ip saddr 172.30.64.0/19 oifname "wan0" masquerade
	}
}
NFT

listen host 2200
listen eng1 2222 8000
listen eng2 8080 8000
listen ingest 8000 9000
# On every address, to show the firewall alone keeps the engines off the API
# (in the deployment it also listens on its hs-app address only).
listen backend 8000
listen shop 3000 3001
listen internet 443 444
sleep 0.5

echo "==> Without the rules (the paths must be open, or the test proves nothing)"
expect connected eng1 198.51.100.2 443   "engine -> internet"
expect connected eng1 172.30.67.1 2200   "engine -> host, engine bridge"
expect connected eng1 172.30.71.2 8000   "engine -> API, control bridge"
expect connected eng1 172.30.67.11 8080  "engine -> other engine"
expect connected eng1 fd00:67::1 2200    "engine -> host, IPv6"
if [[ $FAILED -ne 0 ]]; then
  echo "The test network is not behaving as expected; aborting." >&2
  exit 2
fi

run_egress() { HS_EGRESS_RUN_DIR="$WORK/run" HS_EGRESS_CONF="${CONF:-$WORK/none.conf}" bash "$EGRESS" "$@"; }

assertions() {
  echo "  -- inbound still works"
  expect connected internet 198.51.100.1 2222 "internet -> published decoy port"
  echo "  -- an engine cannot leave"
  expect blocked eng1 198.51.100.2 443      "engine -> internet"
  expect blocked eng1 198.51.100.1 2200     "engine -> host, outside address"
  expect blocked eng1 172.30.66.1 2200      "engine -> host, decoy bridge"
  expect blocked eng1 172.30.67.1 2200      "engine -> host, engine bridge"
  expect blocked eng1 172.30.71.1 2200      "engine -> host, control bridge"
  expect blocked eng2 172.30.68.1 2200      "web engine -> host, shop bridge"
  expect blocked eng1 172.30.70.1 2200      "engine -> host, a bridge it is not on"
  expect blocked eng1 fd00:67::1 2200       "engine -> host, IPv6"
  echo "  -- an engine reaches the ingest service and nothing else"
  expect connected eng1 172.30.67.20 8000   "engine -> ingest:8000"
  expect connected eng2 172.30.67.20 8000   "web engine -> ingest:8000"
  expect blocked eng1 172.30.67.20 9000     "engine -> ingest, another port"
  expect blocked eng1 172.30.67.11 8080     "engine -> other engine, engine bridge"
  expect blocked eng1 172.30.66.3 8080      "engine -> other engine, decoy bridge"
  expect blocked eng1 172.30.71.11 8000     "engine -> other engine's control API"
  expect blocked eng1 172.30.71.2 8000      "engine -> API, control bridge"
  expect blocked eng1 172.30.70.10 8000     "engine -> API, its dashboard address"
  expect blocked ingest 172.30.67.10 2222   "ingest -> engine (no connections back)"
  echo "  -- the API controls the engines; the web engine reaches its shop"
  expect connected backend 172.30.71.10 8000 "API -> engine control"
  expect connected backend 172.30.71.11 8000 "API -> web engine control"
  expect connected eng2 172.30.68.20 3000    "web engine -> shop:3000"
  expect blocked eng2 172.30.68.20 3001      "web engine -> shop, another port"
  expect blocked shop 172.30.68.11 8080      "shop -> web engine"
  expect blocked shop 172.30.68.1 2200       "shop -> host"
  echo "  -- the rest of the stack works and is contained too"
  expect connected web 172.30.70.10 8000     "dashboard proxy -> API"
  expect blocked backend 172.30.70.1 2200    "API -> host"
  expect blocked ingest 172.30.67.1 2200     "ingest -> host"
}

echo "==> With the rules"
run_egress apply >/dev/null
assertions

# br_netfilter makes switched frames pass the routed hooks as well. Docker
# releases before 28 load it; the rules have to hold either way. The switch
# is per namespace, and absent when the module is not loaded on this kernel.
if [[ -w /proc/sys/net/bridge/bridge-nf-call-iptables ]]; then
  echo "==> With the rules and br_netfilter (bridge-nf-call-iptables=1)"
  sysctl -qw net.bridge.bridge-nf-call-iptables=1
  sysctl -qw net.bridge.bridge-nf-call-ip6tables=1 2>/dev/null || true
  assertions
  sysctl -qw net.bridge.bridge-nf-call-iptables=0
else
  echo "==> br_netfilter is not loaded on this kernel; that variant was not run"
fi

echo "==> check, tampering and watch"
check() {          # check <want status> <what>
  local want=$1 what=$2 got=0
  run_egress check >/dev/null 2>&1 || got=$?
  if [[ $got -eq $want ]]; then
    PASSED=$((PASSED + 1)); printf '  ok    %s\n' "$what"
  else
    FAILED=$((FAILED + 1)); printf '  FAIL  %s (check exited %s, wanted %s)\n' "$what" "$got" "$want"
  fi
}
check 0 "check passes on freshly applied rules"
before=$(nft -s list ruleset | sha256sum)
run_egress apply >/dev/null
if [[ "$(nft -s list ruleset | sha256sum)" == "$before" ]]; then
  PASSED=$((PASSED + 1)); echo "  ok    applying twice changes nothing"
else
  FAILED=$((FAILED + 1)); echo "  FAIL  applying twice changed the ruleset"
fi

handle=$(nft -a list chain inet honeysentinel input | sed -n 's/.*iifname "hs-\*".*# handle \([0-9]*\)$/\1/p')
nft delete rule inet honeysentinel input handle "$handle"
check 1 "check fails when one rule is deleted"
CONF="$WORK/sensor.conf"
printf 'PROFILE=sensor\n' > "$CONF"      # no dashboard here to alert through
run_egress watch >/dev/null 2>&1 || true
check 0 "watch restores a deleted rule"
nft delete table bridge honeysentinel
check 1 "check fails when the bridge table is gone"
run_egress watch >/dev/null 2>&1 || true
check 0 "watch restores a deleted table"
expect blocked eng1 172.30.67.1 2200 "engine -> host after the restore"

echo "==> One permitted destination (the remote sensor's ingest endpoint)"
printf 'PROFILE=sensor\nALLOW_OUT="hs-decoy:198.51.100.2:443"\n' > "$CONF"
run_egress apply >/dev/null
expect connected eng1 198.51.100.2 443  "engine -> the permitted address and port"
expect blocked eng1 198.51.100.2 444    "engine -> the permitted address, another port"
expect blocked eng1 198.51.100.1 2200   "engine -> host"
expect connected internet 198.51.100.1 2222 "internet -> published decoy port"

printf 'ALLOW_OUT="hs-decoy:198.51.100.2:443; drop"\n' > "$CONF"
if run_egress render >/dev/null 2>&1; then
  FAILED=$((FAILED + 1)); echo "  FAIL  a malformed ALLOW_OUT entry was accepted"
else
  PASSED=$((PASSED + 1)); echo "  ok    a malformed ALLOW_OUT entry is refused"
fi

echo
echo "$PASSED passed, $FAILED failed"
[[ $FAILED -eq 0 ]]
