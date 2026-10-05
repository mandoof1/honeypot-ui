#!/usr/bin/env bash
#
# Stop the honeypot engine from opening any connection of its own.
#
# The engine has to sit on a normal bridge (hs-decoy) for Docker to publish
# its ports, and a normal bridge routes to the internet. These rules sit in
# DOCKER-USER, which Docker evaluates before its own forwarding rules and
# never flushes, and allow only replies to connections that came in:
#
#   inbound  internet -> hs-decoy          allowed (Docker's published ports)
#   replies  hs-decoy -> internet          allowed (ESTABLISHED/RELATED)
#   new      hs-decoy -> anywhere          logged and dropped
#
# The INPUT rule covers the host itself, which a container reaches through
# its bridge gateway without passing through FORWARD.
#
# Runs before docker.service (see honeysentinel-egress.service), so the rules
# are in place before any container starts. Idempotent.

set -euo pipefail

IFACE=hs-decoy
CHAIN=HS-DECOY-EGRESS

for ipt in iptables ip6tables; do
  $ipt -w -N DOCKER-USER 2>/dev/null || true
  $ipt -w -N "$CHAIN" 2>/dev/null || true
  $ipt -w -F "$CHAIN"
  $ipt -w -A "$CHAIN" -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
  $ipt -w -A "$CHAIN" -m limit --limit 6/min --limit-burst 10 \
    -j LOG --log-prefix "hs-decoy egress blocked: "
  $ipt -w -A "$CHAIN" -j DROP

  for hook in "DOCKER-USER" "INPUT"; do
    $ipt -w -C "$hook" -i "$IFACE" -j "$CHAIN" 2>/dev/null \
      || $ipt -w -I "$hook" 1 -i "$IFACE" -j "$CHAIN"
  done
done

echo "Egress from ${IFACE} blocked (replies to inbound connections only)."
