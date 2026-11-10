#!/usr/bin/env python3
"""Check that a compose project and the egress firewall describe the same thing.

    docker compose -f deploy/server/docker-compose.yml config --format json \
        | python3 scripts/check-network-plan.py --resolved -

The firewall (deploy/server/honeysentinel-egress.sh) is written against
bridge names, subnets and a handful of container addresses. Compose files
define the same values a second time. If the two drift apart nothing fails:
the stack starts, the rules load, and the rules simply no longer describe the
traffic. This script reads the plan out of the shell script and compares it
with what Compose resolved, so the drift is an error in CI and at the top of
install.sh instead.

It also holds every service to the baseline the deployment promises:
capabilities dropped, no-new-privileges, a memory and a process limit, and a
read-only root filesystem.

Input is the JSON from `docker compose config --format json` (a file, or `-`
for standard input), so it needs only the standard library and sees exactly
what Compose will run, override files and variable substitution included.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

EGRESS = Path(__file__).resolve().parent.parent / "deploy" / "server" / "honeysentinel-egress.sh"
BRIDGE_OPTION = "com.docker.network.bridge.name"

#: Bridges an engine (or another deliberately exposed service) sits on. An
#: address on one of them must never count as a trusted proxy.
EXPOSED = {"hs-decoy", "hs-engine", "hs-control", "hs-shop", "hs-shop-decoy",
           "hs-test", "hs-sensors", "hs-sensor", "hs-cowrie"}
#: The stock Cowrie image writes inside its own tree; it is run unmodified.
WRITABLE_ROOT_ALLOWED = {"cowrie"}


def read_plan() -> tuple[dict, dict]:
    text = EGRESS.read_text(encoding="utf-8")
    networks = {}
    for name, subnet, internal in re.findall(
        r'^\s*"(hs-[a-z0-9-]+)\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(yes|no)\s', text, re.M
    ):
        networks[name] = (ipaddress.ip_network(subnet), internal == "yes")
    constants = {}
    for match in re.finditer(r'^([A-Z_]+)="?([0-9., /]+?)"?\s*(?:#.*)?$', text, re.M):
        constants[match[1]] = [item.strip() for item in match[2].split(",") if item.strip()]
    if not networks or "INGEST_ENGINE" not in constants:
        sys.exit(f"could not read the address plan from {EGRESS}")
    return networks, constants


def check(project: dict, plan: dict, constants: dict) -> list[str]:
    problems: list[str] = []
    bridge_of: dict[str, str] = {}

    for key, net in (project.get("networks") or {}).items():
        bridge = (net.get("driver_opts") or {}).get(BRIDGE_OPTION, "")
        bridge_of[key] = bridge
        if bridge not in plan:
            problems.append(f"network {key}: bridge name '{bridge}' is not in the address plan")
            continue
        want_subnet, want_internal = plan[bridge]
        subnets = [c.get("subnet") for c in (net.get("ipam") or {}).get("config") or []]
        if subnets != [str(want_subnet)]:
            problems.append(f"network {key} ({bridge}): subnet {subnets}, the plan says {want_subnet}")
        if bool(net.get("internal")) != want_internal:
            problems.append(f"network {key} ({bridge}): internal={bool(net.get('internal'))}, the plan says {want_internal}")
        if net.get("enable_ipv6"):
            problems.append(f"network {key} ({bridge}): IPv6 enabled; the plan is IPv4 only")

    def address(service: dict, bridge: str) -> str | None:
        for key, attachment in (service.get("networks") or {}).items():
            if bridge_of.get(key) == bridge:
                return (attachment or {}).get("ipv4_address") or ""
        return None

    services = project.get("services") or {}
    expected = {
        ("ingest", "hs-engine"): constants["INGEST_ENGINE"],
        ("backend", "hs-control"): constants["BACKEND_CONTROL"],
        ("honeypot", "hs-control"): constants["ENGINES_CONTROL"],
        ("honeypot-web", "hs-control"): constants["ENGINES_CONTROL"],
        ("honeypot-web", "hs-shop"): constants["WEB_ENGINE_SHOP"],
        ("shop", "hs-shop"): constants["SHOP"],
        ("honeypot-web", "hs-shop-decoy"): constants["WEB_ENGINE_SHOP_DECOY"],
        ("shop-decoy", "hs-shop-decoy"): constants["SHOP_DECOY"],
    }
    for (name, bridge), allowed in expected.items():
        if name not in services:
            continue
        got = address(services[name], bridge)
        if got is None:
            if (name, bridge) in {("ingest", "hs-engine"), ("backend", "hs-control"),
                                  ("honeypot", "hs-control"), ("honeypot-web", "hs-control")}:
                problems.append(f"{name}: not attached to {bridge}")
        elif got not in allowed:
            problems.append(f"{name} on {bridge}: address '{got}', the firewall expects {' or '.join(allowed)}")

    for name, service in services.items():
        # Who shares a bridge with the engines is the heart of the design.
        if name not in {"backend", "honeypot", "honeypot-web"} and address(service, "hs-control") is not None:
            problems.append(f"{name}: attached to hs-control, which is for the API and the engines only")
        if name == "backend":
            if address(service, "hs-engine") is not None:
                problems.append("backend: attached to hs-engine; engines must only find the ingest service there")
            command = service.get("command") or []
            app_address = address(service, "hs-app")
            host = command[command.index("--host") + 1] if "--host" in command else None
            if host != app_address:
                problems.append(f"backend: listens on {host}, must be its hs-app address {app_address} only")
            trusted = (service.get("environment") or {}).get("TRUSTED_PROXIES", "")
            for item in filter(None, (part.strip() for part in trusted.split(","))):
                try:
                    proxy = ipaddress.ip_network(item, strict=False)
                except ValueError:
                    problems.append(f"backend: TRUSTED_PROXIES entry '{item}' is not an address or network")
                    continue
                for bridge in EXPOSED:
                    if proxy.version == 4 and proxy.overlaps(plan[bridge][0]):
                        problems.append(f"backend: TRUSTED_PROXIES entry {item} covers {bridge}")
        if name == "ingest" and (service.get("environment") or {}).get("API_ROLE") != "ingest":
            problems.append("ingest: API_ROLE must be 'ingest'")

        # The baseline every container gets.
        if "ALL" not in (service.get("cap_drop") or []):
            problems.append(f"{name}: cap_drop does not include ALL")
        if "no-new-privileges:true" not in (service.get("security_opt") or []):
            problems.append(f"{name}: no-new-privileges is not set")
        if not service.get("mem_limit"):
            problems.append(f"{name}: no memory limit")
        if not service.get("pids_limit"):
            problems.append(f"{name}: no process limit")
        if not service.get("read_only") and name not in WRITABLE_ROOT_ALLOWED:
            problems.append(f"{name}: root filesystem is not read-only")
        if (service.get("logging") or {}).get("driver") == "json-file" and not (service["logging"].get("options") or {}).get("max-size"):
            problems.append(f"{name}: json-file logging without max-size")
        if not service.get("logging"):
            problems.append(f"{name}: no log rotation configured")
        for port in service.get("ports") or []:
            if port.get("host_ip") in (None, "", "::"):
                problems.append(f"{name}: port {port.get('published')} is published without an IPv4 host address")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "--resolved":
        print(__doc__.strip().split("\n\n")[0], file=sys.stderr)
        print("\nusage: check-network-plan.py --resolved <config.json | ->", file=sys.stderr)
        return 2
    stream = sys.stdin if argv[1] == "-" else open(argv[1], encoding="utf-8")
    with stream:
        project = json.load(stream)
    plan, constants = read_plan()
    problems = check(project, plan, constants)
    for problem in problems:
        print(problem)
    if not problems:
        print(f"{project.get('name', 'project')}: networks, addresses and hardening match the plan")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
