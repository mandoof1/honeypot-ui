#!/usr/bin/env python3
"""Per-engine ingest tokens: one for each node, bound to its name.

    sudo python3 node_tokens.py list                 # node names (never tokens)
    sudo python3 node_tokens.py add <node-name>      # a token for a remote sensor
    sudo python3 node_tokens.py remove <node-name>
    sudo python3 node_tokens.py sync --local name=VAR ...   # used by install.sh

The backend reads HONEYPOT_NODE_TOKENS, a JSON object {"node-name": "token"},
and accepts a token only for the node it belongs to. With the single shared
token used before, anything that learned it (one compromised engine was
enough) could register nodes and write sessions under any name.

Where the tokens live:

  .env                       HONEYPOT_NODE_TOKEN_* for the engines in this
                             compose project, and the assembled
                             HONEYPOT_NODE_TOKENS the backend reads
  state/sensor-tokens.json   tokens of remote sensors (deploy/node), so that
                             a later `sync` keeps them

Both are root-only and inside the backup's config archive. A token is shown
once, by `add`, to be copied into that sensor's own .env.

Standard library only: it runs on the host, before any container exists.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENV_FILE = Path(os.environ.get("HS_ENV_FILE", HERE / ".env"))
SENSORS = Path(os.environ.get("HS_SENSOR_TOKENS", HERE / "state" / "sensor-tokens.json"))
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAP_VAR = "HONEYPOT_NODE_TOKENS"


def read_env() -> dict[str, str]:
    values: dict[str, str] = {}
    if not ENV_FILE.exists():
        return values
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def write_private(path: Path, text: str) -> None:
    """Replace a file in one step, never readable by anyone but root."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(temporary, path)
    except BaseException:
        os.unlink(temporary)
        raise


def set_env(key: str, value: str) -> None:
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []
    kept = [line for line in lines if not line.startswith(key + "=")]
    kept.append(f"{key}={value}")
    write_private(ENV_FILE, "\n".join(kept) + "\n")


def read_sensors() -> dict[str, str]:
    if not SENSORS.exists():
        return {}
    data = json.loads(SENSORS.read_text(encoding="utf-8"))
    return {str(name): str(token) for name, token in data.items()}


def current_map() -> dict[str, str]:
    raw = read_env().get(MAP_VAR, "")
    try:
        data = json.loads(raw) if raw else {}
    except ValueError:
        data = {}
    return data if isinstance(data, dict) else {}


def write_map(mapping: dict[str, str]) -> None:
    # Single quotes: Compose and the shell both take the JSON literally, and
    # a token (URL-safe base64) cannot contain one.
    set_env(MAP_VAR, "'" + json.dumps(mapping, separators=(",", ":"), sort_keys=True) + "'")


def check_name(name: str) -> str:
    if not NAME.match(name):
        sys.exit(f"'{name}' is not a usable node name (letters, digits, . _ -, at most 64)")
    return name


def sync(pairs: list[str]) -> None:
    """Rebuild the map: the local engines named on the command line, then the sensors."""
    env = read_env()
    mapping: dict[str, str] = {}
    for pair in pairs:
        name, _, variable = pair.partition("=")
        token = env.get(variable, "")
        if not token:
            sys.exit(f"{variable} is not set in {ENV_FILE}")
        if check_name(name) in mapping:
            sys.exit(f"two engines are both named '{name}'; give each its own name")
        mapping[name] = token
    for name, token in read_sensors().items():
        if name in mapping:
            sys.exit(f"remote sensor '{name}' has the same name as a local engine")
        mapping[name] = token
    if len(set(mapping.values())) != len(mapping):
        sys.exit("two nodes share a token; regenerate one of them")
    write_map(mapping)
    print(f"{MAP_VAR}: {', '.join(sorted(mapping))}")


def add(name: str) -> None:
    mapping, sensors = current_map(), read_sensors()
    if check_name(name) in mapping:
        sys.exit(f"'{name}' already has a token; remove it first to issue a new one")
    token = secrets.token_urlsafe(48)
    sensors[name] = token
    mapping[name] = token
    write_private(SENSORS, json.dumps(sensors, indent=2, sort_keys=True) + "\n")
    write_map(mapping)
    print(f"Token for node '{name}' (shown once; put it in that sensor's .env as HONEYPOT_NODE_TOKEN):\n")
    print(f"  {token}\n")
    print("Apply it:  docker compose up -d backend ingest")


def remove(name: str) -> None:
    mapping, sensors = current_map(), read_sensors()
    if name not in sensors:
        sys.exit(f"'{name}' is not a remote sensor (the local engines' tokens are managed by install.sh)")
    sensors.pop(name)
    mapping.pop(name, None)
    write_private(SENSORS, json.dumps(sensors, indent=2, sort_keys=True) + "\n")
    write_map(mapping)
    print(f"Removed '{name}'. Apply it:  docker compose up -d backend ingest")


def main(argv: list[str]) -> None:
    if len(argv) >= 1 and argv[0] == "list":
        sensors = read_sensors()
        for name in sorted(current_map()):
            print(f"{name}\t{'remote sensor' if name in sensors else 'local engine'}")
    elif len(argv) == 2 and argv[0] == "add":
        add(argv[1])
    elif len(argv) == 2 and argv[0] == "remove":
        remove(argv[1])
    elif len(argv) >= 3 and argv[0] == "sync" and argv[1] == "--local":
        sync(argv[2:])
    else:
        sys.exit(__doc__.split("\n\n")[1])


if __name__ == "__main__":
    main(sys.argv[1:])
