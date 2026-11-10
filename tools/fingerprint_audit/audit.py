"""Run one protocol's probes against both targets and build the result."""

from __future__ import annotations

import datetime
import json
import os
import platform
import socket
import subprocess
import time
from typing import Any, Callable, Optional

from . import SCHEMA
from .checks import Check, compare, summarise
from .net import Pacer, Target
from .probe import Prober, Settings

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))


def _collector(protocol: str) -> Callable[[Prober], list[Check]]:
    # Imported on demand so that auditing HTTP does not need asyncssh.
    if protocol == "ssh":
        from . import ssh_probes as module
    elif protocol == "ftp":
        from . import ftp_probes as module
    elif protocol == "http":
        from . import http_probes as module
    elif protocol == "telnet":
        from . import telnet_probes as module
    else:
        raise ValueError(f"unknown protocol: {protocol}")
    return module.collect


def _git(*arguments: str) -> Optional[str]:
    try:
        done = subprocess.run(
            ["git", "-C", PACKAGE_DIR, *arguments],
            capture_output=True, text=True, timeout=15, check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip()


def tool_revision() -> dict:
    """Which revision of this tool produced a result.

    ``GIT_REVISION`` wins when set, for runs from an exported tree or an
    image with no .git; otherwise git is asked, and the result also says
    whether the tool's files had changes that commit does not contain.
    """
    from_environment = os.environ.get("GIT_REVISION", "").strip()
    status = _git("status", "--porcelain", "--", PACKAGE_DIR)
    return {
        "name": "tools.fingerprint_audit",
        "git_revision": from_environment or _git("rev-parse", "HEAD"),
        "git_revision_source": "GIT_REVISION" if from_environment else "git rev-parse HEAD",
        "uncommitted_changes": None if status is None else bool(status),
        "python": platform.python_version(),
    }


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def wait_until_listening(targets: list[Target], timeout: float) -> None:
    """Block until every target accepts a TCP connection."""
    deadline = time.monotonic() + timeout
    for target in targets:
        while True:
            try:
                socket.create_connection((target.host, target.port), timeout=2).close()
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"{target} is not accepting connections")
                time.sleep(0.5)


def run_audit(
    protocol: str,
    decoy: Target,
    reference: Target,
    settings: Settings,
    decoy_description: Optional[str] = None,
    reference_description: Optional[str] = None,
    raw_dir: Optional[str] = None,
    progress: Callable[[str], None] = lambda _message: None,
) -> dict:
    """Probe the decoy, then the reference, and compare.

    One after the other, never interleaved: a single pacer spaces every
    connection of the run, so at no point are two connections open.
    """
    collect = _collector(protocol)
    pacer = Pacer(settings.delay)
    started = utc_now()

    sides = {}
    for side, target in (("decoy", decoy), ("reference", reference)):
        progress(f"probing the {side} at {target}")
        prober = Prober(
            target, settings, pacer,
            raw_dir=os.path.join(raw_dir, side) if raw_dir else None,
        )
        sides[side] = (collect(prober), prober.errors)

    rows = compare(sides["decoy"][0], sides["reference"][0])
    tool = tool_revision()
    if protocol == "ssh":
        import asyncssh

        tool["asyncssh"] = asyncssh.__version__
    return {
        "schema": SCHEMA,
        "generated_at": started,
        "tool": tool,
        "environment": {
            # parse_target refuses anything else, so this is a property of
            # the run, not a claim about it.
            "network": "both targets were reached at loopback addresses from the "
                       "process that ran the audit, so both ran on the same machine",
            "kernel": platform.release(),
        },
        "protocol": protocol,
        "decoy": {
            "address": str(decoy),
            "description": decoy_description,
            "probe_errors": sides["decoy"][1],
        },
        "reference": {
            "address": str(reference),
            "description": reference_description,
            "probe_errors": sides["reference"][1],
        },
        "settings": settings.stored(),
        "summary": summarise(rows),
        "checks": rows,
    }


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def write_json(path: str, document: dict) -> None:
    _write(path, json.dumps(document, indent=2, ensure_ascii=True) + "\n")


# ------------------------------------------------------------------ markdown

def _cell(value: Any, limit: int = 70) -> str:
    """A value squeezed into one table cell."""
    if isinstance(value, dict) and {"length", "sha256", "text"} <= set(value):
        text = f"{value['text']} ({value['length']} bytes)"
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        text = ", ".join(value) if value else "(none)"
    elif isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=True)
    if len(text) > limit:
        text = text[:limit - 3] + "..."
    # Backticks keep markdown from reading protocol text as markup.
    return "`" + text.replace("`", "'").replace("|", "\\|") + "`"


def to_markdown(result: dict) -> str:
    """The result as a metadata list and one table row per check. Long
    values are cut short here; the JSON file holds them whole."""
    summary = result["summary"]
    tool = result["tool"]
    lines = [
        f"# Fingerprint audit: {result['protocol']}",
        "",
        f"- Date (UTC): {result['generated_at']}",
        f"- Tool revision: {tool['git_revision']} (from {tool['git_revision_source']}"
        f"{', with uncommitted changes' if tool['uncommitted_changes'] else ''})",
        f"- Decoy: {result['decoy']['address']} - {result['decoy']['description'] or 'not described'}",
        f"- Reference: {result['reference']['address']} - {result['reference']['description'] or 'not described'}",
        f"- Network: {result['environment']['network']}",
        f"- Checks: {summary['checks']}, matching {summary['matches']}, differing {summary['mismatches']}",
        f"- Timing rows (informational): {summary['informational_timing_rows']}, "
        f"outside tolerance {summary['timing_rows_outside_tolerance']}",
        "",
    ]
    for side in ("decoy", "reference"):
        for group, error in result[side]["probe_errors"].items():
            lines.append(f"- Could not run `{group}` against the {side}: {error}")
    lines += [
        "",
        "| Check | Comparison | Result | Similarity | Decoy | Reference |",
        "|---|---|---|---|---|---|",
    ]
    for row in result["checks"]:
        verdict = "match" if row["match"] else "MISMATCH"
        if row["informational"]:
            verdict = "within tolerance" if row["match"] else "outside tolerance"
        if row["decoy"]["error"] or row["reference"]["error"]:
            verdict = "not measured"
        lines.append(
            f"| `{row['id']}` | {row['comparison']} | {verdict} | {row['similarity']:.2f} "
            f"| {_cell(row['decoy']['value'])} | {_cell(row['reference']['value'])} |"
        )
    return "\n".join(lines) + "\n"


def write_markdown(path: str, result: dict) -> None:
    _write(path, to_markdown(result))
