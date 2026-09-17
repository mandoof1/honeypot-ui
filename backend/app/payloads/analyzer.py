"""Run every applicable analyser over one sample and assemble the report.

This is the entry point the sandbox calls. It takes bytes and returns a plain
dict — no database, no settings, no I/O beyond reading the bytes it was given —
so it can run unchanged in-process (for tests) or inside the locked-down
subprocess the worker spawns.

The report is built to be read top-down: what the file is, what it can do, who
it talks to, and what it was built with. Every layer is defensive; a parser
that throws on malformed input yields an ``error`` for its own section and the
rest of the report still stands.
"""

from __future__ import annotations

import hashlib
import traceback

from app.payloads import archive, bytestats, elf, family, identify, indicators, pe, script

ANALYSER_VERSION = "1"

#: How far archive recursion goes. One level catches JARs and tarballs; deeper
#: is where nested-archive bombs live.
MAX_RECURSION_DEPTH = 2
MAX_NESTED_SAMPLES = 40


def analyse(data: bytes) -> dict:
    report: dict = {
        "analyser_version": ANALYSER_VERSION,
        "hashes": _hashes(data),
        "size": len(data),
        "entropy": bytestats.rounded(bytestats.entropy(data)),
    }
    strings = bytestats.strings(data)
    report["string_count"] = len(strings)

    file_type = identify.identify(data)
    report["file_type"] = file_type.as_dict()
    report["file_kind"] = file_type.kind

    # Indicators over the raw strings always run; every other analyser is
    # chosen by file kind. Strings themselves are summarised, not dumped: the
    # sample is stored, so an analyst can always pull the full set.
    report["indicators"] = indicators.extract([(s, "strings") for s in strings])

    try:
        _dispatch(data, file_type, strings, report, depth=0, budget=[MAX_NESTED_SAMPLES])
    except Exception as exc:  # pragma: no cover - a parser bug must not lose the report
        report["dispatch_error"] = f"{type(exc).__name__}: {exc}"[:300]
        report["traceback"] = traceback.format_exc()[-1500:]

    report["indicator_count"] = indicators.count(report["indicators"])
    report["family"] = family.classify({**report, "strings": strings})
    report["inferred_kind"] = family.infer_kind(report)
    report["summary"] = _summary(report)
    report["notable"] = _notable(report)
    return report


def _dispatch(data, file_type, strings, report, depth, budget):
    kind = file_type.kind
    if kind == "elf":
        report["elf"] = elf.analyse(data)
    elif kind in ("pe", "dos"):
        report["pe"] = pe.analyse(data)
    elif kind == "script" or (kind in ("text", "ssh_key") and file_type.subtype):
        report["script"] = script.analyse(data, file_type.subtype)
        _merge_indicators(report, report["script"].get("indicators", {}))
    elif kind == "archive":
        report["archive"] = _walk_archive(data, file_type.subtype, depth, budget)


def _walk_archive(data, container, depth, budget):
    result = archive.analyse(data, container)
    extracted = result.pop("_extracted", [])
    if depth >= MAX_RECURSION_DEPTH:
        return result

    children = []
    for name, content in extracted:
        if budget[0] <= 0:
            break
        budget[0] -= 1
        child_type = identify.identify(content)
        child: dict = {
            "name": name[:255], "size": len(content),
            "file_type": child_type.as_dict(),
            "hashes": {"sha256": hashlib.sha256(content).hexdigest()},
        }
        child_report: dict = {"indicators": {}}
        try:
            _dispatch(content, child_type, bytestats.strings(content), child_report, depth + 1, budget)
        except Exception as exc:  # pragma: no cover
            child["error"] = f"{type(exc).__name__}: {exc}"[:200]
        for section in ("elf", "pe", "script", "archive"):
            if section in child_report:
                child[section] = child_report[section]
        children.append(child)
    if children:
        result["extracted"] = children
    return result


def _merge_indicators(report, more):
    for key, values in (more or {}).items():
        bucket = report["indicators"].setdefault(key, [])
        seen = {_indicator_key(v) for v in bucket}
        for value in values:
            if _indicator_key(value) not in seen:
                bucket.append(value)
                seen.add(_indicator_key(value))


def _indicator_key(value):
    if isinstance(value, dict):
        return value.get("value") or value.get("indicator") or value.get("fingerprint") or str(value)
    return value


def _hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _summary(report: dict) -> str:
    kind = report["file_kind"]
    if kind == "elf" and "elf" in report:
        base = elf.summary(report["elf"])
    elif kind in ("pe", "dos") and "pe" in report:
        base = pe.summary(report["pe"])
    elif kind == "script" and "script" in report:
        base = script.summary(report["script"])
    elif kind == "archive" and "archive" in report:
        base = archive.summary(report["archive"])
    else:
        base = report["file_type"]["label"]
    fam = report.get("family")
    if fam:
        base += f" — likely {fam['family']} ({fam['confidence']:.0%} on heuristics)"
    elif report.get("inferred_kind"):
        base += f" — {report['inferred_kind']}"
    return base


def _notable(report: dict) -> list[str]:
    """The two or three things an analyst should see first."""
    notes: list[str] = []
    elf_info = report.get("elf", {})
    pe_info = report.get("pe", {})
    script_info = report.get("script", {})

    if (elf_info.get("packer") or pe_info.get("packer")):
        packer = (elf_info.get("packer") or pe_info.get("packer"))
        notes.append(f"Packed ({packer.get('name') or 'unknown packer'})")
    if elf_info.get("rwx_segments"):
        notes.append("Has a writable+executable segment (self-modifying or unpacking)")
    if pe_info.get("pdb_path"):
        notes.append(f"Leaks a build path: {pe_info['pdb_path']}")
    if pe_info.get("compile_time_note"):
        notes.append(f"Compile timestamp {pe_info['compile_time_note']}")
    for capability in pe_info.get("capabilities", []):
        notes.append(capability["label"])
    behaviours = script_info.get("behaviours", [])
    if any(b["id"] == "multi_arch" for b in behaviours):
        notes.append("Fetches multiple CPU architectures (IoT botnet loader)")
    if any(b["id"] == "kill_competitors" for b in behaviours):
        notes.append("Kills competing malware")
    channels = report["indicators"].get("c2_channels", [])
    if channels:
        notes.append(f"{len(channels)} operator channel(s) (Telegram/Discord/IRC)")
    if report["indicators"].get("wallets"):
        notes.append(f"{len(report['indicators']['wallets'])} cryptocurrency wallet(s)")
    if report["indicators"].get("ssh_keys"):
        notes.append("Embeds an SSH key (persistence)")
    return notes[:8]
