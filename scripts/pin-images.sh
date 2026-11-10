#!/usr/bin/env bash
#
# Pin container images by digest, and report pins that have fallen behind.
#
#   bash scripts/pin-images.sh            # report only; exit 1 if anything is
#                                         # unpinned or behind its tag
#   bash scripts/pin-images.sh --write    # rewrite the files
#
# A tag such as python:3.12-slim names whatever the registry serves today, so
# two builds of the same commit can produce different images. A digest names
# one image. The convention in this repository keeps both: the tag in a
# comment for people, the digest on the next line for Docker.
#
#     # postgres:16-alpine
#     image: postgres@sha256:7218...
#
# This script reads that pair, asks the registry what the tag points at now,
# and with --write replaces the digest. A reference still written as a plain
# tag (FROM node:22-alpine) is converted to the pair. It contacts registries
# but pulls nothing. Review the diff before committing: a new digest is new
# code, and the point of pinning is that taking it is a decision.
#
# Images built here (honeysentinel-*, bolt-and-batten-web) have no registry
# and are skipped.
#
# The digest is looked up with the first of these that is installed:
# `docker buildx imagetools`, `crane`, `skopeo`. To use something else, set
# PIN_IMAGES_RESOLVE_CMD to a command that takes name:tag and prints sha256:...

set -euo pipefail
cd "$(dirname "$0")/.."

WRITE=0
case "${1:-}" in
  --write) WRITE=1 ;;
  ""|--check) ;;
  *) echo "usage: $0 [--check|--write]" >&2; exit 2 ;;
esac

mapfile -t FILES < <(
  find . -path ./node_modules -prune -o -path ./.git -prune -o -type f \
    \( -name 'Dockerfile*' -o -name 'docker-compose*.yml' \) -print | sort
)

WRITE=$WRITE python3 - "${FILES[@]}" <<'PY'
import os, re, shutil, subprocess, sys

WRITE = os.environ["WRITE"] == "1"
REF = r"[A-Za-z0-9][A-Za-z0-9._/-]*"
TAG = r"[A-Za-z0-9_][A-Za-z0-9._-]*"
COMMENT = re.compile(rf"^\s*#\s*(?P<name>{REF}):(?P<tag>{TAG})\s*$")
PINNED = re.compile(rf"(?P<name>{REF})@sha256:(?P<digest>[0-9a-f]{{64}})")
PLAIN = re.compile(rf"^(?P<head>\s*(?:FROM|image:)\s+)(?P<name>{REF}):(?P<tag>{TAG})(?P<tail>(?:\s+AS\s+\S+)?\s*)$", re.I)
_cache: dict[str, str | None] = {}


def resolve(ref: str) -> str | None:
    """sha256:... of what the registry serves for name:tag, or None."""
    if ref in _cache:
        return _cache[ref]
    custom = os.environ.get("PIN_IMAGES_RESOLVE_CMD")
    commands = []
    if custom:
        commands.append(custom.split() + [ref])
    if shutil.which("docker"):
        commands.append(["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{.Manifest.Digest}}"])
    if shutil.which("crane"):
        commands.append(["crane", "digest", ref])
    if shutil.which("skopeo"):
        commands.append(["skopeo", "inspect", "--format", "{{.Digest}}", f"docker://{ref}"])
    digest = None
    for command in commands:
        try:
            out = subprocess.run(command, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            continue
        match = re.search(r"sha256:[0-9a-f]{64}", out.stdout)
        if out.returncode == 0 and match:
            digest = match.group(0)
            break
    _cache[ref] = digest
    return digest


rows, changed, problems = [], 0, 0
for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().split("\n")
    out, index, dirty = [], 0, False
    while index < len(lines):
        line = lines[index]
        comment = COMMENT.match(line)
        following = lines[index + 1] if index + 1 < len(lines) else ""
        pinned = PINNED.search(following) if comment else None
        if comment and pinned and pinned["name"] == comment["name"]:
            ref = f"{comment['name']}:{comment['tag']}"
            current = "sha256:" + pinned["digest"]
            latest = resolve(ref)
            if latest is None:
                state = "could not be resolved"
                problems += 1
            elif latest == current:
                state = "current"
            else:
                state = "BEHIND " + latest[:19]
                problems += 1
                if WRITE:
                    following = following.replace(current, latest)
                    state, dirty = "updated to " + latest[:19], True
                    problems -= 1
            rows.append((path, ref, current[:19], state))
            out += [line, following]
            index += 2
            continue
        plain = PLAIN.match(line)
        if plain and not line.lstrip().startswith("#"):
            ref = f"{plain['name']}:{plain['tag']}"
            latest = resolve(ref)
            problems += 1
            state = "NOT PINNED" + ("" if latest else " (and could not be resolved)")
            if WRITE and latest:
                indent = re.match(r"\s*", line).group(0)
                out.append(f"{indent}# {ref}")
                line = f"{plain['head']}{plain['name']}@{latest}{plain['tail']}"
                state, dirty = "pinned to " + latest[:19], True
                problems -= 1
            rows.append((path, ref, "-", state))
        out.append(line)
        index += 1
    if dirty:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(out))
        changed += 1

width = max((len(r[0]) for r in rows), default=4)
for path, ref, current, state in rows:
    print(f"{path:{width}}  {ref:36} {current:20} {state}")
print()
if WRITE:
    print(f"{changed} file(s) rewritten. Review with `git diff` before committing.")
if problems:
    print(f"{problems} reference(s) unpinned, behind or unresolved.")
sys.exit(1 if problems else 0)
PY
