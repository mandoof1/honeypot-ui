"""Look inside archives, within strict bounds.

Attackers deliver multi-file payloads as archives — a JAR, an APK, a tarball
of a miner plus its config plus a persistence unit. Listing the members and
recursing one level into them recovers far more than treating the container as
one opaque blob.

Archives are also the classic decompression-bomb vector, so every limit here
is a refusal, not a best effort: total uncompressed size, member count, and a
compression ratio past which extraction stops. Nothing is written to disk;
members are read into bounded memory buffers and handed back for one more pass
of the analyser.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile

MAX_MEMBERS = 500
MAX_TOTAL_UNCOMPRESSED = 128 * 1024 * 1024
MAX_MEMBER_SIZE = 32 * 1024 * 1024
#: Uncompressed-to-compressed ratio past which a container is treated as a bomb.
MAX_RATIO = 300


def analyse(data: bytes, container: str) -> dict:
    try:
        if container == "zip":
            return _zip(data)
        if container in ("gzip", "bzip2", "xz"):
            return _single_stream(data, container)
        if container == "tar":
            return _tar(tarfile.open(fileobj=io.BytesIO(data)))
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, ValueError) as exc:
        return {"container": container, "error": f"Could not read archive: {exc}"[:200], "members": []}
    return {"container": container, "members": [], "note": "container not recursed"}


def _record(members, total, name, size, extra=None):
    entry = {"name": name[:255], "size": size}
    if extra:
        entry.update(extra)
    members.append(entry)
    return total + size


def _zip(data: bytes) -> dict:
    members: list[dict] = []
    extracted: list[tuple[str, bytes]] = []
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()[:MAX_MEMBERS]
        for info in infos:
            if info.is_dir():
                continue
            entry = {"encrypted": bool(info.flag_bits & 0x1)}
            if info.compress_size and info.file_size / max(info.compress_size, 1) > MAX_RATIO:
                entry["note"] = "compression ratio exceeds bomb threshold; not extracted"
                total = _record(members, total, info.filename, info.file_size, entry)
                continue
            if info.file_size > MAX_MEMBER_SIZE or total + info.file_size > MAX_TOTAL_UNCOMPRESSED:
                entry["note"] = "over size budget; not extracted"
                total = _record(members, total, info.filename, info.file_size, entry)
                continue
            total = _record(members, total, info.filename, info.file_size, entry)
            if not entry["encrypted"]:
                try:
                    extracted.append((info.filename, archive.read(info)))
                except (RuntimeError, zipfile.BadZipFile):
                    entry["note"] = "could not extract"
    return {"container": "zip", "member_count": len(members), "members": members, "_extracted": extracted}


def _tar(archive: tarfile.TarFile) -> dict:
    members: list[dict] = []
    extracted: list[tuple[str, bytes]] = []
    total = 0
    with archive:
        for member in archive:
            if len(members) >= MAX_MEMBERS:
                break
            if not member.isfile():
                continue
            entry = {}
            if member.size > MAX_MEMBER_SIZE or total + member.size > MAX_TOTAL_UNCOMPRESSED:
                entry["note"] = "over size budget; not extracted"
                total = _record(members, total, member.name, member.size, entry)
                continue
            total = _record(members, total, member.name, member.size, entry)
            try:
                handle = archive.extractfile(member)
                if handle is not None:
                    extracted.append((member.name, handle.read(MAX_MEMBER_SIZE)))
            except (tarfile.TarError, OSError):
                entry["note"] = "could not extract"
    return {"container": "tar", "member_count": len(members), "members": members, "_extracted": extracted}


def _single_stream(data: bytes, container: str) -> dict:
    decompressor = {"gzip": gzip.decompress, "bzip2": bz2.decompress, "xz": lzma.decompress}[container]
    try:
        raw = decompressor(data)
    except (OSError, EOFError, lzma.LZMAError) as exc:
        return {"container": container, "error": f"Could not decompress: {exc}"[:200], "members": []}
    if len(raw) > MAX_TOTAL_UNCOMPRESSED:
        return {"container": container, "error": "decompressed size exceeds budget", "members": []}
    # A .tar.gz decompresses to a tar; recurse so its members are listed.
    if raw[257:262] == b"ustar":
        inner = _tar(tarfile.open(fileobj=io.BytesIO(raw)))
        inner["container"] = f"{container}+tar"
        return inner
    return {
        "container": container, "member_count": 1,
        "members": [{"name": "(stream)", "size": len(raw)}],
        "_extracted": [("(decompressed)", raw)],
    }


def summary(info: dict) -> str:
    if "error" in info:
        return f"{info['container']} archive (unreadable)"
    return f"{info['container']} archive, {info.get('member_count', 0)} file(s)"
