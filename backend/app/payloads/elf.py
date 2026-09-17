"""ELF internals: what a Linux binary targets and what it was built with.

The architecture alone is informative on a honeypot: an SSH box running
x86-64 that receives MIPS, ARM and SuperH builds of the same file is being hit
by an IoT botnet loader that sprays every architecture it has.

The build fingerprints — compiler identification, Go module paths, Rust
toolchain commits, build IDs and paths left in the binary — are the closest
thing a stripped binary carries to a signature from whoever compiled it. Each
is reported as a clue with a caveat, never as an identification: every one of
them can be forged.
"""

from __future__ import annotations

import io
import re

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection, SymbolTableSection

from app.payloads import bytestats

MAX_SECTIONS = 64
MAX_SYMBOLS = 300
MAX_SECTION_ENTROPY_BYTES = 8 * 1024 * 1024

_MACHINES = {
    "EM_386": "x86", "EM_X86_64": "x86-64", "EM_ARM": "ARM", "EM_AARCH64": "ARM64",
    "EM_MIPS": "MIPS", "EM_MIPS_RS3_LE": "MIPS", "EM_PPC": "PowerPC",
    "EM_PPC64": "PowerPC64", "EM_SPARC": "SPARC", "EM_SPARCV9": "SPARC64",
    "EM_SH": "SuperH", "EM_68K": "m68k", "EM_RISCV": "RISC-V", "EM_ARC": "ARC",
    "EM_ARC_COMPACT": "ARC", "EM_S390": "s390",
}

#: Imported functions that each say something about capability.
_CAPABILITY_IMPORTS = {
    "network": {"socket", "connect", "bind", "listen", "accept", "sendto", "recvfrom", "gethostbyname", "getaddrinfo", "inet_addr"},
    "process": {"fork", "execve", "execl", "execvp", "system", "popen", "daemon", "setsid", "kill"},
    "anti_debug": {"ptrace", "prctl"},
    "filesystem": {"unlink", "rename", "chmod", "opendir", "readdir", "readlink"},
    "raw_sockets": {"sendmsg", "setsockopt"},
}

_GO_VERSION = re.compile(rb"go1\.\d{1,2}(?:\.\d{1,2})?")
_GO_MODULE = re.compile(rb"(?:path|mod)\t([\w.\-]+\.[a-z]{2,}/[\w.\-/]+)")
_RUSTC = re.compile(rb"/rustc/([0-9a-f]{40})/")


def analyse(data: bytes) -> dict:
    try:
        elf = ELFFile(io.BytesIO(data))
    except (ELFError, ValueError, OSError, IndexError) as exc:
        return {"error": f"Not a parseable ELF: {exc}"[:300]}

    header = elf.header
    machine = _MACHINES.get(header["e_machine"], str(header["e_machine"]).removeprefix("EM_"))
    little = elf.little_endian
    if machine == "MIPS":
        machine = "MIPS (little-endian)" if little else "MIPS (big-endian)"

    info: dict = {
        "architecture": machine,
        "bits": elf.elfclass,
        "endianness": "little" if little else "big",
        "type": str(header["e_type"]).removeprefix("ET_"),
        "os_abi": str(header["e_ident"]["EI_OSABI"]).removeprefix("ELFOSABI_"),
        "entry_point": hex(header["e_entry"]),
        "sections": [],
        "libraries": [],
        "imports": [],
        "capabilities": [],
        "interpreter": None,
        "linking": "static",
        "stripped": True,
        "rwx_segments": 0,
        "build": {},
        "errors": [],
    }

    try:
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_INTERP":
                info["interpreter"] = segment.get_interpreter()
                info["linking"] = "dynamic"
            flags = segment["p_flags"]
            if segment["p_type"] == "PT_LOAD" and flags & 0x1 and flags & 0x2:
                info["rwx_segments"] += 1
    except Exception as exc:  # malformed program headers are common in packed samples
        info["errors"].append(f"program headers: {exc}"[:200])

    imports: set[str] = set()
    try:
        for index, section in enumerate(elf.iter_sections()):
            if index >= MAX_SECTIONS:
                break
            name = section.name or ""
            size = section["sh_size"]
            entry = {"name": name, "size": size}
            if section["sh_type"] != "SHT_NOBITS" and 0 < size <= MAX_SECTION_ENTROPY_BYTES:
                try:
                    entry["entropy"] = bytestats.rounded(bytestats.entropy(section.data()))
                except Exception:
                    pass
            info["sections"].append(entry)

            if name == ".symtab":
                info["stripped"] = False
            if isinstance(section, DynamicSection):
                info["linking"] = "dynamic"
                for tag in section.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        info["libraries"].append(tag.needed)
            if isinstance(section, SymbolTableSection) and name == ".dynsym":
                for symbol in section.iter_symbols():
                    if symbol["st_shndx"] == "SHN_UNDEF" and symbol.name:
                        imports.add(symbol.name.split("@")[0])
                    if len(imports) >= MAX_SYMBOLS:
                        break
            if name == ".comment":
                comment = section.data().replace(b"\x00", b"\n").decode("utf-8", errors="replace")
                compilers = sorted({line.strip() for line in comment.splitlines() if line.strip()})
                if compilers:
                    info["build"]["compiler"] = compilers[:5]
            if isinstance(section, NoteSection):
                for note in section.iter_notes():
                    if note["n_type"] == "NT_GNU_BUILD_ID":
                        info["build"]["build_id"] = note["n_desc"]
            if name in (".go.buildinfo", ".note.go.buildid", ".gopclntab"):
                info["build"]["language"] = "Go"
            if name == ".rustc":
                info["build"]["language"] = "Rust"
    except Exception as exc:
        info["errors"].append(f"sections: {exc}"[:200])

    info["imports"] = sorted(imports)
    info["capabilities"] = sorted(
        capability for capability, names in _CAPABILITY_IMPORTS.items() if names & imports
    )

    # Toolchain markers that survive stripping, read from the raw bytes.
    go_version = _GO_VERSION.search(data)
    if go_version and (info["build"].get("language") == "Go" or b"Go build ID" in data or b"runtime.main" in data):
        info["build"]["language"] = "Go"
        info["build"]["go_version"] = go_version.group(0).decode()
        modules = sorted({m.group(1).decode(errors="replace") for m in _GO_MODULE.finditer(data)})
        if modules:
            info["build"]["go_modules"] = modules[:20]
    rustc = _RUSTC.search(data)
    if rustc:
        info["build"]["language"] = "Rust"
        info["build"]["rustc_commit"] = rustc.group(1).decode()

    info["packer"] = detect_packer(data, [s["name"] for s in info["sections"]])
    if not info["errors"]:
        del info["errors"]
    return info


def detect_packer(data: bytes, section_names: list[str]) -> dict | None:
    """UPX leaves its section names and a magic; most other packers do not."""
    evidence = []
    if any(name in ("UPX0", "UPX1", "UPX2", "UPX!") for name in section_names):
        evidence.append("UPX section names")
    if b"UPX!" in data[:4096] or b"UPX!" in data[-4096:]:
        evidence.append("UPX! magic")
    if b"$Info: This file is packed with the UPX" in data:
        evidence.append("UPX info string")
    if evidence:
        return {"name": "UPX", "evidence": evidence}
    return None


def summary(info: dict) -> str:
    if "error" in info:
        return "ELF (unparseable headers)"
    parts = [f"{info['bits']}-bit {info['architecture']} ELF {info['type'].lower()}"]
    parts.append(f"{info['linking']}ally linked")
    if info.get("stripped"):
        parts.append("stripped")
    return ", ".join(parts)
