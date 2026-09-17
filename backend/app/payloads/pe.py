"""PE internals: what a Windows binary imports and what its build left behind.

Windows payloads on a Linux honeypot are mostly webshell uploads and spray
from scanners that do not check the target, but they carry more attribution
than any other format: a CodeView debug record naming the PDB path on the
author's machine (often under ``C:\\Users\\<name>``), version resources the
author filled in, a Rich header fingerprinting the exact Visual Studio build
environment, and a compile timestamp. All of it is forgeable and reported as
such; the Rich hash and imphash in particular are for linking samples to each
other, not to a person.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pefile

from app.payloads import bytestats

MAX_IMPORTS = 600
MAX_EXPORTS = 100
MAX_SECTIONS = 32

_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x1C4: "ARMv7 Thumb"}
_SUBSYSTEMS = {1: "native", 2: "GUI", 3: "console", 9: "Windows CE", 10: "EFI application", 16: "boot application"}

#: Import combinations that mean something, each mapped to ATT&CK.
CAPABILITY_RULES = [
    ("process_injection", "Process injection", {"VirtualAllocEx", "WriteProcessMemory"}, {"CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext"}, ("T1055", "Process Injection")),
    ("downloader", "Downloads files", {"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA", "InternetOpenUrlW", "WinHttpOpenRequest", "HttpSendRequestA", "HttpSendRequestW"}, set(), ("T1105", "Ingress Tool Transfer")),
    ("registry_persistence", "Writes the registry", {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"}, set(), ("T1112", "Modify Registry")),
    ("service_persistence", "Creates services", {"CreateServiceA", "CreateServiceW"}, set(), ("T1543.003", "Create or Modify System Process: Windows Service")),
    ("anti_debug", "Detects debuggers", {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"}, set(), ("T1622", "Debugger Evasion")),
    ("keylogging", "Captures keystrokes", {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState"}, set(), ("T1056.001", "Input Capture: Keylogging")),
    ("screen_capture", "Captures the screen", {"BitBlt"}, {"GetDC", "GetWindowDC", "CreateCompatibleBitmap"}, ("T1113", "Screen Capture")),
    ("clipboard", "Reads the clipboard", {"GetClipboardData"}, set(), ("T1115", "Clipboard Data")),
    ("token_manipulation", "Adjusts token privileges", {"AdjustTokenPrivileges", "ImpersonateLoggedOnUser", "DuplicateTokenEx"}, set(), ("T1134", "Access Token Manipulation")),
    ("crypto", "Uses cryptographic APIs", {"CryptEncrypt", "BCryptEncrypt", "CryptAcquireContextA", "CryptAcquireContextW"}, set(), ("T1027", "Obfuscated Files or Information")),
    ("execution", "Starts processes", {"CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW"}, set(), ("T1106", "Native API")),
]


def analyse(data: bytes) -> dict:
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        return {"error": f"Not a parseable PE: {exc}"[:300]}

    errors: list[str] = []
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
        ])
    except Exception as exc:
        errors.append(f"data directories: {exc}"[:200])

    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    timestamp = fh.TimeDateStamp
    compiled = None
    timestamp_note = None
    if timestamp:
        compiled_dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        compiled = compiled_dt.isoformat()
        if compiled_dt > datetime.now(timezone.utc):
            timestamp_note = "in the future: forged, or a reproducible-build hash"
        elif compiled_dt.year < 2000:
            timestamp_note = "before 2000: almost certainly forged or zeroed by the toolchain"

    directories = oh.DATA_DIRECTORY
    info: dict = {
        "architecture": _MACHINES.get(fh.Machine, hex(fh.Machine)),
        "bits": 64 if oh.Magic == 0x20B else 32,
        "is_dll": bool(fh.Characteristics & 0x2000),
        "subsystem": _SUBSYSTEMS.get(oh.Subsystem, str(oh.Subsystem)),
        "entry_point": hex(oh.AddressOfEntryPoint),
        "compile_time": compiled,
        "compile_time_note": timestamp_note,
        "dotnet": len(directories) > 14 and directories[14].VirtualAddress != 0,
        "signed": len(directories) > 4 and directories[4].Size > 0,
        "sections": [],
        "imports": {},
        "exports": [],
        "imphash": None,
        "rich_hash": None,
        "pdb_path": None,
        "version_info": {},
        "tls_callbacks": hasattr(pe, "DIRECTORY_ENTRY_TLS"),
        "overlay": None,
        "capabilities": [],
    }

    for section in pe.sections[:MAX_SECTIONS]:
        characteristics = section.Characteristics
        info["sections"].append({
            "name": section.Name.rstrip(b"\x00").decode("latin-1", errors="replace"),
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": bytestats.rounded(section.get_entropy()),
            "writable_and_executable": bool(characteristics & 0x80000000 and characteristics & 0x20000000),
        })

    count = 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("latin-1", errors="replace") if entry.dll else "?"
        names = []
        for imp in entry.imports:
            if count >= MAX_IMPORTS:
                break
            names.append(imp.name.decode("latin-1", errors="replace") if imp.name else f"ordinal_{imp.ordinal}")
            count += 1
        info["imports"][dll] = names
    try:
        info["imphash"] = pe.get_imphash() or None
    except Exception:
        pass

    exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exports:
        info["exports"] = [
            s.name.decode("latin-1", errors="replace") for s in exports.symbols[:MAX_EXPORTS] if s.name
        ]

    try:
        rich = pe.parse_rich_header()
        if rich:
            info["rich_hash"] = pe.get_rich_header_hash()
    except Exception:
        pass

    for debug in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        entry = getattr(debug, "entry", None)
        path = getattr(entry, "PdbFileName", None)
        if path:
            info["pdb_path"] = path.rstrip(b"\x00").decode("utf-8", errors="replace")[:260]
            break

    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        for file_info in getattr(pe, "FileInfo", []) or []:
            for block in file_info:
                for table in getattr(block, "StringTable", []) or []:
                    for key, value in table.entries.items():
                        name = key.decode("latin-1", errors="replace")
                        text = value.decode("utf-8", errors="replace").strip()
                        if text:
                            info["version_info"][name] = text[:200]
    except Exception as exc:
        errors.append(f"version info: {exc}"[:200])

    try:
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset:
            overlay = data[overlay_offset:]
            info["overlay"] = {
                "offset": overlay_offset,
                "size": len(overlay),
                "entropy": bytestats.rounded(bytestats.entropy(overlay[:8 * 1024 * 1024])),
                "embedded_pe": overlay[:2] == b"MZ",
            }
    except Exception:
        pass

    imported = {name for names in info["imports"].values() for name in names}
    for rule_id, label, any_of, also_one_of, technique in CAPABILITY_RULES:
        if imported & any_of and (not also_one_of or imported & also_one_of):
            info["capabilities"].append({
                "id": rule_id, "label": label,
                "evidence": sorted(imported & (any_of | also_one_of))[:6],
                "technique": {"id": technique[0], "name": technique[1]},
            })

    info["packer"] = _packer(info)
    if errors:
        info["errors"] = errors
    pe.close()
    return info


def _packer(info: dict) -> dict | None:
    names = {s["name"] for s in info["sections"]}
    if names & {"UPX0", "UPX1"}:
        return {"name": "UPX", "evidence": ["UPX section names"]}
    for marker, packer in ((".aspack", "ASPack"), (".MPRESS1", "MPRESS"), (".themida", "Themida"), (".vmp0", "VMProtect"), (".petite", "Petite")):
        if marker in names:
            return {"name": packer, "evidence": [f"{marker} section"]}
    import_count = sum(len(v) for v in info["imports"].values())
    high = [s for s in info["sections"] if s["entropy"] >= 7.2 and s["raw_size"] > 4096]
    if high and import_count < 10:
        return {"name": None, "evidence": [f"{len(high)} high-entropy section(s) and only {import_count} import(s)"]}
    return None


def summary(info: dict) -> str:
    if "error" in info:
        return "PE (unparseable headers)"
    kind = ".NET assembly" if info["dotnet"] else ("DLL" if info["is_dll"] else "executable")
    return f"{info['bits']}-bit {info['architecture']} Windows {kind} ({info['subsystem']})"
