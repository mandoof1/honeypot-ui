"""What a file is, from its bytes rather than its name.

An attacker names a Mirai build ``update.sh`` and a shell script ``x86``; the
extension is the one field guaranteed not to be evidence. Identification uses
magic numbers first and content heuristics second, and says which it used.
"""

from __future__ import annotations

import re
import struct
from dataclasses import asdict, dataclass

_SHEBANG = re.compile(rb"^#!\s*(\S+)(?:\s+(\S+))?")
_SSH_KEY = re.compile(
    rb"^(?:[^\n]*\s)?(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com)\s+AAAA",
    re.MULTILINE,
)
_CRON_LINE = re.compile(rb"^\s*(?:@(?:reboot|hourly|daily|weekly|monthly|yearly)|[\d*/,-]+\s+[\d*/,-]+\s+[\d*/,-]+\s+[\d*/,-]+\s+[\d*/,-]+)\s+\S", re.MULTILINE)

_SCRIPT_HINTS = [
    ("php", re.compile(rb"<\?(?:php|=)", re.IGNORECASE)),
    ("jsp", re.compile(rb"<%[@!=]?\s*(?:page|import|Runtime|request\.)", re.IGNORECASE)),
    ("asp", re.compile(rb"<%@?\s*(?:Page|Language)\s*=|Server\.CreateObject|eval\s*\(\s*Request", re.IGNORECASE)),
    ("powershell", re.compile(rb"(?:Invoke-(?:Expression|WebRequest)|IEX\s*\(|\$env:|New-Object\s+Net\.WebClient|-EncodedCommand)", re.IGNORECASE)),
    ("python", re.compile(rb"^(?:import \w|from \w+ import |def \w+\(|if __name__ == )", re.MULTILINE)),
    ("perl", re.compile(rb"^(?:use (?:strict|warnings|IO::Socket|Socket)|my \$\w+\s*=)", re.MULTILINE)),
    ("sh", re.compile(rb"^\s*(?:cd |wget |curl |chmod |echo |rm -|export |for \w+ in |if \[|busybox |nohup |crontab |killall |pkill )", re.MULTILINE)),
    ("javascript", re.compile(rb"(?:function\s*\(|document\.|window\.|require\(['\"]child_process)")),
]

_INTERPRETERS = {
    "sh": "sh", "bash": "sh", "dash": "sh", "ash": "sh", "zsh": "sh", "ksh": "sh",
    "python": "python", "python2": "python", "python3": "python",
    "perl": "perl", "php": "php", "ruby": "ruby", "node": "javascript",
}


@dataclass
class FileType:
    #: Broad class the rest of the analyser dispatches on.
    kind: str
    #: Human-readable label.
    label: str
    mime: str
    #: For scripts, the language; for archives, the container format.
    subtype: str = ""
    #: How the type was determined: "magic" or "heuristic".
    basis: str = "magic"

    def as_dict(self) -> dict:
        return asdict(self)


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:65536]
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample)


def _is_text(data: bytes) -> bool:
    if b"\x00" in data[:8192]:
        return False
    if printable_ratio(data) >= 0.92:
        return True
    try:
        data[:65536].decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def identify(data: bytes) -> FileType:
    if not data:
        return FileType("empty", "Empty file", "application/x-empty")

    head = data[:512]

    if head.startswith(b"\x7fELF"):
        return FileType("elf", "ELF executable", "application/x-executable")

    if head.startswith(b"MZ"):
        if len(data) >= 0x40:
            (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
            if 0 < pe_offset < len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                return FileType("pe", "Windows PE executable", "application/vnd.microsoft.portable-executable")
        return FileType("dos", "DOS executable", "application/x-dosexec")

    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return FileType("macho", "Mach-O executable", "application/x-mach-binary")

    if head.startswith(b"\xca\xfe\xba\xbe") and len(data) >= 8:
        # Shared by Java class files and fat Mach-O: a fat header counts
        # architectures (a handful), a class file stores its version there.
        (value,) = struct.unpack_from(">I", data, 4)
        if value < 32:
            return FileType("macho", "Mach-O universal binary", "application/x-mach-binary")
        return FileType("java", "Java class file", "application/java-vm")

    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        if b"AndroidManifest.xml" in data[:65536]:
            return FileType("archive", "Android package (APK)", "application/vnd.android.package-archive", "zip")
        if b"META-INF/MANIFEST.MF" in data[:65536]:
            return FileType("archive", "Java archive (JAR)", "application/java-archive", "zip")
        return FileType("archive", "ZIP archive", "application/zip", "zip")
    if head.startswith(b"\x1f\x8b"):
        return FileType("archive", "gzip compressed data", "application/gzip", "gzip")
    if head.startswith(b"BZh"):
        return FileType("archive", "bzip2 compressed data", "application/x-bzip2", "bzip2")
    if head.startswith(b"\xfd7zXZ\x00"):
        return FileType("archive", "xz compressed data", "application/x-xz", "xz")
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return FileType("archive", "7-Zip archive", "application/x-7z-compressed", "7z")
    if head.startswith(b"Rar!\x1a\x07"):
        return FileType("archive", "RAR archive", "application/vnd.rar", "rar")
    if len(data) > 262 and data[257:262] == b"ustar":
        return FileType("archive", "tar archive", "application/x-tar", "tar")

    if head.startswith(b"%PDF"):
        return FileType("document", "PDF document", "application/pdf")
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return FileType("document", "OLE compound document (legacy Office)", "application/x-ole-storage")

    for magic, label, mime in (
        (b"\x89PNG\r\n\x1a\n", "PNG image", "image/png"),
        (b"\xff\xd8\xff", "JPEG image", "image/jpeg"),
        (b"GIF87a", "GIF image", "image/gif"),
        (b"GIF89a", "GIF image", "image/gif"),
    ):
        if head.startswith(magic):
            # A valid image carrying PHP is the classic upload-filter bypass.
            if re.search(rb"<\?(?:php|=)", data, re.IGNORECASE):
                return FileType("script", f"{label} with embedded PHP (polyglot)", "application/x-httpd-php", "php")
            return FileType("image", label, mime)

    shebang = _SHEBANG.match(data)
    if shebang:
        interpreter = shebang.group(1).decode("latin-1").rsplit("/", 1)[-1]
        if interpreter == "env" and shebang.group(2):
            interpreter = shebang.group(2).decode("latin-1")
        language = _INTERPRETERS.get(re.sub(r"[\d.]+$", "", interpreter), interpreter)
        return FileType("script", f"{language} script", f"text/x-{language}", language)

    if _is_text(data):
        sample = data[:262144]
        if _SSH_KEY.search(sample):
            return FileType("ssh_key", "SSH public key list (authorized_keys)", "text/plain", "authorized_keys", "heuristic")
        for language, pattern in _SCRIPT_HINTS:
            if pattern.search(sample):
                return FileType("script", f"{language} script", f"text/x-{language}", language, "heuristic")
        if _CRON_LINE.search(sample):
            return FileType("script", "crontab", "text/plain", "crontab", "heuristic")
        return FileType("text", "Text", "text/plain", basis="heuristic")

    return FileType("data", "Binary data", "application/octet-stream", basis="heuristic")
