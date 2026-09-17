"""Read a captured script the way an analyst would, then a layer deeper.

Loader scripts are the most common upload an SSH honeypot sees, and the most
immediately readable: they name the next-stage host, the architectures the
operator built for, the competitors they kill, and how they persist. This
unwraps the obfuscation first — reusing the backend's own recursive decoder,
so ``base64 -d | sh`` blobs and ``\\xNN`` tables are read, not just noted —
and then matches behaviour over the original text and every decoded layer.

Static only: the script is never executed and no host it names is contacted.
"""

from __future__ import annotations

import re

from app.ai.deobfuscate import deobfuscate
from app.payloads import indicators

MAX_TEXT = 2 * 1024 * 1024

#: (id, label, ATT&CK id, ATT&CK name, pattern). Ordered roughly by the stage
#: of an intrusion they belong to.
BEHAVIOURS = [
    ("download", "Downloads a further stage", "T1105", "Ingress Tool Transfer",
     re.compile(r"\b(?:wget|curl|tftp|ftpget|(?:s)?ftp)\b|\bInvoke-WebRequest\b|\bcertutil\b.*-urlcache", re.IGNORECASE)),
    ("multi_arch", "Fetches multiple CPU architectures", "T1105", "Ingress Tool Transfer",
     re.compile(r"(?:mips(?:el)?|arm(?:v[4-7]l?|64)?|x86_?64|i[356]86|sh4|ppc|sparc|m68k|arc)\b.*(?:mips(?:el)?|arm|x86|i[356]86|sh4|ppc|sparc|m68k|arc)\b", re.IGNORECASE | re.DOTALL)),
    ("make_executable", "Marks a file executable", "T1222.002", "Linux and Mac File and Directory Permissions Modification",
     re.compile(r"\bchmod\s+(?:\+x|[0-7]*[157][0-7]*)\b", re.IGNORECASE)),
    ("execute", "Runs a downloaded file", "T1059.004", "Unix Shell",
     re.compile(r"(?:\./|/tmp/|/var/run/|/dev/shm/)\S+|\bsh\s+-c\b|\|\s*(?:ba)?sh\b", re.IGNORECASE)),
    ("cron_persistence", "Persists via cron", "T1053.003", "Scheduled Task/Job: Cron",
     re.compile(r"\bcrontab\b|/etc/cron|/var/spool/cron", re.IGNORECASE)),
    ("systemd_persistence", "Persists via systemd or init", "T1543.002", "Create or Modify System Process: Systemd Service",
     re.compile(r"systemctl|/etc/systemd/system|/etc/init\.d/|/etc/rc\.local|update-rc\.d", re.IGNORECASE)),
    ("ssh_key_persistence", "Adds an SSH authorized_key", "T1098.004", "SSH Authorized Keys",
     re.compile(r"authorized_keys|\.ssh/authorized", re.IGNORECASE)),
    ("defense_evasion", "Clears history or logs", "T1070", "Indicator Removal",
     re.compile(r"history\s+-c|HISTFILE|/dev/null\s*$|>\s*/var/log/|\brm\s+-rf?\b.*(?:\.bash_history|/var/log)", re.IGNORECASE | re.MULTILINE)),
    ("disable_security", "Disables firewall or security tooling", "T1562.001", "Impair Defenses",
     re.compile(r"\b(?:iptables\s+-F|ufw\s+disable|setenforce\s+0|systemctl\s+(?:stop|disable)\s+(?:firewalld|apparmor)|service\s+\w*(?:firewall|iptables)\w*\s+stop)\b", re.IGNORECASE)),
    ("kill_competitors", "Kills rival malware or miners", "T1489", "Service Stop",
     re.compile(r"\b(?:pkill|killall|kill)\b.*(?:kinsing|kdevtmpfsi|xmrig|\.xmr|kworker|xmr-stak|minerd|watchdog)|/proc/\d+.*rm", re.IGNORECASE)),
    ("mining", "Runs or configures a cryptominer", "T1496", "Resource Hijacking",
     re.compile(r"\bxmrig\b|stratum\+tcp|--donate-level|minerd|cpuminer|\bnanopool\b|\bsupportxmr\b|--coin\s+monero", re.IGNORECASE)),
    ("credential_access", "Reads credential files", "T1552.001", "Unsecured Credentials: Credentials In Files",
     re.compile(r"/etc/shadow|\.aws/credentials|\.ssh/id_(?:rsa|ed25519)|/etc/passwd\b", re.IGNORECASE)),
    ("discovery", "Enumerates the host", "T1082", "System Information Discovery",
     re.compile(r"\b(?:uname\s+-|/proc/cpuinfo|nproc|lscpu|cat\s+/etc/os-release|whoami|id\b)", re.IGNORECASE)),
    ("lateral_movement", "Scans or spreads to other hosts", "T1021", "Remote Services",
     re.compile(r"\b(?:sshpass|hydra|masscan|zmap|pnscan|\.ssh/known_hosts)\b|for\s+.*in.*sshd?", re.IGNORECASE)),
    ("anti_analysis", "Checks for a sandbox or VM", "T1497", "Virtualization/Sandbox Evasion",
     re.compile(r"/sys/class/dmi|VMware|VirtualBox|QEMU|hypervisor|/\.dockerenv", re.IGNORECASE)),
    ("shell_persistence", "Writes to a shell profile", "T1546.004", "Unix Shell Configuration Modification",
     re.compile(r"\.bashrc|\.bash_profile|/etc/profile\.d/|\.zshrc", re.IGNORECASE)),
]

_DEFANG = [
    (re.compile(r"\[\.\]"), "."), (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\[?hxxp", re.IGNORECASE), "http"), (re.compile(r"\[:\]"), ":"),
]


def _refang(text: str) -> str:
    for pattern, replacement in _DEFANG:
        text = pattern.sub(replacement, text)
    return text


def analyse(data: bytes, language: str = "") -> dict:
    text = data[:MAX_TEXT].decode("utf-8", errors="replace")

    decoded = deobfuscate(_refang(text))
    layers = decoded.as_dict()
    combined = decoded.combined

    behaviours = []
    for rule_id, label, tid, tname, pattern in BEHAVIOURS:
        match = pattern.search(combined)
        if match:
            behaviours.append({
                "id": rule_id, "label": label,
                "technique": {"id": tid, "name": tname},
                "evidence": match.group(0).strip()[:160],
            })

    # Indicators over the original and each decoded layer, so the origin field
    # shows an address that was only reachable after base64-decoding.
    sources = [(text, "script")]
    for layer in decoded.layers:
        sources.append((layer.decoded, f"decoded:{layer.encoding}"))
    found = indicators.extract(sources)

    return {
        "language": language,
        "line_count": text.count("\n") + 1,
        "obfuscation": {
            "layers": layers["layer_count"],
            "max_depth": layers["max_depth"],
            "encodings": layers["encodings"],
        },
        "behaviours": behaviours,
        "indicators": found,
        "indicator_count": indicators.count(found),
    }


def summary(info: dict) -> str:
    language = info.get("language") or "shell"
    behaviours = len(info.get("behaviours", []))
    if info["obfuscation"]["layers"]:
        return f"{language} script, {info['obfuscation']['layers']} obfuscation layer(s), {behaviours} behaviour(s)"
    return f"{language} script, {behaviours} behaviour(s)"
