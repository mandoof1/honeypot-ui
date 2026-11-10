"""What a command does, read from the command itself.

The rule tables of the analysis layer. Each recorded line has already been
turned into simple commands (``shell_parse``); this decides what each one is
evidence of. A rule looks at the program in command position and its
arguments, never at a word that merely occurs in the text, so a comment, an
``echo`` or a file name that happens to contain ``nmap`` is not a finding.

A finding carries the furthest stage it supports on the pipeline's four-class
scale, plus the tool/category/intent labels the console already shows. Its
key is what the ATT&CK mapper looks techniques up by (``mitre_mapper``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional

from app.ai.shell_parse import SHELLS, Command

BENIGN = "benign"
RECON = "reconnaissance"
EXPLOIT = "exploitation"
EXFIL = "exfiltration"

STAGE_RANK = {BENIGN: 0, RECON: 1, EXPLOIT: 2, EXFIL: 3}


@dataclass(frozen=True)
class Finding:
    key: str
    stage: str
    #: Labels kept for the console and the exports: the tool name and its
    #: category, and the intent the action serves.
    tool: str = ""
    tool_category: str = ""
    intent: str = ""
    #: An offensive framework whose use alone raises the severity.
    critical: bool = False


F = Finding

# -- findings ---------------------------------------------------------------
# Discovery: the session only looked.
SYSTEM_INFO = F("system_info", RECON, "enum_linux", "reconnaissance", "reconnaissance")
USER_DISCOVERY = F("user_discovery", RECON, "enum_linux", "reconnaissance", "reconnaissance")
ACCOUNT_DISCOVERY = F("account_discovery", RECON, "enum_linux", "reconnaissance", "reconnaissance")
GROUP_DISCOVERY = F("group_discovery", RECON, "enum_linux", "reconnaissance", "reconnaissance")
NETWORK_CONFIG = F("network_config", RECON, "enum_linux", "reconnaissance", "reconnaissance")
NETWORK_CONNECTIONS = F("network_connections", RECON, "enum_linux", "reconnaissance", "reconnaissance")
PROCESS_DISCOVERY = F("process_discovery", RECON, "enum_linux", "reconnaissance", "reconnaissance")
SERVICE_DISCOVERY = F("service_discovery", RECON, "enum_linux", "reconnaissance", "reconnaissance")
FILE_DISCOVERY = F("file_discovery", RECON, "", "", "reconnaissance")
SCHEDULED_TASK_DISCOVERY = F("scheduled_task_discovery", RECON, "", "", "reconnaissance")
SHELL_HISTORY_READ = F("shell_history_read", RECON, "", "", "reconnaissance")
SUDO_LIST = F("sudo_list", RECON, "enum_linux", "reconnaissance", "privilege_escalation")
SUDO_EXEC = F("sudo_exec", RECON, "", "", "privilege_escalation")
SUID_SEARCH = F("suid_search", RECON, "", "", "privilege_escalation")
CREDENTIAL_SEARCH = F("credential_search", RECON, "", "", "credential_harvesting")
WINDOWS_SYSTEM_INFO = F("windows_system_info", RECON, "enum_windows", "reconnaissance", "reconnaissance")
WINDOWS_ACCOUNT_DISCOVERY = F("windows_account_discovery", RECON, "enum_windows", "reconnaissance", "reconnaissance")
WINDOWS_GROUP_DISCOVERY = F("windows_group_discovery", RECON, "enum_windows", "reconnaissance", "reconnaissance")
WINDOWS_NETWORK_CONFIG = F("windows_network_config", RECON, "enum_windows", "reconnaissance", "reconnaissance")
PORT_SCAN = F("port_scan", RECON, "nmap", "scanner", "reconnaissance")
DIR_ENUM_TOOL = F("dir_enum_tool", RECON, "gobuster", "directory_enum", "reconnaissance")
VULN_SCAN_TOOL = F("vuln_scan_tool", RECON, "nikto", "vulnerability_scanner", "reconnaissance")
NETWORK_SNIFF = F("network_sniff", RECON, "", "", "reconnaissance")
IOT_BOT_PROBE = F("iot_bot_probe", RECON, "busybox_bot", "iot_botnet", "botnet")

# Marked for the analyst, without moving the category on their own.
REMOTE_FETCH = F("remote_fetch", BENIGN)
NETCAT = F("netcat", BENIGN, "netcat", "network_utility")
DECODE = F("decode", BENIGN)
INTERPRETER_INLINE = F("interpreter_inline", BENIGN)
NAMED_PIPE = F("named_pipe", BENIGN)

# Gaining, extending or keeping control.
DOWNLOAD = F("download", EXPLOIT, "wget_curl", "file_download")
DOWNLOAD_EXECUTE = F("download_execute", EXPLOIT, "wget_curl", "file_download")
IOT_BOT_DOWNLOAD = F("iot_bot_download", EXPLOIT, "busybox_bot", "iot_botnet", "botnet")
DECODE_EXECUTE = F("decode_execute", EXPLOIT)
PIPE_TO_SHELL = F("pipe_to_shell", EXPLOIT)
RUN_DROPPED_FILE = F("run_dropped_file", EXPLOIT)
MAKE_EXECUTABLE = F("make_executable", EXPLOIT, "chmod_chown", "privilege_modification")
SETUID = F("setuid", EXPLOIT, "chmod_chown", "privilege_modification", "privilege_escalation")
IMMUTABLE_FLAG = F("immutable_flag", EXPLOIT, "persistence", "persistence", "persistence")
REVERSE_SHELL = F("reverse_shell", EXPLOIT, "reverse_shell", "reverse_shell")
NETCAT_LISTEN = F("netcat_listen", EXPLOIT, "netcat", "network_utility")
CRON_PERSIST = F("cron_persist", EXPLOIT, "persistence", "persistence", "persistence")
SERVICE_PERSIST = F("service_persist", EXPLOIT, "persistence", "persistence", "persistence")
BOOT_PERSIST = F("boot_persist", EXPLOIT, "persistence", "persistence", "persistence")
SHELL_PROFILE_PERSIST = F("shell_profile_persist", EXPLOIT, "persistence", "persistence", "persistence")
SSH_KEY_PERSIST = F("ssh_key_persist", EXPLOIT, "persistence", "persistence", "persistence")
PRELOAD_HIJACK = F("preload_hijack", EXPLOIT, "persistence", "persistence", "persistence")
ACCOUNT_CREATE = F("account_create", EXPLOIT, "", "", "persistence")
ACCOUNT_MODIFY = F("account_modify", EXPLOIT, "", "", "persistence")
SWITCH_USER = F("switch_user", EXPLOIT, "", "", "privilege_escalation")
PRIVESC_EXPLOIT = F("privesc_exploit", EXPLOIT, "", "", "privilege_escalation")
CREDENTIAL_DUMP = F("credential_dump", EXPLOIT, "", "", "credential_harvesting")
PRIVATE_KEY_READ = F("private_key_read", EXPLOIT, "", "", "credential_harvesting")
CREDENTIAL_FILE_READ = F("credential_file_read", EXPLOIT, "", "", "credential_harvesting")
MIMIKATZ = F("mimikatz", EXPLOIT, "mimikatz", "credential_theft", "credential_harvesting", critical=True)
PASSWORD_CRACKING = F("password_cracking", EXPLOIT, "hashcat", "password_cracker", "credential_harvesting")
PASSWORD_ATTACK_TOOL = F("password_attack_tool", EXPLOIT, "hydra", "password_cracker", "lateral_movement")
METASPLOIT = F("metasploit", EXPLOIT, "metasploit", "exploitation_framework", critical=True)
C2_FRAMEWORK = F("c2_framework", EXPLOIT, "cobalt_strike", "c2_framework", "botnet", critical=True)
EMPIRE = F("empire", EXPLOIT, "empire", "c2_framework", "botnet", critical=True)
SQLMAP = F("sqlmap", EXPLOIT, "sqlmap", "sql_injection")
REMOTE_LOGIN = F("remote_login", EXPLOIT, "lateral_movement", "lateral_movement", "lateral_movement")
REMOTE_DESKTOP = F("remote_desktop", EXPLOIT, "lateral_movement", "lateral_movement", "lateral_movement")
SMB_ACCESS = F("smb_access", EXPLOIT, "lateral_movement", "lateral_movement", "lateral_movement")
REMOTE_EXEC = F("remote_exec", EXPLOIT, "lateral_movement", "lateral_movement", "lateral_movement")
TUNNEL = F("tunnel", EXPLOIT, "lateral_movement", "lateral_movement", "lateral_movement")
HISTORY_EVASION = F("history_evasion", EXPLOIT, "", "", "defense_evasion")
LOG_CLEAR = F("log_clear", EXPLOIT, "", "", "defense_evasion")
TIMESTOMP = F("timestomp", EXPLOIT, "", "", "defense_evasion")
FIREWALL_DISABLE = F("firewall_disable", EXPLOIT, "", "", "defense_evasion")
DEFENCE_DISABLE = F("defence_disable", EXPLOIT, "", "", "defense_evasion")
SERVICE_STOP = F("service_stop", EXPLOIT, "", "", "impact")
DATA_DESTRUCTION = F("data_destruction", EXPLOIT, "", "", "impact")
ENCRYPT_FILES = F("encrypt_files", EXPLOIT, "", "", "ransomware")
DENIAL_OF_SERVICE = F("denial_of_service", EXPLOIT, "", "", "denial_of_service")
DEFACEMENT = F("defacement", EXPLOIT, "", "", "defacement")
CRYPTOMINER = F("cryptominer", EXPLOIT, "cryptominer", "cryptomining", "cryptomining")
DB_DUMP = F("db_dump", EXPLOIT, "", "", "collection")
FTP_SITE_EXEC = F("ftp_site_exec", EXPLOIT)

# Data leaving for another system.
EXFIL_UPLOAD = F("exfil_upload", EXFIL, "data_exfil", "exfiltration", "data_exfiltration")
EXFIL_NETCAT = F("exfil_netcat", EXFIL, "data_exfil", "exfiltration", "data_exfiltration")
EXFIL_COPY = F("exfil_copy", EXFIL, "data_exfil", "exfiltration", "data_exfiltration")


# -- helpers ----------------------------------------------------------------

_URL_SCHEMES = ("http://", "https://", "ftp://", "tftp://")
#: ``user@host:path`` or ``host:path``, the remote side of scp and rsync.
_REMOTE_SPEC = re.compile(r"(?:[\w.\-]{1,64}@)?[\w.\-]{1,255}:(?!//)[^\s]{0,512}")
_OCTAL_MODE = re.compile(r"[0-7]{3,4}")
_SYMBOLIC_EXEC = re.compile(r"[ugoa]{0,4}[+=][rwst]{0,4}x")
_SYMBOLIC_SETID = re.compile(r"[ugoa]{0,4}[+=][rwx]{0,3}s")

_FILE_READERS = frozenset({
    "cat", "head", "tail", "less", "more", "strings", "tac", "nl", "xxd", "od",
    "hexdump", "base64", "grep", "egrep", "awk", "sed", "cut", "sort", "cp",
    "dd", "tar", "zip", "gzip", "bzip2", "xz", "7z", "mysqldump", "pg_dump",
    "mongodump", "find",
})
_SECURITY_SERVICES = frozenset({
    "auditd", "apparmor", "selinux", "fail2ban", "rsyslog", "syslog",
    "syslog-ng", "crowdsec", "clamav", "clamav-daemon", "ossec", "wazuh-agent",
    "falco", "aide", "osqueryd", "sysmon",
})
_FIREWALL_SERVICES = frozenset({"firewalld", "ufw", "iptables", "nftables", "ip6tables"})
_TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")


def _has_flag(args: Iterable[str], *flags: str) -> bool:
    """Whether any of the flags is present, alone or inside a short bundle."""
    for arg in args:
        if arg in flags:
            return True
        if arg.startswith("-") and not arg.startswith("--"):
            if any(len(flag) == 2 and flag[1] in arg[1:] for flag in flags if flag.startswith("-")):
                return True
    return False


def _urls(args: Iterable[str]) -> List[str]:
    return [a for a in args if a.lower().startswith(_URL_SCHEMES)]


def _is_remote(spec: str) -> bool:
    return not spec.startswith(("/", "./", "-")) and bool(_REMOTE_SPEC.fullmatch(spec))


def read_target(path: str) -> Optional[Finding]:
    """What reading this path is evidence of, if anything."""
    p = path.lower()
    name = p.rsplit("/", 1)[-1]
    if p in ("/etc/shadow", "/etc/gshadow", "/etc/master.passwd", "/etc/security/opasswd"):
        return CREDENTIAL_DUMP
    if name in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519") or "/.ssh/id_" in p or name.endswith((".pem", ".ppk")):
        return PRIVATE_KEY_READ
    if (
        name in (".git-credentials", ".netrc", ".pgpass", ".my.cnf", "wp-config.php", ".env",
                 ".htpasswd", "credentials.json", "credentials.xml", "credentials")
        or p.endswith(("/.aws/credentials", "/.docker/config.json", "/.kube/config"))
        or name.endswith(".kdbx")
        or re.fullmatch(r"passwords?\.(?:txt|db|lst|csv)", name)
    ):
        return CREDENTIAL_FILE_READ
    if name in (".bash_history", ".zsh_history", ".mysql_history", ".sh_history", ".history"):
        return SHELL_HISTORY_READ
    if p in ("/etc/passwd", "/etc/group"):
        return ACCOUNT_DISCOVERY
    if p in ("/etc/issue", "/etc/os-release", "/etc/hostname", "/proc/version", "/proc/cpuinfo",
             "/proc/meminfo", "/etc/lsb-release") or (p.startswith("/etc/") and p.endswith("-release")):
        return SYSTEM_INFO
    if p in ("/etc/hosts", "/etc/resolv.conf", "/etc/network/interfaces"):
        return NETWORK_CONFIG
    if p == "/etc/crontab" or p.startswith(("/etc/cron", "/var/spool/cron")):
        return SCHEDULED_TASK_DISCOVERY
    if p == "/etc/sudoers" or p.startswith("/etc/sudoers.d"):
        return SUDO_LIST
    if p.endswith(("/.ssh/authorized_keys", "/.ssh/known_hosts", "/.ssh/config")) or p.endswith("/.ssh"):
        return FILE_DISCOVERY
    return None


def write_target(path: str) -> Optional[Finding]:
    """What writing to this path is evidence of, if anything."""
    p = path.lower()
    name = p.rsplit("/", 1)[-1]
    if name == "authorized_keys" or name == "authorized_keys2":
        return SSH_KEY_PERSIST
    if p == "/etc/crontab" or p.startswith(("/etc/cron", "/var/spool/cron")):
        return CRON_PERSIST
    if name == "rc.local" or p.startswith(("/etc/init.d/", "/etc/rc")):
        return BOOT_PERSIST
    if p.startswith(("/etc/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/")):
        return SERVICE_PERSIST
    if name in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".bash_login") or p == "/etc/profile" \
            or p.startswith("/etc/profile.d/"):
        return SHELL_PROFILE_PERSIST
    if p == "/etc/ld.so.preload":
        return PRELOAD_HIJACK
    if p in ("/etc/passwd", "/etc/shadow", "/etc/sudoers") or p.startswith("/etc/sudoers.d/"):
        return ACCOUNT_MODIFY
    if name in (".bash_history", ".zsh_history"):
        return HISTORY_EVASION
    if p.startswith("/var/log/"):
        return LOG_CLEAR
    if p.startswith(("/var/www/", "/usr/share/nginx/", "/srv/www/")) and name.startswith("index."):
        return DEFACEMENT
    return None


def _paths(args: Iterable[str]) -> List[str]:
    """Arguments that name a file by path. A bare word is not one: the first
    operand of grep is a pattern, and "id_rsa" there is not a key being read."""
    return [a for a in args if not a.startswith("-") and (a.startswith((".", "~/")) or "/" in a)]


def _expand_home(path: str) -> str:
    # "~/.ssh/id_rsa" and "$HOME/.ssh/id_rsa" name the same kind of file.
    return "/home/user" + path[1:] if path.startswith("~/") else path


# -- command handlers -------------------------------------------------------
# Each takes the command and returns the findings it supports.

def _curl(cmd: Command) -> List[Finding]:
    args = cmd.args
    for position, arg in enumerate(args):
        value = args[position + 1] if position + 1 < len(args) else ""
        if arg in ("-T", "--upload-file"):
            return [EXFIL_UPLOAD]
        if arg in ("-F", "--form") and "@" in value:
            return [EXFIL_UPLOAD]
        if arg in ("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode") and value.startswith("@"):
            return [EXFIL_UPLOAD]
        if arg.startswith("--upload-file=") or (arg.startswith(("--data-binary=@", "--data=@"))):
            return [EXFIL_UPLOAD]
    if not _urls(args) and not any("://" in a or "." in a for a in args if not a.startswith("-")):
        return []
    saves = _has_flag(args, "-o", "-O", "--output", "--remote-name", "-J")
    return [DOWNLOAD if saves else REMOTE_FETCH]


def _wget(cmd: Command) -> List[Finding]:
    args = cmd.args
    if any(a.startswith(("--post-file", "--body-file")) for a in args):
        return [EXFIL_UPLOAD]
    targets = [a for a in args if not a.startswith("-")]
    if not targets:
        return []
    # wget saves by default; "-O -" (also written "-qO-") prints instead.
    to_stdout = any(
        (a == "-O" and position + 1 < len(args) and args[position + 1] == "-")
        or (a.startswith("-") and not a.startswith("--") and a.endswith("O-"))
        or a == "--output-document=-"
        for position, a in enumerate(args)
    )
    if "--spider" in args:
        return [REMOTE_FETCH]
    return [REMOTE_FETCH if to_stdout else DOWNLOAD]


def _tftp(cmd: Command) -> List[Finding]:
    args = [a.lower() for a in cmd.args]
    if _has_flag(args, "-p") or "put" in args:
        return [EXFIL_UPLOAD]
    if _has_flag(args, "-g") or "get" in args:
        return [DOWNLOAD]
    return []


def _copy_over_network(cmd: Command) -> List[Finding]:
    """scp and rsync: the direction decides between a download and exfiltration."""
    operands = [a for a in cmd.args if not a.startswith("-")]
    if len(operands) < 2:
        return []
    sources, destination = operands[:-1], operands[-1]
    if _is_remote(destination) and not any(_is_remote(s) for s in sources):
        return [EXFIL_COPY]
    if any(_is_remote(s) for s in sources) and not _is_remote(destination):
        return [DOWNLOAD]
    return []


def _chmod(cmd: Command) -> List[Finding]:
    modes = [a for a in cmd.args if not a.startswith("-") or _SYMBOLIC_EXEC.fullmatch(a.lstrip("-"))]
    if not modes:
        return []
    mode = modes[0]
    if _OCTAL_MODE.fullmatch(mode):
        if len(mode) == 4 and mode[0] in "2467":
            return [SETUID]
        return [MAKE_EXECUTABLE] if any(int(d) & 1 for d in mode[-3:]) else []
    if _SYMBOLIC_SETID.fullmatch(mode):
        return [SETUID]
    return [MAKE_EXECUTABLE] if _SYMBOLIC_EXEC.fullmatch(mode) else []


def _chattr(cmd: Command) -> List[Finding]:
    return [IMMUTABLE_FLAG] if any(a.startswith(("+", "-")) and "i" in a for a in cmd.args) else []


def _crontab(cmd: Command) -> List[Finding]:
    args = cmd.args
    if _has_flag(args, "-l") and not _has_flag(args, "-e", "-r"):
        return [SCHEDULED_TASK_DISCOVERY]
    # "-e", "-r", a file to install, "-" for stdin, or a bare "crontab" fed
    # by a pipe all change the table.
    if _has_flag(args, "-e", "-r") or any(not a.startswith("-") or a == "-" for a in args) or cmd.pipe_in:
        return [CRON_PERSIST]
    return []


def _service_action(action: str, units: List[str]) -> List[Finding]:
    names = {u.lower().removesuffix(".service") for u in units}
    if action == "enable":
        return [SERVICE_PERSIST]
    if action in ("stop", "disable", "mask", "kill"):
        if names & _FIREWALL_SERVICES:
            return [FIREWALL_DISABLE]
        if names & _SECURITY_SERVICES:
            return [DEFENCE_DISABLE]
        return [SERVICE_STOP] if action in ("stop", "kill") else []
    if action in ("list-units", "list-unit-files", "status", "--status-all", "list"):
        return [SERVICE_DISCOVERY]
    return []


def _systemctl(cmd: Command) -> List[Finding]:
    operands = [a for a in cmd.args if not a.startswith("-")]
    if not operands:
        return [SERVICE_DISCOVERY]
    return _service_action(operands[0].lower(), operands[1:])


def _service(cmd: Command) -> List[Finding]:
    args = cmd.args
    if "--status-all" in args:
        return [SERVICE_DISCOVERY]
    operands = [a for a in args if not a.startswith("-")]
    if len(operands) >= 2:
        return _service_action(operands[1].lower(), operands[:1])
    return []


def _iptables(cmd: Command) -> List[Finding]:
    args = cmd.args
    if _has_flag(args, "-F", "-X", "--flush") or ("-P" in args and "ACCEPT" in args):
        return [FIREWALL_DISABLE]
    if _has_flag(args, "-L", "-S", "--list"):
        return [NETWORK_CONFIG]
    return []


def _ufw(cmd: Command) -> List[Finding]:
    return [FIREWALL_DISABLE] if "disable" in cmd.args or "reset" in cmd.args else []


def _setenforce(cmd: Command) -> List[Finding]:
    return [DEFENCE_DISABLE] if cmd.args[:1] in (["0"], ["permissive"], ["Permissive"]) else []


_SUDO_VALUE_OPTIONS = frozenset({"-u", "-g", "-h", "-p", "-C", "-r", "-t", "-U", "-D"})


def _sudo(cmd: Command) -> List[Finding]:
    # Only sudo's own options count: "sudo ls -l" lists a directory, it
    # does not list sudo rights.
    own: List[str] = []
    rest = list(cmd.args)
    while rest and rest[0].startswith("-"):
        option = rest.pop(0)
        own.append(option)
        if option in _SUDO_VALUE_OPTIONS and rest:
            rest.pop(0)
    if not own and not rest:
        return []
    if _has_flag(own, "-l", "--list", "-v", "-V"):
        return [SUDO_LIST]
    inner_name = rest[0].rsplit("/", 1)[-1] if rest else ""
    if (not rest and _has_flag(own, "-i", "-s")) or inner_name in SHELLS or inner_name == "su":
        return [SWITCH_USER]
    return [SUDO_EXEC] if rest else []


def _su(cmd: Command) -> List[Finding]:
    return [SWITCH_USER]


def _passwd(cmd: Command) -> List[Finding]:
    return [ACCOUNT_MODIFY]


def _usermod(cmd: Command) -> List[Finding]:
    return [ACCOUNT_MODIFY]


def _net(cmd: Command) -> List[Finding]:
    args = [a.lower() for a in cmd.args]
    if not args:
        return []
    if args[0] in ("user", "users"):
        return [ACCOUNT_CREATE] if "/add" in args else [WINDOWS_ACCOUNT_DISCOVERY]
    if args[0] in ("localgroup", "group"):
        return [ACCOUNT_MODIFY] if "/add" in args else [WINDOWS_GROUP_DISCOVERY]
    if args[0] in ("view", "share", "accounts", "config"):
        return [WINDOWS_SYSTEM_INFO]
    return []


def _ipconfig(cmd: Command) -> List[Finding]:
    return [WINDOWS_NETWORK_CONFIG]


def _ip(cmd: Command) -> List[Finding]:
    operands = [a for a in cmd.args if not a.startswith("-")]
    if operands and operands[0] in ("a", "addr", "address", "r", "route", "link", "l", "n", "neigh", "neighbor"):
        return [NETWORK_CONFIG]
    return []


def _ss(cmd: Command) -> List[Finding]:
    return [NETWORK_CONNECTIONS] if any(a.startswith("-") for a in cmd.args) else []


def _arp(cmd: Command) -> List[Finding]:
    return [NETWORK_CONFIG]


def _ssh(cmd: Command) -> List[Finding]:
    operands = [a for a in cmd.args if not a.startswith("-")]
    if _has_flag(cmd.args, "-V") and not operands:
        return []
    if _has_flag(cmd.args, "-D", "-L", "-R"):
        return [TUNNEL]
    return [REMOTE_LOGIN] if operands else []


def _netcat(cmd: Command) -> List[Finding]:
    args = cmd.args
    if _has_flag(args, "-e", "-c", "--exec", "--sh-exec"):
        return [NETCAT, REVERSE_SHELL]
    if _has_flag(args, "-z"):
        return [NETCAT, PORT_SCAN]
    if _has_flag(args, "-l", "--listen"):
        return [NETCAT_LISTEN]
    if any(r and r != "/dev/null" for r in cmd.reads):
        return [NETCAT, EXFIL_NETCAT]
    return [NETCAT]


def _socat(cmd: Command) -> List[Finding]:
    joined = " ".join(cmd.args).lower()
    if "exec:" in joined or "system:" in joined:
        return [NETCAT, REVERSE_SHELL]
    return [NETCAT]


def _shell(cmd: Command) -> List[Finding]:
    """sh/bash given a script file to run."""
    scripts = [a for a in cmd.args if not a.startswith("-")]
    if scripts and not _has_flag(cmd.args, "-c"):
        return [RUN_DROPPED_FILE]
    return []


_REVERSE_SHELL_CODE = re.compile(r"socket", re.IGNORECASE)
_SHELL_SPAWN_CODE = ("subprocess", "os.dup2", "pty.spawn", "/bin/sh", "/bin/bash", "exec(", "fsockopen", "proc_open")


def _interpreter(cmd: Command) -> List[Finding]:
    """python -c, perl -e, php -r: inline code is where a reverse shell hides."""
    args = cmd.args
    code = ""
    for position, arg in enumerate(args):
        if arg in ("-c", "-e", "-r", "-E") and position + 1 < len(args):
            code = args[position + 1]
            break
    if not code:
        return []
    lowered = code.lower()
    if ("socket" in lowered or "fsockopen" in lowered) and any(m in lowered for m in _SHELL_SPAWN_CODE):
        return [REVERSE_SHELL]
    if "b64decode" in lowered or "base64_decode" in lowered or "frombase64string" in lowered:
        return [DECODE_EXECUTE]
    return [INTERPRETER_INLINE]


def _base64(cmd: Command) -> List[Finding]:
    return [DECODE] if _has_flag(cmd.args, "-d", "-D", "--decode") else []


def _openssl(cmd: Command) -> List[Finding]:
    args = cmd.args
    if not args:
        return []
    if args[0] == "enc" or args[0] in ("base64", "aes-256-cbc", "aes-128-cbc", "des3"):
        if _has_flag(args, "-d"):
            return [DECODE]
        # Encrypting a named file in place is the ransomware idiom; plain
        # "openssl enc -base64" in a pipe is only an encoding.
        if "-in" in args and args[0] != "base64" and "-base64" not in args[:2]:
            return [ENCRYPT_FILES]
    return []


def _gpg(cmd: Command) -> List[Finding]:
    return [ENCRYPT_FILES] if _has_flag(cmd.args, "-c", "--symmetric") else []


def _rm(cmd: Command) -> List[Finding]:
    findings: List[Finding] = []
    recursive = _has_flag(cmd.args, "-r", "-R", "--recursive")
    for path in (a for a in cmd.args if not a.startswith("-")):
        p = path.lower()
        if recursive and (p in ("/", "/*", "/home", "/var", "/etc", "/usr") or "--no-preserve-root" in cmd.args):
            findings.append(DATA_DESTRUCTION)
        elif p.startswith("/var/log") :
            findings.append(LOG_CLEAR)
        elif p.rsplit("/", 1)[-1] in (".bash_history", ".zsh_history"):
            findings.append(HISTORY_EVASION)
    return findings[:2]


def _history(cmd: Command) -> List[Finding]:
    return [HISTORY_EVASION] if _has_flag(cmd.args, "-c", "-w") else []


def _unset(cmd: Command) -> List[Finding]:
    return [HISTORY_EVASION] if any(a in ("HISTFILE", "HISTSIZE", "HISTFILESIZE") for a in cmd.args) else []


def _export(cmd: Command) -> List[Finding]:
    for arg in cmd.args:
        name, _, value = arg.partition("=")
        if name == "HISTFILE" and value in ("/dev/null", "", "''"):
            return [HISTORY_EVASION]
        if name in ("HISTSIZE", "HISTFILESIZE") and value == "0":
            return [HISTORY_EVASION]
    return []


def _set(cmd: Command) -> List[Finding]:
    return [HISTORY_EVASION] if cmd.args[:2] == ["+o", "history"] else []


def _touch(cmd: Command) -> List[Finding]:
    return [TIMESTOMP] if _has_flag(cmd.args, "-r", "-t", "-d", "--reference", "--date") else []


def _dd(cmd: Command) -> List[Finding]:
    target = next((a[3:] for a in cmd.args if a.startswith("of=")), "")
    return [DATA_DESTRUCTION] if target.startswith(("/dev/sd", "/dev/nvme", "/dev/vd", "/dev/hd", "/dev/mmcblk")) else []


def _find(cmd: Command) -> List[Finding]:
    args = cmd.args
    for position, arg in enumerate(args):
        value = args[position + 1].lower() if position + 1 < len(args) else ""
        if arg == "-perm" and ("4000" in value or "2000" in value or "6000" in value or "u=s" in value or "g=s" in value):
            return [SUID_SEARCH]
        if arg in ("-name", "-iname") and any(
            marker in value for marker in ("id_rsa", ".pem", ".kdbx", "passw", "credential", ".env", "secret", ".ppk")
        ):
            return [CREDENTIAL_SEARCH]
    return []


_SECRET_WORDS = ("passw", "secret", "token", "api_key", "apikey", "credential", "aws_access")


def _grep(cmd: Command) -> List[Finding]:
    operands = [a for a in cmd.args if not a.startswith("-")]
    if not operands:
        return []
    pattern = operands[0].lower()
    searches_files = len(operands) > 1 or _has_flag(cmd.args, "-r", "-R", "--recursive")
    if searches_files and any(word in pattern for word in _SECRET_WORDS):
        return [CREDENTIAL_SEARCH]
    return []


def _ls(cmd: Command) -> List[Finding]:
    for path in (a for a in cmd.args if not a.startswith("-")):
        finding = read_target(_expand_home(path))
        if finding in (FILE_DISCOVERY, SCHEDULED_TASK_DISCOVERY, SUDO_LIST):
            return [finding]
        if path.rstrip("/").endswith("/.ssh") or path.rstrip("/") in ("/root", "/home"):
            return [FILE_DISCOVERY]
    return []


def _tcpdump(cmd: Command) -> List[Finding]:
    return [NETWORK_SNIFF]


def _ftp_site(cmd: Command) -> List[Finding]:
    return [FTP_SITE_EXEC] if cmd.args and cmd.args[0].lower() in ("exec", "chmod") else []


def _ftp_retrieve(cmd: Command) -> List[Finding]:
    findings = [read_target(a) for a in cmd.args[:1]]
    return [f for f in findings if f is not None]


#: The program alone is the evidence.
BY_NAME: Dict[str, Finding] = {}
for _names, _finding in (
    (("uname", "hostnamectl", "lsb_release", "nproc", "lscpu", "free", "df", "lsblk",
      "dmidecode", "uptime", "printenv", "env", "hostname", "mount"), SYSTEM_INFO),
    (("whoami", "id", "w", "who", "last", "lastlog", "users", "logname"), USER_DISCOVERY),
    (("groups", "getent"), GROUP_DISCOVERY),
    (("ifconfig", "route", "iwconfig", "nmcli"), NETWORK_CONFIG),
    (("netstat", "lsof"), NETWORK_CONNECTIONS),
    (("ps", "top", "htop", "pstree"), PROCESS_DISCOVERY),
    (("systeminfo", "ver", "tasklist"), WINDOWS_SYSTEM_INFO),
    (("nmap", "masscan", "zmap", "zgrab", "zgrab2"), PORT_SCAN),
    (("gobuster", "dirb", "dirbuster", "ffuf", "wfuzz", "feroxbuster"), DIR_ENUM_TOOL),
    (("nikto", "nuclei", "wpscan", "openvas", "nessus"), VULN_SCAN_TOOL),
    (("msfconsole", "msfvenom", "msfdb", "meterpreter", "msfrpcd"), METASPLOIT),
    (("mimikatz", "mimikatz.exe", "invoke-mimikatz"), MIMIKATZ),
    (("cobaltstrike", "teamserver"), C2_FRAMEWORK),
    (("empire", "powershell-empire"), EMPIRE),
    (("hydra", "medusa", "ncrack", "patator", "crowbar"), PASSWORD_ATTACK_TOOL),
    (("hashcat", "john", "unshadow"), PASSWORD_CRACKING),
    (("sqlmap",), SQLMAP),
    (("xmrig", "minerd", "cpuminer", "kdevtmpfsi", "kinsing", "ccminer", "cgminer", "xmr-stak"), CRYPTOMINER),
    (("useradd", "adduser"), ACCOUNT_CREATE),
    (("chpasswd",), ACCOUNT_MODIFY),
    (("pkexec",), SWITCH_USER),
    (("dirtycow", "dirty", "pwnkit", "cve-2021-4034"), PRIVESC_EXPLOIT),
    (("sshpass", "ssh-copy-id"), REMOTE_LOGIN),
    (("rdesktop", "xfreerdp"), REMOTE_DESKTOP),
    (("smbclient", "smbmap"), SMB_ACCESS),
    (("psexec", "psexec.py", "wmic", "wmiexec.py"), REMOTE_EXEC),
    (("proxychains", "proxychains4", "chisel"), TUNNEL),
    (("hping", "hping3", "slowloris", "slowhttptest"), DENIAL_OF_SERVICE),
    (("mkfs", "shred", "wipefs"), DATA_DESTRUCTION),
    (("mysqldump", "pg_dump", "pg_dumpall", "mongodump"), DB_DUMP),
    (("mkfifo",), NAMED_PIPE),
    (("ftpget",), DOWNLOAD),
    (("ftpput",), EXFIL_UPLOAD),
):
    for _name in _names:
        BY_NAME[_name] = _finding

#: The arguments decide.
HANDLERS: Dict[str, Callable[[Command], List[Finding]]] = {
    "curl": _curl, "wget": _wget, "fetch": _wget, "tftp": _tftp,
    "scp": _copy_over_network, "rsync": _copy_over_network,
    "chmod": _chmod, "chattr": _chattr, "crontab": _crontab,
    "systemctl": _systemctl, "service": _service,
    "iptables": _iptables, "ip6tables": _iptables, "ufw": _ufw, "setenforce": _setenforce,
    "sudo": _sudo, "doas": _sudo, "su": _su, "passwd": _passwd, "usermod": _usermod,
    "net": _net, "net.exe": _net, "ipconfig": _ipconfig,
    "ip": _ip, "ss": _ss, "arp": _arp, "ssh": _ssh,
    "nc": _netcat, "ncat": _netcat, "netcat": _netcat, "socat": _socat,
    "python": _interpreter, "python2": _interpreter, "python3": _interpreter,
    "perl": _interpreter, "php": _interpreter, "ruby": _interpreter,
    "node": _interpreter, "lua": _interpreter,
    "base64": _base64, "openssl": _openssl, "gpg": _gpg,
    "rm": _rm, "history": _history, "unset": _unset, "export": _export, "set": _set,
    "touch": _touch, "dd": _dd, "find": _find, "grep": _grep, "egrep": _grep,
    "ls": _ls, "dir": _ls, "tcpdump": _tcpdump, "tshark": _tcpdump,
    # FTP verbs arrive as commands on the FTP decoy.
    "site": _ftp_site, "retr": _ftp_retrieve,
}
for _shell_name in SHELLS:
    HANDLERS[_shell_name] = _shell

_MINING_MARKERS = ("stratum+tcp://", "stratum+ssl://", "stratum2+tcp://")
_MIMIKATZ_MODULES = ("sekurlsa::", "lsadump::", "kerberos::")


def findings_for(cmd: Command, upstream: Optional[Command] = None) -> List[Finding]:
    """Everything one simple command is evidence of.

    ``upstream`` is the command whose output it reads, when it is the reading
    end of a pipe: what flows into a shell or out through netcat decides what
    the pipeline was for.
    """
    name = cmd.name
    if not name:
        # A bare redirection ("> /var/log/auth.log") still writes a file.
        return _dedupe(write_target(_expand_home(t)) for t in cmd.writes)

    findings: List[Optional[Finding]] = []
    handler = HANDLERS.get(name)
    if handler is not None:
        findings.extend(handler(cmd))
    elif name in BY_NAME:
        findings.append(BY_NAME[name])
    elif cmd.busybox and cmd.argv[0].isupper() and 2 < len(cmd.argv[0]) <= 16:
        # "/bin/busybox ECCHI": an applet that does not exist, run to see
        # whether the reply is a real BusyBox. A bot's first question.
        findings.append(IOT_BOT_PROBE)
    elif cmd.argv[0].startswith(_TEMP_DIRS + ("./",)):
        findings.append(RUN_DROPPED_FILE)

    if cmd.busybox and name in ("wget", "tftp", "ftpget") and DOWNLOAD in findings:
        # BusyBox's own downloader is what IoT bots use: full wget and curl
        # are rarely on the devices they target.
        findings.append(IOT_BOT_DOWNLOAD)

    # A redirection to /dev/tcp is a socket: with a shell on the other end
    # of it this is the classic reverse shell.
    if any("/dev/tcp/" in t or "/dev/udp/" in t for t in cmd.reads + cmd.writes):
        findings.append(REVERSE_SHELL)

    # What any command reads or writes matters whatever the program is.
    if name in _FILE_READERS or name in ("vi", "vim", "nano"):
        for path in _paths(cmd.args)[:8]:
            findings.append(read_target(_expand_home(path)))
    for path in cmd.reads[:4]:
        findings.append(read_target(_expand_home(path)))
    for path in cmd.writes[:4]:
        findings.append(write_target(_expand_home(path)))
    if name in ("tee", "cp", "mv", "ln", "install") and cmd.args:
        findings.append(write_target(_expand_home(cmd.args[-1])))
    if name == "sed" and _has_flag(cmd.args, "-i"):
        findings.append(write_target(_expand_home(cmd.args[-1])))

    for arg in cmd.args[:32]:
        lowered = arg.lower()
        if lowered.startswith(_MINING_MARKERS):
            findings.append(CRYPTOMINER)
        elif lowered.startswith(_MIMIKATZ_MODULES):
            findings.append(MIMIKATZ)

    if upstream is not None:
        findings.extend(_pipeline(cmd, upstream))
    return _dedupe(findings)


def _pipeline(cmd: Command, upstream: Command) -> List[Finding]:
    name, source = cmd.name, upstream.name
    if name in SHELLS and not _has_flag(cmd.args, "-c") and not [a for a in cmd.args if not a.startswith("-")]:
        if source in ("curl", "wget", "fetch"):
            return [DOWNLOAD_EXECUTE]
        if source in ("base64", "xxd", "openssl", "gunzip", "zcat", "gzip"):
            return [DECODE_EXECUTE]
        return [PIPE_TO_SHELL]
    if name in ("nc", "ncat", "netcat", "socat") and not _has_flag(cmd.args, "-l", "--listen"):
        if source in SHELLS:
            # "cat /tmp/f | sh -i 2>&1 | nc host port > /tmp/f"
            return [REVERSE_SHELL]
        if source in _FILE_READERS:
            return [EXFIL_NETCAT]
    if name == "curl" and source in _FILE_READERS and any(
        a in ("-T", "--upload-file", "-d", "--data", "--data-binary", "-F") for a in cmd.args
    ):
        return [EXFIL_UPLOAD]
    return []


def _dedupe(findings: Iterable[Optional[Finding]]) -> List[Finding]:
    seen = set()
    out: List[Finding] = []
    for finding in findings:
        if finding is not None and finding.key not in seen:
            seen.add(finding.key)
            out.append(finding)
    return out
