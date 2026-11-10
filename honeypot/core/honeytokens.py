"""Planted secrets that are only ever seen by someone who read the decoy.

A honeypot's own files are a second sensor. A database password in a
``.env``, a cloud access key in ``~/.aws/credentials`` and a login in the
shell history are things an intruder collects and tries — here, or anywhere
else. Nobody learns these values by guessing: each is generated for this
deployment from the host identity's seed, exists nowhere but in the decoy's
virtual files, and is long enough not to be hit by a wordlist. So when one of
them comes back, on any protocol, the source demonstrably read this decoy's
files (or was handed what someone else read), and that is worth an event of
its own.

Nothing here is a credential for anything real. The access key id has the
shape of one but was drawn from this deployment's seed, not issued by any
provider.

``match_credential`` is called wherever a session records a login attempt,
so SSH, Telnet, FTP and the web login forms are all covered without each
emulator knowing about it. ``scan_text`` looks for the secrets inside a
command line. ``env_secrets`` is for the HTTP decoy, so the ``/.env`` it
serves carries the same values as the one in the shell's filesystem.
"""

from __future__ import annotations

import random
import threading
from dataclasses import dataclass
from typing import Optional

_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_SECRET = _ALNUM + "+/"

#: Usernames the planted login can have. None of them is in the decoy's own
#: list of weak accounts, so the pair never succeeds by coincidence.
_LOGIN_NAMES = ["deploy", "svc-backup", "ansible", "jenkins", "gitlab-runner", "monitor"]
_DB_NAMES = ["appdb", "portal", "inventory", "billing", "crm_prod", "shopdata"]
_DB_USERS = ["app", "appuser", "webapp", "portal_rw", "svc_app"]


@dataclass(frozen=True)
class Honeytokens:
    seed: int
    db_name: str
    db_user: str
    db_password: str
    aws_access_key_id: str
    aws_secret_access_key: str
    app_key: str
    username: str
    password: str

    # -- where the secrets are planted -----------------------------------

    def env_file(self) -> str:
        """The web application's ``.env``."""
        return (
            "APP_NAME=Portal\nAPP_ENV=production\n"
            f"APP_KEY=base64:{self.app_key}\nAPP_DEBUG=false\n\n"
            "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\n"
            f"DB_DATABASE={self.db_name}\nDB_USERNAME={self.db_user}\n"
            f"DB_PASSWORD={self.db_password}\n\n"
            f"AWS_ACCESS_KEY_ID={self.aws_access_key_id}\n"
            f"AWS_SECRET_ACCESS_KEY={self.aws_secret_access_key}\n"
            "AWS_DEFAULT_REGION=eu-west-1\nAWS_BUCKET=portal-backups\n"
        )

    def config_backup(self) -> str:
        """An old PHP config left beside the backups."""
        return (
            "<?php\n// config.php (backup before migration)\n"
            f"define('DB_NAME', '{self.db_name}');\n"
            f"define('DB_USER', '{self.db_user}');\n"
            f"define('DB_PASSWORD', '{self.db_password}');\n"
            "define('DB_HOST', '127.0.0.1');\n"
            f"define('DEPLOY_USER', '{self.username}');\n"
            f"define('DEPLOY_PASS', '{self.password}');\n"
        )

    def aws_credentials(self) -> str:
        return (
            "[default]\n"
            f"aws_access_key_id = {self.aws_access_key_id}\n"
            f"aws_secret_access_key = {self.aws_secret_access_key}\n"
        )

    def history_lines(self) -> list[str]:
        """Lines for root's ``.bash_history`` that leak two of the secrets."""
        return [
            f"mysql -u {self.db_user} -p'{self.db_password}' {self.db_name}",
            f"sshpass -p '{self.password}' ssh {self.username}@localhost",
        ]

    def env_secrets(self) -> dict[str, str]:
        return {
            "DB_DATABASE": self.db_name,
            "DB_USERNAME": self.db_user,
            "DB_PASSWORD": self.db_password,
            "AWS_ACCESS_KEY_ID": self.aws_access_key_id,
            "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key,
            "APP_KEY": f"base64:{self.app_key}",
        }

    # -- recognising them -------------------------------------------------

    def match_credential(self, username: str, password: str) -> Optional[dict]:
        """The ``honeytoken_used`` details for a login attempt, or None."""
        username, password = username or "", password or ""
        if password == self.password:
            exact = username == self.username
            return {
                "token_id": "login_pair",
                "kind": "credential",
                "detail": (
                    f"planted login {self.username} presented"
                    if exact else
                    f"planted password for {self.username} presented as {username[:64]!r}"
                ),
            }
        if password == self.db_password:
            return {
                "token_id": "db_password",
                "kind": "credential",
                "detail": f"planted database password presented as {username[:64]!r}",
            }
        if password == self.aws_secret_access_key or username == self.aws_access_key_id:
            return {
                "token_id": "aws_access_key",
                "kind": "api_key",
                "detail": "planted cloud access key presented at a login",
            }
        return None

    def scan_text(self, text: str) -> list[dict]:
        """Planted secrets that appear in ``text`` (a command line, a body)."""
        found = []
        if self.aws_access_key_id in text or self.aws_secret_access_key in text:
            found.append({
                "token_id": "aws_access_key",
                "kind": "api_key",
                "detail": "planted cloud access key used in a command",
            })
        if self.db_password in text:
            found.append({
                "token_id": "db_password",
                "kind": "credential",
                "detail": "planted database password used in a command",
            })
        if self.password in text:
            found.append({
                "token_id": "login_pair",
                "kind": "credential",
                "detail": f"planted password for {self.username} used in a command",
            })
        return found


def derive(seed: int) -> Honeytokens:
    rng = random.Random(f"{seed}:honeytokens")

    def pick(alphabet: str, length: int) -> str:
        return "".join(rng.choice(alphabet) for _ in range(length))

    return Honeytokens(
        seed=seed,
        db_name=rng.choice(_DB_NAMES),
        db_user=rng.choice(_DB_USERS),
        db_password=pick(_ALNUM, 20),
        aws_access_key_id="AKIA" + pick(_BASE32, 16),
        aws_secret_access_key=pick(_SECRET, 40),
        app_key=pick(_SECRET, 43) + "=",
        username=rng.choice(_LOGIN_NAMES),
        password=pick(_ALNUM, 14),
    )


_lock = threading.Lock()
_cached: Optional[Honeytokens] = None


def get_honeytokens() -> Honeytokens:
    """This deployment's planted secrets, the same on every call."""
    global _cached
    from honeypot.core.identity import get_identity

    seed = get_identity().seed
    with _lock:
        if _cached is None or _cached.seed != seed:
            _cached = derive(seed)
        return _cached


def match_credential(username: str, password: str) -> Optional[dict]:
    return get_honeytokens().match_credential(username, password)


def scan_text(text: str) -> list[dict]:
    return get_honeytokens().scan_text(text)


def env_secrets() -> dict[str, str]:
    """For the HTTP decoy: the values its ``/.env`` bait should serve.

    They are the ones in ``/var/www/html/.env`` on the shell side, so a
    visitor who reads the file over HTTP and one who reads it over SSH get
    the same secrets, and either one using them raises the same event.
    """
    return get_honeytokens().env_secrets()


def env_file_text() -> str:
    """The whole ``.env`` as served or read, ready to send."""
    return get_honeytokens().env_file()
