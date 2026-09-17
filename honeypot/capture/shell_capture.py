"""Glue between the shell-write interpreter and a live SSH session.

``shell_writes`` is pure: text in, writes out. This applies those writes to the
session's in-memory shell state, so a file assembled over forty ``echo``
commands exists as one file, and hands content piped straight into an
interpreter to the session manager at once, since it has no path to be
collected from later.
"""

from __future__ import annotations

import posixpath

from honeypot.capture.shell_writes import Interpretation, interpret
from honeypot.core.session import session_manager
from honeypot.core.shell_state import ShellState, shell_states


async def capture_command(session_id: str, command: str, home: str) -> Interpretation:
    """Record what one command line writes. Never raises into the shell."""
    shell = shell_states.get(session_id)
    try:
        result = interpret(command, cwd=shell.cwd, home=home, read_file=shell.read_content)
    except Exception:  # pragma: no cover - defensive: capture must not break the session
        return Interpretation(stdout=None)

    refused = []
    for write in result.writes:
        if not shell.write_content(write.path, write.content, write.append, write.method):
            refused.append(write.path)
    if refused:
        await session_manager.record_network_event(
            session_id,
            "shell_write_refused",
            {"paths": [p[:200] for p in refused[:8]], "reason": "capture bounds"},
        )

    for execution in result.executions:
        await session_manager.record_file_upload(
            session_id,
            f"stdin.{execution.interpreter}",
            execution.content,
            remote_path=f"(piped to {execution.interpreter})",
            source="ssh_piped",
            methods=[execution.method],
        )
    return result


async def flush_session_files(session_id: str, shell: ShellState | None) -> None:
    """Hand every file the session wrote through the shell to the recorder.

    Called once, as the connection closes, with the final content of each
    path — an echoloader's forty appends become one file, not forty.
    """
    if shell is None:
        return
    for path, content, methods in shell.captured():
        await session_manager.record_file_upload(
            session_id,
            posixpath.basename(path) or path,
            content,
            remote_path=path,
            source="ssh_shell",
            methods=methods,
        )
