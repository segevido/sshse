"""Helpers for launching SSH sessions from CLI interactions."""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable

import typer

from sshse.core.history import HistoryEntry

__all__ = ["build_ssh_command", "run_ssh"]


def build_ssh_command(entry: HistoryEntry) -> list[str]:
    """Construct the argv list for invoking the system ssh binary."""

    target = entry.hostname
    if entry.username:
        target = f"{entry.username}@{target}"

    command: list[str] = ["ssh", target]
    if entry.port:
        command.extend(["-p", str(entry.port)])
    return command


def _normalize_exit_status(status: int) -> int:
    """Convert platform-specific wait status values to standard exit codes."""

    waitstatus_to_exitcode: Callable[[int], int] | None = getattr(
        os, "waitstatus_to_exitcode", None
    )
    if waitstatus_to_exitcode is not None:
        return waitstatus_to_exitcode(status)

    wifexited: Callable[[int], bool] | None = getattr(os, "WIFEXITED", None)
    if wifexited is not None and wifexited(status):
        exit_status: Callable[[int], int] = getattr(os, "WEXITSTATUS", lambda value: value)
        return exit_status(status)

    wifsignaled: Callable[[int], bool] | None = getattr(os, "WIFSIGNALED", None)
    if wifsignaled is not None and wifsignaled(status):
        wtermsig: Callable[[int], int] | None = getattr(os, "WTERMSIG", None)
        if wtermsig is not None:
            return 128 + wtermsig(status)

    return status


def _spawn_ssh(argv: list[str]) -> int:
    """Invoke the system ssh binary using a pseudo-terminal when available."""

    try:
        import pty
    except ImportError as exc:  # pragma: no cover - platform specific
        msg = "PTY support is required to launch interactive ssh sessions"
        raise RuntimeError(msg) from exc

    return pty.spawn(argv)


def run_ssh(entry: HistoryEntry) -> int:
    """Execute an SSH connection for the provided history entry."""

    command = build_ssh_command(entry)
    ssh_path = shutil.which(command[0])
    if ssh_path is None:
        typer.echo("ssh command not found", err=True)
        return 1

    argv = [ssh_path, *command[1:]]
    try:
        status = _spawn_ssh(argv)
    except RuntimeError as exc:  # pragma: no cover - platform specific
        typer.echo(str(exc), err=True)
        return 1
    except OSError as exc:  # pragma: no cover - unexpected OS errors
        typer.echo(str(exc), err=True)
        return 1
    return _normalize_exit_status(status)
