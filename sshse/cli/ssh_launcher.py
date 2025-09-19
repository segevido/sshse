"""Helpers for launching SSH sessions from CLI interactions."""

from __future__ import annotations

import subprocess

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


def run_ssh(entry: HistoryEntry) -> int:
    """Execute an SSH connection for the provided history entry."""

    command = build_ssh_command(entry)
    try:
        return subprocess.call(command)
    except FileNotFoundError:  # pragma: no cover - defensive guard
        typer.echo("ssh command not found", err=True)
        return 1
