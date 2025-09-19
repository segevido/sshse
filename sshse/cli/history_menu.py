"""Interactive terminal menu for selecting SSH history entries."""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Iterable

import typer

from sshse.cli.ssh_launcher import run_ssh
from sshse.core.history import HistoryEntry, HistoryStore


PromptFn = Callable[[str], str]
OutputFn = Callable[[str], None]
LauncherFn = Callable[[HistoryEntry], int]


def _default_prompt(message: str) -> str:
    """Prompt the user for input using Typer's utilities."""

    return typer.prompt(message, default="")


def _default_output(message: str) -> None:
    """Emit a single line of output to the terminal."""

    typer.echo(message)


class HistoryMenu:
    """Simple text-based menu that surfaces recent SSH targets."""

    def __init__(
        self,
        store: HistoryStore | None = None,
        *,
        prompt: PromptFn | None = None,
        output: OutputFn | None = None,
        launcher: LauncherFn | None = None,
    ) -> None:
        self._store = store if store is not None else HistoryStore()
        self._prompt = prompt if prompt is not None else _default_prompt
        self._output = output if output is not None else _default_output
        self._launcher = launcher if launcher is not None else run_ssh

    def run(self) -> int:
        """Display the history menu and act on the user's selection."""

        entries = self._store.load()
        if not entries:
            self._output("No SSH history yet. Connect to a host to populate the list.")
            return 0

        self._render(entries)

        while True:
            try:
                selection = self._prompt("Select host # (or 'q' to quit)").strip()
            except (EOFError, KeyboardInterrupt):
                self._output("")
                return 1

            if not selection or selection.lower() in {"q", "quit"}:
                return 0

            if selection.isdigit():
                index = int(selection) - 1
                if 0 <= index < len(entries):
                    return self._launcher(entries[index])

            self._output("Invalid selection. Enter a valid number or 'q' to exit.")

    def _render(self, entries: Iterable[HistoryEntry]) -> None:
        """Print the menu header and available history entries."""

        self._output("Recent SSH connections:")
        for idx, entry in enumerate(entries, start=1):
            summary = self._format_entry(entry)
            self._output(f"  {idx:>2}. {summary}")

    @staticmethod
    def _format_entry(entry: HistoryEntry) -> str:
        """Generate a readable summary line for a history entry."""

        target = entry.hostname
        if entry.username:
            target = f"{entry.username}@{target}"
        if entry.port:
            target = f"{target}:{entry.port}"

        timestamp = HistoryMenu._format_timestamp(entry.last_connected_at)
        return f"{target} — last connected {timestamp}"

    @staticmethod
    def _format_timestamp(timestamp: datetime) -> str:
        """Render timestamps in a compact, local-time representation."""

        localized = timestamp.astimezone()
        return localized.strftime("%Y-%m-%d %H:%M")


def launch_history_menu() -> int:
    """Convenience wrapper to instantiate and run the history menu."""

    return HistoryMenu().run()
