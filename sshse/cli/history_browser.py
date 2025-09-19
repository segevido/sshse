"""Interactive browser for SSH history with lightweight filtering."""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Iterable, Sequence

import typer

from sshse.cli.ssh_launcher import run_ssh
from sshse.core.history import HistoryEntry, HistoryStore

__all__ = ["HistoryBrowser", "launch_history_browser", "launch_history_menu"]

PromptFn = Callable[[str], str]
OutputFn = Callable[[str], None]
LauncherFn = Callable[[HistoryEntry], int]

_SELECTION_PROMPT = "Select entry #, type to search, or 'q' to quit"


def _default_prompt(message: str) -> str:
    """Prompt the user for input using Typer's utilities."""

    return typer.prompt(message, default="")


def _default_output(message: str) -> None:
    """Emit a single line of output to the terminal."""

    typer.echo(message)


class HistoryBrowser:
    """Browse previously connected SSH targets with incremental filtering."""

    def __init__(
        self,
        store: HistoryStore | None = None,
        *,
        prompt: PromptFn | None = None,
        output: OutputFn | None = None,
        launcher: LauncherFn | None = None,
        page_size: int = 15,
    ) -> None:
        self._store = store if store is not None else HistoryStore()
        self._prompt = prompt if prompt is not None else _default_prompt
        self._output = output if output is not None else _default_output
        self._launcher = launcher if launcher is not None else run_ssh
        self._page_size = max(5, page_size)

    def run(self) -> int:
        """Display the browser and act on the user's selection or search."""

        entries = self._store.load()
        if not entries:
            self._output("No SSH history yet. Connect to a host to populate the list.")
            return 0

        active_query = ""
        filtered = entries
        total_entries = len(entries)
        self._render(filtered, total_entries, active_query)

        while True:
            try:
                raw_selection = self._prompt(_SELECTION_PROMPT)
            except (EOFError, KeyboardInterrupt):
                self._output("")
                return 1

            selection = raw_selection.strip()
            if not selection:
                return 0

            lower_selection = selection.lower()
            if lower_selection in {"q", "quit", "exit"}:
                return 0
            if lower_selection == "clear":
                active_query = ""
                filtered = entries
                self._render(filtered, total_entries, active_query)
                continue

            if selection.isdigit():
                index = int(selection) - 1
                if 0 <= index < len(filtered):
                    return self._launcher(filtered[index])
                self._output(
                    "Invalid selection. Choose a listed number, enter text to filter, or 'q' to exit."
                )
                continue

            active_query = selection
            filtered = self._filter_entries(entries, active_query)
            if filtered:
                self._render(filtered, total_entries, active_query)
                continue

            self._output(
                f"No matches for '{active_query}'. Type 'clear' to reset or refine your search."
            )

    def _render(self, entries: Sequence[HistoryEntry], total: int, query: str) -> None:
        """Print the header and the currently visible entries."""

        match_label = "match" if len(entries) == 1 else "matches"
        header = f"Recent SSH connections: {len(entries)} {match_label} of {total} total"
        if query:
            header = f"{header} (filter: '{query}')"

        self._output("")
        self._output(header)

        for idx, entry in enumerate(entries[: self._page_size], start=1):
            summary = self._format_entry(entry)
            self._output(f"  {idx:>2}. {summary}")

        remaining = len(entries) - self._page_size
        if remaining > 0:
            more_label = "result" if remaining == 1 else "results"
            self._output(
                f"     … {remaining} more {more_label}. Narrow the filter to see additional connections."
            )

        self._output(
            "Commands: number = connect • text = filter • 'clear' = reset filter • 'q' = quit"
        )

    @staticmethod
    def _filter_entries(entries: Iterable[HistoryEntry], query: str) -> list[HistoryEntry]:
        """Return entries containing all search tokens in their metadata."""

        tokens = [token for token in query.lower().split() if token]
        if not tokens:
            return list(entries)

        filtered: list[HistoryEntry] = []
        for entry in entries:
            haystacks = HistoryBrowser._build_search_haystack(entry)
            if all(any(token in value for value in haystacks) for token in tokens):
                filtered.append(entry)
        return filtered

    @staticmethod
    def _build_search_haystack(entry: HistoryEntry) -> tuple[str, ...]:
        """Construct lowercase values used for matching search tokens."""

        values = [entry.hostname.lower()]
        if entry.username:
            values.append(entry.username.lower())
        if entry.port is not None:
            values.append(str(entry.port))
        return tuple(values)

    @staticmethod
    def _format_entry(entry: HistoryEntry) -> str:
        """Generate a readable summary line for a history entry."""

        target = entry.hostname
        if entry.username:
            target = f"{entry.username}@{target}"
        if entry.port:
            target = f"{target}:{entry.port}"

        timestamp = HistoryBrowser._format_timestamp(entry.last_connected_at)
        return f"{target} — last connected {timestamp}"

    @staticmethod
    def _format_timestamp(timestamp: datetime) -> str:
        """Render timestamps in a compact, local-time representation."""

        localized = timestamp.astimezone()
        return localized.strftime("%Y-%m-%d %H:%M")


def launch_history_browser() -> int:
    """Convenience wrapper to instantiate and run the history browser."""

    return HistoryBrowser().run()


# Backwards-compatible export for legacy imports within the project.
launch_history_menu = launch_history_browser
