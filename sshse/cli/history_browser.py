"""Interactive SSH history browser with curses-backed navigation."""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

import typer

from sshse.cli.ssh_launcher import run_ssh
from sshse.core.history import HistoryEntry, HistoryStore

__all__ = [
    "HistoryBrowser",
    "HistorySession",
    "HistoryUI",
    "PromptHistoryUI",
    "launch_history_browser",
    "launch_history_menu",
]

PromptFn = Callable[[str], str]
OutputFn = Callable[[str], None]
LauncherFn = Callable[[HistoryEntry], int]


_DEF_MESSAGE_EMPTY = "No SSH history yet. Connect to a host to populate the list."
_DEF_MESSAGE_NO_MATCH = "No entries to select. Type 'clear' to reset or 'q' to quit."


def _default_output(message: str) -> None:
    """Emit a single line of output to the terminal."""

    typer.echo(message)


class HistoryUI(Protocol):
    """UI contract for rendering and selecting a history entry."""

    def run(self, session: HistorySession) -> HistoryEntry | None: ...


def _filter_entries(entries: Iterable[HistoryEntry], query: str) -> list[HistoryEntry]:
    tokens = [token for token in query.lower().split() if token]
    if not tokens:
        return list(entries)

    filtered: list[HistoryEntry] = []
    for entry in entries:
        haystacks: list[str] = [entry.hostname.lower()]
        if entry.username:
            haystacks.append(entry.username.lower())
        if entry.port is not None:
            haystacks.append(str(entry.port))
        if all(any(token in value for value in haystacks) for token in tokens):
            filtered.append(entry)
    return filtered


@dataclass(slots=True)
class HistorySession:
    """Mutable state shared between the UI and browser logic."""

    entries: list[HistoryEntry]
    page_size: int
    filter_query: str = ""
    selection_index: int = 0
    filtered_entries: list[HistoryEntry] = field(init=False, repr=False, default_factory=list)

    def __post_init__(self) -> None:
        """Normalize defaults once the dataclass is created."""
        self.page_size = max(5, self.page_size)
        self.filtered_entries = list(self.entries)
        self.selection_index = 0 if self.filtered_entries else -1

    def apply_filter(self, query: str) -> None:
        self.filter_query = query
        self.filtered_entries = _filter_entries(self.entries, self.filter_query)
        if not self.filtered_entries:
            self.selection_index = -1
        else:
            self.selection_index = max(0, min(self.selection_index, len(self.filtered_entries) - 1))

    def clear_filter(self) -> None:
        self.apply_filter("")

    def move_selection(self, delta: int) -> None:
        if not self.filtered_entries:
            self.selection_index = -1
            return
        self.selection_index = _clamp(
            self.selection_index + delta, 0, len(self.filtered_entries) - 1
        )

    def set_selection(self, index: int) -> bool:
        if not self.filtered_entries:
            self.selection_index = -1
            return False
        if 0 <= index < len(self.filtered_entries):
            self.selection_index = index
            return True
        return False

    def filtered(self) -> list[HistoryEntry]:
        return list(self.filtered_entries)

    def current(self) -> HistoryEntry | None:
        if not self.filtered_entries or self.selection_index < 0:
            return None
        return self.filtered_entries[self.selection_index]

    def total_count(self) -> int:
        return len(self.entries)

    def filtered_count(self) -> int:
        return len(self.filtered_entries)

    def page_bounds(self) -> tuple[int, int]:
        if self.selection_index < 0:
            return (0, self.page_size)
        start = (self.selection_index // self.page_size) * self.page_size
        return (start, start + self.page_size)


class CursesHistoryUI:
    """Render the session using Python's built-in curses toolkit."""

    def run(
        self,
        session: HistorySession,
    ) -> HistoryEntry | None:  # pragma: no cover - requires tty
        with suppress(ImportError):
            import curses

            if not sys.stdin.isatty() or not sys.stdout.isatty():
                raise RuntimeError("curses UI requires a TTY")

            return curses.wrapper(lambda stdscr: self._main(stdscr, session, curses))
        raise RuntimeError("curses library not available on this platform")

    def _main(self, stdscr, session: HistorySession, curses):  # pragma: no cover - requires tty
        curses.curs_set(0)
        stdscr.nodelay(False)
        stdscr.keypad(True)

        filter_buffer = session.filter_query
        session.apply_filter(filter_buffer)

        while True:
            self._render(stdscr, session, filter_buffer, curses)
            key = stdscr.get_wch()

            if isinstance(key, str):
                if key in {"\n", "\r"}:
                    return session.current()
                if key in {"\x1b", "q", "Q"}:
                    return None
                if key in {"\b", "\x7f"}:
                    if filter_buffer:
                        filter_buffer = filter_buffer[:-1]
                        session.apply_filter(filter_buffer)
                    continue
                if key == "\u0015":  # Ctrl+U
                    filter_buffer = ""
                    session.clear_filter()
                    continue
                if key == "\t":
                    continue
                if key.isprintable():
                    filter_buffer += key
                    session.apply_filter(filter_buffer)
                    continue
            else:
                if key == curses.KEY_UP:
                    session.move_selection(-1)
                    continue
                if key == curses.KEY_DOWN:
                    session.move_selection(1)
                    continue
                if key == curses.KEY_NPAGE:
                    session.move_selection(session.page_size)
                    continue
                if key == curses.KEY_PPAGE:
                    session.move_selection(-session.page_size)
                    continue
                if key == curses.KEY_HOME:
                    session.set_selection(0)
                    continue
                if key == curses.KEY_END:
                    session.set_selection(session.filtered_count() - 1)
                    continue
                if key == curses.KEY_BACKSPACE:
                    if filter_buffer:
                        filter_buffer = filter_buffer[:-1]
                        session.apply_filter(filter_buffer)
                    continue

    def _render(
        self,
        stdscr,
        session: HistorySession,
        buffer: str,
        curses,
    ) -> None:  # pragma: no cover - requires tty
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        if height <= 0 or width <= 0:
            stdscr.refresh()
            return

        def _safe_add(y: int, text: str, attr: int = curses.A_NORMAL) -> None:
            if 0 <= y < height:
                with suppress(curses.error):
                    stdscr.addnstr(y, 0, text.ljust(width)[:width], width, attr)

        filter_label = "Filter: " + buffer
        _safe_add(0, filter_label, curses.A_BOLD)

        entries = session.filtered()
        total = len(entries)
        header = "{:<25} {:<12} {:<30} {:<6}".format("Name", "User", "Destination", "Port")
        _safe_add(2, header, curses.A_UNDERLINE)

        # Reserve rows: 0 filter, 1 blank, 2 header, footer at height-1.
        available_rows = max(0, height - 4)
        if available_rows == 0:
            _safe_add(height - 1, "Window too small — resize or use prompt UI.", curses.A_DIM)
            stdscr.refresh()
            return

        start, _ = session.page_bounds()
        if session.selection_index >= 0:
            start = min(start, session.selection_index)
            if session.selection_index >= start + available_rows:
                start = session.selection_index - available_rows + 1
        start = max(0, min(start, max(total - available_rows, 0)))
        visible = entries[start : start + available_rows]

        if not visible:
            _safe_add(4, "No matches. Type to search or ESC to quit.")
        else:
            for offset, entry in enumerate(visible):
                idx = start + offset
                row = 3 + offset
                if row >= height - 1:
                    break
                selected = idx == session.selection_index
                user = entry.username or "-"
                destination = entry.hostname
                port = entry.port or "-"
                line = f"{entry.hostname:<25} {user:<12} {destination:<30} {port:<6}"
                attr = curses.A_REVERSE if selected else curses.A_NORMAL
                _safe_add(row, line, attr)

        footer = "(Esc) quit • arrows move • enter connect"
        _safe_add(height - 1, footer, curses.A_DIM)
        stdscr.refresh()


class PromptHistoryUI:
    """Fallback text-mode UI used when curses is unavailable."""

    def __init__(self, prompt: PromptFn, output: OutputFn) -> None:
        self._prompt = prompt
        self._output = output

    def run(self, session: HistorySession) -> HistoryEntry | None:
        self._render(session)
        while True:
            if not session.filtered_count():
                self._output(_DEF_MESSAGE_NO_MATCH)
            try:
                selection = self._prompt("Select number, type to filter, or 'q' to quit").strip()
            except (EOFError, KeyboardInterrupt):
                self._output("")
                return None

            if not selection:
                entry = session.current()
                if entry is not None:
                    return entry
                continue

            lowered = selection.lower()
            if lowered in {"q", "quit", "exit"}:
                return None
            if lowered == "clear":
                session.clear_filter()
                self._render(session)
                continue
            if lowered.isdigit():
                index = int(lowered) - 1
                if session.set_selection(index):
                    entry = session.current()
                    if entry is not None:
                        return entry

                self._output("Invalid selection. Choose a valid number or filter query.")
                continue

            session.apply_filter(selection)
            session.set_selection(0)
            if session.filtered_count():
                self._render(session)
            else:
                self._output(f"No matches for '{selection}'. Type 'clear' to reset the filter.")

    def _render(self, session: HistorySession) -> None:
        entries = session.filtered()
        total = session.total_count()
        match_label = "match" if len(entries) == 1 else "matches"
        header = f"Recent SSH connections: {len(entries)} {match_label} of {total} total"
        if session.filter_query:
            header += f" (filter: '{session.filter_query}')"
        self._output("")
        self._output(header)
        start, end = session.page_bounds()
        for absolute_index, entry in enumerate(entries[start:end], start=start):
            summary = _format_entry(entry)
            pointer = ">" if absolute_index == session.selection_index else " "
            self._output(f"{pointer} {absolute_index + 1:>3}. {summary}")
        remaining = len(entries) - end
        if remaining > 0:
            more_label = "result" if remaining == 1 else "results"
            self._output(
                f"     ... {remaining} more {more_label}. "
                "Narrow the filter to see additional connections."
            )
        self._output(
            "Commands: enter = connect highlighted • number = connect by index • text = filter "
            "• 'clear' resets"
        )


class HistoryBrowser:
    """High-level orchestrator that loads history and delegates to a UI."""

    def __init__(
        self,
        store: HistoryStore | None = None,
        *,
        output: OutputFn | None = None,
        launcher: LauncherFn | None = None,
        page_size: int = 15,
        ui: HistoryUI | None = None,
        prompt: PromptFn | None = None,
    ) -> None:
        self._store = store if store is not None else HistoryStore()
        self._output = output if output is not None else _default_output
        self._launcher = launcher if launcher is not None else run_ssh
        self._page_size = max(5, page_size)
        self._ui = ui
        self._prompt = prompt if prompt is not None else typer.prompt

    def run(self) -> int:
        entries = self._store.load()
        if not entries:
            self._output(_DEF_MESSAGE_EMPTY)
            return 0

        session = HistorySession(entries, page_size=self._page_size)
        session.apply_filter("")
        ui = self._ui or self._build_ui()

        try:
            selection = ui.run(session)
        except RuntimeError as exc:
            self._output(str(exc))
            ui = PromptHistoryUI(self._prompt, self._output)
            selection = ui.run(session)

        if selection is None:
            return 0
        return self._launcher(selection)

    def _build_ui(self) -> HistoryUI:
        return CursesHistoryUI()


def _format_entry(entry: HistoryEntry) -> str:
    target = entry.hostname
    if entry.username:
        target = f"{entry.username}@{target}"
    if entry.port:
        target = f"{target}:{entry.port}"
    timestamp = _format_timestamp(entry.last_connected_at)
    return f"{target} — last connected {timestamp}"


def _format_timestamp(timestamp: datetime) -> str:
    localized = timestamp.astimezone()
    return localized.strftime("%Y-%m-%d %H:%M")


def _clamp(value: int, lower: int, upper: int) -> int:
    return max(lower, min(upper, value))


def launch_history_browser() -> int:
    return HistoryBrowser().run()


launch_history_menu = launch_history_browser
