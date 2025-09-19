"""Tests for the interactive history menu used by the CLI."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sshse.cli.history_menu import HistoryMenu
from sshse.core.history import HistoryEntry, HistoryStore


class StubStore(HistoryStore):
    """History store that returns a fixed set of entries."""

    def __init__(self, entries: list[HistoryEntry]):
        self._entries = entries

    def load(self) -> list[HistoryEntry]:  # type: ignore[override]
        return list(self._entries)


def _make_entry(hostname: str, *, username: str | None = None, port: int | None = None) -> HistoryEntry:
    return HistoryEntry(
        hostname=hostname,
        username=username,
        port=port,
        last_connected_at=datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
    )


def test_history_menu_handles_empty_history(capsys: pytest.CaptureFixture[str]) -> None:
    """The menu should inform the user when there is no history to display."""

    menu = HistoryMenu(store=StubStore([]))
    exit_code = menu.run()
    captured = capsys.readouterr().out

    assert exit_code == 0
    assert "No SSH history" in captured


def test_history_menu_launches_selected_entry() -> None:
    """Selecting a valid entry should trigger the launcher with that entry."""

    entries = [
        _make_entry("alpha.example.com", username="root"),
        _make_entry("beta.example.com", username="deploy", port=2222),
    ]

    prompts = iter(["2"])
    launched: list[HistoryEntry] = []

    def fake_prompt(_: str) -> str:
        return next(prompts)

    def fake_launcher(entry: HistoryEntry) -> int:
        launched.append(entry)
        return 7

    menu = HistoryMenu(
        store=StubStore(entries),
        prompt=fake_prompt,
        output=lambda _: None,
        launcher=fake_launcher,
    )

    exit_code = menu.run()

    assert exit_code == 7
    assert launched == [entries[1]]


def test_history_menu_reprompts_on_invalid_choice() -> None:
    """Invalid selections should display feedback and prompt again."""

    entries = [_make_entry("gamma.example.com")]
    prompts = iter(["abc", "5", "1"])
    log: list[str] = []

    def fake_prompt(_: str) -> str:
        return next(prompts)

    def fake_output(message: str) -> None:
        log.append(message)

    def fake_launcher(_: HistoryEntry) -> int:
        return 0

    menu = HistoryMenu(
        store=StubStore(entries),
        prompt=fake_prompt,
        output=fake_output,
        launcher=fake_launcher,
    )

    exit_code = menu.run()

    assert exit_code == 0
    assert any("Invalid selection" in line for line in log)
