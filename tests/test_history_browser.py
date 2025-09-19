"""Tests for the interactive history browser used by the CLI."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sshse.cli.history_browser import HistoryBrowser, HistorySession, PromptHistoryUI
from sshse.core.history import HistoryEntry, HistoryStore


class StubStore(HistoryStore):
    """History store that returns a fixed set of entries."""

    def __init__(self, entries: list[HistoryEntry]):
        self._entries = entries

    def load(self) -> list[HistoryEntry]:  # type: ignore[override]
        return list(self._entries)


def _make_entry(
    hostname: str,
    *,
    username: str | None = None,
    port: int | None = None,
) -> HistoryEntry:
    return HistoryEntry(
        hostname=hostname,
        username=username,
        port=port,
        last_connected_at=datetime(2024, 1, 1, 12, 0, tzinfo=UTC),
    )


def test_history_browser_handles_empty_history(capsys: pytest.CaptureFixture[str]) -> None:
    """The browser should inform the user when there is no history to display."""

    browser = HistoryBrowser(store=StubStore([]))
    exit_code = browser.run()
    captured = capsys.readouterr().out

    assert exit_code == 0
    assert "No SSH history" in captured

def test_history_browser_filters_and_launches_selected_entry() -> None:
    """Filtering the list should narrow the options before launching the entry."""

    entries = [
        _make_entry("alpha.internal", username="root"),
        _make_entry("prod-db.example.com", username="deploy", port=2222),
        _make_entry("staging-app.example.com", username="service"),
    ]

    prompts = iter(["prod", "1"])
    launched: list[HistoryEntry] = []
    log: list[str] = []

    def fake_prompt(_: str) -> str:
        return next(prompts)

    def fake_output(message: str) -> None:
        log.append(message)

    def fake_launcher(entry: HistoryEntry) -> int:
        launched.append(entry)
        return 42

    ui = PromptHistoryUI(prompt=fake_prompt, output=fake_output)
    browser = HistoryBrowser(
        store=StubStore(entries),
        output=fake_output,
        launcher=fake_launcher,
        ui=ui,
    )

    exit_code = browser.run()

    assert exit_code == 42
    assert launched == [entries[1]]
    assert any("filter: 'prod'" in line for line in log)


def test_history_browser_clear_resets_filter_before_launch() -> None:
    """Entering 'clear' should restore the full list and its numbering."""

    entries = [
        _make_entry("alpha.internal"),
        _make_entry("beta.internal"),
        _make_entry("gamma.internal"),
    ]

    prompts = iter(["beta", "clear", "3"])
    launched: list[HistoryEntry] = []

    def fake_prompt(_: str) -> str:
        return next(prompts)

    def fake_launcher(entry: HistoryEntry) -> int:
        launched.append(entry)
        return 5

    ui = PromptHistoryUI(prompt=fake_prompt, output=lambda _: None)
    browser = HistoryBrowser(
        store=StubStore(entries),
        output=lambda _: None,
        launcher=fake_launcher,
        ui=ui,
    )

    exit_code = browser.run()

    assert exit_code == 5
    assert launched == [entries[2]]


def test_history_browser_reprompts_on_invalid_choice() -> None:
    """Invalid selections should display feedback and prompt again."""

    entries = [_make_entry("gamma.example.com")]
    prompts = iter(["5", "1"])
    log: list[str] = []

    def fake_prompt(_: str) -> str:
        return next(prompts)

    def fake_output(message: str) -> None:
        log.append(message)

    def fake_launcher(_: HistoryEntry) -> int:
        return 0

    ui = PromptHistoryUI(prompt=fake_prompt, output=fake_output)
    browser = HistoryBrowser(
        store=StubStore(entries),
        output=fake_output,
        launcher=fake_launcher,
        ui=ui,
    )

    exit_code = browser.run()

    assert exit_code == 0
    assert any("Invalid selection" in line for line in log)


def test_history_browser_guides_when_no_matches() -> None:
    """When a filter matches nothing the user should see a helpful hint."""

    entries = [_make_entry("delta.example.com")]
    prompts = iter(["prod", "clear", "1"])
    log: list[str] = []

    def fake_prompt(_: str) -> str:
        return next(prompts)

    def fake_output(message: str) -> None:
        log.append(message)

    def fake_launcher(_: HistoryEntry) -> int:
        return 0

    ui = PromptHistoryUI(prompt=fake_prompt, output=fake_output)
    browser = HistoryBrowser(
        store=StubStore(entries),
        output=fake_output,
        launcher=fake_launcher,
        ui=ui,
    )

    exit_code = browser.run()

    assert exit_code == 0
    assert any("No matches" in line for line in log)


def test_history_session_filters_on_username_and_port() -> None:
    """Filtering should match against username and port metadata."""

    entries = [
        _make_entry("alpha.example.com", username="admin", port=22),
        _make_entry("beta.example.com", username="deploy", port=2222),
        _make_entry("gamma.example.com", username="service", port=2200),
    ]

    session = HistorySession(entries, page_size=10)
    session.apply_filter("deploy 2222")

    filtered_hosts = [entry.hostname for entry in session.filtered()]
    assert filtered_hosts == ["beta.example.com"]
