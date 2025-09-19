"""Tests for the interactive history browser used by the CLI."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sshse.cli import history_browser as hb
from sshse.cli.history_browser import (
    HistoryBrowser,
    HistorySession,
    PromptHistoryUI,
    _clamp,
    launch_history_browser,
)
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


def test_history_session_navigation_when_empty() -> None:
    """Navigation helpers should gracefully handle empty result sets."""

    session = HistorySession([], page_size=1)
    session.apply_filter("anything")
    session.move_selection(1)

    assert session.selection_index == -1
    assert session.current() is None
    assert session.page_bounds() == (0, session.page_size)


def test_prompt_ui_handles_interrupt() -> None:
    """EOF during prompting should return without launching a session."""

    log: list[str] = []
    session = HistorySession([_make_entry("alpha")], page_size=5)

    def raise_eof(_: str) -> str:
        raise EOFError

    ui = PromptHistoryUI(prompt=raise_eof, output=log.append)

    assert ui.run(session) is None
    assert log[-1] == ""


def test_prompt_ui_accepts_current_selection_on_enter() -> None:
    """Submitting an empty string should accept the highlighted entry."""

    prompts = iter([""])
    session = HistorySession([_make_entry("alpha")], page_size=5)

    def fake_prompt(_: str) -> str:
        return next(prompts)

    ui = PromptHistoryUI(prompt=fake_prompt, output=lambda _: None)

    entry = ui.run(session)
    assert entry is not None
    assert entry.hostname == "alpha"


def test_prompt_ui_handles_quit_commands() -> None:
    """Entering quit keywords should abort the session."""

    prompts = iter(["q"])
    session = HistorySession([_make_entry("alpha")], page_size=5)

    def fake_prompt(_: str) -> str:
        return next(prompts)

    ui = PromptHistoryUI(prompt=fake_prompt, output=lambda _: None)

    assert ui.run(session) is None


def test_prompt_ui_render_reports_remaining_results() -> None:
    """The renderer should advertise when additional results are available."""

    entries = [_make_entry(f"host-{idx}") for idx in range(7)]
    session = HistorySession(entries, page_size=5)
    session.apply_filter("")

    log: list[str] = []
    ui = PromptHistoryUI(prompt=lambda _: "", output=log.append)
    ui._render(session)

    assert any("more" in line for line in log)


def test_history_browser_recovers_from_runtime_error() -> None:
    """Runtime errors from the primary UI should trigger the prompt fallback."""

    entries = [_make_entry("alpha")]
    log: list[str] = []
    prompts = iter(["q"])

    class ExplodingUI:
        def run(self, session: HistorySession) -> HistoryEntry | None:
            raise RuntimeError("boom")

    def fake_prompt(_: str) -> str:
        return next(prompts)

    browser = HistoryBrowser(
        store=StubStore(entries),
        output=log.append,
        launcher=lambda _: 99,
        ui=ExplodingUI(),
        prompt=fake_prompt,
    )

    exit_code = browser.run()

    assert exit_code == 0
    assert any("boom" in line for line in log)


def test_history_browser_build_ui_returns_curses_ui() -> None:
    """The browser should fabricate a curses UI when needed."""

    browser = HistoryBrowser(store=StubStore([_make_entry("alpha")]), ui=None)
    ui = browser._build_ui()
    assert isinstance(ui, hb.CursesHistoryUI)


def test_launch_history_browser_uses_history_browser(monkeypatch: pytest.MonkeyPatch) -> None:
    """The module-level launcher should delegate to HistoryBrowser."""

    calls: list[str] = []

    class DummyBrowser:
        def __init__(self) -> None:
            calls.append("init")

        def run(self) -> int:
            calls.append("run")
            return 13

    monkeypatch.setattr(hb, "HistoryBrowser", DummyBrowser)

    exit_code = launch_history_browser()

    assert exit_code == 13
    assert calls == ["init", "run"]


def test_history_session_move_selection_clamps_bounds() -> None:
    """Selection changes should clamp to the available range."""

    entries = [_make_entry("one"), _make_entry("two"), _make_entry("three")]
    session = HistorySession(entries, page_size=5)
    session.apply_filter("")
    session.move_selection(5)
    assert session.selection_index == 2
    session.move_selection(-10)
    assert session.selection_index == 0


def test_prompt_ui_skips_when_no_current_entry() -> None:
    """Empty selections should loop until a valid choice is made."""

    prompts = iter(["", "q"])
    log: list[str] = []
    session = HistorySession([], page_size=5)

    def fake_prompt(_: str) -> str:
        return next(prompts)

    ui = PromptHistoryUI(prompt=fake_prompt, output=log.append)

    assert ui.run(session) is None
    assert any("No entries" in line for line in log)


def test_prompt_ui_handles_missing_entry_after_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    """If a selection disappears the UI should prompt again gracefully."""

    prompts = iter(["1", "q"])
    log: list[str] = []
    session = HistorySession([_make_entry("alpha")], page_size=5)
    original_method = hb.HistorySession.current
    calls = {"count": 0}

    def fake_current(self: hb.HistorySession) -> HistoryEntry | None:
        if self is session:
            calls["count"] += 1
            if calls["count"] == 1:
                return None
        return original_method(self)

    monkeypatch.setattr(hb.HistorySession, "current", fake_current)

    def fake_prompt(_: str) -> str:
        return next(prompts)

    ui = PromptHistoryUI(prompt=fake_prompt, output=log.append)

    assert ui.run(session) is None
    assert any("Invalid selection" in line for line in log)


def test_prompt_ui_reports_invalid_selection_direct() -> None:
    """Typing an out-of-range number should display feedback immediately."""

    prompts = iter(["5", "q"])
    log: list[str] = []
    session = HistorySession([_make_entry("alpha")], page_size=5)

    def fake_prompt(_: str) -> str:
        return next(prompts)

    ui = PromptHistoryUI(prompt=fake_prompt, output=log.append)

    assert ui.run(session) is None
    assert any("Invalid selection" in line for line in log)


def test_clamp_bounds_values() -> None:
    """The clamp helper should confine values to the requested bounds."""

    assert _clamp(10, 0, 5) == 5
    assert _clamp(-3, 0, 5) == 0
    assert _clamp(3, 0, 5) == 3
