"""Basic smoke tests for the CLI skeleton."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import typer
from typer import Typer
from typer.main import TyperCommand
from typer.testing import CliRunner

from sshse import __version__
from sshse.cli.app import app, main
from sshse.core.history import HistoryEntry

cli_module = importlib.import_module("sshse.cli.app")

runner = CliRunner()


def test_app_is_typer_instance() -> None:
    """Ensure the CLI stub exposes a Typer application."""
    assert isinstance(app, Typer)


def test_main_returns_success() -> None:
    """Main entry point should return success for default invocation."""
    calls: list[int] = []

    def _fake_menu() -> int:
        calls.append(1)
        return 0

    module = importlib.import_module("sshse.cli.app")
    original = module.launch_history_browser
    module.launch_history_browser = _fake_menu  # type: ignore[attr-defined]
    try:
        assert main([]) == 0
        assert len(calls) == 1
    finally:
        module.launch_history_browser = original  # type: ignore[attr-defined]


def test_main_handles_version_flag(capsys: Any) -> None:
    """Entry point should surface version output when flags are provided."""
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == __version__


def test_version_option_outputs_package_version() -> None:
    """The CLI should emit the package version when requested."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_short_version_flag_alias() -> None:
    """Short flag should behave identically to the long option."""
    result = runner.invoke(app, ["-V"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_main_connects_direct_host(monkeypatch: Any) -> None:
    """Providing a host argument should trigger an SSH launch."""

    recorded: dict[str, Any] = {}

    class DummyStore:
        def __init__(self) -> None:
            recorded["store"] = self
            self.calls: list[tuple[str, str | None]] = []

        def record(
            self,
            hostname: str,
            *,
            username: str | None = None,
            port: int | None = None,
        ) -> HistoryEntry:
            self.calls.append((hostname, username))
            return HistoryEntry(hostname=hostname, username=username, port=port)

    def fake_run(entry: HistoryEntry) -> int:
        recorded["entry"] = entry
        return 0

    module = importlib.import_module("sshse.cli.app")
    monkeypatch.setattr(module, "HistoryStore", lambda: DummyStore())
    monkeypatch.setattr(module, "run_ssh", fake_run)

    exit_code = main(["alice@example.com"])

    assert exit_code == 0
    store = recorded["store"]
    assert store.calls == [("example.com", "alice")]
    entry = recorded["entry"]
    assert entry.hostname == "example.com"
    assert entry.username == "alice"


def test_cli_skips_when_subcommand_invoked() -> None:
    """The callback should exit early when a subcommand is requested."""

    ctx = typer.Context(TyperCommand(app))
    ctx.invoked_subcommand = "dummy"

    assert cli_module.cli(ctx, version=False) is None


def test_connect_to_host_requires_hostname(capsys: Any) -> None:
    """Connecting without a hostname should report an error and exit code."""

    exit_code = cli_module._connect_to_host("")

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "must be supplied" in captured.err


def test_split_target_variants() -> None:
    """Target parsing should handle usernames and malformed inputs."""

    assert cli_module._split_target("server") == ("server", None)
    assert cli_module._split_target("user@server") == ("server", "user")
    assert cli_module._split_target("user@") == ("user@", None)


def test_main_returns_exit_code_from_typer_exit(monkeypatch: Any) -> None:
    """When Typer raises Exit the captured code should be returned."""

    def fake_app(*args: Any, **kwargs: Any) -> Any:
        raise typer.Exit(code=5)

    monkeypatch.setattr(cli_module, "app", fake_app)
    assert cli_module.main([]) == 5


def test_module_run_invokes_cli_main(monkeypatch: Any) -> None:
    """The module-level run helper should delegate to the CLI entry point."""

    calls: dict[str, Any] = {}

    def fake_main(argv: Any | None = None) -> int:
        calls["argv"] = argv
        return 7

    monkeypatch.setattr(cli_module, "main", fake_main)
    from sshse.__main__ import run

    assert run() == 7
    assert calls["argv"] is None


def test_config_cli_add_show_and_remove(tmp_path: Path, monkeypatch: Any) -> None:
    """Config subcommands should manage shared auth patterns on disk."""

    monkeypatch.setattr("sshse.config.user_data_path", lambda _: tmp_path)

    add_result = runner.invoke(app, ["config", "add-shared-auth", r"^prod-.*$"])
    assert add_result.exit_code == 0
    config_path = tmp_path / "config.json"
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["shared_auth_host_patterns"] == [r"^prod-.*$"]

    show_result = runner.invoke(app, ["config", "show"])
    assert show_result.exit_code == 0
    assert r"^prod-.*$" in show_result.stdout

    remove_result = runner.invoke(app, ["config", "remove-shared-auth", r"^prod-.*$"])
    assert remove_result.exit_code == 0
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload["shared_auth_host_patterns"] == []

    missing_result = runner.invoke(app, ["config", "remove-shared-auth", r"^prod-.*$"])
    assert missing_result.exit_code == 1
    assert "not configured" in missing_result.stderr


def test_config_cli_add_duplicate_pattern(tmp_path: Path, monkeypatch: Any) -> None:
    """Re-adding an existing pattern should report a no-op."""

    monkeypatch.setattr("sshse.config.user_data_path", lambda _: tmp_path)

    runner.invoke(app, ["config", "add-shared-auth", "pattern"])
    duplicate = runner.invoke(app, ["config", "add-shared-auth", "pattern"])

    assert duplicate.exit_code == 0
    assert "already present" in duplicate.stdout


def test_config_cli_rejects_empty_pattern(tmp_path: Path, monkeypatch: Any) -> None:
    """Adding a blank pattern via the CLI should fail with an error."""

    monkeypatch.setattr("sshse.config.user_data_path", lambda _: tmp_path)

    result = runner.invoke(app, ["config", "add-shared-auth", "   "])
    assert result.exit_code == 2
    assert "must not be empty" in result.stderr
