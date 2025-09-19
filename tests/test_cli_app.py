"""Basic smoke tests for the CLI skeleton."""

from __future__ import annotations

from typing import Any

import importlib

from typer import Typer
from typer.testing import CliRunner

from sshse import __version__
from sshse.cli.app import app, main

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
    original = module.launch_history_menu
    module.launch_history_menu = _fake_menu  # type: ignore[attr-defined]
    try:
        assert main([]) == 0
        assert len(calls) == 1
    finally:
        module.launch_history_menu = original  # type: ignore[attr-defined]


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
