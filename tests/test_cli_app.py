"""Basic smoke tests for the CLI skeleton."""

from __future__ import annotations

from typing import Any

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
    assert main([]) == 0


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
