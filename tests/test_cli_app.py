"""Basic smoke tests for the CLI skeleton."""

from __future__ import annotations

from typer import Typer

from sshse.cli.app import app, main


def test_app_is_typer_instance() -> None:
    """Ensure the CLI stub exposes a Typer application."""
    assert isinstance(app, Typer)


def test_main_returns_success() -> None:
    """Main entry point should return success without side effects."""
    assert main() == 0
