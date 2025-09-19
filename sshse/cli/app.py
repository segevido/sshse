"""Command-line interface stubs for the sshse application."""

from __future__ import annotations

import typer

app = typer.Typer(help="SSH Manager CLI (stub)")


def main() -> int:
    """Entry point for the sshse CLI.

    The placeholder implementation returns success without performing any actions.
    """
    return 0


if __name__ == "__main__":  # pragma: no cover - manual execution only
    raise SystemExit(main())
