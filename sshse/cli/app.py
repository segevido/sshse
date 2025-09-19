"""Command-line interface stubs for the sshse application."""

from __future__ import annotations

from typing import Sequence

import typer

from sshse import __version__

app = typer.Typer(help="SSH Manager CLI (stub)")


@app.callback(invoke_without_command=True)
def cli(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show the application's version and exit.",
        is_eager=True,
    ),
) -> None:
    """Handle top-level options for the CLI."""
    if version:
        typer.echo(__version__)
        raise typer.Exit()


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the sshse CLI."""

    try:
        app(args=list(argv) if argv is not None else None, standalone_mode=False)
    except typer.Exit as exc:  # exit path already handled by Typer
        return exc.exit_code
    except Exception as exc:  # pragma: no cover - unexpected errors bubble to the shell
        typer.echo(str(exc), err=True)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - manual execution only
    raise SystemExit(main())
