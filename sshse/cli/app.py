"""Command-line interface stubs for the sshse application."""

from __future__ import annotations

import sys
from collections.abc import Sequence

import typer

from sshse import __version__
from sshse.cli.config import config_app
from sshse.cli.creds import creds_app
from sshse.cli.history_browser import launch_history_browser
from sshse.cli.ssh_launcher import run_ssh
from sshse.core.history import HistoryStore

app = typer.Typer(help="SSH Manager CLI (stub)")
app.add_typer(config_app, name="config", help="Inspect and adjust configuration")
app.add_typer(creds_app, name="creds", help="Manage encrypted SSH credentials")


@app.callback(invoke_without_command=True)
def cli(
    ctx: typer.Context,
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

    if ctx.invoked_subcommand is not None or ctx.resilient_parsing:
        return

    if ctx.args:
        return

    exit_code = launch_history_browser()
    raise typer.Exit(exit_code)


def _connect_to_host(target: str) -> int:
    """Initiate an SSH session to the provided target."""

    hostname, username = _split_target(target)
    if not hostname:
        typer.echo("A host value must be supplied.", err=True)
        return 2

    store = HistoryStore()
    entry = store.record(hostname=hostname, username=username)
    return run_ssh(entry)


def _split_target(target: str) -> tuple[str, str | None]:
    """Split a target string into hostname and optional username parts."""

    if "@" not in target:
        return target, None

    username, _, hostname = target.partition("@")
    if username and hostname:
        return hostname, username
    return target, None


def _known_subcommand_names() -> set[str]:
    """Collect all registered top-level command names."""

    names: set[str] = {info.name for info in app.registered_commands if info.name is not None}
    names.update(name for info in app.registered_groups if (name := info.name) is not None)
    return names


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the sshse CLI."""

    args = list(argv) if argv is not None else list(sys.argv[1:])
    if args:
        first = args[0]
        if not first.startswith("-") and first not in _known_subcommand_names():
            return _connect_to_host(first)

    try:
        app(args=args, standalone_mode=False)
    except typer.Exit as exc:  # exit path already handled by Typer
        return exc.exit_code
    except Exception as exc:  # pragma: no cover - unexpected errors bubble to the shell
        typer.echo(str(exc), err=True)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - manual execution only
    raise SystemExit(main())
