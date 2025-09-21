"""Configuration-related CLI commands."""

from __future__ import annotations

import json

import typer

from sshse.cli._shared import show_help_if_no_subcommand
from sshse.config import ConfigStore

config_app = typer.Typer(help="Manage application configuration")


@config_app.callback(invoke_without_command=True)
def config_root(ctx: typer.Context) -> None:
    """Display contextual help when no subcommand is provided."""

    show_help_if_no_subcommand(ctx)


@config_app.command("show")
def show_config() -> None:
    """Display the current application configuration."""

    store = ConfigStore()
    config = store.load()
    typer.echo(json.dumps(config.to_payload(), indent=2))


@config_app.command("add-shared-auth")
def add_shared_auth_pattern(
    pattern: str = typer.Argument(
        ...,
        metavar="PATTERN",
        help="Regular expression for hosts that share authentication context.",
    ),
) -> None:
    """Persist a shared authentication host pattern in the config file."""

    store = ConfigStore()
    config = store.load()
    try:
        added = config.add_shared_auth_host_pattern(pattern)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc
    store.save(config)
    if added:
        typer.echo(f"Added shared authentication pattern: {pattern}")
    else:
        typer.echo("Pattern already present; configuration unchanged.")


@config_app.command("remove-shared-auth")
def remove_shared_auth_pattern(
    pattern: str = typer.Argument(
        ...,
        metavar="PATTERN",
        help="Remove a regular expression previously added for shared authentication.",
    ),
) -> None:
    """Remove a configured shared authentication pattern if it exists."""

    store = ConfigStore()
    config = store.load()
    removed = config.remove_shared_auth_host_pattern(pattern)
    if not removed:
        typer.echo("Pattern was not configured.", err=True)
        raise typer.Exit(1)
    store.save(config)
    typer.echo(f"Removed shared authentication pattern: {pattern}")
