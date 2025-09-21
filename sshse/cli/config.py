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
