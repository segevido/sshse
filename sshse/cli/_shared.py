"""Shared helpers for Typer-based CLI components."""

from __future__ import annotations

import typer


def show_help_if_no_subcommand(ctx: typer.Context) -> None:
    """Emit contextual help when a subcommand is not provided."""

    if ctx.invoked_subcommand or ctx.resilient_parsing:
        return
    typer.echo(ctx.get_help())
    raise typer.Exit()
