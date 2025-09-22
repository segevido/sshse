"""End-to-end CLIRunners for the credential CLI to cover direct Typer formatting."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from sshse.cli.app import app

runner = CliRunner()


def test_init_command_outputs_success(tmp_path: Path) -> None:
    """Running the init command should emit a success message."""

    store_path = tmp_path / "creds.json"

    result = runner.invoke(
        app,
        [
            "creds",
            "init",
            "--mode",
            "passphrase",
            "--passphrase",
            "prompted",
            "--path",
            str(store_path),
        ],
    )

    assert result.exit_code == 0
    assert "initialized" in result.stdout.lower()


def test_export_overwrite_confirmation(tmp_path: Path) -> None:
    """Declining the overwrite prompt should abort the export command."""

    store_path = tmp_path / "creds.json"
    output_path = tmp_path / "export.json"

    runner.invoke(
        app,
        [
            "creds",
            "init",
            "--mode",
            "passphrase",
            "--passphrase",
            "pw",
            "--path",
            str(store_path),
        ],
    )
    runner.invoke(
        app,
        [
            "creds",
            "add",
            "--username",
            "alice",
            "--host",
            "example.com",
            "--password",
            "secret",
            "--passphrase",
            "pw",
            "--path",
            str(store_path),
        ],
    )
    output_path.write_text(json.dumps([{"username": "bob"}]), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "creds",
            "export",
            "--passphrase",
            "pw",
            "--path",
            str(store_path),
            "--output",
            str(output_path),
        ],
        input="n\n",
    )

    assert result.exit_code != 0
    assert "overwrite" in result.stdout.lower()
