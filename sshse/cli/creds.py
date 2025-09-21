"""CLI commands for managing the encrypted credential store."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any, TypeVar

import typer

from sshse.cli._shared import show_help_if_no_subcommand
from sshse.core.credentials import (
    CredentialRecord,
    CredentialStore,
    CredentialStoreError,
    DerivationType,
    InvalidKeyError,
    default_credentials_path,
)

DEFAULT_SSH_KEY_PATH = Path("~/.ssh/id_rsa").expanduser()

creds_app = typer.Typer(help="Manage encrypted SSH credentials")

T = TypeVar("T")


def _scrub_secret(secret: str | None) -> None:
    """Best-effort attempt to redact sensitive values from memory."""

    if not secret:
        return
    buffer = bytearray(secret.encode("utf-8"))
    for idx in range(len(buffer)):
        buffer[idx] = 0


def _handle_error(exc: CredentialStoreError) -> None:
    """Render a user-friendly error and exit with appropriate code."""

    message = str(exc) or exc.__class__.__name__
    exit_code = 2 if isinstance(exc, InvalidKeyError) else 1
    typer.echo(message, err=True)
    raise typer.Exit(exit_code)


def _resolve_store(path: Path | None) -> CredentialStore:
    """Instantiate the credential store for a given path."""

    return CredentialStore(path=path if path is not None else default_credentials_path())


def _prompt_for_passphrase(
    provided: str | None,
    *,
    prompt_text: str,
    confirm: bool = False,
) -> str:
    """Obtain a passphrase either from CLI options or interactive input."""

    if provided is not None:
        if not provided:
            typer.echo("Passphrase must not be empty.", err=True)
            raise typer.Exit(2)
        return provided
    value = typer.prompt(prompt_text, hide_input=True, confirmation_prompt=confirm)
    if not value:
        typer.echo("Passphrase must not be empty.", err=True)
        raise typer.Exit(2)
    return value


def _prompt_for_ssh_key_path(
    provided: Path | None,
    *,
    prompt_text: str,
) -> Path:
    """Obtain an SSH private key path from options or interactive input."""

    if provided is not None:
        return provided
    value = typer.prompt(prompt_text, default=str(DEFAULT_SSH_KEY_PATH))
    path = Path(value).expanduser()
    return path


@contextmanager
def _store_session(
    store: CredentialStore,
    *,
    passphrase: str | None,
    ssh_key_path: Path | None,
    prompt_text: str = "Master passphrase",
) -> Iterator[tuple[DerivationType, str | None, Path | None]]:
    """Yield the derivation type and reusable secrets for the store."""

    mode = store.derivation_type()
    if mode is DerivationType.PASSPHRASE:
        secret = _prompt_for_passphrase(passphrase, prompt_text=prompt_text)
        try:
            yield mode, secret, None
        finally:
            _scrub_secret(secret)
    else:
        key_path = _prompt_for_ssh_key_path(ssh_key_path, prompt_text="Path to SSH private key")
        yield mode, None, key_path


def _record_identity(record: CredentialRecord) -> tuple[str, str | None, str | None]:
    """Return a tuple representing a record's identity for comparisons."""

    return (record.username, record.hostname, record.host_pattern)


def _require_value(value: T | None, message: str) -> T:
    """Ensure optional secrets are populated before proceeding."""

    if value is None:
        raise CredentialStoreError(message)
    return value


@creds_app.callback(invoke_without_command=True)
def creds_root(ctx: typer.Context) -> None:
    """Display contextual help when no credential subcommand is chosen."""

    show_help_if_no_subcommand(ctx)


@creds_app.command("init")
def init_store(
    mode: DerivationType = typer.Option(
        DerivationType.SSH_KEY,
        "--mode",
        help="Select passphrase or SSH key derivation for the master key.",
        case_sensitive=False,
    ),
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        help="Provide the master passphrase non-interactively (use with caution).",
    ),
    ssh_key: Path = typer.Option(
        DEFAULT_SSH_KEY_PATH,
        "--ssh-key",
        help="Path to the SSH private key used for key derivation.",
        show_default=str(DEFAULT_SSH_KEY_PATH),
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite an existing credential store.",
    ),
    path: Path | None = typer.Option(
        None,
        "--path",
        help="Location of the credential store file.",
    ),
) -> None:
    """Initialize a new encrypted credential store."""

    store = _resolve_store(path)

    try:
        if mode is DerivationType.PASSPHRASE:
            secret = _prompt_for_passphrase(
                passphrase,
                prompt_text="Master passphrase",
                confirm=True,
            )
            try:
                store.initialize_with_passphrase(secret, overwrite=force)
            finally:
                _scrub_secret(secret)
        else:
            key_path = _prompt_for_ssh_key_path(ssh_key, prompt_text="Path to SSH private key")
            store.initialize_with_ssh_key(key_path, overwrite=force)
    except CredentialStoreError as exc:
        _handle_error(exc)
    else:
        typer.echo(f"Credential store initialized at {store.path}")


@creds_app.command("add")
def add_record(
    username: str = typer.Option(..., "--username", help="Username for the credential."),
    host: str | None = typer.Option(
        None,
        "--host",
        help="Hostname this credential applies to.",
    ),
    host_pattern: str | None = typer.Option(
        None,
        "--host-pattern",
        help="Pattern matching hosts this credential applies to.",
    ),
    password: str | None = typer.Option(
        None,
        "--password",
        help="Password to store (omit to be prompted securely).",
    ),
    path: Path | None = typer.Option(
        None,
        "--path",
        help="Location of the credential store file.",
    ),
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        help="Passphrase for passphrase-derived stores.",
    ),
    ssh_key: Path | None = typer.Option(
        None,
        "--ssh-key",
        help="SSH private key path for key-derived stores.",
    ),
) -> None:
    """Add or update credentials for a host or host pattern."""

    if bool(host) == bool(host_pattern):
        typer.echo("Provide exactly one of --host or --host-pattern.", err=True)
        raise typer.Exit(2)

    store = _resolve_store(path)

    secret_password = password
    if secret_password is None:
        secret_password = typer.prompt("Password", hide_input=True)
        if not secret_password:
            typer.echo("Password must not be empty.", err=True)
            raise typer.Exit(2)

    record = CredentialRecord(
        username=username,
        password=secret_password,
        hostname=host,
        host_pattern=host_pattern,
    )

    replaced = False

    try:
        with _store_session(
            store,
            passphrase=passphrase,
            ssh_key_path=ssh_key,
        ) as (derivation, passphrase_secret, key_path):
            if derivation is DerivationType.PASSPHRASE:
                passphrase_secret = _require_value(passphrase_secret, "passphrase is required")
                existing_records = store.load_records_with_passphrase(passphrase_secret)
            else:
                key_path = _require_value(key_path, "ssh key path is required")
                existing_records = store.load_records_with_ssh_key(key_path)

            updated: list[CredentialRecord] = []
            target_identity = _record_identity(record)
            for item in existing_records:
                if _record_identity(item) == target_identity:
                    replaced = True
                    continue
                updated.append(item)
            updated.append(record)

            if derivation is DerivationType.PASSPHRASE:
                passphrase_secret = _require_value(passphrase_secret, "passphrase is required")
                store.save_records_with_passphrase(updated, passphrase_secret)
            else:
                key_path = _require_value(key_path, "ssh key path is required")
                store.save_records_with_ssh_key(updated, key_path)
    except CredentialStoreError as exc:
        _handle_error(exc)
    finally:
        _scrub_secret(secret_password)
    typer.echo("Credential updated." if replaced else "Credential added.")


@creds_app.command("list")
def list_records(
    path: Path | None = typer.Option(
        None,
        "--path",
        help="Location of the credential store file.",
    ),
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        help="Passphrase for passphrase-derived stores.",
    ),
    ssh_key: Path | None = typer.Option(
        None,
        "--ssh-key",
        help="SSH private key path for key-derived stores.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit credentials in JSON form with redacted secrets.",
    ),
) -> None:
    """List the credentials in the store without revealing passwords."""

    store = _resolve_store(path)

    try:
        with _store_session(
            store,
            passphrase=passphrase,
            ssh_key_path=ssh_key,
        ) as (derivation, passphrase_secret, key_path):
            if derivation is DerivationType.PASSPHRASE:
                passphrase_secret = _require_value(passphrase_secret, "passphrase is required")
                records = store.load_records_with_passphrase(passphrase_secret)
            else:
                key_path = _require_value(key_path, "ssh key path is required")
                records = store.load_records_with_ssh_key(key_path)
    except CredentialStoreError as exc:
        _handle_error(exc)

    entries = sorted(
        records,
        key=lambda item: (
            item.hostname or item.host_pattern or "",
            item.username,
        ),
    )

    if json_output:
        payload = [
            {
                "hostname": item.hostname,
                "host_pattern": item.host_pattern,
                "username": item.username,
                "password": "***",
            }
            for item in entries
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    if not entries:
        typer.echo("No credentials stored yet.")
        return

    for item in entries:
        target = item.hostname if item.hostname is not None else item.host_pattern
        typer.echo(f"{item.username}@{target} (password: ***)")


@creds_app.command("remove")
def remove_record(
    username: str = typer.Option(..., "--username", help="Username linked to the credential."),
    host: str | None = typer.Option(
        None,
        "--host",
        help="Hostname whose credentials should be deleted.",
    ),
    host_pattern: str | None = typer.Option(
        None,
        "--host-pattern",
        help="Host pattern whose credentials should be deleted.",
    ),
    path: Path | None = typer.Option(
        None,
        "--path",
        help="Location of the credential store file.",
    ),
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        help="Passphrase for passphrase-derived stores.",
    ),
    ssh_key: Path | None = typer.Option(
        None,
        "--ssh-key",
        help="SSH private key path for key-derived stores.",
    ),
) -> None:
    """Remove a credential entry from the store."""

    if bool(host) == bool(host_pattern):
        typer.echo("Provide exactly one of --host or --host-pattern.", err=True)
        raise typer.Exit(2)

    store = _resolve_store(path)

    try:
        with _store_session(
            store,
            passphrase=passphrase,
            ssh_key_path=ssh_key,
        ) as (derivation, passphrase_secret, key_path):
            if derivation is DerivationType.PASSPHRASE:
                passphrase_secret = _require_value(passphrase_secret, "passphrase is required")
                records = store.load_records_with_passphrase(passphrase_secret)
            else:
                key_path = _require_value(key_path, "ssh key path is required")
                records = store.load_records_with_ssh_key(key_path)

            target_identity = (username, host, host_pattern)
            updated = [item for item in records if _record_identity(item) != target_identity]

            if len(updated) == len(records):
                typer.echo("Credential not found.", err=True)
                raise typer.Exit(1)

            if derivation is DerivationType.PASSPHRASE:
                passphrase_secret = _require_value(passphrase_secret, "passphrase is required")
                store.save_records_with_passphrase(updated, passphrase_secret)
            else:
                key_path = _require_value(key_path, "ssh key path is required")
                store.save_records_with_ssh_key(updated, key_path)
    except CredentialStoreError as exc:
        _handle_error(exc)

    typer.echo("Credential removed.")


@creds_app.command("rotate-key")
def rotate_key(
    target: DerivationType = typer.Option(
        DerivationType.PASSPHRASE,
        "--to",
        help="Re-encrypt the store using this derivation type.",
        case_sensitive=False,
    ),
    path: Path | None = typer.Option(
        None,
        "--path",
        help="Location of the credential store file.",
    ),
    current_passphrase: str | None = typer.Option(
        None,
        "--current-passphrase",
        help="Current passphrase when the store uses passphrase derivation.",
    ),
    current_ssh_key: Path | None = typer.Option(
        None,
        "--current-ssh-key",
        help="Current SSH private key when the store uses key derivation.",
    ),
    new_passphrase: str | None = typer.Option(
        None,
        "--new-passphrase",
        help="New passphrase when rotating to passphrase derivation.",
    ),
    new_ssh_key: Path | None = typer.Option(
        None,
        "--new-ssh-key",
        help="New SSH private key path when rotating to key derivation.",
    ),
) -> None:
    """Re-encrypt the credential store with a new key."""

    store = _resolve_store(path)

    try:
        current_mode = store.derivation_type()
    except CredentialStoreError as exc:
        _handle_error(exc)

    secret: str | None = None
    secret_key_path: Path | None = None
    try:
        if current_mode is DerivationType.PASSPHRASE:
            secret = _prompt_for_passphrase(
                current_passphrase,
                prompt_text="Current passphrase",
            )
        else:
            secret_key_path = _prompt_for_ssh_key_path(
                current_ssh_key,
                prompt_text="Path to current SSH private key",
            )

        if current_mode is DerivationType.PASSPHRASE:
            secret = _require_value(secret, "current passphrase required")
            current_secret: str | Path = secret
        else:
            secret_key_path = _require_value(secret_key_path, "current SSH key path required")
            current_secret = secret_key_path

        if target is DerivationType.PASSPHRASE:
            new_secret = _prompt_for_passphrase(
                new_passphrase,
                prompt_text="New passphrase",
                confirm=True,
            )
            store.rotate_key_to_passphrase(
                current_secret=current_secret,
                new_passphrase=new_secret,
                current_uses_ssh_key=(current_mode is DerivationType.SSH_KEY),
            )
            _scrub_secret(new_secret)
        else:
            target_key_path = _prompt_for_ssh_key_path(
                new_ssh_key,
                prompt_text="Path to new SSH private key",
            )
            store.rotate_key_to_ssh_key(
                current_secret=current_secret,
                new_private_key_path=target_key_path,
                current_uses_ssh_key=(current_mode is DerivationType.SSH_KEY),
            )
    except CredentialStoreError as exc:
        _handle_error(exc)
    finally:
        if current_mode is DerivationType.PASSPHRASE:
            _scrub_secret(secret)

    typer.echo("Credential store key rotated.")


@creds_app.command("export")
def export_records(
    path: Path | None = typer.Option(
        None,
        "--path",
        help="Location of the credential store file.",
    ),
    passphrase: str | None = typer.Option(
        None,
        "--passphrase",
        help="Passphrase for passphrase-derived stores.",
    ),
    ssh_key: Path | None = typer.Option(
        None,
        "--ssh-key",
        help="SSH private key path for key-derived stores.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Optional file to receive exported credentials (JSON).",
    ),
    assume_yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip confirmation when writing to a file.",
    ),
) -> None:
    """Export decrypted credentials as JSON for external use."""

    store = _resolve_store(path)

    try:
        with _store_session(
            store,
            passphrase=passphrase,
            ssh_key_path=ssh_key,
        ) as (derivation, passphrase_secret, key_path):
            if derivation is DerivationType.PASSPHRASE:
                passphrase_secret = _require_value(passphrase_secret, "passphrase is required")
                records = store.load_records_with_passphrase(passphrase_secret)
            else:
                key_path = _require_value(key_path, "ssh key path is required")
                records = store.load_records_with_ssh_key(key_path)
    except CredentialStoreError as exc:
        _handle_error(exc)

    payload: list[dict[str, Any]] = [
        {
            "hostname": item.hostname,
            "host_pattern": item.host_pattern,
            "username": item.username,
            "password": item.password,
        }
        for item in records
    ]

    serialized = json.dumps(payload, indent=2)

    if output is None:
        typer.echo(serialized)
        return

    if output.exists() and not assume_yes:
        typer.confirm(f"Overwrite existing file at {output}?", abort=True)

    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(serialized)
    with suppress(PermissionError, NotImplementedError):  # pragma: no cover - platform specific
        os.chmod(output, 0o600)
    typer.echo(f"Credentials exported to {output}")
