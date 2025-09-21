"""Integration-style tests exercising the credential CLI commands."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from sshse.cli import creds as creds_module
from sshse.cli.app import app
from sshse.core.credentials import (
    CredentialStore,
    CredentialStoreError,
    DerivationType,
    InvalidKeyError,
)

runner = CliRunner()


def test_init_add_list_remove_workflow(tmp_path: Path) -> None:
    """End-to-end passphrase workflow covering CRUD operations."""

    store_path = tmp_path / "creds.json"

    init_result = runner.invoke(
        app,
        [
            "creds",
            "init",
            "--mode",
            "passphrase",
            "--passphrase",
            "hunter2",
            "--path",
            str(store_path),
        ],
    )
    assert init_result.exit_code == 0
    assert store_path.exists()

    add_result = runner.invoke(
        app,
        [
            "creds",
            "add",
            "--username",
            "alice",
            "--host",
            "example.com",
            "--password",
            "s3cret",
            "--passphrase",
            "hunter2",
            "--path",
            str(store_path),
        ],
    )
    assert add_result.exit_code == 0
    assert "added" in add_result.stdout.lower()

    list_result = runner.invoke(
        app,
        [
            "creds",
            "list",
            "--json",
            "--passphrase",
            "hunter2",
            "--path",
            str(store_path),
        ],
    )
    assert list_result.exit_code == 0
    payload = json.loads(list_result.stdout)
    assert payload == [
        {
            "hostname": "example.com",
            "host_pattern": None,
            "username": "alice",
            "password": "***",
        }
    ]

    remove_result = runner.invoke(
        app,
        [
            "creds",
            "remove",
            "--username",
            "alice",
            "--host",
            "example.com",
            "--passphrase",
            "hunter2",
            "--path",
            str(store_path),
        ],
    )
    assert remove_result.exit_code == 0

    empty_list = runner.invoke(
        app,
        [
            "creds",
            "list",
            "--passphrase",
            "hunter2",
            "--path",
            str(store_path),
        ],
    )
    assert empty_list.exit_code == 0
    assert "No credentials" in empty_list.stdout


def test_add_updates_existing_record(tmp_path: Path) -> None:
    """Adding the same identity twice should update the stored password."""

    store_path = tmp_path / "creds.json"

    runner.invoke(
        app,
        [
            "creds",
            "init",
            "--mode",
            "passphrase",
            "--passphrase",
            "first",
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
            "bob",
            "--host",
            "example.com",
            "--password",
            "initial",
            "--passphrase",
            "first",
            "--path",
            str(store_path),
        ],
    )

    update = runner.invoke(
        app,
        [
            "creds",
            "add",
            "--username",
            "bob",
            "--host",
            "example.com",
            "--password",
            "updated",
            "--passphrase",
            "first",
            "--path",
            str(store_path),
        ],
    )
    assert update.exit_code == 0
    assert "updated" in update.stdout.lower()

    store = CredentialStore(path=store_path)
    records = store.load_records_with_passphrase("first")
    assert records[0].password == "updated"


def test_rotate_key_to_new_passphrase(tmp_path: Path) -> None:
    """Rotating the master passphrase should invalidate the old secret."""

    store_path = tmp_path / "store.json"

    runner.invoke(
        app,
        [
            "creds",
            "init",
            "--mode",
            "passphrase",
            "--passphrase",
            "oldpass",
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
            "carol",
            "--host-pattern",
            "^db-.*$",
            "--password",
            "pw",
            "--passphrase",
            "oldpass",
            "--path",
            str(store_path),
        ],
    )

    rotate = runner.invoke(
        app,
        [
            "creds",
            "rotate-key",
            "--current-passphrase",
            "oldpass",
            "--new-passphrase",
            "newpass",
            "--path",
            str(store_path),
        ],
    )
    assert rotate.exit_code == 0

    store = CredentialStore(path=store_path)
    records = store.load_records_with_passphrase("newpass")
    assert records[0].username == "carol"

    with pytest.raises(InvalidKeyError):
        store.load_records_with_passphrase("oldpass")


def test_export_writes_json_file(tmp_path: Path) -> None:
    """Export should emit decrypted JSON and set secure permissions."""

    store_path = tmp_path / "creds.json"
    output_path = tmp_path / "dump.json"

    runner.invoke(
        app,
        [
            "creds",
            "init",
            "--mode",
            "passphrase",
            "--passphrase",
            "secret",
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
            "dave",
            "--host",
            "example.com",
            "--password",
            "pw",
            "--passphrase",
            "secret",
            "--path",
            str(store_path),
        ],
    )

    export = runner.invoke(
        app,
        [
            "creds",
            "export",
            "--passphrase",
            "secret",
            "--path",
            str(store_path),
            "--output",
            str(output_path),
            "--yes",
        ],
    )
    assert export.exit_code == 0
    assert output_path.exists()

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload[0]["password"] == "pw"

    if os.name == "posix":  # pragma: no cover - platform dependent
        mode = output_path.stat().st_mode & 0o777
        assert mode == 0o600


def test_init_interactive_prompts_passphrase(tmp_path: Path) -> None:
    """Interactive prompting should allow initializing without supplying secrets."""

    store_path = tmp_path / "creds.json"
    result = runner.invoke(
        app,
        ["creds", "init", "--mode", "passphrase", "--path", str(store_path)],
        input="promptpass\npromptpass\n",
    )
    assert result.exit_code == 0
    assert store_path.exists()


def test_list_with_wrong_passphrase(tmp_path: Path) -> None:
    """Providing the wrong passphrase should produce a clear error."""

    store_path = tmp_path / "creds.json"
    runner.invoke(
        app,
        [
            "creds",
            "init",
            "--mode",
            "passphrase",
            "--passphrase",
            "correct",
            "--path",
            str(store_path),
        ],
    )

    result = runner.invoke(
        app,
        [
            "creds",
            "list",
            "--passphrase",
            "wrong",
            "--path",
            str(store_path),
        ],
    )
    assert result.exit_code == 2
    assert "unable to decrypt" in result.stderr.lower()


def test_init_with_ssh_key_mode(tmp_path: Path) -> None:
    """Initialization should support deriving from an SSH private key."""

    key_path = tmp_path / "id_ecdsa"
    key_path.write_bytes(b"-----KEY-----\n0123\n")
    store_path = tmp_path / "creds.json"

    result = runner.invoke(
        app,
        [
            "creds",
            "init",
            "--mode",
            "ssh-key",
            "--ssh-key",
            str(key_path),
            "--path",
            str(store_path),
        ],
    )

    assert result.exit_code == 0
    store = CredentialStore(path=store_path)
    assert store.derivation_type() is DerivationType.SSH_KEY


def test_add_requires_single_target(tmp_path: Path) -> None:
    """Adding credentials must receive exactly one targeting flag."""

    store_path = tmp_path / "creds.json"
    runner.invoke(
        app,
        ["creds", "init", "--mode", "passphrase", "--passphrase", "pw", "--path", str(store_path)],
    )

    result = runner.invoke(
        app,
        [
            "creds",
            "add",
            "--username",
            "alice",
            "--host",
            "example.com",
            "--host-pattern",
            r"^example-.*$",
            "--passphrase",
            "pw",
            "--path",
            str(store_path),
        ],
    )

    assert result.exit_code == 2
    assert "exactly one" in result.stderr.lower()


def test_add_prompts_for_password_and_handles_blank(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A blank password supplied via prompt should abort the command."""

    store_path = tmp_path / "creds.json"
    runner.invoke(
        app,
        ["creds", "init", "--mode", "passphrase", "--passphrase", "pw", "--path", str(store_path)],
    )

    monkeypatch.setattr("sshse.cli.creds.typer.prompt", lambda *args, **kwargs: "")

    result = runner.invoke(
        app,
        [
            "creds",
            "add",
            "--username",
            "bob",
            "--host",
            "example.com",
            "--passphrase",
            "pw",
            "--path",
            str(store_path),
        ],
    )

    assert result.exit_code == 2
    assert "must not be empty" in result.stderr.lower()


def test_add_prompted_password_for_host_pattern(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Prompted passwords should be accepted and stored for host patterns."""

    store_path = tmp_path / "creds.json"
    runner.invoke(
        app,
        ["creds", "init", "--mode", "passphrase", "--passphrase", "pw", "--path", str(store_path)],
    )

    monkeypatch.setattr("sshse.cli.creds.typer.prompt", lambda *args, **kwargs: "prompted")

    result = runner.invoke(
        app,
        [
            "creds",
            "add",
            "--username",
            "cindy",
            "--host-pattern",
            r"^db-.*$",
            "--passphrase",
            "pw",
            "--path",
            str(store_path),
        ],
    )

    assert result.exit_code == 0
    runner.invoke(
        app,
        [
            "creds",
            "add",
            "--username",
            "dan",
            "--host",
            "other.example",
            "--password",
            "prompted",
            "--passphrase",
            "pw",
            "--path",
            str(store_path),
        ],
    )
    store = CredentialStore(path=store_path)
    records = store.load_records_with_passphrase("pw")
    assert records[0].host_pattern == r"^db-.*$"


def test_remove_nonexistent_credential(tmp_path: Path) -> None:
    """Removing a missing record should return a failure exit code."""

    store_path = tmp_path / "creds.json"
    runner.invoke(
        app,
        ["creds", "init", "--mode", "passphrase", "--passphrase", "pw", "--path", str(store_path)],
    )
    runner.invoke(
        app,
        [
            "creds",
            "add",
            "--username",
            "dave",
            "--host",
            "example.com",
            "--password",
            "pw",
            "--passphrase",
            "pw",
            "--path",
            str(store_path),
        ],
    )

    result = runner.invoke(
        app,
        [
            "creds",
            "remove",
            "--username",
            "dave",
            "--host",
            "missing.com",
            "--passphrase",
            "pw",
            "--path",
            str(store_path),
        ],
    )

    assert result.exit_code == 1
    assert "not found" in result.stderr.lower()


def test_remove_requires_single_target(tmp_path: Path) -> None:
    """Removal command should enforce mutually exclusive targeting flags."""

    store_path = tmp_path / "creds.json"
    runner.invoke(
        app,
        ["creds", "init", "--mode", "passphrase", "--passphrase", "pw", "--path", str(store_path)],
    )

    result = runner.invoke(
        app,
        [
            "creds",
            "remove",
            "--username",
            "any",
            "--host",
            "one",
            "--host-pattern",
            "two",
            "--passphrase",
            "pw",
            "--path",
            str(store_path),
        ],
    )

    assert result.exit_code == 2
    assert "exactly one" in result.stderr.lower()


def test_export_to_stdout(tmp_path: Path) -> None:
    """Export without an output file should print JSON to stdout."""

    store_path = tmp_path / "creds.json"
    runner.invoke(
        app,
        ["creds", "init", "--mode", "passphrase", "--passphrase", "pw", "--path", str(store_path)],
    )
    runner.invoke(
        app,
        [
            "creds",
            "add",
            "--username",
            "erin",
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

    export_result = runner.invoke(
        app,
        [
            "creds",
            "export",
            "--passphrase",
            "pw",
            "--path",
            str(store_path),
        ],
    )

    assert export_result.exit_code == 0
    assert "secret" in export_result.stdout


def test_export_overwrite_prompt_abort(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When overwrite is declined the command should abort gracefully."""

    store_path = tmp_path / "creds.json"
    output_path = tmp_path / "dump.json"

    runner.invoke(
        app,
        ["creds", "init", "--mode", "passphrase", "--passphrase", "pw", "--path", str(store_path)],
    )
    runner.invoke(
        app,
        [
            "creds",
            "add",
            "--username",
            "fran",
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

    output_path.write_text("existing", encoding="utf-8")

    def _abort(*args: object, **kwargs: object) -> bool:
        raise typer.Abort()

    monkeypatch.setattr("sshse.cli.creds.typer.confirm", _abort)

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
    )

    assert result.exit_code != 0


def test_export_overwrite_prompt_accept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Accepting the overwrite prompt should proceed with writing."""

    store_path = tmp_path / "creds.json"
    output_path = tmp_path / "dump.json"

    runner.invoke(
        app,
        ["creds", "init", "--mode", "passphrase", "--passphrase", "pw", "--path", str(store_path)],
    )
    runner.invoke(
        app,
        [
            "creds",
            "add",
            "--username",
            "gina",
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

    output_path.write_text("existing", encoding="utf-8")
    monkeypatch.setattr("sshse.cli.creds.typer.confirm", lambda *args, **kwargs: True)

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
    )

    assert result.exit_code == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))[0]["password"] == "secret"


def test_rotate_key_to_ssh_mode(tmp_path: Path) -> None:
    """Rotating to SSH key derivation should succeed."""

    store_path = tmp_path / "creds.json"
    new_key_path = tmp_path / "id_ed25519"
    new_key_path.write_bytes(b"-----BEGIN KEY-----\nabc\n")

    runner.invoke(
        app,
        ["creds", "init", "--mode", "passphrase", "--passphrase", "pw", "--path", str(store_path)],
    )
    runner.invoke(
        app,
        [
            "creds",
            "add",
            "--username",
            "hank",
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

    rotate_result = runner.invoke(
        app,
        [
            "creds",
            "rotate-key",
            "--to",
            "ssh-key",
            "--current-passphrase",
            "pw",
            "--new-ssh-key",
            str(new_key_path),
            "--path",
            str(store_path),
        ],
    )

    assert rotate_result.exit_code == 0

    store = CredentialStore(path=store_path)
    assert store.derivation_type() is DerivationType.SSH_KEY


def test_rotate_key_from_ssh_key_to_passphrase(tmp_path: Path) -> None:
    """Rotating from SSH key derivation should prompt for the key path."""

    store_path = tmp_path / "creds.json"
    key_path = tmp_path / "id_rsa"
    key_path.write_bytes(b"KEY")

    runner.invoke(
        app,
        [
            "creds",
            "init",
            "--mode",
            "ssh-key",
            "--ssh-key",
            str(key_path),
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
            "jack",
            "--host",
            "example.com",
            "--password",
            "pw",
            "--ssh-key",
            str(key_path),
            "--path",
            str(store_path),
        ],
    )

    rotate_result = runner.invoke(
        app,
        [
            "creds",
            "rotate-key",
            "--to",
            "passphrase",
            "--current-ssh-key",
            str(key_path),
            "--new-passphrase",
            "newpass",
            "--path",
            str(store_path),
        ],
    )

    assert rotate_result.exit_code == 0
    store = CredentialStore(path=store_path)
    assert store.derivation_type() is DerivationType.PASSPHRASE


def test_list_with_ssh_key_mode(tmp_path: Path) -> None:
    """Listing credentials should work for SSH-key derived stores."""

    store_path = tmp_path / "creds.json"
    key_path = tmp_path / "id_rsa"
    key_path.write_bytes(b"KEY")

    runner.invoke(
        app,
        [
            "creds",
            "init",
            "--mode",
            "ssh-key",
            "--ssh-key",
            str(key_path),
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
            "ivy",
            "--host",
            "example.com",
            "--password",
            "secret",
            "--ssh-key",
            str(key_path),
            "--path",
            str(store_path),
        ],
    )

    list_result = runner.invoke(
        app,
        [
            "creds",
            "list",
            "--ssh-key",
            str(key_path),
            "--path",
            str(store_path),
        ],
    )

    assert list_result.exit_code == 0
    assert "ivy" in list_result.stdout


def test_remove_with_ssh_key_mode(tmp_path: Path) -> None:
    """Removal should work when credentials are derived from an SSH key."""

    store_path = tmp_path / "creds.json"
    key_path = tmp_path / "id_ecdsa"
    key_path.write_bytes(b"KEY")

    runner.invoke(
        app,
        [
            "creds",
            "init",
            "--mode",
            "ssh-key",
            "--ssh-key",
            str(key_path),
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
            "luis",
            "--host",
            "example.com",
            "--password",
            "secret",
            "--ssh-key",
            str(key_path),
            "--path",
            str(store_path),
        ],
    )

    remove_result = runner.invoke(
        app,
        [
            "creds",
            "remove",
            "--username",
            "luis",
            "--host",
            "example.com",
            "--ssh-key",
            str(key_path),
            "--path",
            str(store_path),
        ],
    )

    assert remove_result.exit_code == 0


def test_add_handles_store_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """CredentialStoreError should be rendered gracefully during add."""

    class BrokenStore:
        def derivation_type(self) -> DerivationType:
            raise CredentialStoreError("boom")

    monkeypatch.setattr("sshse.cli.creds._resolve_store", lambda path: BrokenStore())

    result = runner.invoke(
        app,
        [
            "creds",
            "add",
            "--username",
            "alice",
            "--host",
            "example.com",
            "--password",
            "pw",
        ],
    )

    assert result.exit_code == 1
    assert "boom" in result.stderr


def test_list_handles_store_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Listing should surface store errors via the handler."""

    class BrokenStore:
        def derivation_type(self) -> DerivationType:
            raise CredentialStoreError("broken")

    monkeypatch.setattr("sshse.cli.creds._resolve_store", lambda path: BrokenStore())

    result = runner.invoke(app, ["creds", "list"])

    assert result.exit_code == 1
    assert "broken" in result.stderr


def test_remove_handles_store_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Removal should surface errors using the shared handler."""

    class BrokenStore:
        def derivation_type(self) -> DerivationType:
            raise CredentialStoreError("remove-error")

    monkeypatch.setattr("sshse.cli.creds._resolve_store", lambda path: BrokenStore())

    result = runner.invoke(
        app,
        [
            "creds",
            "remove",
            "--username",
            "alice",
            "--host",
            "example.com",
        ],
    )

    assert result.exit_code == 1
    assert "remove-error" in result.stderr


def test_rotate_handles_store_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Rotation should bail out cleanly when derivation lookup fails."""

    class BrokenStore:
        def derivation_type(self) -> DerivationType:
            raise CredentialStoreError("rotate-error")

    monkeypatch.setattr("sshse.cli.creds._resolve_store", lambda path: BrokenStore())

    result = runner.invoke(app, ["creds", "rotate-key"])

    assert result.exit_code == 1
    assert "rotate-error" in result.stderr


def test_export_handles_store_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Export should rely on the shared error reporting helper."""

    class BrokenStore:
        def derivation_type(self) -> DerivationType:
            raise CredentialStoreError("export-error")

    monkeypatch.setattr("sshse.cli.creds._resolve_store", lambda path: BrokenStore())

    result = runner.invoke(app, ["creds", "export"])

    assert result.exit_code == 1
    assert "export-error" in result.stderr


def test_init_handles_store_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Initialization should surface credential store errors."""

    class BrokenStore(CredentialStore):
        def initialize_with_passphrase(self, passphrase: str, *, overwrite: bool = False) -> None:
            raise CredentialStoreError("init-error")

    monkeypatch.setattr(
        "sshse.cli.creds._resolve_store",
        lambda path: BrokenStore(path=Path("dummy")),
    )

    result = runner.invoke(app, ["creds", "init", "--mode", "passphrase", "--passphrase", "pw"])

    assert result.exit_code == 1
    assert "init-error" in result.stderr


def test_init_store_direct_echo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Direct invocation of init_store should emit a success message."""

    store_path = tmp_path / "creds.json"
    monkeypatch.setattr(
        "sshse.cli.creds._resolve_store", lambda path: CredentialStore(path=store_path)
    )
    messages: list[str] = []
    monkeypatch.setattr("sshse.cli.creds.typer.echo", lambda msg, **kwargs: messages.append(msg))

    creds_module.init_store(
        mode=DerivationType.PASSPHRASE,
        passphrase="secret",
        path=store_path,
    )

    assert any("Credential store initialized" in message for message in messages)


def test_cli_init_defaults_to_ssh_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Calling init without options should derive the key from the default SSH path."""

    store_path = tmp_path / "creds.json"
    recorded: dict[str, object] = {}

    monkeypatch.setattr(
        "sshse.cli.creds._resolve_store", lambda path: CredentialStore(path=store_path)
    )

    def _fake_initialize(
        self: CredentialStore, private_key_path: Path, *, overwrite: bool = False
    ) -> None:
        recorded["path"] = private_key_path
        recorded["overwrite"] = overwrite

    monkeypatch.setattr(
        CredentialStore,
        "initialize_with_ssh_key",
        _fake_initialize,
        raising=False,
    )

    result = runner.invoke(app, ["creds", "init", "--force"])

    assert result.exit_code == 0
    assert recorded["path"] == creds_module.DEFAULT_SSH_KEY_PATH
    assert recorded["overwrite"] is True


def test_export_with_ssh_key_mode(tmp_path: Path) -> None:
    """Export should decrypt credentials from an SSH-key-derived store."""

    store_path = tmp_path / "creds.json"
    key_path = tmp_path / "id_ed25519"
    key_path.write_bytes(b"KEY")

    runner.invoke(
        app,
        [
            "creds",
            "init",
            "--mode",
            "ssh-key",
            "--ssh-key",
            str(key_path),
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
            "mila",
            "--host",
            "example.com",
            "--password",
            "pw",
            "--ssh-key",
            str(key_path),
            "--path",
            str(store_path),
        ],
    )

    export_result = runner.invoke(
        app,
        [
            "creds",
            "export",
            "--ssh-key",
            str(key_path),
            "--path",
            str(store_path),
        ],
    )

    assert export_result.exit_code == 0
    assert "example.com" in export_result.stdout


def test_rotate_handles_second_stage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Failures during rotation after mode detection should be reported."""

    class BrokenStore:
        def derivation_type(self) -> DerivationType:
            return DerivationType.PASSPHRASE

        def rotate_key_to_passphrase(self, **kwargs: object) -> None:
            raise CredentialStoreError("rotate-step")

        def rotate_key_to_ssh_key(self, **kwargs: object) -> None:
            raise CredentialStoreError("rotate-step")

    monkeypatch.setattr("sshse.cli.creds._resolve_store", lambda path: BrokenStore())
    monkeypatch.setattr(
        "sshse.cli.creds._prompt_for_passphrase", lambda provided, **kwargs: "current"
    )

    result = runner.invoke(app, ["creds", "rotate-key", "--new-passphrase", "new"])

    assert result.exit_code == 1
    assert "rotate-step" in result.stderr
