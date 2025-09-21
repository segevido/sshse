"""Focused tests for helper functions in the credentials CLI module."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer

from sshse.cli import creds
from sshse.core.credentials import DerivationType


def test_scrub_secret_noop_for_none() -> None:
    """Passing ``None`` to the scrubber should be a no-op."""

    creds._scrub_secret(None)


def test_prompt_for_passphrase_rejects_empty_input(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty passphrases provided directly should raise a usage error."""

    with pytest.raises(typer.Exit):
        creds._prompt_for_passphrase("", prompt_text="passphrase")

    monkeypatch.setattr("sshse.cli.creds.typer.prompt", lambda *args, **kwargs: "")
    with pytest.raises(typer.Exit):
        creds._prompt_for_passphrase(None, prompt_text="passphrase")


def test_prompt_for_ssh_key_path_prompts_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """When no path is provided the helper should prompt the user with a default."""

    called: dict[str, object] = {}

    def _fake_prompt(message: str, **kwargs: object) -> str:
        called["message"] = message
        called["default"] = kwargs.get("default")
        return "~/id_rsa"

    monkeypatch.setattr("sshse.cli.creds.typer.prompt", _fake_prompt)
    result = creds._prompt_for_ssh_key_path(None, prompt_text="Key path")
    assert result == Path("~/id_rsa").expanduser()
    assert called["message"] == "Key path"
    assert called["default"] == str(creds.DEFAULT_SSH_KEY_PATH)


def test_store_session_handles_both_derivation_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The context manager should surface both passphrase and SSH secrets."""

    class DummyStore:
        def __init__(self, mode: DerivationType) -> None:
            self._mode = mode

        def derivation_type(self) -> DerivationType:
            return self._mode

    monkeypatch.setattr(
        "sshse.cli.creds._prompt_for_passphrase",
        lambda provided, **kwargs: provided or "prompted-passphrase",
    )
    with creds._store_session(
        DummyStore(DerivationType.PASSPHRASE), passphrase="secret", ssh_key_path=None
    ) as (
        mode,
        passphrase,
        key,
    ):
        assert mode is DerivationType.PASSPHRASE
        assert passphrase == "secret"
        assert key is None

    monkeypatch.setattr(
        "sshse.cli.creds._prompt_for_ssh_key_path",
        lambda provided, **kwargs: Path("/tmp/id_ed25519"),
    )
    with creds._store_session(
        DummyStore(DerivationType.SSH_KEY), passphrase=None, ssh_key_path=None
    ) as (
        mode,
        passphrase,
        key,
    ):
        assert mode is DerivationType.SSH_KEY
        assert passphrase is None
        assert key == Path("/tmp/id_ed25519")


def test_require_value_raises_for_missing_data() -> None:
    """_require_value should raise when provided with ``None``."""

    with pytest.raises(creds.CredentialStoreError):
        creds._require_value(None, "missing value")
