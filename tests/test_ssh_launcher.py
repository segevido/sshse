"""Unit tests for CLI SSH launching helpers."""

from __future__ import annotations

from typing import Any

import pytest

from sshse.cli import ssh_launcher
from sshse.core.history import HistoryEntry


def test_build_command_includes_username_and_port() -> None:
    """The generated command should reflect entry metadata."""

    entry = HistoryEntry(hostname="example.com", username="alice", port=2222)

    command = ssh_launcher.build_ssh_command(entry)

    assert command == ["ssh", "alice@example.com", "-p", "2222"]


def test_run_ssh_invokes_subprocess(monkeypatch: Any) -> None:
    """run_ssh should delegate to subprocess.call with the built command."""

    entry = HistoryEntry(hostname="example.com")
    captured: dict[str, Any] = {}

    def fake_call(command: list[str]) -> int:
        captured["command"] = command
        return 42

    monkeypatch.setattr(ssh_launcher.subprocess, "call", fake_call)

    exit_code = ssh_launcher.run_ssh(entry)

    assert exit_code == 42
    assert captured["command"] == ["ssh", "example.com"]


def test_run_ssh_handles_missing_binary(
    monkeypatch: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A missing ssh binary should produce a friendly error."""

    entry = HistoryEntry(hostname="example.com")

    def fake_call(_: list[str]) -> int:
        raise FileNotFoundError

    monkeypatch.setattr(ssh_launcher.subprocess, "call", fake_call)

    exit_code = ssh_launcher.run_ssh(entry)

    assert exit_code == 1
    assert "ssh command not found" in capsys.readouterr().err
