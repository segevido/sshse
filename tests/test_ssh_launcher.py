"""Unit tests for CLI SSH launching helpers."""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from sshse.cli import ssh_launcher
from sshse.core.history import HistoryEntry


def test_build_command_includes_username_and_port() -> None:
    """The generated command should reflect entry metadata."""

    entry = HistoryEntry(hostname="example.com", username="alice", port=2222)

    command = ssh_launcher.build_ssh_command(entry)

    assert command == ["ssh", "alice@example.com", "-p", "2222"]


def test_run_ssh_invokes_spawn(monkeypatch: Any) -> None:
    """run_ssh should invoke the spawn helper with the resolved ssh binary."""

    entry = HistoryEntry(hostname="example.com")
    captured: dict[str, Any] = {}

    def fake_which(_: str) -> str:
        return "/usr/bin/ssh"

    def fake_spawn(argv: list[str]) -> int:
        captured["argv"] = list(argv)
        return 42 << 8

    monkeypatch.setattr(ssh_launcher.shutil, "which", fake_which)
    monkeypatch.setattr(ssh_launcher, "_spawn_ssh", fake_spawn)

    exit_code = ssh_launcher.run_ssh(entry)

    assert exit_code == 42
    assert captured["argv"] == ["/usr/bin/ssh", "example.com"]


def test_run_ssh_handles_missing_binary(
    monkeypatch: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A missing ssh binary should produce a friendly error."""

    entry = HistoryEntry(hostname="example.com")

    monkeypatch.setattr(ssh_launcher.shutil, "which", lambda _: None)

    exit_code = ssh_launcher.run_ssh(entry)

    assert exit_code == 1
    assert "ssh command not found" in capsys.readouterr().err


def test_normalize_exit_status_prefers_waitstatus(monkeypatch: Any) -> None:
    """When available, waitstatus_to_exitcode should be preferred."""

    monkeypatch.setattr(ssh_launcher.os, "waitstatus_to_exitcode", lambda status: status // 256)
    assert ssh_launcher._normalize_exit_status(256) == 1


def test_normalize_exit_status_uses_wait_macros(monkeypatch: Any) -> None:
    """Fallback should rely on POSIX wait macros when available."""

    monkeypatch.setattr(ssh_launcher.os, "waitstatus_to_exitcode", None, raising=False)
    monkeypatch.setattr(ssh_launcher.os, "WIFEXITED", lambda status: True)
    monkeypatch.setattr(ssh_launcher.os, "WEXITSTATUS", lambda status: 17)
    assert ssh_launcher._normalize_exit_status(0x1100) == 17


def test_normalize_exit_status_for_signals(monkeypatch: Any) -> None:
    """Signal termination should map to the conventional 128+signal code."""

    monkeypatch.setattr(ssh_launcher.os, "waitstatus_to_exitcode", None, raising=False)
    monkeypatch.setattr(ssh_launcher.os, "WIFEXITED", lambda status: False)
    monkeypatch.setattr(ssh_launcher.os, "WIFSIGNALED", lambda status: True)
    monkeypatch.setattr(ssh_launcher.os, "WTERMSIG", lambda status: 9)
    assert ssh_launcher._normalize_exit_status(0) == 137


def test_normalize_exit_status_passthrough(monkeypatch: Any) -> None:
    """When helpers are unavailable the original status should be returned."""

    monkeypatch.setattr(ssh_launcher.os, "waitstatus_to_exitcode", None, raising=False)
    monkeypatch.setattr(ssh_launcher.os, "WIFEXITED", lambda status: False)
    monkeypatch.setattr(ssh_launcher.os, "WIFSIGNALED", lambda status: False)
    assert ssh_launcher._normalize_exit_status(99) == 99


def test_normalize_exit_status_when_termsig_missing(monkeypatch: Any) -> None:
    """If the platform lacks WTERMSIG the raw status should be returned."""

    monkeypatch.setattr(ssh_launcher.os, "waitstatus_to_exitcode", None, raising=False)
    monkeypatch.setattr(ssh_launcher.os, "WIFEXITED", lambda status: False)
    monkeypatch.setattr(ssh_launcher.os, "WIFSIGNALED", lambda status: True)
    monkeypatch.setattr(ssh_launcher.os, "WTERMSIG", None, raising=False)
    assert ssh_launcher._normalize_exit_status(255) == 255


def test_spawn_ssh_imports_pty(monkeypatch: Any) -> None:
    """_spawn_ssh should delegate to the platform PTY implementation."""

    captured: dict[str, Any] = {}

    def fake_spawn(argv: list[str]) -> int:
        captured["argv"] = list(argv)
        return 23

    module = types.SimpleNamespace(spawn=fake_spawn)
    monkeypatch.setitem(sys.modules, "pty", module)

    assert ssh_launcher._spawn_ssh(["ssh", "example.com"]) == 23
    assert captured["argv"] == ["ssh", "example.com"]


def test_run_ssh_normalizes_exit_status(monkeypatch: Any) -> None:
    """The top-level helper should return normalized exit codes."""

    entry = HistoryEntry(hostname="example.com")

    monkeypatch.setattr(ssh_launcher.shutil, "which", lambda _: "/usr/bin/ssh")
    monkeypatch.setattr(ssh_launcher, "_spawn_ssh", lambda argv: 5)
    monkeypatch.setattr(ssh_launcher.os, "waitstatus_to_exitcode", lambda status: status)

    assert ssh_launcher.run_ssh(entry) == 5
