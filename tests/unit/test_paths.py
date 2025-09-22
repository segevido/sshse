"""Tests for filesystem path resolution helpers."""

from __future__ import annotations

from pathlib import Path

from sshse import paths


def test_data_dir_honours_override(monkeypatch, tmp_path) -> None:
    """Setting SSHSE_DATA_DIR should redirect the resolved data directory."""

    override = tmp_path / "custom"
    monkeypatch.setenv("SSHSE_DATA_DIR", str(override))

    resolved = paths.data_dir()

    assert resolved == override
    assert override.exists()


def test_data_dir_defaults_to_platformdirs(monkeypatch, tmp_path) -> None:
    """When no override is set, platformdirs should provide the base path."""

    target = tmp_path / "platform"

    def fake_user_data(path: str) -> Path:
        assert path == "sshse"
        return target

    monkeypatch.delenv("SSHSE_DATA_DIR", raising=False)
    monkeypatch.setattr(paths, "user_data_path", fake_user_data)

    resolved = paths.data_dir()

    assert resolved == target
    assert target.exists()
