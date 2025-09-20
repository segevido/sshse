"""Tests for configuration persistence and models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sshse.config import AppConfig, ConfigStore, default_config_path


@pytest.fixture()
def tmp_config_path(tmp_path: Path) -> Path:
    """Provide a temporary config file location."""

    return tmp_path / "config.json"


def test_default_config_path_uses_platformdirs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The default config path should rely on the platform data directory."""

    expected_dir = tmp_path / "data"
    monkeypatch.setattr("sshse.config.user_data_path", lambda _: expected_dir)

    default_path = default_config_path()

    assert default_path == expected_dir / "config.json"
    assert default_path.parent.exists()


def test_config_store_load_returns_defaults_for_missing_file(tmp_config_path: Path) -> None:
    """Loading a non-existent config file should produce default values."""

    store = ConfigStore(path=tmp_config_path)
    config = store.load()

    assert config.shared_auth_host_patterns == []


def test_config_store_path_property(tmp_config_path: Path) -> None:
    """The path property should expose the configured location."""

    store = ConfigStore(path=tmp_config_path)
    assert store.path == tmp_config_path


def test_config_store_save_roundtrip(tmp_config_path: Path) -> None:
    """Saving and loading should round-trip configuration data."""

    store = ConfigStore(path=tmp_config_path)
    config = AppConfig()
    config.add_shared_auth_host_pattern(r"^prod-.*$")
    config.add_shared_auth_host_pattern(".*\\.example\\.com$")

    store.save(config)

    assert tmp_config_path.exists()
    loaded = store.load()
    assert loaded.shared_auth_host_patterns == [
        r"^prod-.*$",
        ".*\\.example\\.com$",
    ]

    payload = json.loads(tmp_config_path.read_text(encoding="utf-8"))
    assert payload["shared_auth_host_patterns"] == [
        r"^prod-.*$",
        ".*\\.example\\.com$",
    ]


def test_config_store_load_with_invalid_json(tmp_config_path: Path) -> None:
    """Invalid JSON content should fall back to default configuration."""

    tmp_config_path.write_text("not-json", encoding="utf-8")
    store = ConfigStore(path=tmp_config_path)

    config = store.load()

    assert config.shared_auth_host_patterns == []


def test_config_store_load_with_non_mapping(tmp_config_path: Path) -> None:
    """A non-dict payload should return default configuration values."""

    tmp_config_path.write_text("[]", encoding="utf-8")
    store = ConfigStore(path=tmp_config_path)

    assert store.load().shared_auth_host_patterns == []


def test_config_store_load_with_blank_file(tmp_config_path: Path) -> None:
    """Whitespace-only files should also yield default configuration values."""

    tmp_config_path.write_text("\n", encoding="utf-8")
    store = ConfigStore(path=tmp_config_path)

    assert store.load().shared_auth_host_patterns == []


def test_add_shared_auth_pattern_rejects_empty() -> None:
    """Attempting to add an empty pattern should raise an error."""

    config = AppConfig()
    with pytest.raises(ValueError):
        config.add_shared_auth_host_pattern("   ")


def test_add_shared_auth_pattern_deduplicates() -> None:
    """Adding the same pattern twice should report no new entries."""

    config = AppConfig()
    assert config.add_shared_auth_host_pattern("one") is True
    assert config.add_shared_auth_host_pattern("one") is False


def test_clear_shared_auth_patterns() -> None:
    """Clearing patterns should leave the list empty."""

    config = AppConfig(shared_auth_host_patterns=["one", "two"])
    config.clear_shared_auth_host_patterns()
    assert config.shared_auth_host_patterns == []


def test_app_config_from_payload_filters_invalid_entries() -> None:
    """from_payload should discard unusable entries and deduplicate values."""

    payload = {
        "shared_auth_host_patterns": [r"^prod-.*$", "", None, r"^prod-.*$", 42],
    }

    config = AppConfig.from_payload(payload)

    assert config.shared_auth_host_patterns == [r"^prod-.*$"]


def test_app_config_from_payload_non_list() -> None:
    """Non-list payload values should be ignored."""

    payload = {"shared_auth_host_patterns": "not-a-list"}

    config = AppConfig.from_payload(payload)

    assert config.shared_auth_host_patterns == []


def test_remove_shared_auth_pattern_handles_missing_entries() -> None:
    """Removing a pattern should report whether the entry existed."""

    config = AppConfig(shared_auth_host_patterns=["one", "two"])

    assert config.remove_shared_auth_host_pattern("one") is True
    assert config.shared_auth_host_patterns == ["two"]
    assert config.remove_shared_auth_host_pattern("missing") is False


def test_config_store_load_handles_read_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreadable file should behave like missing configuration."""

    path = tmp_path / "config.json"
    path.write_text("{}", encoding="utf-8")

    store = ConfigStore(path=path)
    original_read_text = Path.read_text

    def boom_read_text(self: Path, *args: Any, **kwargs: Any) -> str:
        if self == path:
            raise OSError("boom")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", boom_read_text)

    config = store.load()

    assert config.shared_auth_host_patterns == []
