"""Configuration models and persistence helpers for sshse."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from platformdirs import user_data_path

__all__ = ["AppConfig", "ConfigStore", "default_config_path"]

_DEFAULT_CONFIG_FILENAME = "config.json"


@dataclass(slots=True)
class AppConfig:
    """Top-level application configuration settings."""

    shared_auth_host_patterns: list[str] = field(default_factory=list)

    def to_payload(self) -> dict[str, Any]:
        """Serialize the configuration into a JSON-compatible structure."""

        return {
            "shared_auth_host_patterns": list(self.shared_auth_host_patterns),
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> AppConfig:
        """Create a configuration instance from serialized data."""

        raw_patterns = payload.get("shared_auth_host_patterns", [])
        patterns: list[str] = []
        if isinstance(raw_patterns, list):
            for item in raw_patterns:
                if not isinstance(item, str):
                    continue
                normalized = item.strip()
                if normalized and normalized not in patterns:
                    patterns.append(normalized)
        return cls(shared_auth_host_patterns=patterns)

    def add_shared_auth_host_pattern(self, pattern: str) -> bool:
        """Add a new host pattern used for shared authentication, if absent."""

        normalized = pattern.strip()
        if not normalized:
            msg = "Pattern must not be empty."
            raise ValueError(msg)
        if normalized in self.shared_auth_host_patterns:
            return False
        self.shared_auth_host_patterns.append(normalized)
        return True

    def remove_shared_auth_host_pattern(self, pattern: str) -> bool:
        """Remove an existing shared authentication pattern if present."""

        normalized = pattern.strip()
        try:
            self.shared_auth_host_patterns.remove(normalized)
        except ValueError:
            return False
        return True

    def clear_shared_auth_host_patterns(self) -> None:
        """Remove all configured shared authentication patterns."""

        self.shared_auth_host_patterns.clear()


def default_config_path() -> Path:
    """Return the default location for the application's configuration file."""

    data_dir = user_data_path("sshse")
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / _DEFAULT_CONFIG_FILENAME


class ConfigStore:
    """Manage persistence of the application configuration file."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path if path is not None else default_config_path()

    @property
    def path(self) -> Path:
        """Expose the backing configuration file path."""

        return self._path

    def load(self) -> AppConfig:
        """Load configuration from disk, returning defaults when absent."""

        if not self._path.exists():
            return AppConfig()
        try:
            raw = self._path.read_text(encoding="utf-8")
        except OSError:
            return AppConfig()
        if not raw.strip():
            return AppConfig()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return AppConfig()
        if not isinstance(payload, dict):
            return AppConfig()
        return AppConfig.from_payload(payload)

    def save(self, config: AppConfig) -> None:
        """Persist the provided configuration to disk atomically."""

        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(config.to_payload(), indent=2, sort_keys=True)
        tmp_path = self._path.with_suffix(".tmp")
        tmp_path.write_text(data, encoding="utf-8")
        tmp_path.replace(self._path)
