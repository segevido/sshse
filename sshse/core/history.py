"""Persistence helpers for tracking SSH connection history."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from platformdirs import user_data_path

__all__ = [
    "HistoryEntry",
    "HistoryStore",
    "default_history_path",
]

_DEFAULT_HISTORY_FILENAME = "history.json"
_DEFAULT_MAX_ENTRIES = 128


def _utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


@dataclass(slots=True)
class HistoryEntry:
    """Represents a single SSH connection made by the user."""

    hostname: str
    username: str | None = None
    port: int | None = None
    last_connected_at: datetime = field(default_factory=_utcnow)

    def to_payload(self) -> dict[str, Any]:
        """Serialize the entry into a JSON-compatible dictionary."""

        payload: dict[str, Any] = {
            "hostname": self.hostname,
            "last_connected_at": self.last_connected_at.isoformat(timespec="seconds"),
        }
        if self.username is not None:
            payload["username"] = self.username
        if self.port is not None:
            payload["port"] = self.port
        return payload

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> HistoryEntry:
        """Reconstruct an entry instance from serialized data."""

        hostname = payload.get("hostname")
        if not hostname:
            msg = "History entry is missing 'hostname'"
            raise ValueError(msg)

        raw_timestamp = payload.get("last_connected_at")
        if not raw_timestamp:
            msg = "History entry is missing 'last_connected_at'"
            raise ValueError(msg)

        try:
            timestamp = datetime.fromisoformat(raw_timestamp)
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError("Invalid timestamp in history entry") from exc

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)

        port = payload.get("port")
        if port is not None:
            port = int(port)

        return cls(
            hostname=hostname,
            username=payload.get("username"),
            port=port,
            last_connected_at=timestamp,
        )


def default_history_path() -> Path:
    """Resolve the default location for history persistence."""

    data_dir = user_data_path("sshse")
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / _DEFAULT_HISTORY_FILENAME


class HistoryStore:
    """Manage on-disk persistence of SSH connection history."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        max_entries: int = _DEFAULT_MAX_ENTRIES,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._path = path if path is not None else default_history_path()
        self._max_entries = max_entries
        self._clock = clock if clock is not None else _utcnow

    @property
    def path(self) -> Path:
        """Return the backing file path for history data."""

        return self._path

    def load(self) -> list[HistoryEntry]:
        """Load history entries from disk sorted by recency."""

        raw_entries = self._read_payloads()
        entries = [HistoryEntry.from_payload(item) for item in raw_entries]
        return sorted(entries, key=lambda entry: entry.last_connected_at, reverse=True)

    def record(
        self,
        hostname: str,
        *,
        username: str | None = None,
        port: int | None = None,
        connected_at: datetime | None = None,
    ) -> HistoryEntry:
        """Persist a new history entry, updating previous records if needed."""

        timestamp = connected_at if connected_at is not None else self._clock()
        entries = self.load()
        fresh_entry = HistoryEntry(
            hostname=hostname,
            username=username,
            port=port,
            last_connected_at=timestamp,
        )
        entries = self._merge(entries, fresh_entry)
        self._write_payloads(entry.to_payload() for entry in entries)
        return fresh_entry

    def truncate(self, *, max_entries: int | None = None) -> None:
        """Trim the history file down to a maximum number of entries."""

        limit = max_entries if max_entries is not None else self._max_entries
        if limit is not None and limit <= 0:
            return
        entries = self.load()
        if limit and len(entries) > limit:
            entries = entries[:limit]
            self._write_payloads(entry.to_payload() for entry in entries)

    def _merge(
        self,
        entries: Sequence[HistoryEntry],
        fresh_entry: HistoryEntry,
    ) -> list[HistoryEntry]:
        """Place the most recent entry first and deduplicate by connection details."""

        merged = [fresh_entry]
        for entry in entries:
            if (
                entry.hostname == fresh_entry.hostname
                and entry.username == fresh_entry.username
                and entry.port == fresh_entry.port
            ):
                continue
            merged.append(entry)
        limit = self._max_entries
        if limit is not None and limit > 0:
            return merged[:limit]
        return merged

    def _read_payloads(self) -> list[dict[str, Any]]:
        """Read serialized history data from disk."""

        if not self._path.exists():
            return []
        try:
            raw = self._path.read_text(encoding="utf-8")
        except OSError:
            return []
        if not raw.strip():
            return []
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, list):
            return []
        filtered: list[dict[str, Any]] = []
        for item in payload:
            if isinstance(item, dict) and "hostname" in item:
                filtered.append(item)
        return filtered

    def _write_payloads(self, payloads: Iterable[dict[str, Any]]) -> None:
        """Write the serialized history data to disk atomically."""

        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(list(payloads), indent=2)
        tmp_path = self._path.with_suffix(".tmp")
        tmp_path.write_text(data, encoding="utf-8")
        tmp_path.replace(self._path)

    def __iter__(self) -> Iterator[HistoryEntry]:  # pragma: no cover - convenience helper
        return iter(self.load())
