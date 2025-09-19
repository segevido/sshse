"""Tests for the SSH history persistence helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sshse.core.history import HistoryEntry, HistoryStore, default_history_path


@pytest.fixture()
def tmp_history_path(tmp_path: Path) -> Path:
    """Provide a dedicated path for history persistence in tests."""

    return tmp_path / "history.json"


def test_record_creates_history_file(
    tmp_history_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recording a connection should create a persistent entry on disk."""

    fixed_time = datetime(2024, 5, 1, 12, 30, tzinfo=UTC)
    monkeypatch.setattr("sshse.core.history._utcnow", lambda: fixed_time)

    store = HistoryStore(path=tmp_history_path)
    entry = store.record("example.com", username="alice", port=2222)

    assert entry.hostname == "example.com"
    assert entry.username == "alice"
    assert entry.port == 2222
    assert entry.last_connected_at == fixed_time
    assert tmp_history_path.exists()

    payload = json.loads(tmp_history_path.read_text(encoding="utf-8"))
    assert payload == [
        {
            "hostname": "example.com",
            "username": "alice",
            "port": 2222,
            "last_connected_at": fixed_time.isoformat(timespec="seconds"),
        }
    ]


def test_record_deduplicates_and_orders_by_recency(
    tmp_history_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-recording the same host should bubble it to the top with a new timestamp."""

    base = datetime(2024, 1, 1, tzinfo=UTC)
    timestamps = iter(base + timedelta(minutes=offset) for offset in range(3))
    monkeypatch.setattr("sshse.core.history._utcnow", lambda: next(timestamps))

    store = HistoryStore(path=tmp_history_path)
    store.record("host-one", username="bob")
    store.record("host-two")
    store.record("host-one", username="bob")

    entries = store.load()
    assert [(entry.hostname, entry.username) for entry in entries] == [
        ("host-one", "bob"),
        ("host-two", None),
    ]
    assert entries[0].last_connected_at > entries[1].last_connected_at


def test_store_respects_max_entries(
    tmp_history_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HistoryStore should enforce the configured maximum history length."""

    base = datetime(2024, 2, 1, tzinfo=UTC)
    timestamps = iter(base + timedelta(minutes=offset) for offset in range(4))
    monkeypatch.setattr("sshse.core.history._utcnow", lambda: next(timestamps))

    store = HistoryStore(path=tmp_history_path, max_entries=2)
    store.record("one")
    store.record("two")
    store.record("three")

    entries = store.load()
    assert [entry.hostname for entry in entries] == ["three", "two"]


def test_default_history_path_uses_platformdirs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The default history path should be derived from the platform data directory."""

    expected_dir = tmp_path / "data"
    monkeypatch.setattr("sshse.core.history.user_data_path", lambda appname: expected_dir)

    default_path = default_history_path()
    assert default_path == expected_dir / "history.json"
    assert default_path.parent.exists()


def test_history_entry_roundtrip() -> None:
    """History entries should serialize and deserialize without data loss."""

    entry = HistoryEntry(
        hostname="example.org",
        username="carol",
        port=2200,
        last_connected_at=datetime(2024, 3, 1, 9, 0, tzinfo=UTC),
    )
    payload = entry.to_payload()
    restored = HistoryEntry.from_payload(payload)
    assert restored == entry
