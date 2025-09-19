"""Tests for the SSH history persistence helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

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


def test_history_entry_requires_hostname() -> None:
    """Deserialization should fail when the hostname is missing."""

    payload = {"last_connected_at": datetime.now(tz=UTC).isoformat()}
    with pytest.raises(ValueError):
        HistoryEntry.from_payload(payload)


def test_history_entry_requires_timestamp() -> None:
    """Deserialization should fail when the timestamp is absent."""

    payload = {"hostname": "example"}
    with pytest.raises(ValueError):
        HistoryEntry.from_payload(payload)


def test_history_entry_coerces_naive_timestamp() -> None:
    """Naive timestamps should be interpreted as UTC for compatibility."""

    payload = {
        "hostname": "example",
        "last_connected_at": "2024-03-01T09:00:00",
    }
    entry = HistoryEntry.from_payload(payload)
    assert entry.last_connected_at.tzinfo is UTC


def test_history_store_path_property(tmp_history_path: Path) -> None:
    """The path property should expose the configured history location."""

    store = HistoryStore(path=tmp_history_path)
    assert store.path == tmp_history_path


def test_history_store_truncate_ignores_non_positive_limits(
    tmp_history_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-positive limit should leave the history untouched."""

    monkeypatch.setattr("sshse.core.history._utcnow", lambda: datetime(2024, 6, 1, tzinfo=UTC))
    store = HistoryStore(path=tmp_history_path, max_entries=0)
    store.record("one")
    store.truncate()

    payload = json.loads(tmp_history_path.read_text(encoding="utf-8"))
    assert len(payload) == 1


def test_history_store_truncate_applies_explicit_limit(tmp_history_path: Path) -> None:
    """truncate should rewrite the file when more entries than allowed exist."""

    store = HistoryStore(path=tmp_history_path, max_entries=10)
    entries = [
        HistoryEntry(
            hostname=f"host-{idx}", last_connected_at=datetime(2024, 1, idx + 1, tzinfo=UTC)
        )
        for idx in range(4)
    ]
    store._write_payloads(entry.to_payload() for entry in entries)

    store.truncate(max_entries=2)

    payload = json.loads(tmp_history_path.read_text(encoding="utf-8"))
    assert [item["hostname"] for item in payload] == ["host-3", "host-2"]


def test_history_store_merge_without_limit(tmp_history_path: Path) -> None:
    """_merge should return all entries when the limit is disabled."""

    store = HistoryStore(path=tmp_history_path, max_entries=-1)
    existing = [HistoryEntry(hostname="one"), HistoryEntry(hostname="two")]
    fresh = HistoryEntry(hostname="three")

    merged = store._merge(existing, fresh)

    assert [entry.hostname for entry in merged] == ["three", "one", "two"]


def test_history_store_truncate_skips_when_under_limit(tmp_history_path: Path) -> None:
    """If the entry count is within the limit no rewrite should occur."""

    store = HistoryStore(path=tmp_history_path, max_entries=10)
    entries = [HistoryEntry(hostname="only", last_connected_at=datetime(2024, 4, 1, tzinfo=UTC))]
    store._write_payloads(entry.to_payload() for entry in entries)

    before = tmp_history_path.read_text(encoding="utf-8")
    store.truncate(max_entries=5)
    after = tmp_history_path.read_text(encoding="utf-8")

    assert before == after


def test_history_read_payloads_handles_blank_file(tmp_history_path: Path) -> None:
    """Blank files should be treated as missing data."""

    store = HistoryStore(path=tmp_history_path)
    tmp_history_path.write_text("   \n", encoding="utf-8")
    assert store._read_payloads() == []


def test_history_read_payloads_handles_invalid_json(tmp_history_path: Path) -> None:
    """Invalid JSON should be ignored during load."""

    store = HistoryStore(path=tmp_history_path)
    tmp_history_path.write_text("not json", encoding="utf-8")
    assert store._read_payloads() == []


def test_history_read_payloads_filters_invalid_entries(tmp_history_path: Path) -> None:
    """Only payloads with the expected schema should be kept."""

    store = HistoryStore(path=tmp_history_path)
    data = [
        {
            "hostname": "valid",
            "last_connected_at": datetime(2024, 1, 1, tzinfo=UTC).isoformat(),
        },
        {"hostname": "", "last_connected_at": datetime(2024, 1, 2, tzinfo=UTC).isoformat()},
        ["unexpected"],
        {"host": "missing"},
    ]
    tmp_history_path.write_text(json.dumps(data), encoding="utf-8")

    payloads = store._read_payloads()

    assert payloads == data[:2]


def test_history_read_payloads_ignores_non_list_payload(tmp_history_path: Path) -> None:
    """Only list payloads should be accepted."""

    store = HistoryStore(path=tmp_history_path)
    tmp_history_path.write_text("{}", encoding="utf-8")
    assert store._read_payloads() == []


def test_history_read_payloads_handles_oserror(
    tmp_history_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Read failures should be handled gracefully by returning an empty list."""

    store = HistoryStore(path=tmp_history_path)
    tmp_history_path.write_text("[]", encoding="utf-8")

    original = Path.read_text

    def failing_read(self: Path, *args: Any, **kwargs: Any):
        if self == tmp_history_path:
            raise OSError("boom")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", failing_read)

    assert store._read_payloads() == []
