"""Tests for the encrypted credential store."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from sshse.core.credentials import (
    CredentialRecord,
    CredentialStore,
    CredentialStoreError,
    DerivationType,
    InvalidKeyError,
    NotInitializedError,
    default_credentials_path,
)


@pytest.fixture()
def store_path(tmp_path: Path) -> Path:
    """Return a path for the credential store within a temporary directory."""

    return tmp_path / "creds.json"


def test_initialize_and_round_trip_with_passphrase(store_path: Path) -> None:
    """Passphrase derived keys should round-trip credential records."""

    store = CredentialStore(path=store_path)
    store.initialize_with_passphrase("tr1ck-h0rse")

    records = [
        CredentialRecord(username="alice", password="s3cret", hostname="example.com"),
        CredentialRecord(
            username="bob",
            password="pw",
            host_pattern=r"^web-.*$",
        ),
    ]

    store.save_records_with_passphrase(records, "tr1ck-h0rse")
    loaded = store.load_records_with_passphrase("tr1ck-h0rse")

    assert {
        (item.username, item.hostname, item.host_pattern, item.password) for item in loaded
    } == {
        ("alice", "example.com", None, "s3cret"),
        ("bob", None, r"^web-.*$", "pw"),
    }


def test_initialize_raises_if_store_exists_without_overwrite(store_path: Path) -> None:
    """Reinitializing without the overwrite flag should be rejected."""

    store = CredentialStore(path=store_path)
    store.initialize_with_passphrase("alpha")

    with pytest.raises(CredentialStoreError):
        store.initialize_with_passphrase("beta")


def test_initialize_with_overwrite_allowed(store_path: Path) -> None:
    """The overwrite flag should permit reinitializing the store."""

    store = CredentialStore(path=store_path)
    store.initialize_with_passphrase("first")
    store.initialize_with_passphrase("second", overwrite=True)

    assert store.load_records_with_passphrase("second") == []


def test_store_permissions_are_restricted(store_path: Path) -> None:
    """Credential store should be created with user-only permissions on POSIX."""

    store = CredentialStore(path=store_path)
    store.initialize_with_passphrase("perm-check")

    if os.name != "posix":  # pragma: no cover - platform-specific behaviour
        pytest.skip("permission bits only validated on POSIX platforms")

    mode = store_path.stat().st_mode & 0o777
    assert mode == 0o600


def test_wrong_passphrase_raises_invalid_key(store_path: Path) -> None:
    """Using an incorrect passphrase should trigger an explicit error."""

    store = CredentialStore(path=store_path)
    store.initialize_with_passphrase("correct-horse")

    with pytest.raises(InvalidKeyError):
        store.load_records_with_passphrase("not-the-passphrase")


def test_tamper_detection_via_ciphertext_mutation(store_path: Path) -> None:
    """Modifying the ciphertext should cause authentication failure."""

    store = CredentialStore(path=store_path)
    store.initialize_with_passphrase("correct-horse")

    records = [CredentialRecord(username="carol", password="pw", hostname="host")]
    store.save_records_with_passphrase(records, "correct-horse")

    payload = json.loads(store_path.read_text(encoding="utf-8"))
    ciphertext = payload["ciphertext"]
    mutated = (
        (ciphertext[:-1] + ("A" if ciphertext[-1] != "A" else "B")) if ciphertext else ciphertext
    )
    payload["ciphertext"] = mutated
    store_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(InvalidKeyError):
        store.load_records_with_passphrase("correct-horse")


def test_store_requires_initialization_before_use(store_path: Path) -> None:
    """Attempting to load from an absent store should raise an error."""

    store = CredentialStore(path=store_path)

    with pytest.raises(NotInitializedError):
        store.load_records_with_passphrase("anything")


def test_initialize_and_use_ssh_key_derivation(tmp_path: Path, store_path: Path) -> None:
    """SSH private key derivation should support round-trip encryption."""

    private_key_path = tmp_path / "id_rsa"
    private_key_path.write_bytes(b"-----BEGIN FAKE KEY-----\n0123456789\n")

    store = CredentialStore(path=store_path)
    store.initialize_with_ssh_key(private_key_path)

    records = [CredentialRecord(username="dave", password="pw", hostname="host")]
    store.save_records_with_ssh_key(records, private_key_path)

    loaded = store.load_records_with_ssh_key(private_key_path)

    assert [(item.username, item.password, item.hostname) for item in loaded] == [
        ("dave", "pw", "host"),
    ]


def test_rotate_from_passphrase_to_passphrase(store_path: Path) -> None:
    """Credential records should survive passphrase rotation."""

    store = CredentialStore(path=store_path)
    store.initialize_with_passphrase("one")
    store.save_records_with_passphrase(
        [CredentialRecord(username="erin", password="pw", hostname="host")],
        "one",
    )

    store.rotate_key_to_passphrase(
        current_secret="one",
        new_passphrase="two",
        current_uses_ssh_key=False,
    )

    loaded = store.load_records_with_passphrase("two")
    assert loaded[0].username == "erin"


def test_rotate_from_passphrase_to_ssh_key(store_path: Path, tmp_path: Path) -> None:
    """Credential rotation to an SSH key derived secret should work."""

    current = CredentialStore(path=store_path)
    current.initialize_with_passphrase("alpha")
    current.save_records_with_passphrase(
        [CredentialRecord(username="frank", password="pw", hostname="host")],
        "alpha",
    )

    new_key_path = tmp_path / "id_ed25519"
    new_key_path.write_bytes(b"-----BEGIN KEY-----\nabc\n")

    current.rotate_key_to_ssh_key(
        current_secret="alpha",
        new_private_key_path=new_key_path,
        current_uses_ssh_key=False,
    )

    loaded = current.load_records_with_ssh_key(new_key_path)
    assert loaded[0].password == "pw"


def test_record_validation_enforces_minimum_fields() -> None:
    """CredentialRecord should validate required properties."""

    with pytest.raises(ValueError):
        CredentialRecord(username="", password="pw", hostname="host")

    with pytest.raises(ValueError):
        CredentialRecord(username="user", password="", hostname="host")

    with pytest.raises(ValueError):
        CredentialRecord(username="user", password="pw")


def test_record_from_payload_handles_invalid_field_types() -> None:
    """Non-string host values should be coerced to ``None`` during loading."""

    record_with_numeric_host = CredentialRecord.from_payload(
        {
            "username": "alice",
            "password": "pw",
            "hostname": 123,
            "host_pattern": r"^db-.*$",
        }
    )
    assert record_with_numeric_host.hostname is None
    assert record_with_numeric_host.host_pattern == r"^db-.*$"

    record_with_numeric_pattern = CredentialRecord.from_payload(
        {
            "username": "bob",
            "password": "pw",
            "hostname": "host.example",
            "host_pattern": 456,
        }
    )
    assert record_with_numeric_pattern.hostname == "host.example"
    assert record_with_numeric_pattern.host_pattern is None


def test_record_from_payload_requires_username_and_password() -> None:
    """Missing credential fields should trigger an error."""

    with pytest.raises(CredentialStoreError):
        CredentialRecord.from_payload({"username": None, "password": "pw"})


def test_default_credentials_path_uses_platformdirs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The default storage path should respect the platform data directory."""

    monkeypatch.setattr("sshse.core.credentials.user_data_path", lambda _: tmp_path)
    path = default_credentials_path()
    assert path.parent == tmp_path


def test_derivation_type_requires_mapping(tmp_path: Path) -> None:
    """Invalid derivation metadata should raise a descriptive error."""

    payload = {"version": 1, "derivation": "invalid"}
    location = tmp_path / "creds.json"
    location.write_text(json.dumps(payload), encoding="utf-8")

    store = CredentialStore(path=location)
    with pytest.raises(CredentialStoreError):
        store.derivation_type()


def test_derivation_type_rejects_unknown_value(tmp_path: Path) -> None:
    """Unknown derivation types must be rejected."""

    payload = {"version": 1, "derivation": {"type": "mystery"}}
    location = tmp_path / "creds.json"
    location.write_text(json.dumps(payload), encoding="utf-8")

    store = CredentialStore(path=location)
    with pytest.raises(CredentialStoreError):
        store.derivation_type()


def test_derivation_metadata_requires_dict(tmp_path: Path) -> None:
    """The metadata accessor should validate structure."""

    location = tmp_path / "creds.json"
    location.write_text(json.dumps({"version": 1, "derivation": "not-a-dict"}), encoding="utf-8")
    store = CredentialStore(path=location)

    with pytest.raises(CredentialStoreError):
        store.derivation_metadata()


def test_load_records_with_passphrase_missing_salt(tmp_path: Path) -> None:
    """Missing Argon2 parameters should raise an error."""

    payload = {"version": 1, "derivation": {"argon2": {}}}
    location = tmp_path / "creds.json"
    location.write_text(json.dumps(payload), encoding="utf-8")

    store = CredentialStore(path=location)
    with pytest.raises(CredentialStoreError):
        store.load_records_with_passphrase("pw")


def test_load_records_with_ssh_key_missing_parameters(tmp_path: Path) -> None:
    """HKDF derivation requires both salt and info values."""

    payload = {"version": 1, "derivation": {"salt": ""}}
    location = tmp_path / "creds.json"
    location.write_text(json.dumps(payload), encoding="utf-8")

    store = CredentialStore(path=location)
    with pytest.raises(CredentialStoreError):
        store.load_records_with_ssh_key(tmp_path / "id_rsa")


def test_save_records_with_passphrase_missing_salt(tmp_path: Path) -> None:
    """Saving with passphrase derivation should validate salt data."""

    payload = {"version": 1, "derivation": {"argon2": {"hash_len": 32}}}
    location = tmp_path / "creds.json"
    location.write_text(json.dumps(payload), encoding="utf-8")

    store = CredentialStore(path=location)
    with pytest.raises(CredentialStoreError):
        store.save_records_with_passphrase([], "pw")


def test_save_records_with_ssh_key_missing_info(tmp_path: Path) -> None:
    """Saving with SSH derivation should require HKDF parameters."""

    payload = {"version": 1, "derivation": {"salt": ""}}
    location = tmp_path / "creds.json"
    location.write_text(json.dumps(payload), encoding="utf-8")

    store = CredentialStore(path=location)
    with pytest.raises(CredentialStoreError):
        store.save_records_with_ssh_key([], tmp_path / "id_rsa")


def test_derive_ssh_key_reports_read_errors(tmp_path: Path) -> None:
    """Unreadable private keys should raise a credential store error."""

    store = CredentialStore(path=tmp_path / "creds.json")
    with pytest.raises(CredentialStoreError):
        store._derive_ssh_key(tmp_path / "missing", b"salt", b"info")


def test_decrypt_records_requires_ciphertext(tmp_path: Path) -> None:
    """Decrypt helper should validate ciphertext presence."""

    store = CredentialStore(path=tmp_path / "creds.json")
    with pytest.raises(CredentialStoreError):
        store._decrypt_records({"nonce": None, "ciphertext": None}, bytearray(b"0" * 32))


def test_decrypt_records_rejects_invalid_json(tmp_path: Path) -> None:
    """Corrupted JSON payloads should trigger an error."""

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, b"not-json", None)

    payload = {
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
    }

    store = CredentialStore(path=tmp_path / "creds.json")
    with pytest.raises(CredentialStoreError):
        store._decrypt_records(payload, bytearray(key))


def test_decrypt_records_requires_list_payload(tmp_path: Path) -> None:
    """Decryption should reject payloads that are not a list."""

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, b'"string"', None)

    payload = {
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
    }

    store = CredentialStore(path=tmp_path / "creds.json")
    with pytest.raises(CredentialStoreError):
        store._decrypt_records(payload, bytearray(key))


def test_initialize_with_ssh_key_requires_overwrite(tmp_path: Path) -> None:
    """Reinitializing with an SSH key should enforce the overwrite flag."""

    store_path = tmp_path / "creds.json"
    key = tmp_path / "id_rsa"
    key.write_bytes(b"KEY")

    store = CredentialStore(path=store_path)
    store.initialize_with_ssh_key(key)

    with pytest.raises(CredentialStoreError):
        store.initialize_with_ssh_key(key)


def test_derivation_metadata_success(store_path: Path) -> None:
    """Accessing derivation metadata should return a shallow copy."""

    store = CredentialStore(path=store_path)
    store.initialize_with_passphrase("secret")
    meta = store.derivation_metadata()
    assert meta["type"] == DerivationType.PASSPHRASE.value


def test_read_payload_error_cases(tmp_path: Path) -> None:
    """_read_payload should guard against malformed files."""

    store = CredentialStore(path=tmp_path / "creds.json")

    with pytest.raises(NotInitializedError):
        store._read_payload()


def test_decrypt_records_skips_non_dict_entries(tmp_path: Path) -> None:
    """Non-dictionary entries in the decrypted payload should be ignored."""

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(
        [
            {
                "username": "user",
                "password": "pw",
                "hostname": "example.com",
            },
            "ignored",
        ]
    ).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    payload = {
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
    }

    store = CredentialStore(path=tmp_path / "creds.json")
    records = store._decrypt_records(payload, bytearray(key))

    assert len(records) == 1
    assert records[0].hostname == "example.com"

    corrupted_path = tmp_path / "bad.json"
    corrupted_path.write_text("not-json", encoding="utf-8")
    store = CredentialStore(path=corrupted_path)
    with pytest.raises(CredentialStoreError):
        store._read_payload()

    wrong_type_path = tmp_path / "wrong.json"
    wrong_type_path.write_text(json.dumps({"version": 1, "derivation": {}}), encoding="utf-8")
    store = CredentialStore(path=wrong_type_path)
    payload = store._read_payload()
    assert isinstance(payload, dict)

    not_dict_path = tmp_path / "list.json"
    not_dict_path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    store = CredentialStore(path=not_dict_path)
    with pytest.raises(CredentialStoreError):
        store._read_payload()

    bad_version_path = tmp_path / "old.json"
    bad_version_path.write_text(json.dumps({"version": 99}), encoding="utf-8")
    store = CredentialStore(path=bad_version_path)
    with pytest.raises(CredentialStoreError):
        store._read_payload()
