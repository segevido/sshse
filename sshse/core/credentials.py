"""Encrypted credential storage for host authentication secrets."""

from __future__ import annotations

import base64
import json
import os
from collections.abc import MutableSequence, Sequence
from contextlib import suppress
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from secrets import token_bytes
from typing import Any

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from platformdirs import user_data_path

__all__ = [
    "CredentialRecord",
    "CredentialStore",
    "CredentialStoreError",
    "InvalidKeyError",
    "NotInitializedError",
    "DerivationType",
    "default_credentials_path",
]

_DEFAULT_FILENAME = "credentials.json"
_DEFAULT_ARGON2_PARAMS = {
    "time_cost": 3,
    "memory_cost": 64 * 1024,
    "parallelism": 2,
    "hash_len": 32,
}
_DEFAULT_HKDF_INFO = b"sshse-credentials"
_STORE_VERSION = 1


class DerivationType(str, Enum):
    """Supported key derivation strategies for the credential store."""

    PASSPHRASE = "passphrase"  # nosec
    SSH_KEY = "ssh-key"  # nosec


def _b64encode(value: bytes) -> str:
    """Encode bytes as URL-safe base64 without padding."""

    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
    """Decode URL-safe base64 restoring padding when required."""

    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _zero_bytes(buffer: MutableSequence[int]) -> None:
    """Overwrite the provided byte buffer with zeroes."""

    for index in range(len(buffer)):
        buffer[index] = 0


class CredentialStoreError(Exception):
    """Base exception type for credential store failures."""


class InvalidKeyError(CredentialStoreError):
    """Raised when supplied secrets cannot decrypt the credential store."""


class NotInitializedError(CredentialStoreError):
    """Raised when accessing a store before it has been initialized."""


@dataclass(slots=True)
class CredentialRecord:
    """Represents credentials for a host or host pattern."""

    username: str
    password: str
    hostname: str | None = None
    host_pattern: str | None = None

    def __post_init__(self) -> None:
        if not self.username:
            msg = "username must not be empty"
            raise ValueError(msg)
        if not self.password:
            msg = "password must not be empty"
            raise ValueError(msg)
        if not self.hostname and not self.host_pattern:
            msg = "either hostname or host_pattern must be provided"
            raise ValueError(msg)

    def to_payload(self) -> dict[str, Any]:
        """Serialize the record to a JSON-compatible payload."""

        payload: dict[str, Any] = {
            "username": self.username,
            "password": self.password,
        }
        if self.hostname is not None:
            payload["hostname"] = self.hostname
        if self.host_pattern is not None:
            payload["host_pattern"] = self.host_pattern
        return payload

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> CredentialRecord:
        """Reconstruct a record from serialized data."""

        username = payload.get("username")
        password = payload.get("password")
        hostname = payload.get("hostname")
        host_pattern = payload.get("host_pattern")
        if not isinstance(username, str) or not isinstance(password, str):
            msg = "record payload missing username/password"
            raise CredentialStoreError(msg)
        if hostname is not None and not isinstance(hostname, str):
            hostname = None
        if host_pattern is not None and not isinstance(host_pattern, str):
            host_pattern = None
        return cls(
            username=username,
            password=password,
            hostname=hostname,
            host_pattern=host_pattern,
        )


def default_credentials_path() -> Path:
    """Return the default credentials file path within the user data dir."""

    base_dir = user_data_path("sshse")
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / _DEFAULT_FILENAME


class CredentialStore:
    """Manage encrypted credential records on disk."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path if path is not None else default_credentials_path()

    @property
    def path(self) -> Path:
        """Expose the backing file path."""

        return self._path

    def is_initialized(self) -> bool:
        """Check whether the credential store file already exists."""

        return self._path.exists()

    def derivation_type(self) -> DerivationType:
        """Return the configured derivation type for the current store."""

        payload = self._read_payload()
        derivation = payload.get("derivation", {})
        if not isinstance(derivation, dict):
            msg = "credential store missing derivation metadata"
            raise CredentialStoreError(msg)
        derivation_type = derivation.get("type")
        try:
            return DerivationType(str(derivation_type))
        except ValueError as exc:
            msg = "unsupported credential derivation type"
            raise CredentialStoreError(msg) from exc

    def derivation_metadata(self) -> dict[str, Any]:
        """Expose a copy of the derivation metadata from disk."""

        payload = self._read_payload()
        derivation = payload.get("derivation", {})
        if not isinstance(derivation, dict):
            msg = "credential store missing derivation metadata"
            raise CredentialStoreError(msg)
        return dict(derivation)

    # ------------------------------------------------------------------
    # Public operations
    # ------------------------------------------------------------------
    def initialize_with_passphrase(self, passphrase: str, *, overwrite: bool = False) -> None:
        """Create a new encrypted store derived from a user passphrase."""

        if self.is_initialized() and not overwrite:
            msg = "credential store already exists"
            raise CredentialStoreError(msg)
        salt = token_bytes(16)
        metadata = {
            "type": DerivationType.PASSPHRASE.value,
            "salt": _b64encode(salt),
            "argon2": dict(_DEFAULT_ARGON2_PARAMS),
        }
        key_material = self._derive_passphrase_key(passphrase, salt, _DEFAULT_ARGON2_PARAMS)
        try:
            self._write_records([], key_material, metadata)
        finally:
            _zero_bytes(key_material)

    def initialize_with_ssh_key(self, private_key_path: Path, *, overwrite: bool = False) -> None:
        """Create a new encrypted store derived from an SSH private key file."""

        if self.is_initialized() and not overwrite:
            msg = "credential store already exists"
            raise CredentialStoreError(msg)
        salt = token_bytes(16)
        info = _DEFAULT_HKDF_INFO
        metadata = {
            "type": DerivationType.SSH_KEY.value,
            "salt": _b64encode(salt),
            "info": _b64encode(info),
        }
        key_material = self._derive_ssh_key(private_key_path, salt, info)
        try:
            self._write_records([], key_material, metadata)
        finally:
            _zero_bytes(key_material)

    def load_records_with_passphrase(self, passphrase: str) -> list[CredentialRecord]:
        """Decrypt and return all records using a passphrase-derived key."""

        payload = self._read_payload()
        derivation = payload.get("derivation", {})
        salt = _b64decode(derivation.get("salt", ""))
        if not salt:
            msg = "credential store missing Argon2 salt"
            raise CredentialStoreError(msg)
        params = derivation.get("argon2", {})
        key_material = self._derive_passphrase_key(passphrase, salt, params)
        try:
            return self._decrypt_records(payload, key_material)
        finally:
            _zero_bytes(key_material)

    def load_records_with_ssh_key(self, private_key_path: Path) -> list[CredentialRecord]:
        """Decrypt and return all records using an SSH private key file."""

        payload = self._read_payload()
        derivation = payload.get("derivation", {})
        salt = _b64decode(derivation.get("salt", ""))
        info = _b64decode(derivation.get("info", ""))
        if not salt or not info:
            msg = "credential store missing HKDF parameters"
            raise CredentialStoreError(msg)
        key_material = self._derive_ssh_key(private_key_path, salt, info)
        try:
            return self._decrypt_records(payload, key_material)
        finally:
            _zero_bytes(key_material)

    def save_records_with_passphrase(
        self,
        records: Sequence[CredentialRecord],
        passphrase: str,
    ) -> None:
        """Persist records encrypting them with a passphrase-derived key."""

        payload = self._read_payload()
        derivation = payload.get("derivation", {})
        salt = _b64decode(derivation.get("salt", ""))
        if not salt:
            msg = "credential store missing Argon2 salt"
            raise CredentialStoreError(msg)
        params = derivation.get("argon2", {})
        key_material = self._derive_passphrase_key(passphrase, salt, params)
        try:
            self._write_records(records, key_material, derivation)
        finally:
            _zero_bytes(key_material)

    def save_records_with_ssh_key(
        self,
        records: Sequence[CredentialRecord],
        private_key_path: Path,
    ) -> None:
        """Persist records encrypting them with a key derived from an SSH key."""

        payload = self._read_payload()
        derivation = payload.get("derivation", {})
        salt = _b64decode(derivation.get("salt", ""))
        info = _b64decode(derivation.get("info", ""))
        if not salt or not info:
            msg = "credential store missing HKDF parameters"
            raise CredentialStoreError(msg)
        key_material = self._derive_ssh_key(private_key_path, salt, info)
        try:
            self._write_records(records, key_material, derivation)
        finally:
            _zero_bytes(key_material)

    def rotate_key_to_passphrase(
        self,
        *,
        current_secret: str | Path,
        new_passphrase: str,
        current_uses_ssh_key: bool,
    ) -> None:
        """Re-encrypt credentials with a new passphrase-derived key."""

        records = (
            self.load_records_with_ssh_key(Path(current_secret))
            if current_uses_ssh_key
            else self.load_records_with_passphrase(str(current_secret))
        )
        salt = token_bytes(16)
        metadata = {
            "type": DerivationType.PASSPHRASE.value,
            "salt": _b64encode(salt),
            "argon2": dict(_DEFAULT_ARGON2_PARAMS),
        }
        key_material = self._derive_passphrase_key(new_passphrase, salt, _DEFAULT_ARGON2_PARAMS)
        try:
            self._write_records(records, key_material, metadata)
        finally:
            _zero_bytes(key_material)

    def rotate_key_to_ssh_key(
        self,
        *,
        current_secret: str | Path,
        new_private_key_path: Path,
        current_uses_ssh_key: bool,
    ) -> None:
        """Re-encrypt credentials with a key derived from an SSH private key."""

        records = (
            self.load_records_with_ssh_key(Path(current_secret))
            if current_uses_ssh_key
            else self.load_records_with_passphrase(str(current_secret))
        )
        salt = token_bytes(16)
        info = _DEFAULT_HKDF_INFO
        metadata = {
            "type": DerivationType.SSH_KEY.value,
            "salt": _b64encode(salt),
            "info": _b64encode(info),
        }
        key_material = self._derive_ssh_key(new_private_key_path, salt, info)
        try:
            self._write_records(records, key_material, metadata)
        finally:
            _zero_bytes(key_material)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _derive_passphrase_key(
        self,
        passphrase: str,
        salt: bytes,
        params: dict[str, Any],
    ) -> bytearray:
        """Derive a symmetric key from a user passphrase via Argon2id."""

        passphrase_bytes = bytearray(passphrase.encode("utf-8"))
        try:
            time_cost = int(params.get("time_cost", _DEFAULT_ARGON2_PARAMS["time_cost"]))
            memory_cost = int(params.get("memory_cost", _DEFAULT_ARGON2_PARAMS["memory_cost"]))
            parallelism = int(params.get("parallelism", _DEFAULT_ARGON2_PARAMS["parallelism"]))
            hash_len = int(params.get("hash_len", _DEFAULT_ARGON2_PARAMS["hash_len"]))
            derived = hash_secret_raw(
                bytes(passphrase_bytes),
                salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=hash_len,
                type=Argon2Type.ID,
            )
            return bytearray(derived)
        finally:
            _zero_bytes(passphrase_bytes)

    def _derive_ssh_key(self, private_key_path: Path, salt: bytes, info: bytes) -> bytearray:
        """Derive a symmetric key from an SSH private key file using HKDF."""

        try:
            key_bytes = bytearray(private_key_path.read_bytes())
        except OSError as exc:
            raise CredentialStoreError("unable to read SSH private key for derivation") from exc
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=_DEFAULT_ARGON2_PARAMS["hash_len"],
                salt=salt,
                info=info,
            )
            derived = hkdf.derive(bytes(key_bytes))
            return bytearray(derived)
        finally:
            _zero_bytes(key_bytes)

    def _read_payload(self) -> dict[str, Any]:
        """Read and validate the encrypted payload from disk."""

        if not self._path.exists():
            msg = "credential store has not been initialized"
            raise NotInitializedError(msg)
        try:
            raw_text = self._path.read_text(encoding="utf-8")
        except OSError as exc:  # pragma: no cover - filesystem errors are rare
            raise CredentialStoreError("unable to read credential store") from exc
        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise CredentialStoreError("credential store is corrupted") from exc
        if not isinstance(payload, dict):
            msg = "unexpected credential store format"
            raise CredentialStoreError(msg)
        if payload.get("version") != _STORE_VERSION:
            msg = "unsupported credential store version"
            raise CredentialStoreError(msg)
        return payload

    def _decrypt_records(
        self,
        payload: dict[str, Any],
        key_material: bytearray,
    ) -> list[CredentialRecord]:
        """Decrypt stored credentials using AES-256-GCM."""

        nonce = payload.get("nonce")
        ciphertext = payload.get("ciphertext")
        if not isinstance(nonce, str) or not isinstance(ciphertext, str):
            msg = "credential store payload missing ciphertext"
            raise CredentialStoreError(msg)
        aesgcm = AESGCM(bytes(key_material))
        try:
            plaintext = aesgcm.decrypt(_b64decode(nonce), _b64decode(ciphertext), None)
        except InvalidTag as exc:
            raise InvalidKeyError(
                "unable to decrypt credentials; key mismatch or data tampering detected"
            ) from exc
        try:
            records_payload = json.loads(plaintext.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise CredentialStoreError("credential records payload is corrupted") from exc
        if not isinstance(records_payload, list):
            msg = "credential records payload must be a list"
            raise CredentialStoreError(msg)
        records: list[CredentialRecord] = []
        for item in records_payload:
            if isinstance(item, dict):
                records.append(CredentialRecord.from_payload(item))
        return records

    def _write_records(
        self,
        records: Sequence[CredentialRecord],
        key_material: bytearray,
        derivation_metadata: dict[str, Any],
    ) -> None:
        """Encrypt records and persist them atomically with secure permissions."""

        payload = [record.to_payload() for record in records]
        plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        aesgcm = AESGCM(bytes(key_material))
        nonce = token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        envelope = {
            "version": _STORE_VERSION,
            "derivation": derivation_metadata,
            "nonce": _b64encode(nonce),
            "ciphertext": _b64encode(ciphertext),
        }
        serialized = json.dumps(envelope, indent=2, sort_keys=True)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_suffix(".tmp")
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(serialized)
            os.replace(tmp_path, self._path)
            with suppress(PermissionError, NotImplementedError):  # pragma: no cover
                os.chmod(self._path, 0o600)
        finally:
            if os.path.exists(tmp_path):  # pragma: no cover - defensive cleanup
                with suppress(PermissionError, NotImplementedError):  # pragma: no cover
                    os.chmod(tmp_path, 0o600)
                os.remove(tmp_path)
