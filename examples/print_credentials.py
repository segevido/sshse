#!/usr/bin/env python3
"""Example script that prints stored credentials with redacted passwords."""

from __future__ import annotations

from getpass import getpass

from sshse.core.credentials import (
    CredentialStore,
    CredentialStoreError,
    InvalidKeyError,
    default_credentials_path,
)


def main() -> int:
    store = CredentialStore()
    try:
        passphrase = getpass("Vault passphrase: ")
        records = store.load_records_with_passphrase(passphrase)
    except InvalidKeyError:
        print("Unable to decrypt credentials; check the passphrase.")
        return 2
    except CredentialStoreError as exc:
        print(f"Failed to open credential store: {exc}")
        return 1

    print(f"Credential store: {default_credentials_path()}")
    if not records:
        print("No credentials saved yet.")
        return 0

    for record in records:
        target = record.hostname if record.hostname else record.host_pattern
        print(f"{record.username}@{target}: password=***")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
