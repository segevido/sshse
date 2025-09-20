# `ssh creds` Command Reference

The `ssh creds` command group manages the local encrypted credential vault used to
store `{host, username, password}` records for SSH automation workflows. Records
are encrypted at rest with AES-256-GCM. Keys are derived either from a user
passphrase (Argon2id) or from the contents of an SSH private key (HKDF-SHA256).
All files are written atomically with `0600` permissions.

> **Security note:** The vault never prints stored passwords. Human-readable views
> always redact secrets (`***`). Only the `export` subcommand emits plaintext
> credentials, and it requires explicit user action.

## Quick Start

```bash
# Initialize a new store guarded by a passphrase
sshse creds init

# Add credentials for a specific host
sshse creds add --username alice --host db01.example.com

# List stored credentials in JSON (password redacted)
sshse creds list --json

# Rotate the master key to a new passphrase
sshse creds rotate-key --new-passphrase "new secret"
```

Passphrase prompts hide input and request confirmation during initialization and
key rotation. Provide `--passphrase` flags for non-interactive use (for example
in CI environments) while being mindful of shell history retention.

## Subcommands

### `init`

```
sshse creds init [--mode passphrase|ssh-key] [--passphrase TEXT] [--ssh-key PATH]
                 [--path PATH] [--force]
```

Creates a new, empty credential store. The default mode derives the encryption
key from a user-supplied passphrase using Argon2id with memory-hard defaults.

- `--mode ssh-key` reads an SSH private key file and derives the master key via
  HKDF-SHA256. Provide the key path with `--ssh-key` (prompts if omitted).
- `--path` overrides the default location (`<user-data>/sshse/credentials.json`).
- `--force` allows overwriting an existing store; otherwise initialization fails
  to protect prior data.

### `add`

```
sshse creds add --username TEXT (--host TEXT | --host-pattern TEXT)
                [--password TEXT] [--passphrase TEXT | --ssh-key PATH]
                [--path PATH]
```

Decrypts the store, inserts or replaces a record, and re-encrypts the payload.
Records are uniquely identified by the tuple `(username, host, host_pattern)`.
If `--password` is omitted, the command prompts securely.

### `list`

```
sshse creds list [--json] [--passphrase TEXT | --ssh-key PATH] [--path PATH]
```

Displays the catalog of stored credentials. Output always redacts passwords.
Using `--json` emits a machine-friendly array of objects with `password: "***"`.

### `remove`

```
sshse creds remove --username TEXT (--host TEXT | --host-pattern TEXT)
                   [--passphrase TEXT | --ssh-key PATH] [--path PATH]
```

Deletes a single credential. The command exits with status code `1` if no
matching record is found.

### `rotate-key`

```
sshse creds rotate-key [--to passphrase|ssh-key]
                       [--current-passphrase TEXT | --current-ssh-key PATH]
                       [--new-passphrase TEXT | --new-ssh-key PATH]
                       [--path PATH]
```

Re-encrypts the vault with a new master key. The current derivation method is
auto-detected; provide the appropriate secret via `--current-passphrase` or
`--current-ssh-key`. Use `--to ssh-key` alongside `--new-ssh-key` to switch to an
SSH-key-derived vault, or `--to passphrase` with `--new-passphrase` to return to
a passphrase-protected store.

### `export`

```
sshse creds export [--passphrase TEXT | --ssh-key PATH] [--path PATH]
                   [--output PATH] [--yes]
```

Outputs decrypted credentials in JSON. Without `--output` the JSON is printed to
stdout. When writing to a file the command enforces `0600` permissions and
requires confirmation unless `--yes` is specified.

## Operational Guidelines

- Run `sshse creds list --json` to integrate with other tooling; secrets stay
  redacted in any logs.
- Back up the credentials file together with the Argon2 salt or HKDF metadata
  (embedded in the JSON envelope) to ensure future recoverability.
- Re-run `sshse creds rotate-key` periodically to refresh Argon2 salts.
- Store exported plaintext (`creds export`) securely and delete it when finished.
