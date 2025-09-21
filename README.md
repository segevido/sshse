# sshse

![Status](https://img.shields.io/badge/status-alpha-orange) ![Version](https://img.shields.io/badge/version-0.2.0-blue) ![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white) ![License](https://img.shields.io/badge/license-MIT-green)

SSH Session Manager (`sshse`) streamlines opening secure shell sessions, keeps a rich connection history, and lays the groundwork for automation around inventory, scripting, and file transfer.

## Table of Contents
- [sshse](#sshse)
	- [Table of Contents](#table-of-contents)
	- [Overview](#overview)
	- [Features](#features)
	- [Installation](#installation)
		- [For Users](#for-users)
		- [For Developers](#for-developers)
	- [Usage](#usage)
	- [Credential Store](#credential-store)
	- [Connection History](#connection-history)
	- [Project Structure](#project-structure)
	- [Development](#development)
	- [Contributing](#contributing)
	- [License](#license)

## Overview
sshse is a Typer-based command-line application for managing SSH workflows. The current focus is on an ergonomic interactive launcher backed by a persistent history store, with an architecture designed to support inventory management, multi-host execution, and pluggable transports as the project matures.

## Features
- Quick-connect shorthand: run `sshse host` or `sshse user@host` to open a session immediately.
- Interactive history browser that supports fuzzy filtering, keyboard navigation, and graceful fallbacks when a full TUI is unavailable.
- Persistent history powered by `HistoryStore`, stored in the OS-specific data directory (for example `~/.local/share/sshse/history.json` on Linux, `~/Library/Application Support/sshse/history.json` on macOS).
- Encrypted credential vault managed via `ssh creds` with AES-256-GCM encryption and Argon2id key stretching.
- Clean CLI ergonomics built with Typer, including a built-in `--version` flag and helpful error messaging.
- Modular layout prepared for adapters, plugins, and inventory integrations so new capabilities can be added without disrupting the core.

## Installation
### For Users
Install the latest published build from PyPI:

```bash
pip install sshse
```

### For Developers
Set up a local development environment directly from this repository:

```bash
git clone https://github.com/segevido/sshse.git
cd sshse
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[dev]'
```

Optional but recommended:

```bash
pre-commit install
```

This installs the project in editable mode with linting, formatting, and testing tools available for local development.

## Usage
Launch the CLI without arguments to open the interactive browser:

```bash
sshse
```

Connect directly to a host:

```bash
sshse user@example.com
```

Additional options:

- `sshse --version` prints the application version and exits.
- `sshse --help` displays the Typer-generated help screen for all commands and options.

The CLI returns a non-zero exit code on failure so it can be composed in scripts.

## Credential Store
Initialize a local encrypted credential store (defaults to deriving from `~/.ssh/id_rsa`):

```bash
sshse creds init
```

Add or update credentials for a host:

```bash
sshse creds add --username alice --host example.com
```

List stored credentials without exposing secrets:

```bash
sshse creds list --json
```

Refer to [docs/commands/creds.md](docs/commands/creds.md) for detailed workflows, key rotation, and export guidance.

## Connection History
Every successful connection is recorded through `HistoryStore`, which:
- Deduplicates entries by host, user, and port while keeping the most recent connection first.
- Stores timestamps in UTC for reliable ordering across platforms.
- Limits history size (defaults to 128 entries) and truncates automatically.

The history file can be inspected or managed manually if desired. Integrations can import `HistoryStore` from `sshse.core.history` to record connections performed outside of the interactive launcher.

## Project Structure
```
sshse/
|-- adapters/          # Future SSH backend implementations
|-- cli/               # Typer CLI entry points, history browser, SSH launcher
|-- config/            # Configuration models and loaders (planned)
|-- core/              # Domain logic such as connection history
|-- plugins/           # Extension points for providers and integrations
```

Top-level tooling:
- `pyproject.toml` configures dependencies, Ruff, Black, pytest, mypy, and packaging metadata.
- `tests/` contains unit tests that exercise the CLI and core modules.

## Development
With the virtual environment active, run the following to validate changes:

```bash
ruff check .
black .
mypy sshse
pytest --cov=sshse --cov-report=term-missing --cov-fail-under=100
```

Bandit (`bandit -r sshse -q`) is also configured for security scanning. Pre-commit hooks will enforce formatting and linting on each commit when enabled.

## Contributing
Contributions, bug reports, and feedback are welcome while the project evolves. Please open an issue or discussion describing the proposed change, follow conventional commits for messages, and ensure the test suite passes before submitting a pull request.

## License
sshse is available under the [MIT License](LICENSE).
