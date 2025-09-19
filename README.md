# sshse

SSH Session Manager (sshse) application.
## Getting Started

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[dev]'
```

Run the test suite:

```bash
pytest
```

## Connection History

sshse now persists recent SSH targets to a per-user data file so the interactive menu can surface them quickly.
The default location follows the operating system's data directory conventions (for example `~/.local/share/sshse/history.json` on Linux and `~/Library/Application Support/sshse/history.json` on macOS).
Run `sshse` without arguments to open the TUI, pick a recorded host, and immediately launch `ssh` with the saved username and port.
Use `HistoryStore` from `sshse.core.history` to record connections from integrations or future CLI commands.
