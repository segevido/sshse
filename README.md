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

sshse now persists recent SSH targets to a per-user data file so the interactive browser can surface them quickly.
The default location follows the operating system's data directory conventions (for example `~/.local/share/sshse/history.json` on Linux and `~/Library/Application Support/sshse/history.json` on macOS).
Run `sshse` without arguments to open the interactive browser. On TTYs it launches a lightweight curses UI where you can type to filter, use the arrow keys (or `j`/`k`) to move between saved hosts, press `Enter` to connect, and hit `Esc`/`q` to exit. `Ctrl+U` clears the active filter. When curses is unavailable the browser falls back to a simple prompt-driven flow with the same commands.
Use `HistoryStore` from `sshse.core.history` to record connections from integrations or future CLI commands.
