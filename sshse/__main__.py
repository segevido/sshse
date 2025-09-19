"""Module entry point for ``python -m sshse``."""

from __future__ import annotations

from sshse.cli.app import main


def run() -> int:
    """Execute the CLI entry point."""
    return main()


if __name__ == "__main__":  # pragma: no cover - manual execution only
    raise SystemExit(run())
