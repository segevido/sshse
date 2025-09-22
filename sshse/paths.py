"""Utilities for resolving filesystem locations used by sshse."""

from __future__ import annotations

import os
from pathlib import Path

from platformdirs import user_data_path

__all__ = ["data_dir"]


def data_dir() -> Path:
    """Return the base directory for mutable application data.

    The path defaults to the platform-specific user data directory exposed by
    :mod:`platformdirs`. When the ``SSHSE_DATA_DIR`` environment variable is
    set the value is treated as an override, allowing tests or alternative
    deployments to isolate their state.
    """

    override = os.getenv("SSHSE_DATA_DIR")
    path = Path(override).expanduser() if override else user_data_path("sshse")

    path.mkdir(parents=True, exist_ok=True)
    return path
