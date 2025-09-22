"""Fixtures supporting CLI system tests."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import pytest

RunCli = Callable[
    [Sequence[str] | None, Mapping[str, str] | None, str | None],
    subprocess.CompletedProcess[str],
]


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Return the repository root."""

    return Path(__file__).resolve().parents[2]


@pytest.fixture
def system_environment(
    tmp_path,
    project_root: Path,
) -> tuple[dict[str, str], Path]:
    """Provide an isolated environment for invoking the CLI as a subprocess."""

    data_dir = tmp_path / "data"
    env = os.environ.copy()
    env["SSHSE_DATA_DIR"] = str(data_dir)

    existing_path = env.get("PYTHONPATH")
    components = [str(project_root)]
    if existing_path:
        components.append(existing_path)
    env["PYTHONPATH"] = os.pathsep.join(components)

    return env, data_dir


@pytest.fixture
def run_cli(
    system_environment: tuple[dict[str, str], Path],
    project_root: Path,
) -> RunCli:
    """Return a helper that executes the CLI via ``python -m sshse``."""

    base_env, _ = system_environment

    def _run(
        args: Sequence[str] | None,
        extra_env: Mapping[str, str] | None = None,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, "-m", "sshse"]
        if args:
            command.extend(args)

        env = base_env.copy()
        if extra_env:
            env.update(extra_env)

        return subprocess.run(
            command,
            cwd=project_root,
            env=env,
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )

    return _run


@pytest.fixture
def system_data_dir(system_environment: tuple[dict[str, str], Path]) -> Path:
    """Expose the data directory used during system tests."""

    _, data_dir = system_environment
    return data_dir
