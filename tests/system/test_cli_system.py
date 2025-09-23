"""System-level tests that exercise the CLI via subprocess execution."""

from __future__ import annotations

import json

import pytest

from sshse import __version__
from sshse.config import AppConfig, ConfigStore
from sshse.core.history import HistoryStore

pytestmark = pytest.mark.system


def test_version_flag_reports_package_version(run_cli) -> None:
    """The --version flag should report the installed package version."""

    result = run_cli(["--version"])

    assert result.returncode == 0
    assert result.stdout.strip() == __version__
    assert result.stderr == ""


def test_config_show_outputs_default_payload(run_cli) -> None:
    """The config show command should emit the default configuration."""

    result = run_cli(["config", "show"])

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload == {"shared_auth_host_patterns": []}


def test_config_show_respects_existing_config(run_cli, system_data_dir) -> None:
    """Pre-populated configuration files should be surfaced by the CLI."""

    store = ConfigStore(path=system_data_dir / "config.json")
    config = AppConfig(shared_auth_host_patterns=["prod*", "db.example.com"])
    store.save(config)

    result = run_cli(["config", "show"])

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["shared_auth_host_patterns"] == ["prod*", "db.example.com"]


def test_cli_connects_to_openssh_backend(
    run_cli,
    system_data_dir,
    ssh_backend,
    ssh_client_env,
) -> None:
    """Connecting via the CLI should succeed against the ephemeral SSH backend."""

    result = run_cli([ssh_backend.alias], extra_env=ssh_client_env)

    assert result.returncode == 0
    assert "backend-ready" in result.stdout

    history_store = HistoryStore(path=system_data_dir / "history.json")
    entries = history_store.load()

    assert entries, "history should record the successful connection"
    entry = entries[0]
    assert entry.hostname == ssh_backend.alias
    assert entry.username is None
