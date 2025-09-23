"""Helpers for managing ephemeral OpenSSH backends in system tests."""

from __future__ import annotations

import getpass
import os
import shlex
import shutil
import socket
import subprocess
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = [
    "SSHBackendError",
    "SSHBackendUnavailable",
    "OpenSSHBackend",
]


class SSHBackendError(RuntimeError):
    """Base error raised when provisioning the OpenSSH test backend fails."""


class SSHBackendUnavailable(SSHBackendError):
    """Raised when the local environment cannot support an OpenSSH backend."""


def _which(executable: str) -> Path:
    """Resolve an executable path, raising an informative error when missing."""

    resolved = shutil.which(executable)
    if not resolved:
        msg = f"required executable '{executable}' not found on PATH"
        raise SSHBackendUnavailable(msg)
    return Path(resolved)


def _allocate_port() -> int:
    """Return an available TCP port on the loopback interface."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", 0))
        except OSError as exc:
            msg = "unable to reserve a loopback port"
            raise SSHBackendUnavailable(msg) from exc
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _, port = sock.getsockname()
    return port


@dataclass
class _Paths:
    """Collection of important filesystem paths used by the backend."""

    root: Path
    host_key: Path
    client_key: Path
    authorized_keys: Path
    sshd_config: Path
    sshd_log: Path

    @classmethod
    def create(cls, root: Path) -> _Paths:
        root.mkdir(parents=True, exist_ok=True)
        return cls(
            root=root,
            host_key=root / "ssh_host_ed25519_key",
            client_key=root / "client_ed25519",
            authorized_keys=root / "authorized_keys",
            sshd_config=root / "sshd_config",
            sshd_log=root / "sshd.log",
        )


class OpenSSHBackend:
    """Manage a lightweight OpenSSH server for exercising the CLI in tests."""

    def __init__(self, root: Path, *, alias: str = "system-test") -> None:
        self._paths = _Paths.create(root)
        self._alias: Final[str] = alias
        self._username: Final[str] = getpass.getuser()
        self._port: int | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._sshd_path = _which("sshd")
        self._ssh_keygen_path = _which("ssh-keygen")
        self._ssh_path = _which("ssh")

    @property
    def alias(self) -> str:
        """Host alias configured for connecting to the backend."""

        return self._alias

    @property
    def port(self) -> int:
        """Port number the backend is listening on."""

        if self._port is None:
            raise SSHBackendError("backend has not been started yet")
        return self._port

    def start(self) -> None:
        """Provision host/user keys and launch the OpenSSH daemon."""

        if self._process is not None:
            return

        self._port = _allocate_port()
        self._generate_keys()
        self._write_authorized_keys()
        self._write_sshd_config()
        self._launch_daemon()
        try:
            self._wait_for_ready()
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        """Shut down the daemon and clean up process resources."""

        if self._process is None:
            return

        self._process.terminate()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=5)
        finally:
            self._process = None

    def create_client_environment(self, base_dir: Path) -> dict[str, str]:
        """Return environment overrides so ``ssh`` can reach the backend."""

        home = base_dir / "home"
        ssh_dir = home / ".ssh"
        ssh_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(home, 0o700)
        os.chmod(ssh_dir, 0o700)

        identity_path = ssh_dir / "id_ed25519"
        shutil.copyfile(self._paths.client_key, identity_path)
        os.chmod(identity_path, 0o600)

        known_hosts = ssh_dir / "known_hosts"
        known_hosts.write_text(self._known_hosts_entry(), encoding="utf-8")
        os.chmod(known_hosts, 0o600)

        config = ssh_dir / "config"
        config.write_text(
            self._ssh_config_contents(identity_path, known_hosts),
            encoding="utf-8",
        )
        os.chmod(config, 0o600)

        bin_dir = base_dir / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        wrapper = bin_dir / "ssh"
        real_ssh = shlex.quote(str(self._ssh_path))
        config_path = shlex.quote(str(config))
        wrapper.write_text(
            textwrap.dedent(
                f"""
                #!/bin/sh
                exec {real_ssh} -F {config_path} "$@"
                """
            ).lstrip(),
            encoding="utf-8",
        )
        os.chmod(wrapper, 0o700)

        path = os.environ.get("PATH", "")
        env_path = os.pathsep.join(filter(None, [str(bin_dir), path]))

        return {
            "HOME": str(home),
            "SSH_AUTH_SOCK": "",
            "PATH": env_path,
        }

    # --- Internal helpers -------------------------------------------------

    def _generate_keys(self) -> None:
        self._run(
            [
                str(self._ssh_keygen_path),
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(self._paths.host_key),
            ]
        )
        self._run(
            [
                str(self._ssh_keygen_path),
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(self._paths.client_key),
            ]
        )

    def _write_authorized_keys(self) -> None:
        pub_key_path = self._paths.client_key.with_suffix(".pub")
        if not pub_key_path.exists():
            msg = "client public key not generated"
            raise SSHBackendError(msg)
        payload = pub_key_path.read_text(encoding="utf-8")
        self._paths.authorized_keys.write_text(payload, encoding="utf-8")
        os.chmod(self._paths.authorized_keys, 0o600)

    def _write_sshd_config(self) -> None:
        assert self._port is not None  # for mypy
        config = textwrap.dedent(
            f"""
            Port {self._port}
            ListenAddress 127.0.0.1
            HostKey {self._paths.host_key}
            AuthorizedKeysFile {self._paths.authorized_keys}
            PasswordAuthentication no
            ChallengeResponseAuthentication no
            KbdInteractiveAuthentication no
            UsePAM no
            PermitRootLogin no
            StrictModes no
            AllowUsers {self._username}
            Subsystem sftp internal-sftp
            PidFile {self._paths.root / 'sshd.pid'}
            LogLevel ERROR
            ClientAliveInterval 0
            X11Forwarding no
            AllowTcpForwarding no
            PermitTunnel no
            AllowAgentForwarding no
            PrintMotd no
            AuthorizedKeysCommand none
            AuthorizedKeysCommandUser nobody
            HostbasedAuthentication no
            PubkeyAuthentication yes
            """
        ).strip()
        self._paths.sshd_config.write_text(config + "\n", encoding="utf-8")

    def _launch_daemon(self) -> None:
        command = [
            str(self._sshd_path),
            "-D",
            "-f",
            str(self._paths.sshd_config),
            "-E",
            str(self._paths.sshd_log),
        ]
        try:
            self._process = subprocess.Popen(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except FileNotFoundError as exc:
            raise SSHBackendUnavailable("sshd executable is not available") from exc
        except PermissionError as exc:
            msg = "insufficient permissions to launch sshd"
            raise SSHBackendUnavailable(msg) from exc

    def _wait_for_ready(self, *, timeout: float = 5.0) -> None:
        assert self._process is not None
        deadline = time.time() + timeout
        last_error: Exception | None = None
        while time.time() < deadline:
            if self._process.poll() is not None:
                raise SSHBackendError(self._read_log())
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return
            except OSError as exc:
                last_error = exc
                time.sleep(0.05)
        if self._process.poll() is not None:
            raise SSHBackendError(self._read_log())
        raise SSHBackendError(f"sshd did not become ready within {timeout} seconds: {last_error}")

    def _known_hosts_entry(self) -> str:
        host_pub = self._paths.host_key.with_suffix(".pub")
        if not host_pub.exists():
            msg = "host public key not generated"
            raise SSHBackendError(msg)
        raw = host_pub.read_text(encoding="utf-8").strip()
        if not raw:
            msg = "host public key is empty"
            raise SSHBackendError(msg)
        parts = raw.split()
        if len(parts) < 2:
            msg = "invalid host public key format"
            raise SSHBackendError(msg)
        key_type, key_data = parts[0], parts[1]
        return f"[127.0.0.1]:{self.port} {key_type} {key_data}\n"

    def _ssh_config_contents(self, identity_path: Path, known_hosts: Path) -> str:
        return textwrap.dedent(
            f"""
            Host {self.alias}
                HostName 127.0.0.1
                Port {self.port}
                User {self._username}
                IdentityFile {identity_path}
                IdentitiesOnly yes
                PreferredAuthentications publickey
                StrictHostKeyChecking yes
                UserKnownHostsFile {known_hosts}
                GlobalKnownHostsFile /dev/null
                BatchMode yes
                RequestTTY no
                RemoteCommand printf 'backend-ready\\n'
                ExitOnForwardFailure yes
                ConnectTimeout 5
            """
        ).lstrip()

    def _run(self, command: list[str]) -> None:
        result = subprocess.run(command, check=False, capture_output=True)
        if result.returncode != 0:
            stdout = result.stdout.decode("utf-8", errors="ignore")
            stderr = result.stderr.decode("utf-8", errors="ignore")
            msg = f"command {' '.join(command)} failed: {stderr or stdout}"
            raise SSHBackendUnavailable(msg)

    def _read_log(self) -> str:
        if self._paths.sshd_log.exists():
            return self._paths.sshd_log.read_text(encoding="utf-8")
        return "sshd exited before writing logs"
