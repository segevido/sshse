"""Protocol definitions for sshse core services."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any, Protocol


class Result(Protocol):
    """Represents a structured SSH operation result."""

    def __getitem__(self, key: str, /) -> Any: ...

    def __iter__(self) -> Iterator[str]: ...

    def __len__(self) -> int: ...


class SSHClient(Protocol):
    """Protocol for SSH client implementations."""

    def run(self, host: str, command: str, *, timeout: float | None = None) -> Result:
        """Execute a command on a remote host."""

    def put(self, host: str, src: str, dst: str) -> Result:
        """Upload a file to a remote host."""

    def get(self, host: str, src: str, dst: str) -> Result:
        """Download a file from a remote host."""


class Inventory(Protocol):
    """Protocol for resolving hosts from inventory data."""

    def resolve(
        self,
        *,
        host: str | None = None,
        group: str | None = None,
        tags: Iterable[str] = (),
    ) -> list[str]:
        """Resolve hosts using the provided selectors."""
