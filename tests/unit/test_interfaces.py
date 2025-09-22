"""Runtime exercises for protocol definitions in sshse.core.interfaces."""

from __future__ import annotations

from collections.abc import Iterable

from sshse.core import interfaces


def test_result_protocol_structural_usage() -> None:
    """Objects matching the Result protocol should be consumable by utilities."""

    class DummyResult(dict):
        def __iter__(self):  # type: ignore[override]
            yield from ["status", "output"]

    def consume(result: interfaces.Result) -> tuple[int, list[str]]:
        return len(result), list(result)

    result = DummyResult(status=0, output="ok")
    count, keys = consume(result)

    assert count == 2
    assert keys == ["status", "output"]


def test_ssh_client_protocol_operations() -> None:
    """A concrete implementation should satisfy SSHClient usage expectations."""

    class DummyClient:
        def run(self, host: str, command: str, *, timeout: float | None = None):
            return {"host": host, "command": command, "timeout": timeout}

        def put(self, host: str, src: str, dst: str):
            return {"host": host, "src": src, "dst": dst}

        def get(self, host: str, src: str, dst: str):
            return {"host": host, "src": src, "dst": dst}

    def exercise(client: interfaces.SSHClient) -> list[str]:
        run_result = client.run("example.com", "echo hi", timeout=1.0)
        upload = client.put("example.com", "/tmp/file", "/dest")
        download = client.get("example.com", "/src", "/tmp/file")
        return [run_result["command"], upload["dst"], download["src"]]

    assert exercise(DummyClient()) == ["echo hi", "/dest", "/src"]


def test_inventory_protocol_resolution() -> None:
    """Inventory implementations should return a list of hosts."""

    class DummyInventory:
        def resolve(
            self,
            *,
            host: str | None = None,
            group: str | None = None,
            tags: Iterable[str] = (),
        ) -> list[str]:
            resolved = []
            if host:
                resolved.append(host)
            if group:
                resolved.append(f"group:{group}")
            if tags:
                resolved.extend(sorted(tags))
            return resolved

    inventory = DummyInventory()
    assert inventory.resolve(host="alpha", tags={"db", "prod"}) == ["alpha", "db", "prod"]
