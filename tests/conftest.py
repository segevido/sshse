"""Shared pytest configuration for the test suite."""

from __future__ import annotations

import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Tag every test that is not marked as system as a unit test."""

    for item in items:
        if "system" not in item.keywords:
            item.add_marker(pytest.mark.unit)
