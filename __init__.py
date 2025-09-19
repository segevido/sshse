"""Compatibility shim that exposes the installed package during development.

Pytest in VS Code runs from the workspace root, which means the repository
contains a top-level ``sshse`` package directory nested under this module.
This shim delegates to the real package (``sshse/sshse``) so ``import sshse``
behaves identically before and after installation.
"""

from __future__ import annotations

from importlib import import_module
from pathlib import Path
from pkgutil import extend_path

__all__ = ["__version__"]

# Ensure subpackages (e.g. sshse.cli) continue to resolve by including the
# actual package directory on the search path for this package module.
_package_dir = Path(__file__).resolve().parent / "sshse"
__path__ = extend_path(__path__, __name__)
_pkg_path = str(_package_dir)
if _package_dir.exists() and _pkg_path not in __path__:
    __path__.append(_pkg_path)

# Delegate metadata exports to the real package implementation.
_inner_pkg = import_module(".sshse", __name__)
__version__ = _inner_pkg.__version__
