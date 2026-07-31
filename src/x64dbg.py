"""Compatibility facade for the decomposed x64dbg MCP runtime.

The historical import path is intentionally stable: tests, MCP launchers and
Claude/Codex configurations continue to load ``src/x64dbg.py``.  The actual
implementation lives in ``x64dbg_runtime.py`` and is executed in this module's
namespace.  Executing rather than importing it is deliberate: existing
callers monkeypatch module globals (for example ``DebugRun`` or
``_bridge_request``), and those patches must continue to affect every tool.
"""

from __future__ import annotations

import builtins as _builtins
import sys as _sys
import types as _types
from pathlib import Path

# Some of the legacy regression tests load this file with
# ``spec_from_file_location`` without inserting the resulting module in
# ``sys.modules``.  ``dataclasses`` (and a few introspection helpers) require
# that an entry exists while classes are being defined.  Keep a small proxy
# registered for that edge case; runtime functions and globals still live in
# the actual namespace supplied by the loader.
_module_proxy = _sys.modules.get(__name__)
if _module_proxy is None:
    _module_proxy = _types.ModuleType(__name__)
    _module_proxy.__file__ = __file__
    _module_proxy.__package__ = __package__
    _module_proxy.__dict__.update(vars(_builtins))
    _module_proxy.__dict__.update(globals())
    _sys.modules[__name__] = _module_proxy

_RUNTIME_PATH = Path(__file__).with_name("x64dbg_runtime.py")
if not _RUNTIME_PATH.is_file():
    raise ImportError(f"Missing decomposed MCP runtime: {_RUNTIME_PATH}")

_RUNTIME_SOURCE = _RUNTIME_PATH.read_text(encoding="utf-8")
exec(compile(_RUNTIME_SOURCE, str(_RUNTIME_PATH), "exec"), globals(), globals())

# Mirror the finished namespace for code that resolves this module by name
# through ``sys.modules`` (notably dataclass annotation handling).
_module_proxy.__dict__.update(globals())
