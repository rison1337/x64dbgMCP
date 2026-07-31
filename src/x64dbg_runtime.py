"""Integrity-checked loader for the decomposed x64dbg MCP runtime."""

from __future__ import annotations

import hashlib as _runtime_hashlib
import json as _runtime_json
from pathlib import Path as _RuntimePath

_RUNTIME_LOADER_SCHEMA = "x64dbg-mcp-runtime-sections-v1"
_RUNTIME_SECTION_DIR = _RuntimePath(__file__).with_name("runtime_sections")
_RUNTIME_MANIFEST_PATH = _RUNTIME_SECTION_DIR / "manifest.json"
if not _RUNTIME_MANIFEST_PATH.is_file():
    raise ImportError(f"Missing runtime section manifest: {_RUNTIME_MANIFEST_PATH}")

_RUNTIME_MANIFEST = _runtime_json.loads(
    _RUNTIME_MANIFEST_PATH.read_text(encoding="utf-8")
)
if _RUNTIME_MANIFEST.get("schema") != _RUNTIME_LOADER_SCHEMA:
    raise ImportError("Unsupported x64dbg runtime section manifest")

for _runtime_section in _RUNTIME_MANIFEST.get("sections") or []:
    _runtime_name = str(_runtime_section.get("name") or "")
    _runtime_path = (_RUNTIME_SECTION_DIR / _runtime_name).resolve()
    if _runtime_path.parent != _RUNTIME_SECTION_DIR.resolve():
        raise ImportError(f"Unsafe runtime section path: {_runtime_name!r}")
    _runtime_bytes = _runtime_path.read_bytes()
    _runtime_actual = _runtime_hashlib.sha256(_runtime_bytes).hexdigest().upper()
    _runtime_expected = str(_runtime_section.get("sha256") or "").upper()
    if _runtime_actual != _runtime_expected:
        raise ImportError(
            f"Runtime section integrity mismatch for {_runtime_name}: "
            f"expected {_runtime_expected}, got {_runtime_actual}"
        )
    exec(
        compile(_runtime_bytes, str(_runtime_path), "exec"),
        globals(),
        globals(),
    )
