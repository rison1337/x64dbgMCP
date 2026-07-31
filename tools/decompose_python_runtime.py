"""One-shot, deterministic splitter for the historical Python runtime.

The generated sections are executed in one shared module namespace. This keeps
all legacy monkeypatch and ``spec_from_file_location`` behavior while replacing
the single 40k-line implementation file with cohesive, ordered source units.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "x64dbg_runtime.py"
SECTIONS = ROOT / "src" / "runtime_sections"
MANIFEST = SECTIONS / "manifest.json"
LOADER_MARKER = "x64dbg-mcp-runtime-sections-v1"

# Boundaries are top-level AST statement starts in the certified runtime.
# End values are exclusive. Names document responsibility, not Python modules:
# every section deliberately executes in the facade's shared namespace.
SECTION_STARTS = (
    (1, "00_bootstrap_and_session.py"),
    (12267, "10_result_and_transport.py"),
    (14439, "20_debugger_workflows.py"),
    (22412, "30_trace_heap_coverage.py"),
    (28652, "40_unpack_and_dump.py"),
    (33840, "50_debugger_api_surface.py"),
    (37885, "60_evidence_and_managed.py"),
    (40900, "70_registration_and_cli.py"),
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _loader_source() -> str:
    return '''"""Integrity-checked loader for the decomposed x64dbg MCP runtime."""

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
'''


def _refresh_manifest() -> dict:
    """Recompute integrity metadata for an already decomposed runtime."""

    if MANIFEST.is_file():
        current = json.loads(MANIFEST.read_text(encoding="utf-8"))
        names = [
            str(item.get("name") or "")
            for item in current.get("sections") or []
            if str(item.get("name") or "")
        ]
    else:
        names = [name for _, name in SECTION_STARTS]
    if not names:
        raise RuntimeError("No runtime sections were found")

    start = 1
    combined = bytearray()
    manifest_sections = []
    for name in names:
        target = (SECTIONS / name).resolve()
        if target.parent != SECTIONS.resolve() or not target.is_file():
            raise RuntimeError(f"Missing or unsafe runtime section: {name!r}")
        payload = target.read_bytes()
        # All generated sections are newline-terminated. splitlines() keeps
        # the logical source-line count stable across CRLF/LF checkouts.
        line_count = len(payload.decode("utf-8").splitlines())
        end = start + line_count - 1
        manifest_sections.append(
            {
                "name": name,
                "startLine": start,
                "endLine": end,
                "lineCount": line_count,
                "sha256": _sha256(payload),
            }
        )
        combined.extend(payload)
        start = end + 1

    manifest = {
        "schema": LOADER_MARKER,
        "source": SOURCE.name,
        "sourceLineCount": start - 1,
        "sourceSha256": _sha256(bytes(combined)),
        "sections": manifest_sections,
    }
    MANIFEST.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    source = SOURCE.read_text(encoding="utf-8")
    if LOADER_MARKER in source:
        manifest = _refresh_manifest()
        print(
            json.dumps(
                {
                    "ok": True,
                    "refreshed": True,
                    "loader": str(SOURCE),
                    "manifest": str(MANIFEST),
                    "sectionCount": len(manifest["sections"]),
                    "sourceSha256": manifest["sourceSha256"],
                },
                ensure_ascii=False,
            )
        )
        return 0

    lines = source.splitlines(keepends=True)
    tree = ast.parse(source, filename=str(SOURCE))
    top_level_starts = {
        min(
            [int(node.lineno)]
            + [int(item.lineno) for item in getattr(node, "decorator_list", [])]
        )
        for node in tree.body
    }
    invalid = [line for line, _ in SECTION_STARTS if line not in top_level_starts]
    if invalid:
        raise RuntimeError(
            f"Section boundaries are no longer top-level statements: {invalid}"
        )

    SECTIONS.mkdir(parents=True, exist_ok=True)
    manifest_sections = []
    for index, (start, name) in enumerate(SECTION_STARTS):
        end = (
            SECTION_STARTS[index + 1][0]
            if index + 1 < len(SECTION_STARTS)
            else len(lines) + 1
        )
        body = "".join(lines[start - 1 : end - 1])
        # Parse each unit independently so a boundary can never leave a
        # decorator, multiline expression or suite split in half.
        ast.parse(body, filename=name)
        payload = body.encode("utf-8")
        target = SECTIONS / name
        target.write_bytes(payload)
        manifest_sections.append(
            {
                "name": name,
                "startLine": start,
                "endLine": end - 1,
                "lineCount": end - start,
                "sha256": _sha256(payload),
            }
        )

    manifest = {
        "schema": LOADER_MARKER,
        "source": SOURCE.name,
        "sourceLineCount": len(lines),
        "sourceSha256": _sha256(source.encode("utf-8")),
        "sections": manifest_sections,
    }
    MANIFEST.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    SOURCE.write_text(_loader_source(), encoding="utf-8")
    print(
        json.dumps(
            {
                "ok": True,
                "loader": str(SOURCE),
                "manifest": str(MANIFEST),
                "sectionCount": len(manifest_sections),
                "sourceSha256": manifest["sourceSha256"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
