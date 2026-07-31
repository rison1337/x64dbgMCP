"""Transport-neutral x64dbg -> IDA evidence coordinator.

The MCP servers intentionally remain decoupled.  This module turns a validated
``x64dbg-mcp-runtime-evidence`` document plus an IDA image identity into a
deterministic list of IDA MCP calls.  A caller can inspect the plan, send the
listed calls through its connected IDA MCP client, and retain the same
idempotency key for retries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

RUNTIME_SCHEMA = "x64dbg-mcp-runtime-evidence"
PLAN_SCHEMA = "ida-runtime-sync-plan-v1"
MAX_BYTES = 32 * 1024 * 1024


def _json_load(value: str) -> Any:
    if os.path.isfile(value):
        path = os.path.abspath(value)
        if os.path.getsize(path) > MAX_BYTES:
            raise ValueError("input exceeds 32 MiB")
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    if len(value.encode("utf-8")) > MAX_BYTES:
        raise ValueError("inline JSON exceeds 32 MiB")
    return json.loads(value)


def _int(value: Any, default: int | None = None) -> int | None:
    if isinstance(value, bool):
        return default
    try:
        if isinstance(value, int):
            return value
        text = str(value or "").strip()
        if not text:
            return default
        return int(text, 0)
    except (TypeError, ValueError):
        return default


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest().upper()


def _hex_rva(value: Any) -> int:
    parsed = _int(value)
    if parsed is None or parsed < 0:
        raise ValueError("invalid RVA")
    return parsed


def _normalize_runtime(document: dict[str, Any]) -> dict[str, Any]:
    if document.get("schema") != RUNTIME_SCHEMA:
        raise ValueError(f"expected {RUNTIME_SCHEMA}")
    if _int(document.get("version")) != 1:
        raise ValueError("unsupported runtime evidence version")
    image = document.get("image")
    if not isinstance(image, dict):
        raise ValueError("runtime evidence image is missing")
    sha = str(image.get("sha256") or "").strip().upper()
    if len(sha) != 64 or any(ch not in "0123456789ABCDEF" for ch in sha):
        raise ValueError("runtime evidence image SHA-256 is invalid")
    arch = str(image.get("arch") or "").casefold()
    if arch not in {"x86", "x64"}:
        raise ValueError("runtime evidence image architecture is invalid")
    size = _int(image.get("sizeOfImage"))
    if size is None or size <= 0:
        raise ValueError("runtime evidence image size is invalid")
    static = document.get("staticEvidence") or {}
    runtime = document.get("runtimeEvidence") or {}
    if not isinstance(static, dict) or not isinstance(runtime, dict):
        raise ValueError("runtime/static evidence sections must be objects")
    return {"image": image, "sha256": sha, "arch": arch, "size": size, "static": static, "runtime": runtime}


def _ida_identity(value: dict[str, Any]) -> tuple[str, str, int]:
    sha = str(value.get("sha256") or "").strip().upper()
    arch = str(value.get("arch") or "").casefold()
    image_base = _int(value.get("imageBase") or value.get("imagebase"))
    if len(sha) != 64 or any(ch not in "0123456789ABCDEF" for ch in sha):
        raise ValueError("IDA image SHA-256 is invalid")
    if arch not in {"x86", "x64"}:
        raise ValueError("IDA image architecture is invalid")
    if image_base is None or image_base < 0:
        raise ValueError("IDA image base is invalid")
    return sha, arch, image_base


def _iter_list(value: Any) -> Iterable[dict[str, Any]]:
    if not isinstance(value, list):
        return ()
    return (item for item in value if isinstance(item, dict))


def build_sync_plan(runtime_document: dict[str, Any], ida_image: dict[str, Any]) -> dict[str, Any]:
    """Validate identities and build deterministic connector calls."""

    normalized = _normalize_runtime(runtime_document)
    ida_sha, ida_arch, ida_base = _ida_identity(ida_image)
    if ida_sha != normalized["sha256"] or ida_arch != normalized["arch"]:
        raise ValueError("IDA image identity does not match runtime evidence")

    static = normalized["static"]
    actions: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for item in _iter_list(static.get("comments")):
        rva = _hex_rva(item.get("rva"))
        if rva >= normalized["size"]:
            skipped.append({"kind": "comment", "rva": f"0x{rva:X}", "reason": "outside_image"})
            continue
        actions.append(
            {
                "tool": "set_comments",
                "arguments": {
                    "items": {
                        "addr": f"0x{ida_base + rva:X}",
                        "comment": str(item.get("text") or ""),
                    }
                },
                "source": {"kind": "comment", "rva": f"0x{rva:X}"},
            }
        )

    for item in _iter_list(static.get("labels")):
        rva = _hex_rva(item.get("rva"))
        if rva >= normalized["size"]:
            skipped.append({"kind": "label", "rva": f"0x{rva:X}", "reason": "outside_image"})
            continue
        # The IDA connector may expose a set-name operation under a different
        # version.  Keep this action explicit and transport-neutral.
        actions.append(
            {
                "tool": "set_name",
                "arguments": {"addr": f"0x{ida_base + rva:X}", "name": str(item.get("text") or "")},
                "source": {"kind": "label", "rva": f"0x{rva:X}"},
            }
        )

    for item in _iter_list(static.get("functions")):
        start = _hex_rva(item.get("rvaStart"))
        end = _hex_rva(item.get("rvaEndInclusive"))
        if start > end or end >= normalized["size"]:
            skipped.append({"kind": "function", "rvaStart": f"0x{start:X}", "reason": "outside_image"})
            continue
        actions.append(
            {
                "tool": "define_func",
                "arguments": {
                    "items": {
                        "addr": f"0x{ida_base + start:X}",
                        "end": f"0x{ida_base + end + 1:X}",
                    }
                },
                "source": {"kind": "function", "rvaStart": f"0x{start:X}", "rvaEndInclusive": f"0x{end:X}"},
            }
        )

    runtime = normalized["runtime"]
    for artifact in _iter_list(runtime.get("coverageArtifacts")):
        for block in _iter_list(artifact.get("blocks")):
            rva = _hex_rva(block.get("startRva"))
            if rva >= normalized["size"]:
                continue
            hits = _int(block.get("hits"), 0) or 0
            actions.append(
                {
                    "tool": "append_comments",
                    "arguments": {
                        "items": {
                            "addr": f"0x{ida_base + rva:X}",
                            "comment": f"[x64dbg] coverage hits={hits} stable={block.get('stableKey')}",
                            "dedupe": True,
                            "scope": "auto",
                        }
                    },
                    "source": {"kind": "coverage", "rva": f"0x{rva:X}"},
                }
            )

    for trace in _iter_list(runtime.get("apiTraces")):
        for call in _iter_list(trace.get("calls")):
            rva = _int(call.get("callerRva") or call.get("returnRva"))
            if rva is None or rva < 0 or rva >= normalized["size"]:
                skipped.append({"kind": "api", "reason": "missing_module_rva"})
                continue
            api = f"{call.get('module') or ''}!{call.get('func') or ''}".strip("!")
            actions.append(
                {
                    "tool": "append_comments",
                    "arguments": {
                        "items": {
                            "addr": f"0x{ida_base + rva:X}",
                            "comment": f"[x64dbg] API {api} seq={call.get('seq') or call.get('callSeq')}",
                            "dedupe": True,
                            "scope": "line",
                        }
                    },
                    "source": {"kind": "api", "rva": f"0x{rva:X}", "api": api},
                }
            )

    actions.sort(key=lambda item: (str(item.get("source", {}).get("kind")), str(item.get("source", {}).get("rva", "")), item["tool"]))
    body = {
        "schema": PLAN_SCHEMA,
        "version": 1,
        "identity": {
            "sha256": normalized["sha256"],
            "arch": normalized["arch"],
            "idaImageBase": f"0x{ida_base:X}",
        },
        "actionCount": len(actions),
        "actions": actions,
        "skipped": skipped,
    }
    body["idempotencyKey"] = _canonical_digest(body)
    return body


def _main() -> int:
    parser = argparse.ArgumentParser(description="Build a deterministic x64dbg-to-IDA MCP sync plan")
    parser.add_argument("--runtime", required=True, help="runtime evidence JSON path or inline JSON")
    parser.add_argument("--ida-image", required=True, help="IDA image identity JSON path or inline JSON")
    parser.add_argument("--output", default="", help="optional plan output path")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    try:
        runtime = _json_load(args.runtime)
        ida_image = _json_load(args.ida_image)
        plan = build_sync_plan(runtime, ida_image)
        text = json.dumps(plan, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            output = os.path.abspath(args.output)
            if os.path.exists(output) and not args.overwrite:
                raise FileExistsError(output)
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(text, encoding="utf-8")
        print(text, end="")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())
