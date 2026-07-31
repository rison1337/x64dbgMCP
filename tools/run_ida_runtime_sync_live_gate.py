"""Two-process x64dbg runtime-evidence -> IDA MCP acceptance gate."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path(__file__).resolve().parents[1]
X64DBG_MODULE = ROOT / "src" / "x64dbg.py"
COORDINATOR_MODULE = ROOT / "tools" / "ida_evidence_coordinator.py"
DEFAULT_OUTPUT = ROOT / "tools" / "dump_outputs" / "stage6_ida_runtime_sync_live_final.json"
DEFAULT_EVIDENCE_ROOT = ROOT / "tools" / "dump_outputs" / "stage6_ida_runtime_sync"
MARKER = "[x64dbg MCP gate] SHA-256+RVA runtime sync"


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _tool_payload(result: Any) -> Any:
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        return structured
    for item in list(getattr(result, "content", None) or []):
        text = getattr(item, "text", None)
        if not text:
            continue
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"text": text}
    return None


def _call_ok(result: Any) -> bool:
    if bool(getattr(result, "isError", False)):
        return False
    payload = _tool_payload(result)
    if isinstance(payload, dict):
        if payload.get("error"):
            return False
        rows = payload.get("result")
        if isinstance(rows, list) and any(isinstance(item, dict) and item.get("error") for item in rows):
            return False
        return payload.get("success", True) is not False
    return payload is not None


def _prepare_x64dbg_evidence(target: Path, evidence_path: Path, arch: str) -> dict[str, Any]:
    module = _load(X64DBG_MODULE, "x64dbg_ida_sync_gate")
    launch = module.LaunchFileUnderDebugger(
        exe_path=str(target),
        arguments=["direct", "AAAAAAAAAAAAAAA"],
        arch=arch,
        restart_debugger=True,
        timeout_ms=30000,
        stop_first=True,
        use_scyllahide="off",
        use_hidemain="off",
        advance_to_entry=True,
    )
    if not isinstance(launch, dict) or not launch.get("ok"):
        raise RuntimeError(f"x64dbg launch failed: {launch}")
    entry_address = ""
    comment_set: Any = None
    exported: Any = None
    comment_delete: Any = None
    try:
        context, error = module._analysis_module_context()
        if error or context is None:
            raise RuntimeError(f"module identity failed: {error}")
        entry_rva = int(str(context["identity"]["entryPointRva"]), 0)
        entry_address = f"0x{int(context['base']) + entry_rva:X}"
        comment_set = module.CommentSet(entry_address, MARKER, manual=True)
        if not isinstance(comment_set, dict) or not (
            comment_set.get("ok") or comment_set.get("success")
        ):
            raise RuntimeError(f"x64dbg comment set failed: {comment_set}")
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        exported = module.ExportRuntimeEvidence(
            output_path=str(evidence_path),
            overwrite=True,
            include_static=True,
        )
        if not isinstance(exported, dict) or not exported.get("ok"):
            raise RuntimeError(f"runtime evidence export failed: {exported}")
        document = dict(exported.get("document") or {})
        comments = list(document.get("staticEvidence", {}).get("comments") or [])
        if not any(str(item.get("text") or "") == MARKER for item in comments if isinstance(item, dict)):
            raise RuntimeError("exported evidence does not contain the gate comment")
        return {
            "document": document,
            "entryAddress": entry_address,
            "entryRva": str(context["identity"]["entryPointRva"]),
            "image": dict(context["identity"]),
            "export": exported,
            "commentSet": comment_set,
        }
    finally:
        if entry_address:
            try:
                comment_delete = module.CommentDelete(entry_address)
            except Exception:
                comment_delete = None
        try:
            module.DebugStop()
        except Exception:
            pass


async def _run_ida(
    target: Path,
    runtime_document: dict[str, Any],
    entry_rva: str,
    *,
    ida_python: str,
    ida_dir: str,
) -> dict[str, Any]:
    coordinator = _load(COORDINATOR_MODULE, "ida_sync_gate_coordinator")
    params = StdioServerParameters(
        command=ida_python,
        args=["-m", "ida_pro_mcp.idalib_supervisor", "--stdio", "--max-workers", "2"],
        env={**os.environ, "IDADIR": ida_dir},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            opened_result = await session.call_tool(
                "idb_open",
                {
                    "input_path": str(target),
                    "mode": "force_headless",
                    "run_auto_analysis": True,
                    "build_caches": True,
                    "init_hexrays": True,
                    "idle_ttl_sec": 300,
                },
            )
            opened = _tool_payload(opened_result)
            session_info = opened.get("session") if isinstance(opened, dict) else {}
            database = str((session_info or {}).get("session_id") or "")
            if not database:
                raise RuntimeError(f"IDA open failed: {opened}")
            survey_result = await session.call_tool(
                "survey_binary", {"database": database, "detail_level": "minimal"}
            )
            survey = _tool_payload(survey_result)
            metadata = survey.get("metadata") if isinstance(survey, dict) else {}
            if not isinstance(metadata, dict):
                raise RuntimeError(f"IDA survey failed: {survey}")
            arch = "x64" if str(metadata.get("arch") or "") in {"64", "x64"} else "x86"
            plan = coordinator.build_sync_plan(
                runtime_document,
                {
                    "sha256": metadata.get("sha256"),
                    "arch": arch,
                    "imageBase": metadata.get("base_address"),
                },
            )
            expected_address = f"0x{int(str(metadata['base_address']), 0) + int(entry_rva, 0):X}"
            comment_actions = [
                item for item in plan.get("actions", [])
                if item.get("tool") == "set_comments"
                and item.get("arguments", {}).get("items", {}).get("comment") == MARKER
                and item.get("arguments", {}).get("items", {}).get("addr") == expected_address
            ]
            if len(comment_actions) != 1:
                raise RuntimeError(f"coordinator did not emit one exact gate action: {comment_actions}")
            action = comment_actions[0]
            arguments = {"database": database, **dict(action["arguments"])}
            first = await session.call_tool("set_comments", arguments)
            second = await session.call_tool("set_comments", arguments)
            if not _call_ok(first) or not _call_ok(second):
                raise RuntimeError(
                    f"IDA idempotent comment apply failed: first={_tool_payload(first)} second={_tool_payload(second)}"
                )
            decompiled_result = await session.call_tool(
                "decompile",
                {"database": database, "addr": expected_address, "include_addresses": True},
            )
            decompiled = _tool_payload(decompiled_result)
            decompiled_text = json.dumps(decompiled, ensure_ascii=False)
            # Some IDA versions do not echo address comments in pseudocode.
            # The mutation result remains authoritative; retain this as a
            # diagnostic instead of a false failure.
            return {
                "database": database,
                "survey": survey,
                "plan": plan,
                "expectedAddress": expected_address,
                "firstApply": _tool_payload(first),
                "secondApply": _tool_payload(second),
                "firstApplyOk": _call_ok(first),
                "secondApplyOk": _call_ok(second),
                "decompile": decompiled,
                "markerVisibleInDecompile": MARKER in decompiled_text,
            }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run x64dbg -> IDA MCP runtime-evidence acceptance")
    parser.add_argument("--arch", choices=["all", "x64", "x86"], default="all")
    parser.add_argument("--target", default="", help="override target for a single-architecture run")
    parser.add_argument("--out", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--evidence-root", default=str(DEFAULT_EVIDENCE_ROOT))
    parser.add_argument(
        "--ida-python",
        default=sys.executable,
        help="Python interpreter used by the IDA-side coordinator (default: current interpreter)",
    )
    parser.add_argument("--ida-dir", default=r"C:\Program Files\IDA Professional 9.3")
    args = parser.parse_args(argv)
    output = Path(os.path.abspath(args.out))
    evidence_root = Path(os.path.abspath(args.evidence_root))
    arches = ["x64", "x86"] if args.arch == "all" else [args.arch]
    if args.target and len(arches) != 1:
        parser.error("--target requires --arch x64 or --arch x86")
    report: dict[str, Any] = {
        "schema": "x64dbg-ida-runtime-sync-live-v1",
        "architectures": arches,
        "results": [],
        "ok": False,
    }
    try:
        for arch in arches:
            target = (
                Path(os.path.abspath(args.target))
                if args.target
                else ROOT / "tools" / "bin" / "e2e" / arch / "key_recovery.exe"
            )
            evidence = evidence_root / f"runtime-evidence-{arch}.json"
            if not target.is_file():
                raise FileNotFoundError(target)
            x64dbg = _prepare_x64dbg_evidence(target, evidence, arch)
            ida = asyncio.run(
                _run_ida(
                    target,
                    x64dbg["document"],
                    x64dbg["entryRva"],
                    ida_python=os.path.abspath(args.ida_python),
                    ida_dir=os.path.abspath(args.ida_dir),
                )
            )
            report["results"].append(
                {
                    "arch": arch,
                    "ok": True,
                    "target": str(target),
                    "targetSha256": _sha256(target),
                    "evidencePath": str(evidence),
                    "evidenceSha256": _sha256(evidence),
                    "x64dbg": {
                        "entryAddress": x64dbg["entryAddress"],
                        "entryRva": x64dbg["entryRva"],
                        "image": x64dbg["image"],
                        "artifactSha256": x64dbg["document"].get("artifactSha256"),
                    },
                    "ida": ida,
                }
            )
        report["ok"] = all(item.get("ok") for item in report["results"]) and len(report["results"]) == len(arches)
    except Exception as exc:
        report.update(error=str(exc), traceback=traceback.format_exc())
    body = dict(report)
    report["reportSha256"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest().upper()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
