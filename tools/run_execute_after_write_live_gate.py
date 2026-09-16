"""Live x64dbg gate for ordered execute-after-write snapshots and dumps."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "src" / "x64dbg.py"
EXPECTED_MARKER = "EXECUTE_AFTER_WRITE_OK result=42 changed=4 executed=1"
EXPECTED_PAYLOAD = bytes.fromhex("6a2a58c3")


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "x64dbg_execute_after_write_live",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _smoke(path: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [str(path)],
        cwd=str(path.parent),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )
    exit_code = completed.returncode & 0xFFFFFFFF
    return {
        "ok": exit_code == 0 and EXPECTED_MARKER in completed.stdout,
        "exitCode": exit_code,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _export_bytes(path: Path, symbol_name: str, size: int) -> bytes:
    import pefile  # type: ignore

    pe = pefile.PE(str(path), fast_load=False)
    symbol = next(
        (
            item
            for item in pe.DIRECTORY_ENTRY_EXPORT.symbols
            if item.name
            and item.name.decode("ascii", errors="strict") == symbol_name
        ),
        None,
    )
    if symbol is None:
        raise RuntimeError(f"{path} has no export {symbol_name}")
    return pe.get_data(int(symbol.address), size)


def _reset_owned_artifacts(root: Path, *paths: Path) -> None:
    resolved_root = root.resolve()
    for path in paths:
        resolved = path.resolve()
        if resolved.parent != resolved_root:
            raise RuntimeError(
                f"artifact cleanup escaped gate directory: {resolved}"
            )
        resolved.unlink(missing_ok=True)


def _one_arch(module: Any, arch: str, artifact_root: Path) -> dict[str, Any]:
    target = (
        REPO_ROOT
        / "tools"
        / "bin"
        / "e2e"
        / arch
        / "execute_after_write.exe"
    )
    artifact_root.mkdir(parents=True, exist_ok=True)
    dump_path = artifact_root / f"execute_after_write-{arch}.dump.exe"
    evidence_path = artifact_root / f"execute_after_write-{arch}.evidence.json"
    _reset_owned_artifacts(artifact_root, dump_path, evidence_path)
    original_payload = _export_bytes(target, "eaw_buffer", len(EXPECTED_PAYLOAD))
    if original_payload != b"\0" * len(EXPECTED_PAYLOAD):
        raise RuntimeError(
            f"{arch} source eaw_buffer is not pristine: {original_payload.hex()}"
        )
    launch = module.LaunchFileUnderDebugger(
        exe_path=str(target),
        arch=arch,
        restart_debugger=True,
        timeout_ms=30000,
        stop_first=True,
        use_scyllahide="off",
        advance_to_entry=True,
    )
    if not isinstance(launch, dict) or not launch.get("ok"):
        raise RuntimeError(f"{arch} launch failed: {launch}")
    try:
        stage = module.CaptureSymbolicBreakpoint(
            target=f"{target.name}!eaw_stage_write",
            timeout_ms=20000,
            delete_after_hit=True,
            resume=True,
            source="execute-after-write-live-gate",
            symbol_name="eaw_stage_write",
        )
        if not isinstance(stage, dict) or not stage.get("ok"):
            raise RuntimeError(f"{arch} stage breakpoint failed: {stage}")
        loaded = module._resolve_loaded_module_for_dump(target.name)
        if not loaded:
            raise RuntimeError(f"{arch} loaded fixture module was not found")
        buffer_address = module._resolve_loaded_module_symbol(
            loaded,
            "eaw_buffer",
        )
        if not buffer_address:
            raise RuntimeError(f"{arch} eaw_buffer address was not resolved")
        workflow = module.DumpOnEvent(
            event="execute_after_write",
            output_path=str(dump_path),
            module=target.name,
            breakpoint_target=f"{buffer_address},64",
            timeout_ms=30000,
            dump_kind="module",
            resume_after=False,
            auto_run=True,
            event_evidence_path=str(evidence_path),
        )
        if not isinstance(workflow, dict) or not workflow.get("ok"):
            raise RuntimeError(
                f"{arch} execute-after-write dump failed: {workflow}"
            )
        capture = workflow.get("wait") or {}
        if not (
            capture.get("ok")
            and capture.get("writeEvidence")
            and int(capture.get("snapshotCount") or 0) == 3
            and (capture.get("ordering") or {}).get("strictlyOrdered")
            and (capture.get("execute") or {}).get("pointsAtChangedByte")
        ):
            raise RuntimeError(
                f"{arch} ordered execute-after-write evidence is incomplete: "
                f"{capture}"
            )
        final_diff = capture.get("finalDiff") or {}
        if int(final_diff.get("changedByteCount") or 0) != 4:
            raise RuntimeError(
                f"{arch} expected four generated bytes: {final_diff}"
            )
        if int((capture.get("execute") or {}).get("offset", -1)) != 0:
            raise RuntimeError(
                f"{arch} generated execution did not begin at offset zero"
            )
        dumped_payload = _export_bytes(
            dump_path,
            "eaw_buffer",
            len(EXPECTED_PAYLOAD),
        )
        if dumped_payload != EXPECTED_PAYLOAD:
            raise RuntimeError(
                f"{arch} dump did not preserve generated bytes: "
                f"{dumped_payload.hex()}"
            )
        resume = module.DebugRun()
        exit_result = module.WaitForExit(timeout_ms=15000, poll_ms=50)
        if not isinstance(exit_result, dict) or not exit_result.get("exited"):
            raise RuntimeError(
                f"{arch} debuggee did not exit after generated execution: "
                f"{exit_result}"
            )
        smoke = _smoke(dump_path)
        if not smoke.get("ok"):
            raise RuntimeError(f"{arch} dump smoke failed: {smoke}")
        return {
            "ok": True,
            "arch": arch,
            "target": {
                "path": str(target),
                "sha256": _sha256(target),
                "pristinePayloadHex": original_payload.hex(),
            },
            "launch": launch,
            "stage": stage,
            "bufferAddress": buffer_address,
            "workflow": workflow,
            "dump": {
                "path": str(dump_path),
                "sha256": _sha256(dump_path),
                "generatedPayloadHex": dumped_payload.hex(),
            },
            "evidence": {
                "path": str(evidence_path),
                "sha256": _sha256(evidence_path),
            },
            "resume": resume,
            "exit": exit_result,
            "smoke": smoke,
        }
    finally:
        try:
            module.DebugStop()
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--arch",
        choices=("x64", "x86", "all"),
        default="all",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            REPO_ROOT
            / "tools"
            / "dump_outputs"
            / "stage5e_execute_after_write_live_final.json"
        ),
    )
    args = parser.parse_args()
    module = _load_module()
    architectures = (
        ["x64", "x86"] if args.arch == "all" else [args.arch]
    )
    artifact_root = (
        args.output.resolve().parent / "stage5e_execute_after_write_live"
    )
    report: dict[str, Any] = {
        "schema": "stage5e-execute-after-write-live-v1",
        "ok": False,
        "architectures": architectures,
        "results": [],
    }
    try:
        for arch in architectures:
            report["results"].append(
                _one_arch(module, arch, artifact_root)
            )
        report["ok"] = all(
            item.get("ok") for item in report["results"]
        )
    except Exception as exc:
        report["error"] = str(exc)
        report["traceback"] = traceback.format_exc()
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    canonical = json.dumps(
        report,
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")
    report["reportSha256"] = hashlib.sha256(canonical).hexdigest().upper()
    args.output.resolve().write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
