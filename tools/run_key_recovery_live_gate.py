"""Live x64dbg gate for exact comparison-operand key recovery."""

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
CASES = (
    {
        "mode": "direct",
        "probe": "AAAAAAAAAAAAAAA",
        "probeFormat": "utf8",
        "filter": "=lstrcmpa",
        "expected": "polished-key-42",
        "method": "identity-comparison",
    },
    {
        "mode": "xor",
        "probe": "AAAAAAAAA",
        "probeFormat": "utf8",
        "filter": "=lstrcmpa",
        "expected": "XorKey-7!",
        "method": "observed-single-byte-xor",
        "xorKey": 0x23,
    },
    {
        "mode": "wide",
        "probe": "AAAAAAAAAAA",
        "probeFormat": "utf16le",
        "filter": "=lstrcmpw",
        "expected": "wide-key-42",
        "method": "identity-comparison",
    },
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "x64dbg_key_recovery_live",
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


def _smoke(path: Path, mode: str, candidate: str) -> dict[str, Any]:
    completed = subprocess.run(
        [str(path), mode, candidate],
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
    marker = f"KEY_RECOVERY_OK mode={mode}"
    return {
        "ok": exit_code == 0 and marker in completed.stdout,
        "exitCode": exit_code,
        "marker": marker,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _one_case(
    module: Any,
    arch: str,
    target: Path,
    case: dict[str, Any],
    artifact_root: Path,
) -> dict[str, Any]:
    mode = str(case["mode"])
    evidence_path = artifact_root / f"key_recovery-{arch}-{mode}.json"
    evidence_path.unlink(missing_ok=True)
    launch = module.LaunchFileUnderDebugger(
        exe_path=str(target),
        arguments=[mode, str(case["probe"])],
        arch=arch,
        restart_debugger=True,
        timeout_ms=30000,
        stop_first=True,
        use_scyllahide="off",
        advance_to_entry=True,
    )
    if not isinstance(launch, dict) or not launch.get("ok"):
        raise RuntimeError(f"{arch}/{mode} launch failed: {launch}")
    trace_id = ""
    stop = None
    try:
        started = module.StartApiTrace(
            modules_json=json.dumps(["kernel32.dll", "kernelbase.dll"]),
            filter_json=json.dumps([case["filter"]]),
            arg_count=3,
            label=f"key-recovery-{arch}-{mode}",
            max_targets=8,
            capture_returns=True,
            capture_callstack=True,
            max_callstack_frames=12,
            max_out_bytes=256,
            caller_filter="",
            decode_string_args=True,
            collapse_nested_families=False,
            subscribe_modules=False,
            discover_dynamic_resolvers=False,
            native_return_hooks=True,
        )
        if not isinstance(started, dict) or not started.get("ok"):
            raise RuntimeError(f"{arch}/{mode} trace start failed: {started}")
        trace_id = str(started.get("traceId") or "")
        run = module.RunApiTrace(
            trace_id,
            timeout_ms=30000,
            max_calls=8,
            drain_returns=True,
        )
        if not isinstance(run, dict) or int(run.get("returnsRecorded") or 0) < 1:
            raise RuntimeError(f"{arch}/{mode} trace did not return: {run}")
        recovery = module.RecoverComparisonSecret(
            trace_id,
            probe=str(case["probe"]),
            probe_format=str(case["probeFormat"]),
            transform="auto",
            expected_operand=-1,
            evidence_path=str(evidence_path),
            overwrite=False,
        )
        if not isinstance(recovery, dict) or not recovery.get("ok"):
            raise RuntimeError(f"{arch}/{mode} recovery failed: {recovery}")
        matching = [
            item
            for item in list(recovery.get("candidates") or [])
            if item.get("candidateText") == case["expected"]
            and item.get("method") == case["method"]
        ]
        if len(matching) != 1:
            raise RuntimeError(
                f"{arch}/{mode} exact candidate was not unique: "
                f"{recovery.get('candidates')}"
            )
        candidate = matching[0]
        if case.get("xorKey") is not None and int(
            candidate.get("xorKey") or -1
        ) != int(case["xorKey"]):
            raise RuntimeError(
                f"{arch}/{mode} recovered the wrong XOR key: {candidate}"
            )
        stop = module.StopApiTrace(trace_id, delete_breakpoints=True)
        trace_id = ""
        module.DebugRun()
        exit_result = module.WaitForExit(timeout_ms=15000, poll_ms=50)
        if not isinstance(exit_result, dict) or not exit_result.get("exited"):
            raise RuntimeError(
                f"{arch}/{mode} probe process did not exit: {exit_result}"
            )
        smoke = _smoke(target, mode, str(candidate["candidateText"]))
        if not smoke.get("ok"):
            raise RuntimeError(
                f"{arch}/{mode} independent validation failed: {smoke}"
            )
        return {
            "ok": True,
            "arch": arch,
            "mode": mode,
            "launch": launch,
            "traceStart": started,
            "traceRun": run,
            "recovery": recovery,
            "candidate": candidate,
            "traceStop": stop,
            "probeExit": exit_result,
            "independentValidation": smoke,
            "evidence": {
                "path": str(evidence_path),
                "sha256": _sha256(evidence_path),
            },
        }
    finally:
        if trace_id:
            try:
                module.StopApiTrace(trace_id, delete_breakpoints=True)
            except Exception:
                pass
        try:
            module.DebugStop()
        except Exception:
            pass


def _one_arch(module: Any, arch: str, artifact_root: Path) -> dict[str, Any]:
    target = (
        REPO_ROOT / "tools" / "bin" / "e2e" / arch / "key_recovery.exe"
    )
    if not target.is_file():
        raise RuntimeError(f"missing corpus artifact: {target}")
    results = [
        _one_case(module, arch, target, case, artifact_root)
        for case in CASES
    ]
    return {
        "ok": all(item.get("ok") for item in results),
        "arch": arch,
        "target": {
            "path": str(target),
            "sha256": _sha256(target),
        },
        "caseCount": len(results),
        "cases": results,
    }


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
            / "stage6_key_recovery_live_final.json"
        ),
    )
    args = parser.parse_args()
    module = _load_module()
    architectures = (
        ["x64", "x86"] if args.arch == "all" else [args.arch]
    )
    artifact_root = (
        args.output.resolve().parent / "stage6_key_recovery_live"
    )
    artifact_root.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema": "stage6-key-recovery-live-v1",
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
    canonical = json.dumps(
        report,
        ensure_ascii=False,
        sort_keys=True,
    ).encode("utf-8")
    report["reportSha256"] = hashlib.sha256(canonical).hexdigest().upper()
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.output.resolve().write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
