"""Live x64dbg gate for custom/hash import resolver reconstruction."""

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
EXPECTED_NAMES = [
    "GetCurrentProcessId",
    "GetCurrentThreadId",
    "GetTickCount",
    "GetStdHandle",
    "WriteFile",
    "IsDebuggerPresent",
    "RtlExitUserProcess",
]
EXPECTED_MARKER = "CUSTOM_RESOLVER_OK hashes=7 slots=7 pid=1 tid=1 tick=1"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "x64dbg_custom_resolver_live",
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


def _reset_owned_artifacts(artifact_root: Path, *paths: Path) -> None:
    root = artifact_root.resolve()
    for candidate in paths:
        resolved = candidate.resolve()
        if resolved.parent != root:
            raise RuntimeError(
                f"artifact cleanup escaped gate directory: {resolved}"
            )
        resolved.unlink(missing_ok=True)


def _flatten_imports(layout: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "module": str(descriptor.get("dll") or ""),
            "function": str(function or ""),
        }
        for descriptor in list(layout.get("imports") or [])
        if isinstance(descriptor, dict)
        for function in list(descriptor.get("functions") or [])
    ]


def _one_arch(module: Any, arch: str, artifact_root: Path) -> dict[str, Any]:
    target = (
        REPO_ROOT
        / "tools"
        / "bin"
        / "e2e"
        / arch
        / "custom_import_resolver.exe"
    )
    artifact_root.mkdir(parents=True, exist_ok=True)
    raw_path = artifact_root / f"custom_import_resolver-{arch}.raw.exe"
    rebuilt_path = artifact_root / f"custom_import_resolver-{arch}.rebuilt.exe"
    evidence_path = artifact_root / f"custom_import_resolver-{arch}.evidence.json"
    _reset_owned_artifacts(
        artifact_root,
        raw_path,
        rebuilt_path,
        evidence_path,
    )
    packed_layout = module._parse_pe_layout(str(target))
    if packed_layout.get("imports"):
        raise RuntimeError(
            f"{arch} fixture unexpectedly has ordinary imports"
        )
    if (
        int(packed_layout.get("iatDirectory", {}).get("size") or 0) != 0
    ):
        raise RuntimeError(
            f"{arch} fixture unexpectedly has an IAT directory"
        )
    launch = module.LaunchFileUnderDebugger(
        exe_path=str(target),
        arch=arch,
        restart_debugger=True,
        timeout_ms=30000,
        stop_first=True,
        use_scyllahide="off",
        use_hidemain="off",
        advance_to_entry=True,
    )
    if not isinstance(launch, dict) or not launch.get("ok"):
        raise RuntimeError(f"{arch} launch failed: {launch}")
    trace_id = ""
    try:
        custom_target = [
            {
                "module": target.name,
                "symbol": "custom_resolve_export",
                "name": "custom_resolve_export",
                "kind": "import-resolver",
                "resolver": {
                    "keyArgIndex": 1,
                    "moduleArgIndex": 0,
                    "keyEncoding": "fnv1a32",
                    "subscribeResolved": False,
                    "requireExactExport": True,
                },
            }
        ]
        started = module.StartApiTrace(
            modules_json=json.dumps(["kernelbase.dll"]),
            filter_json=json.dumps(["__mcp_never_matches__"]),
            arg_count=2,
            label=f"custom-resolver-{arch}",
            max_targets=16,
            capture_returns=True,
            capture_callstack=False,
            max_out_bytes=0,
            subscribe_modules=False,
            discover_dynamic_resolvers=True,
            native_return_hooks=True,
            custom_targets_json=json.dumps(custom_target),
        )
        if not isinstance(started, dict) or not started.get("ok"):
            raise RuntimeError(
                f"{arch} custom resolver trace start failed: {started}"
            )
        trace_id = str(started.get("traceId") or "")
        if int(started.get("customTargetCount") or 0) != 1:
            raise RuntimeError(
                f"{arch} explicit custom target was not installed: {started}"
            )
        run = module.RunApiTrace(
            trace_id,
            timeout_ms=45000,
            max_calls=7,
            drain_returns=True,
        )
        if not isinstance(run, dict) or not run.get("ok"):
            raise RuntimeError(f"{arch} API trace run failed: {run}")
        log = module.GetApiTraceLog(trace_id, offset=0, limit=100)
        calls = list(log.get("calls") or []) if isinstance(log, dict) else []
        resolver_calls = [
            call
            for call in calls
            if str(call.get("targetKind") or "").casefold()
            == "import-resolver"
        ]
        if len(resolver_calls) != 7:
            raise RuntimeError(
                f"{arch} expected 7 resolver calls, got {len(resolver_calls)}: {log}"
            )
        identities: list[dict[str, Any]] = []
        request_keys: list[int] = []
        for call in resolver_calls:
            if not call.get("returned") or call.get("returnTrackingError"):
                raise RuntimeError(
                    f"{arch} resolver return evidence is incomplete: {call}"
                )
            subscription = call.get("dynamicTargetSubscription") or {}
            observation = subscription.get("resolverEvidence") or {}
            identity = observation.get("identity") or {}
            if not observation.get("exactExport") or not identity.get("ok"):
                raise RuntimeError(
                    f"{arch} resolver target is not an exact export: {call}"
                )
            identities.append(identity)
            request_keys.append(int(observation.get("requestKeyInt") or 0))
        observed_names = [str(item.get("function") or "") for item in identities]
        if observed_names != EXPECTED_NAMES:
            raise RuntimeError(
                f"{arch} resolver sequence mismatch: {observed_names}"
            )
        if len(set(request_keys)) != 7 or any(key == 0 for key in request_keys):
            raise RuntimeError(
                f"{arch} resolver keys are missing or duplicated: {request_keys}"
            )
        stop_trace = module.StopApiTrace(
            trace_id,
            delete_breakpoints=True,
        )
        # A return breakpoint stops before the caller executes the store into
        # the final IAT slot. The fixture's intentional post-population
        # debugbreak is the deterministic commit boundary for the live table.
        settle_run = module.DebugRun()
        settle_pause = module.WaitForPause(
            timeout_ms=15000,
            poll_ms=50,
        )
        if (
            not isinstance(settle_pause, dict)
            or not settle_pause.get("paused")
        ):
            raise RuntimeError(
                f"{arch} populated-table commit boundary was not reached: "
                f"{settle_pause}"
            )
        recovery = module.RecoverRuntimeImports(
            module=target.name,
            table_symbol="custom_import_table",
            table_count=7,
            trace_id=trace_id,
            raw_dump_path=str(raw_path),
            output_path=str(rebuilt_path),
            evidence_path=str(evidence_path),
            overwrite=False,
        )
        if not isinstance(recovery, dict) or not recovery.get("ok"):
            raise RuntimeError(
                f"{arch} runtime import recovery failed: {recovery}"
            )
        verification = recovery.get("structuralVerification") or {}
        if not verification.get("ok"):
            raise RuntimeError(
                f"{arch} rebuilt imports failed structural verification: {recovery}"
            )
        rebuilt_layout = module._parse_pe_layout(str(rebuilt_path))
        rebuilt_imports = _flatten_imports(rebuilt_layout)
        if [item["function"] for item in rebuilt_imports] != EXPECTED_NAMES:
            raise RuntimeError(
                f"{arch} rebuilt import sequence mismatch: {rebuilt_imports}"
            )
        if int(rebuilt_layout.get("iatDirectory", {}).get("size") or 0) != (
            8 * (8 if arch == "x64" else 4)
        ):
            raise RuntimeError(
                f"{arch} rebuilt IAT does not include the null terminator"
            )
        debug_stop = module.DebugStop()
        smoke = _smoke(rebuilt_path)
        if not smoke.get("ok"):
            raise RuntimeError(
                f"{arch} rebuilt import smoke failed: {smoke}"
            )
        return {
            "ok": True,
            "arch": arch,
            "target": {
                "path": str(target),
                "sha256": _sha256(target),
                "originalImportCount": len(
                    _flatten_imports(packed_layout)
                ),
                "originalIatSize": int(
                    packed_layout.get("iatDirectory", {}).get("size") or 0
                ),
            },
            "launch": launch,
            "traceStart": started,
            "traceRun": run,
            "traceStop": stop_trace,
            "tableCommit": {
                "run": settle_run,
                "pause": settle_pause,
            },
            "resolver": {
                "callCount": len(resolver_calls),
                "requestKeys": request_keys,
                "identities": identities,
            },
            "recovery": recovery,
            "rebuilt": {
                "path": str(rebuilt_path),
                "sha256": _sha256(rebuilt_path),
                "imports": rebuilt_imports,
                "iat": rebuilt_layout.get("iatDirectory"),
            },
            "evidence": {
                "path": str(evidence_path),
                "sha256": _sha256(evidence_path),
            },
            "smoke": smoke,
            "debugStop": debug_stop,
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
            / "stage5e_custom_resolver_live_final.json"
        ),
    )
    args = parser.parse_args()
    module = _load_module()
    architectures = (
        ["x64", "x86"] if args.arch == "all" else [args.arch]
    )
    artifact_root = (
        args.output.resolve().parent / "stage5e_custom_resolver_live"
    )
    report: dict[str, Any] = {
        "schema": "stage5e-custom-resolver-live-v1",
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
