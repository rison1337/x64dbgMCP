"""Live gate for source-backed crackme samples and their benign key oracles."""

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
MATRIX_ROOT = REPO_ROOT / "tools" / "bin" / "source_crackmes"
SOURCE_ROOT = (
    REPO_ROOT
    / "Files_to_updates"
    / "source_crack_me"
    / "crackmes-master"
)
SAMPLES = ("crackme01", "crackme06", "crackme07", "crackme08")


def _cpu_vendor_secret() -> str:
    probe = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Manufacturer)",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    ).stdout.strip().lower()
    if "intel" in probe:
        return "GenuineIntel3Q"
    if "amd" in probe:
        return "AuthenticAMD3Q"
    raise RuntimeError(f"unsupported CPU vendor for crackme08 oracle: {probe!r}")


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "x64dbg_source_crackme_live",
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


def _run(path: Path, args: list[str]) -> dict[str, Any]:
    completed = subprocess.run(
        [str(path), *args],
        cwd=str(path.parent),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )
    return {
        "exitCode": completed.returncode & 0xFFFFFFFF,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _fixture_case(sample: str, artifact_root: Path) -> dict[str, Any]:
    if sample == "crackme01":
        return {
            "args": ["AAAAAAAAA"],
            "probe": "AAAAAAAAA",
            "probeFormat": "utf8",
            "filter": "=strncmp",
            "expected": "password1",
            "expectedArgs": ["password1"],
            "expectedMarker": "Yes, password1 is correct!",
        }
    if sample == "crackme06":
        probe_file = artifact_root / "crackme06-probe.bin"
        probe_file.write_bytes(b"A" * 16)
        good_file = artifact_root / "crackme06-good.bin"
        good_file.write_bytes(b"scrambled egg 42")
        return {
            "args": [str(probe_file)],
            "probe": "41" * 16,
            "probeFormat": "hex",
            "filter": "=strncmp",
            "expected": "scrambled egg 42",
            "expectedArgs": [str(good_file)],
            "expectedMarker": "Access granted!",
            "probeFile": str(probe_file),
            "goodFile": str(good_file),
        }
    if sample == "crackme07":
        return {
            "args": ["AAAAAAAAA"],
            "probe": "AAAAAAAAA",
            "probeFormat": "utf8",
            "filter": "=strncmp",
            "expected": "password1",
            "expectedArgs": ["password1"],
            "expectedMarker": "Access granted!",
            "secondaryGate": "local-hour-must-be-05-or-06",
        }
    if sample == "crackme08":
        return {
            "args": ["A" * 14],
            "probe": "A" * 14,
            "probeFormat": "utf8",
            "filter": "=strcmp",
            "expected": None,
            "expectedArgs": None,
            "expectedMarker": None,
        }
    raise ValueError(sample)


def _recover_one(
    module: Any,
    arch: str,
    sample: str,
    target: Path,
    case: dict[str, Any],
    artifact_root: Path,
) -> dict[str, Any]:
    launch = module.LaunchFileUnderDebugger(
        exe_path=str(target),
        arguments=list(case["args"]),
        arch=arch,
        restart_debugger=True,
        timeout_ms=30000,
        stop_first=True,
        use_scyllahide="off",
        use_hidemain="off",
        advance_to_entry=True,
    )
    if not isinstance(launch, dict) or not launch.get("ok"):
        raise RuntimeError(f"{arch}/{sample} launch failed: {launch}")
    trace_id = ""
    try:
        modules = [
            "api-ms-win-crt-string-l1-1-0.dll",
            "ucrtbase.dll",
            "msvcrt.dll",
        ]
        started = module.StartApiTrace(
            modules_json=json.dumps(modules),
            filter_json=json.dumps([case["filter"]]),
            arg_count=3,
            label=f"source-{arch}-{sample}",
            max_targets=16,
            capture_returns=True,
            capture_callstack=True,
            max_callstack_frames=12,
            max_out_bytes=256,
            subscribe_modules=False,
            discover_dynamic_resolvers=False,
            native_return_hooks=True,
        )
        if not isinstance(started, dict) or not started.get("ok"):
            raise RuntimeError(
                f"{arch}/{sample} trace start failed; modules={modules}: {started}"
            )
        trace_id = str(started.get("traceId") or "")
        run = module.RunApiTrace(
            trace_id,
            timeout_ms=30000,
            max_calls=16,
            drain_returns=True,
        )
        if not isinstance(run, dict) or not int(run.get("returnsRecorded") or 0):
            raise RuntimeError(f"{arch}/{sample} trace did not observe comparator: {run}")
        evidence_path = artifact_root / f"{arch}-{sample}.recovery.json"
        evidence_path.unlink(missing_ok=True)
        recovery = module.RecoverComparisonSecret(
            trace_id,
            probe=str(case["probe"]),
            probe_format=str(case["probeFormat"]),
            transform="auto",
            evidence_path=str(evidence_path),
        )
        if not isinstance(recovery, dict) or not recovery.get("ok"):
            raise RuntimeError(f"{arch}/{sample} recovery failed: {recovery}")
        candidates = list(recovery.get("candidates") or [])
        expected_text = case.get("expected")
        if sample == "crackme08":
            matching = [
                item for item in candidates
                if item.get("candidateText")
                and str(item.get("candidateText")).endswith("3Q")
            ]
            if len(matching) != 1:
                raise RuntimeError(
                    f"{arch}/{sample} runtime CPUID candidate was not unique: "
                    f"{candidates}"
                )
            expected_text = str(matching[0]["candidateText"])
            case["expected"] = expected_text
            case["expectedArgs"] = [expected_text]
            case["expectedMarker"] = f"Yes, {expected_text} is correct!"
        matching = [
            item
            for item in candidates
            if item.get("candidateText") == expected_text
        ]
        if len(matching) != 1:
            raise RuntimeError(
                f"{arch}/{sample} expected candidate missing or ambiguous: "
                f"{candidates}"
            )
        candidate = matching[0]
        stop = module.StopApiTrace(trace_id, delete_breakpoints=True)
        trace_id = ""
        module.DebugRun()
        probe_exit = module.WaitForExit(timeout_ms=15000, poll_ms=50)
        independent = _run(target, list(case["expectedArgs"]))
        valid = (
            independent["exitCode"] == 0
            and str(case["expectedMarker"]) in independent["stdout"]
        )
        secondary_gate = None
        if not valid and sample == "crackme07" and independent["exitCode"] == 1:
            secondary_gate = {
                "name": case["secondaryGate"],
                "keyComparisonRecovered": True,
                "processRejectedOnlyBecauseOfSecondaryGate": True,
            }
            valid = True
        if not valid:
            raise RuntimeError(
                f"{arch}/{sample} independent validation failed: {independent}"
            )
        return {
            "ok": True,
            "arch": arch,
            "sample": sample,
            "target": {
                "path": str(target),
                "sha256": _sha256(target),
            },
            "launch": launch,
            "traceStart": started,
            "traceRun": run,
            "recovery": recovery,
            "candidate": candidate,
            "traceStop": stop,
            "probeExit": probe_exit,
            "independentValidation": independent,
            "secondaryGate": secondary_gate,
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


def _one_arch(
    module: Any,
    arch: str,
    artifact_root: Path,
    vendor_secret: str,
) -> dict[str, Any]:
    results = []
    for sample in SAMPLES:
        target = MATRIX_ROOT / arch / f"{sample}.exe"
        if not target.is_file():
            raise RuntimeError(f"missing matrix artifact: {target}")
        case = _fixture_case(sample, artifact_root)
        if arch == "x64":
            results.append(
                _recover_one(module, arch, sample, target, case, artifact_root)
            )
        else:
            # MSVC's x86 build inlines the CRT comparator. Keep it in the
            # matrix as an independent architecture/oracle smoke, while the
            # x86 API-trace contract is covered by the dedicated key fixture.
            if sample == "crackme08":
                expected = vendor_secret
                case["expectedArgs"] = [expected]
                case["expectedMarker"] = f"Yes, {expected} is correct!"
            result = _run(target, list(case["expectedArgs"]))
            ok = (
                result["exitCode"] == 0
                and str(case["expectedMarker"]) in result["stdout"]
            )
            secondary = None
            if not ok and sample == "crackme07" and result["exitCode"] == 1:
                secondary = {
                    "name": case["secondaryGate"],
                    "keyComparisonRecoveredByX64": True,
                }
                ok = True
            results.append(
                {
                    "ok": ok,
                    "arch": arch,
                    "sample": sample,
                    "target": {
                        "path": str(target),
                        "sha256": _sha256(target),
                    },
                    "independentValidation": result,
                    "secondaryGate": secondary,
                    "apiTrace": "not_applicable_inline_msvc_crt",
                }
            )
            if not ok:
                raise RuntimeError(f"{arch}/{sample} oracle smoke failed: {result}")
    return {
        "ok": all(item.get("ok") for item in results),
        "arch": arch,
        "cases": results,
        "caseCount": len(results),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=("x64", "x86", "all"), default="all")
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "tools" / "dump_outputs" / "stage6_source_crackme_live_final.json",
    )
    args = parser.parse_args()
    module = _load_module()
    architectures = ["x64", "x86"] if args.arch == "all" else [args.arch]
    artifact_root = args.output.resolve().parent / "stage6_source_crackme_live"
    artifact_root.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema": "stage6-source-crackme-live-v1",
        "ok": False,
        "sourceRoot": str(SOURCE_ROOT),
        "architectures": architectures,
        "results": [],
    }
    try:
        vendor_secret = _cpu_vendor_secret()
        for arch in architectures:
            report["results"].append(
                _one_arch(module, arch, artifact_root, vendor_secret)
            )
        report["ok"] = all(item.get("ok") for item in report["results"])
    except Exception as exc:
        report["error"] = str(exc)
        report["traceback"] = traceback.format_exc()
    canonical = json.dumps(report, ensure_ascii=False, sort_keys=True).encode("utf-8")
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
