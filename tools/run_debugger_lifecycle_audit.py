"""Run the measured debugger launch/close lifecycle gate.

The audit is intentionally separate from the broad live matrix.  It launches a
fresh x64dbg/x32dbg instance, records a PID+creation-time identity and Windows
process handle counts, closes the instance through the production stop path, and
proves that the exact identity (and all observed descendants) are gone before
the next cycle starts.  It never terminates an unobserved debugger.
"""

from __future__ import annotations

import argparse
import ctypes
import importlib.util
import json
import os
import statistics
import sys
import time
import traceback
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BRIDGE = ROOT / "src" / "x64dbg.py"
DEFAULT_OUT = ROOT / "tools" / "bin" / "live_release" / "phase1b6-debugger-lifecycle.json"
DEBUGGER_NAMES = frozenset({"x32dbg.exe", "x64dbg.exe"})
SCHEMA_VERSION = 1


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location("x64dbg_lifecycle_audit_bridge", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load bridge module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _atomic_write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _process_handle_count(pid: int) -> Optional[int]:
    """Return GetProcessHandleCount for an observed process, or None on error."""

    if os.name != "nt" or int(pid) <= 0:
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    open_process.restype = ctypes.c_void_p
    get_count = kernel32.GetProcessHandleCount
    get_count.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    get_count.restype = ctypes.c_int
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    # PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION
    handle = open_process(0x0400 | 0x1000, 0, int(pid))
    if not handle:
        return None
    try:
        value = ctypes.c_ulong()
        if not get_count(handle, ctypes.byref(value)):
            return None
        return int(value.value)
    finally:
        close_handle(handle)


def _identity_for_pid(items: Sequence[Any], pid: int) -> Optional[Any]:
    return next((item for item in items if int(getattr(item, "pid", 0)) == int(pid)), None)


def _identity_keys(items: Sequence[Any]) -> list[tuple[int, str, int]]:
    return sorted(
        (int(item.pid), str(item.name).casefold(), int(item.creation_time))
        for item in items
        if int(getattr(item, "pid", 0)) > 0
    )


def _expected_name(arch: str) -> str:
    return "x64dbg.exe" if arch == "x64" else "x32dbg.exe"


def _sample_handles(pid: int, count: int = 5, interval: float = 0.10) -> list[int]:
    values: list[int] = []
    for index in range(max(1, int(count))):
        value = _process_handle_count(pid)
        if value is not None:
            values.append(value)
        if index + 1 < count:
            time.sleep(max(0.0, float(interval)))
    return values


def _wait_for_pid(snapshotter, pid: int, timeout: float) -> Optional[Any]:
    deadline = time.monotonic() + max(0.1, float(timeout))
    while time.monotonic() < deadline:
        found = _identity_for_pid(snapshotter(), pid)
        if found is not None and int(getattr(found, "creation_time", 0)) > 0:
            return found
        time.sleep(0.10)
    return None


def _wait_no_debuggers(snapshotter, timeout: float) -> list[Any]:
    deadline = time.monotonic() + max(0.1, float(timeout))
    last: list[Any] = []
    while time.monotonic() < deadline:
        current = snapshotter()
        last = [item for item in current if str(item.name).casefold() in DEBUGGER_NAMES]
        if not last:
            return []
        time.sleep(0.10)
    return last


def _trend(values: Sequence[int]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "min": None, "max": None, "first": None, "last": None, "delta": None}
    return {
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "first": values[0],
        "last": values[-1],
        "delta": values[-1] - values[0],
        "median": statistics.median(values),
    }


def run_audit(
    *,
    bridge_path: Path,
    arch: str,
    cycles: int,
    timeout_seconds: float,
    sample_count: int,
    sample_interval: float,
) -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("The debugger lifecycle gate requires Windows process identities.")
    if arch not in {"x86", "x64"}:
        raise ValueError("arch must be x86 or x64")
    if cycles <= 0:
        raise ValueError("cycles must be positive")

    from run_live_release_matrix import (  # imported lazily for unit-testability
        cleanup_owned_processes,
        descendant_processes,
        debugger_processes,
        same_process_identity,
        snapshot_processes,
    )

    bridge = _load_module(bridge_path)
    initial = debugger_processes(snapshot_processes())
    if initial:
        raise RuntimeError(
            "Refusing lifecycle audit because a debugger already exists: "
            + json.dumps([asdict(item) for item in initial], ensure_ascii=False)
        )

    cases: list[dict[str, Any]] = []
    all_handle_first: list[int] = []
    all_handle_last: list[int] = []
    all_handle_peaks: list[int] = []
    started = time.monotonic()

    for number in range(1, int(cycles) + 1):
        case_started = time.monotonic()
        case: dict[str, Any] = {
            "cycle": number,
            "arch": arch,
            "startedAt": _utc_now(),
            "ok": False,
        }
        owned_roots: list[Any] = []
        owned_descendants: list[Any] = []
        before_keys: set[tuple[int, str, int]] = set()
        try:
            settled = _wait_no_debuggers(snapshot_processes, min(timeout_seconds, 10.0))
            if settled:
                raise RuntimeError(
                    "A debugger from the previous cycle did not settle: "
                    + json.dumps(_identity_keys(settled))
                )
            before = snapshot_processes()
            before_debuggers = debugger_processes(before)
            case["beforeDebuggerKeys"] = _identity_keys(before_debuggers)
            if before_debuggers:
                raise RuntimeError("A debugger appeared before this cycle started.")

            launch = bridge.EnsureDebugger(
                arch=arch,
                timeout_ms=max(1000, int(timeout_seconds * 1000)),
                restart=False,
            )
            case["launch"] = launch
            after_launch = snapshot_processes()
            before_keys = {item.key for item in before_debuggers}
            new_debuggers = [
                item
                for item in debugger_processes(after_launch)
                if item.key not in before_keys and int(item.creation_time) > 0
            ]
            # No debugger existed at the cycle boundary, so any process that
            # appears during this launch attempt is owned by this cycle.  This
            # lets a failed/duplicate startup be cleaned without broad kills.
            owned_roots = list(new_debuggers)
            if not isinstance(launch, dict) or not launch.get("ok"):
                raise RuntimeError(f"EnsureDebugger failed: {launch}")
            if bool(launch.get("alreadyRunning")):
                raise RuntimeError("EnsureDebugger reused an existing debugger; fresh cycle required.")
            active = launch.get("activeDebugger") or {}
            pid = int(active.get("pid") or (launch.get("launch") or {}).get("pid") or 0)
            if pid <= 0:
                raise RuntimeError("EnsureDebugger returned no debugger PID.")
            root = _wait_for_pid(snapshot_processes, pid, timeout_seconds)
            if root is None:
                raise RuntimeError("Launched debugger PID was not observable with a creation-time token.")
            if str(root.name).casefold() != _expected_name(arch):
                raise RuntimeError(f"Unexpected debugger image: {root.name}")
            if all(item.key != root.key for item in owned_roots):
                owned_roots.append(root)
            post_launch = snapshot_processes()
            for item in debugger_processes(post_launch):
                if item.key not in before_keys and all(item.key != owned.key for owned in owned_roots):
                    owned_roots.append(item)
            if len(owned_roots) != 1:
                raise RuntimeError(
                    "More than one fresh debugger identity appeared during launch: "
                    + json.dumps(_identity_keys(owned_roots))
                )
            current = snapshot_processes()
            owned_descendants = descendant_processes(current, [root.pid])
            case["root"] = asdict(root)
            case["descendantsAtReady"] = [asdict(item) for item in owned_descendants]
            handle_samples = _sample_handles(root.pid, sample_count, sample_interval)
            case["handleSamples"] = handle_samples
            case["handleTrend"] = _trend(handle_samples)
            if not handle_samples:
                raise RuntimeError("GetProcessHandleCount returned no samples.")
            all_handle_first.append(handle_samples[0])
            all_handle_last.append(handle_samples[-1])
            all_handle_peaks.append(max(handle_samples))

            stop = bridge._stop_debugger_processes(arch, timeout_ms=max(1000, int(timeout_seconds * 1000)))
            case["stop"] = stop
            if not isinstance(stop, dict) or not stop.get("ok"):
                raise RuntimeError(f"Production debugger stop failed: {stop}")
            # A debugger can create a helper shortly after the root is observed;
            # capture it before the exact orphan check.
            after = snapshot_processes()
            late_descendants = descendant_processes(after, [root.pid])
            for item in late_descendants:
                if item.key not in {x.key for x in owned_descendants}:
                    owned_descendants.append(item)
            owned_expected = owned_roots + owned_descendants
            remaining_exact = [
                item
                for item in debugger_processes(after)
                if any(same_process_identity(item, expected) for expected in owned_roots)
            ]
            remaining_owned = [
                item
                for item in after
                if any(same_process_identity(item, expected) for expected in owned_expected)
            ]
            case["afterDebuggerKeys"] = _identity_keys(debugger_processes(after))
            case["remainingExact"] = [asdict(item) for item in remaining_exact]
            case["remainingOwned"] = [asdict(item) for item in remaining_owned]
            if remaining_exact or remaining_owned or debugger_processes(after):
                # Only exact identities observed in this cycle may be cleaned;
                # unknown processes are reported and never force-killed.
                cleanup = cleanup_owned_processes(owned_roots, owned_descendants)
                case["exactCleanup"] = cleanup
                after_cleanup = snapshot_processes()
                case["afterCleanupDebuggerKeys"] = _identity_keys(debugger_processes(after_cleanup))
                remaining_after_cleanup = [
                    item
                    for item in after_cleanup
                    if any(same_process_identity(item, expected) for expected in owned_expected)
                ]
                case["remainingOwnedAfterCleanup"] = [
                    asdict(item) for item in remaining_after_cleanup
                ]
                if remaining_after_cleanup or debugger_processes(after_cleanup):
                    raise RuntimeError("A debugger identity remained after exact cleanup.")
            settled_after = _wait_no_debuggers(snapshot_processes, min(timeout_seconds, 10.0))
            case["settledAfterStopKeys"] = _identity_keys(settled_after)
            if settled_after:
                raise RuntimeError("A debugger appeared or remained during post-stop settling.")
            case["ok"] = True
        except Exception as exc:
            case["error"] = str(exc)
            case["exceptionType"] = type(exc).__name__
            case["traceback"] = traceback.format_exc()
            # Best effort, identity-scoped cleanup only.  Never call a broad
            # taskkill on an identity we did not capture in this cycle.
            try:
                current_failure = snapshot_processes()
                for item in debugger_processes(current_failure):
                    if item.key not in before_keys and all(
                        item.key != owned.key for owned in owned_roots
                    ):
                        owned_roots.append(item)
            except Exception:
                pass
            if owned_roots:
                try:
                    case["failureCleanup"] = cleanup_owned_processes(owned_roots, owned_descendants)
                except Exception as cleanup_exc:
                    case["failureCleanupError"] = str(cleanup_exc)
        finally:
            case["finishedAt"] = _utc_now()
            case["durationSeconds"] = round(time.monotonic() - case_started, 3)
            cases.append(case)
            if not case.get("ok"):
                # Stop immediately: a failed lifecycle can leave an unknown
                # process behind, and continuing would weaken isolation.
                break

    final_debuggers = debugger_processes(snapshot_processes())
    completed = len(cases)
    first_median = statistics.median(all_handle_first) if all_handle_first else None
    last_median = statistics.median(all_handle_last) if all_handle_last else None
    growth = (last_median - first_median) if first_median is not None and last_median is not None else None
    allowed_growth = max(8.0, float(first_median or 0) * 0.15)
    trend_ok = bool(all_handle_first) and (growth is not None and growth <= allowed_growth)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "name": "x64dbg MCP debugger lifecycle audit",
        "startedAt": _utc_now(),
        "arch": arch,
        "cyclesRequested": int(cycles),
        "cyclesCompleted": completed,
        "durationSeconds": round(time.monotonic() - started, 3),
        "cases": cases,
        "handleTrend": {
            "firstMedian": first_median,
            "lastMedian": last_median,
            "medianDelta": growth,
            "allowedGrowth": allowed_growth,
            "firstSamples": all_handle_first,
            "lastSamples": all_handle_last,
            "peakSamples": all_handle_peaks,
            "ok": trend_ok,
        },
        "orphanAudit": {
            "remainingDebuggerKeys": _identity_keys(final_debuggers),
            "ok": not final_debuggers,
        },
        "ok": completed == int(cycles) and all(bool(item.get("ok")) for item in cases) and trend_ok and not final_debuggers,
        "finishedAt": _utc_now(),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the x64dbg/x32dbg lifecycle stability gate.")
    parser.add_argument("--arch", choices=["x86", "x64", "all"], default="all")
    parser.add_argument("--cycles", type=int, default=100)
    parser.add_argument("--bridge", default=str(DEFAULT_BRIDGE))
    parser.add_argument("--out", help="Exact report path; defaults to tools/bin/live_release.")
    parser.add_argument("--timeout-seconds", type=float, default=45.0)
    parser.add_argument("--sample-count", type=int, default=5)
    parser.add_argument("--sample-interval", type=float, default=0.10)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if args.cycles <= 0 or args.timeout_seconds <= 0 or args.sample_count <= 0 or args.sample_interval < 0:
        raise SystemExit("cycles/timeout/sample-count must be positive and sample-interval non-negative")
    arches = ("x86", "x64") if args.arch == "all" else (args.arch,)
    reports: list[dict[str, Any]] = []
    for selected in arches:
        report = run_audit(
            bridge_path=Path(args.bridge).resolve(),
            arch=selected,
            cycles=args.cycles,
            timeout_seconds=args.timeout_seconds,
            sample_count=args.sample_count,
            sample_interval=args.sample_interval,
        )
        reports.append(report)
        if not report.get("ok"):
            break
    aggregate = {
        "schemaVersion": SCHEMA_VERSION,
        "name": "x64dbg MCP debugger lifecycle audit (aggregate)",
        "requestedArch": args.arch,
        "cyclesPerArch": args.cycles,
        "reports": reports,
        "ok": len(reports) == len(arches) and all(bool(item.get("ok")) for item in reports),
        "finishedAt": _utc_now(),
    }
    output = Path(args.out).resolve() if args.out else DEFAULT_OUT
    _atomic_write(output, aggregate)
    print(json.dumps({"ok": aggregate["ok"], "out": str(output), "reports": reports}, ensure_ascii=False))
    return 0 if aggregate["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
