"""Prove fail-closed bridge startup when the configured loopback port is occupied.

The harness owns port 8888 before launching a fresh x32dbg/x64dbg instance.
The plugin must refuse initialization without publishing an auth descriptor,
while the debugger process itself remains alive and can be closed cleanly.
Only PIDs created by this harness are ever terminated.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = (
    ROOT
    / "tools"
    / "bin"
    / "live_release"
    / "phase2b-r-occupied-port-startup.json"
)
DEBUGGERS = {
    "x86": Path(r"C:\x64dbg\x32\x32dbg.exe"),
    "x64": Path(r"C:\x64dbg\x64\x64dbg.exe"),
}
DEBUGGER_NAMES = {"x32dbg.exe", "x64dbg.exe"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _debugger_processes() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for process in psutil.process_iter(["pid", "name", "create_time"]):
        try:
            name = str(process.info.get("name") or "").casefold()
            if name not in DEBUGGER_NAMES:
                continue
            result.append(
                {
                    "pid": int(process.info["pid"]),
                    "name": name,
                    "createTime": float(process.info.get("create_time") or 0.0),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return result


def _descriptor_path(pid: int) -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    return base / "x64dbgMCP" / f"bridge-{int(pid)}.token"


def _terminate_owned(process: subprocess.Popen[Any], expected_create_time: float) -> dict[str, Any]:
    result: dict[str, Any] = {"pid": int(process.pid), "terminated": False}
    try:
        observed = psutil.Process(process.pid)
        current_create_time = float(observed.create_time())
        result["observedCreateTime"] = current_create_time
        if abs(current_create_time - expected_create_time) > 0.01:
            result["error"] = "PID identity changed; refusing termination"
            return result
        observed.terminate()
        try:
            observed.wait(timeout=5.0)
        except psutil.TimeoutExpired:
            observed.kill()
            observed.wait(timeout=5.0)
        result["terminated"] = not observed.is_running()
    except psutil.NoSuchProcess:
        result["terminated"] = True
        result["alreadyExited"] = True
    except Exception as exc:  # pragma: no cover - live diagnostic
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp-{os.getpid()}-{time.time_ns()}")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def run_audit(cycles: int, settle_seconds: float) -> dict[str, Any]:
    before = _debugger_processes()
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "name": "x64dbg MCP occupied-port startup failure audit",
        "startedAt": _utc_now(),
        "cyclesPerArch": int(cycles),
        "port": 8888,
        "preexistingDebuggers": before,
        "cases": [],
        "ok": False,
    }
    if before:
        report["error"] = "Refusing audit while an unrelated debugger already exists."
        report["finishedAt"] = _utc_now()
        return report

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    listener.bind(("127.0.0.1", 8888))
    listener.listen(1)
    try:
        for arch in ("x86", "x64"):
            executable = DEBUGGERS[arch]
            if not executable.is_file():
                report["cases"].append(
                    {
                        "arch": arch,
                        "ok": False,
                        "error": f"Debugger executable is missing: {executable}",
                    }
                )
                continue
            for cycle in range(1, int(cycles) + 1):
                case: dict[str, Any] = {
                    "arch": arch,
                    "cycle": cycle,
                    "startedAt": _utc_now(),
                    "executable": str(executable),
                    "ok": False,
                }
                process: subprocess.Popen[Any] | None = None
                try:
                    process = subprocess.Popen(
                        [str(executable)],
                        cwd=str(executable.parent),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    observed = psutil.Process(process.pid)
                    create_time = float(observed.create_time())
                    case["pid"] = int(process.pid)
                    case["createTime"] = create_time
                    deadline = time.monotonic() + max(0.5, float(settle_seconds))
                    while time.monotonic() < deadline and process.poll() is None:
                        time.sleep(0.05)
                    descriptor = _descriptor_path(process.pid)
                    alive = process.poll() is None
                    case["debuggerAliveAfterPluginFailure"] = alive
                    case["descriptorPath"] = str(descriptor)
                    case["descriptorPublished"] = descriptor.exists()
                    case["portOwnerStillHarness"] = listener.getsockname() == (
                        "127.0.0.1",
                        8888,
                    )
                    case["cleanup"] = _terminate_owned(process, create_time)
                    case["remainingDebuggers"] = _debugger_processes()
                    case["ok"] = bool(
                        alive
                        and not case["descriptorPublished"]
                        and case["portOwnerStillHarness"]
                        and case["cleanup"].get("terminated")
                        and not case["remainingDebuggers"]
                    )
                except Exception as exc:
                    case["error"] = f"{type(exc).__name__}: {exc}"
                    if process is not None:
                        try:
                            create_time = float(psutil.Process(process.pid).create_time())
                            case["cleanup"] = _terminate_owned(process, create_time)
                        except Exception:
                            pass
                case["finishedAt"] = _utc_now()
                report["cases"].append(case)
                if not case.get("ok"):
                    break
    finally:
        listener.close()
    report["finalDebuggers"] = _debugger_processes()
    expected = int(cycles) * len(DEBUGGERS)
    report["ok"] = bool(
        len(report["cases"]) == expected
        and all(case.get("ok") for case in report["cases"])
        and not report["finalDebuggers"]
    )
    report["finishedAt"] = _utc_now()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--settle-seconds", type=float, default=2.0)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    if args.cycles <= 0 or args.settle_seconds <= 0:
        parser.error("--cycles and --settle-seconds must be positive")
    report = run_audit(args.cycles, args.settle_seconds)
    output = args.out.expanduser().resolve()
    _atomic_write_json(output, report)
    print(
        json.dumps(
            {
                "ok": report.get("ok"),
                "out": str(output),
                "cases": len(report.get("cases") or []),
            },
            ensure_ascii=False,
        )
    )
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
