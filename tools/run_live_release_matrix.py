"""Isolated x86/x64 live release matrix for x64dbg MCP.

The public process is only an orchestrator.  Every live case runs in a fresh
Python worker with a hard wall-clock deadline.  The debugger intentionally
lives outside the worker process tree (the bridge launches it through
Explorer), so the parent also tracks the exact debugger PID/creation-time
identity and performs a PID-scoped cleanup after every case.

This runner is deliberately fail-closed:

* a reported ``skipped`` case is a failure, never a synthetic pass;
* an existing x32dbg/x64dbg session is not touched without the explicit
  ``--take-over-existing-debugger`` option;
* cleanup failure fails the case even when its functional assertions passed;
* worker stdout/stderr and an atomic JSON/JUnit-like report are retained.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence
from urllib.parse import urlsplit


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = Path(__file__).resolve().parent
DEFAULT_BRIDGE = REPO_ROOT / "src" / "x64dbg.py"
# tools/bin is already an ignored generated-artifact tree in this repository.
DEFAULT_RESULTS_ROOT = TOOLS_DIR / "bin" / "live_release"
DEBUGGER_NAMES = frozenset({"x32dbg.exe", "x64dbg.exe"})
ARCHITECTURES = ("x64", "x86")
REPORT_SCHEMA_VERSION = 1
WORKER_SCHEMA_VERSION = 1


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class CaseSpec:
    name: str
    scenario: str
    target: str
    timeout_seconds: float
    description: str


# All required cases are architecture-neutral by construction.  The target is
# either one of the deterministic corpus fixture ids or the legacy watch target
# built by headless_smoke.  Keeping the table here avoids the machine-specific
# defaults (C:\test-files, System32 applications) in exploratory smoke runs.
CASE_SPECS: tuple[CaseSpec, ...] = (
    CaseSpec(
        "plugin_status",
        "plugin_status",
        "corpus:launch_contract",
        60.0,
        "Installed plugin and ScyllaHide integration inventory.",
    ),
    CaseSpec(
        "self_check",
        "self_check",
        "corpus:launch_contract",
        90.0,
        "Live/cache/vendor plugin drift self-check.",
    ),
    CaseSpec(
        "launch_argv_env_cwd",
        "__launch_argv_env_cwd__",
        "corpus:launch_contract",
        120.0,
        "Typed Unicode argv, isolated environment block, cwd and exact captured output.",
    ),
    CaseSpec(
        "launch_bytes_stdio",
        "__launch_bytes_stdio__",
        "corpus:launch_contract",
        120.0,
        "Finite binary stdin bytes plus exact binary stdout/stderr capture.",
    ),
    CaseSpec(
        "launch_pipe_stdio",
        "__launch_pipe_stdio__",
        "corpus:launch_contract",
        120.0,
        "Incremental bounded stdin pipe writes, explicit EOF and binary capture.",
    ),
    CaseSpec(
        "launch_file_stdio",
        "__launch_file_stdio__",
        "corpus:launch_contract",
        120.0,
        "stdin file plus stdout truncate and stderr append contracts.",
    ),
    CaseSpec(
        "launch_bounded_burst",
        "__launch_bounded_burst__",
        "corpus:launch_contract",
        180.0,
        "Interleaved 2 MiB per stream with bounded retention and cursor-drop proof.",
    ),
    CaseSpec(
        "launch_explicit_inherit",
        "__launch_explicit_inherit__",
        "corpus:launch_contract",
        120.0,
        "Explicit standard-handle inheritance succeeds exactly or fails closed.",
    ),
    CaseSpec(
        "re_context",
        "re_context",
        "corpus:launch_contract",
        180.0,
        "Registers, memory, disassembly, stepping and checkpoint context.",
    ),
    CaseSpec(
        "session_identity_cas",
        "__session_identity_cas__",
        "corpus:launch_contract",
        180.0,
        "Protocol-v4 SHA/event guards, stale-session rejection and transactional rollback.",
    ),
    CaseSpec(
        "breakpoint_ownership",
        "__breakpoint_ownership__",
        "corpus:launch_contract",
        180.0,
        "Session-bound software/conditional/hardware/memory breakpoint ownership and expiry.",
    ),
    CaseSpec(
        "http_parser_adversarial",
        "__http_parser_adversarial__",
        "corpus:launch_contract",
        120.0,
        "Authenticated framing/header rejection and pre-auth parse ordering.",
    ),
    CaseSpec(
        "dispatcher_concurrency",
        "__dispatcher_concurrency__",
        "corpus:launch_contract",
        180.0,
        "Bounded FIFO admission, wait/control responsiveness, overload and cleanup.",
    ),
    CaseSpec(
        "decoder_suite",
        "decoder_suite",
        "corpus:launch_contract",
        120.0,
        "Architecture-sensitive structured value decoders.",
    ),
    CaseSpec(
        "trace_summary",
        "trace_summary",
        "corpus:launch_contract",
        90.0,
        "Instruction snapshot history and summary.",
    ),
    CaseSpec(
        "symbolic_bridge",
        "symbolic_bridge",
        "corpus:launch_contract",
        90.0,
        "Module+RVA symbolic breakpoint resolution.",
    ),
    CaseSpec(
        "memory_watchpoint",
        "memory_watchpoint",
        "watch",
        120.0,
        "Write watchpoint with captured cause and byte diff.",
    ),
    CaseSpec(
        "api_trace_sleep",
        "api_trace_sleep",
        "watch",
        120.0,
        "One-shot API trace with breakpoint cleanup.",
    ),
    CaseSpec(
        "api_trace_dynamic_resolver",
        "__api_trace_dynamic_resolver__",
        "corpus:dynamic_api_trace",
        180.0,
        "Late LoadLibrary/GetProcAddress target subscription and resolved call.",
    ),
    CaseSpec(
        "api_trace_exception_unwind",
        "__api_trace_exception_unwind__",
        "corpus:exception_disposition",
        180.0,
        "Native API shadow-stack first/second-chance exception unwind evidence.",
    ),
    CaseSpec(
        "api_trace_managed_exception",
        "__api_trace_managed_exception__",
        "managed:exception",
        180.0,
        "Real .NET Framework managed exception metadata and API-frame correlation.",
    ),
    CaseSpec(
        "managed_runtime_probe",
        "__managed_runtime_probe__",
        "managed:probe",
        240.0,
        "Passive CLR/AppDomain/stack/JIT map capture and post-JIT managed breakpoint.",
    ),
    CaseSpec(
        "heap_trace_live",
        "__heap_resource_trace__",
        "corpus:deterministic_heap",
        120.0,
        "Live allocator/resource lifecycle trace against the deterministic heap fixture.",
    ),
    CaseSpec(
        "heap_resource_families_live",
        "__heap_resource_families__",
        "corpus:deterministic_heap",
        180.0,
        "Cross-family allocator matrix with cross-thread free evidence.",
    ),
    CaseSpec(
        "checkpoint_rewind",
        "checkpoint_rewind",
        "watch",
        120.0,
        "Memory mutation followed by checkpoint rewind.",
    ),
    CaseSpec(
        "minidump_analysis",
        "__minidump_analysis__",
        "corpus:launch_contract",
        180.0,
        "Guarded analysis minidump plus independent verification.",
    ),
    CaseSpec(
        "dump_main",
        "dump_main",
        "watch",
        180.0,
        "Main-module Scylla dump pipeline.",
    ),
    CaseSpec(
        "evidence_roundtrip",
        "__evidence_roundtrip__",
        "corpus:launch_contract",
        180.0,
        "SHA/arch/RVA-bound annotations roundtrip across two sessions.",
    ),
    CaseSpec(
        "dll_overlay_dump",
        "__dll_overlay_dump__",
        "corpus:module_imports",
        180.0,
        "Source-backed loaded-DLL overlay dump plus independent PE verification.",
    ),
    CaseSpec(
        "memory_pe_discovery",
        "__memory_pe_discovery__",
        "corpus:launch_contract",
        180.0,
        "Memory-map manifest, private/mapped PE discovery and atomic raw-region dump.",
    ),
    CaseSpec(
        "native_coverage",
        "__native_coverage__",
        "corpus:deterministic_coverage",
        180.0,
        "Exact CB_TRACEEXECUTE coverage for the deterministic selector-zero path.",
    ),
    CaseSpec(
        "exception_policy_first_chance",
        "__exception_policy_first_chance__",
        "corpus:exception_disposition",
        180.0,
        "Native first-chance not-handled versus handled disposition exit oracles.",
    ),
    CaseSpec(
        "exception_policy_precedence",
        "__exception_policy_precedence__",
        "corpus:exception_disposition",
        180.0,
        "Exact, masked and wildcard native exception-rule precedence plus history cursors.",
    ),
    CaseSpec(
        "exception_policy_second_chance",
        "__exception_policy_second_chance__",
        "corpus:exception_disposition",
        180.0,
        "First-chance pass followed by a deterministic second-chance policy pause.",
    ),
    CaseSpec(
        "exception_policy_lifecycle",
        "__exception_policy_lifecycle__",
        "corpus:exception_disposition",
        180.0,
        "History clear, manual exactly-once disposition and relaunch isolation.",
    ),
)


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    ppid: int
    name: str
    creation_time: int

    @property
    def key(self) -> tuple[int, str, int]:
        return (int(self.pid), str(self.name).casefold(), int(self.creation_time))


@dataclass
class WatchdogOutcome:
    returncode: Optional[int]
    timed_out: bool
    elapsed_seconds: float
    termination: Optional[dict[str, Any]]


def _atomic_write_json(path: Path | str, payload: Any) -> None:
    destination = Path(path).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            if os.path.exists(temporary):
                os.unlink(temporary)
        except OSError:
            pass


def _parse_case_selectors(values: Iterable[str]) -> list[str]:
    selectors: list[str] = []
    for raw in values:
        for item in str(raw or "").split(","):
            normalized = item.strip()
            if normalized and normalized not in selectors:
                selectors.append(normalized)
    return selectors


def select_case_runs(
    arch: str,
    case_selectors: Iterable[str] = (),
    specs: Sequence[CaseSpec] = CASE_SPECS,
) -> list[tuple[str, CaseSpec]]:
    """Return deterministic ``(arch, case)`` runs or reject unknown selectors."""

    normalized_arch = str(arch or "all").strip().lower()
    if normalized_arch not in ("all", "x86", "x64"):
        raise ValueError("arch must be x86, x64, or all")
    selected_arches = ARCHITECTURES if normalized_arch == "all" else (normalized_arch,)
    selectors = _parse_case_selectors(case_selectors)
    known = {spec.name for spec in specs}
    matched_selectors: set[str] = set()
    runs: list[tuple[str, CaseSpec]] = []
    for selected_arch in selected_arches:
        for spec in specs:
            if not selectors:
                runs.append((selected_arch, spec))
                continue
            accepted = False
            for selector in selectors:
                selector_arch = ""
                selector_name = selector
                if "." in selector:
                    selector_arch, selector_name = selector.split(".", 1)
                    selector_arch = selector_arch.lower()
                if selector_name not in known:
                    continue
                if selector_arch and selector_arch != selected_arch:
                    continue
                if selector_name == spec.name:
                    accepted = True
                    matched_selectors.add(selector)
            if accepted:
                runs.append((selected_arch, spec))
    unknown = [selector for selector in selectors if selector not in matched_selectors]
    if unknown:
        raise ValueError(f"unknown or out-of-scope case selector(s): {', '.join(unknown)}")
    if not runs:
        raise ValueError("case selection is empty")
    return runs


def _windows_creation_time(pid: int) -> int:
    if os.name != "nt" or int(pid) <= 0:
        return 0
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    open_process.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    get_process_times = kernel32.GetProcessTimes
    get_process_times.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ulonglong),
    ]
    get_process_times.restype = ctypes.c_int
    handle = open_process(0x1000, 0, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return 0
    try:
        creation = ctypes.c_ulonglong()
        exit_time = ctypes.c_ulonglong()
        kernel = ctypes.c_ulonglong()
        user = ctypes.c_ulonglong()
        if not get_process_times(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            return 0
        return int(creation.value)
    finally:
        close_handle(handle)


def snapshot_processes() -> list[ProcessIdentity]:
    """Take a Toolhelp snapshot with a creation-time anti-PID-reuse token."""

    if os.name != "nt":
        return []
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_snapshot = kernel32.CreateToolhelp32Snapshot
    create_snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    create_snapshot.restype = wintypes.HANDLE
    process_first = kernel32.Process32FirstW
    process_first.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    process_first.restype = wintypes.BOOL
    process_next = kernel32.Process32NextW
    process_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    process_next.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    invalid_handle = ctypes.c_void_p(-1).value
    handle = create_snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if int(handle or 0) == int(invalid_handle or -1):
        raise OSError(f"CreateToolhelp32Snapshot failed: {ctypes.get_last_error()}")
    raw: list[tuple[int, int, str]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = bool(process_first(handle, ctypes.byref(entry)))
        while ok:
            raw.append(
                (
                    int(entry.th32ProcessID),
                    int(entry.th32ParentProcessID),
                    str(entry.szExeFile),
                )
            )
            ok = bool(process_next(handle, ctypes.byref(entry)))
    finally:
        close_handle(handle)
    # Opening every process handle on every watchdog poll is needlessly costly.
    # Hydrate the anti-reuse token only for debugger roots and their current
    # descendants. ``lookup_process_identity`` hydrates an explicitly requested
    # PID as a fallback after its parent has already exited.
    provisional = [ProcessIdentity(pid, ppid, name, 0) for pid, ppid, name in raw]
    root_pids = {
        item.pid for item in provisional if item.name.casefold() in DEBUGGER_NAMES
    }
    interesting = root_pids | {
        item.pid for item in descendant_processes(provisional, root_pids)
    }
    return [
        ProcessIdentity(
            item.pid,
            item.ppid,
            item.name,
            _windows_creation_time(item.pid) if item.pid in interesting else 0,
        )
        for item in provisional
    ]


def debugger_processes(
    processes: Optional[Iterable[ProcessIdentity]] = None,
) -> list[ProcessIdentity]:
    items = snapshot_processes() if processes is None else list(processes)
    return [item for item in items if item.name.casefold() in DEBUGGER_NAMES]


def descendant_processes(
    processes: Iterable[ProcessIdentity], root_pids: Iterable[int]
) -> list[ProcessIdentity]:
    items = list(processes)
    children: dict[int, list[ProcessIdentity]] = {}
    for item in items:
        children.setdefault(int(item.ppid), []).append(item)
    pending = [int(pid) for pid in root_pids if int(pid) > 0]
    seen = set(pending)
    result: list[ProcessIdentity] = []
    while pending:
        parent = pending.pop()
        for child in children.get(parent, []):
            if child.pid in seen:
                continue
            seen.add(child.pid)
            pending.append(child.pid)
            result.append(child)
    return result


def lookup_process_identity(
    pid: int,
    snapshotter: Callable[[], list[ProcessIdentity]] = snapshot_processes,
) -> Optional[ProcessIdentity]:
    item = next((entry for entry in snapshotter() if entry.pid == int(pid)), None)
    if item is not None and item.creation_time <= 0 and os.name == "nt":
        item = ProcessIdentity(
            item.pid,
            item.ppid,
            item.name,
            _windows_creation_time(item.pid),
        )
    return item


def same_process_identity(expected: ProcessIdentity, current: ProcessIdentity) -> bool:
    """Fail closed when creation time is unavailable or PID was recycled."""

    return bool(
        expected.pid == current.pid
        and expected.name.casefold() == current.name.casefold()
        and expected.creation_time > 0
        and current.creation_time > 0
        and expected.creation_time == current.creation_time
    )


def _taskkill_pid(pid: int, timeout_seconds: float = 10.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["taskkill", "/PID", str(int(pid)), "/T", "/F"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=max(1.0, float(timeout_seconds)),
        check=False,
        creationflags=0x08000000 if os.name == "nt" else 0,
    )


def terminate_process_identity(
    expected: ProcessIdentity,
    *,
    allowed_names: Optional[set[str] | frozenset[str]] = None,
    lookup: Callable[[int], Optional[ProcessIdentity]] = lookup_process_identity,
    taskkill: Callable[[int, float], Any] = _taskkill_pid,
    timeout_seconds: float = 10.0,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Terminate only the exact captured process identity, never a reused PID."""

    allowed = {name.casefold() for name in allowed_names} if allowed_names else None
    if allowed is not None and expected.name.casefold() not in allowed:
        return {
            "ok": False,
            "pid": expected.pid,
            "errorCode": "UNEXPECTED_PROCESS_NAME",
            "error": f"Refusing to terminate unexpected image {expected.name!r}.",
        }
    current = lookup(expected.pid)
    if current is None:
        return {"ok": True, "pid": expected.pid, "alreadyExited": True}
    if not same_process_identity(expected, current):
        return {
            "ok": False,
            "pid": expected.pid,
            "errorCode": "PID_IDENTITY_MISMATCH",
            "error": "PID was reused or its creation-time identity is unavailable; refusing taskkill.",
            "expected": asdict(expected),
            "current": asdict(current),
        }
    try:
        completed = taskkill(expected.pid, timeout_seconds)
        returncode = int(getattr(completed, "returncode", completed if isinstance(completed, int) else -1))
        stdout = str(getattr(completed, "stdout", "") or "")
        stderr = str(getattr(completed, "stderr", "") or "")
    except Exception as exc:
        return {
            "ok": False,
            "pid": expected.pid,
            "errorCode": "TASKKILL_FAILED",
            "error": str(exc),
        }
    deadline = time.monotonic() + max(0.1, float(timeout_seconds))
    while time.monotonic() < deadline:
        after = lookup(expected.pid)
        if after is None or not same_process_identity(expected, after):
            return {
                "ok": True,
                "pid": expected.pid,
                "returncode": returncode,
                "stdout": stdout.strip(),
                "stderr": stderr.strip(),
            }
        sleeper(0.05)
    return {
        "ok": False,
        "pid": expected.pid,
        "returncode": returncode,
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
        "errorCode": "PROCESS_STILL_ALIVE",
        "error": "The exact captured process identity remained alive after taskkill.",
    }


def cleanup_owned_processes(
    debugger_roots: Iterable[ProcessIdentity],
    descendants: Iterable[ProcessIdentity] = (),
    *,
    lookup: Callable[[int], Optional[ProcessIdentity]] = lookup_process_identity,
    taskkill: Callable[[int, float], Any] = _taskkill_pid,
) -> dict[str, Any]:
    """Kill captured debugger roots first, then any exact surviving descendants."""

    unique_roots = {item.key: item for item in debugger_roots}
    unique_descendants = {item.key: item for item in descendants}
    results: list[dict[str, Any]] = []
    for root in sorted(unique_roots.values(), key=lambda item: item.pid):
        results.append(
            terminate_process_identity(
                root,
                allowed_names=DEBUGGER_NAMES,
                lookup=lookup,
                taskkill=taskkill,
            )
        )
    for child in sorted(unique_descendants.values(), key=lambda item: item.pid, reverse=True):
        if lookup(child.pid) is None:
            continue
        results.append(
            terminate_process_identity(child, lookup=lookup, taskkill=taskkill)
        )
    remaining: list[dict[str, Any]] = []
    for item in list(unique_roots.values()) + list(unique_descendants.values()):
        current = lookup(item.pid)
        if current is not None and same_process_identity(item, current):
            remaining.append(asdict(current))
    return {
        "ok": not remaining and all(bool(item.get("ok")) for item in results),
        "attempts": results,
        "remaining": remaining,
        "rootCount": len(unique_roots),
        "descendantCount": len(unique_descendants),
    }


def _terminate_worker_tree(pid: int) -> dict[str, Any]:
    if int(pid) <= 0:
        return {"ok": False, "error": "Invalid worker PID"}
    try:
        if os.name == "nt":
            completed = _taskkill_pid(pid, 10.0)
            return {
                "ok": completed.returncode == 0,
                "pid": int(pid),
                "returncode": int(completed.returncode),
                "stdout": str(completed.stdout or "").strip(),
                "stderr": str(completed.stderr or "").strip(),
            }
        os.kill(pid, 9)
        return {"ok": True, "pid": int(pid)}
    except Exception as exc:
        return {"ok": False, "pid": int(pid), "error": str(exc)}


def wait_with_watchdog(
    process: Any,
    timeout_seconds: float,
    *,
    poll_interval: float = 0.1,
    on_poll: Optional[Callable[[], None]] = None,
    terminate: Callable[[int], dict[str, Any]] = _terminate_worker_tree,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> WatchdogOutcome:
    """Wait for a child with a real parent-owned hard deadline."""

    started = monotonic()
    deadline = started + max(0.01, float(timeout_seconds))
    while True:
        if on_poll is not None:
            on_poll()
        returncode = process.poll()
        if returncode is not None:
            return WatchdogOutcome(
                int(returncode), False, max(0.0, monotonic() - started), None
            )
        now = monotonic()
        if now >= deadline:
            termination = terminate(int(process.pid))
            try:
                returncode = process.wait(timeout=5.0)
            except Exception:
                try:
                    process.kill()
                    returncode = process.wait(timeout=2.0)
                except Exception:
                    returncode = None
            return WatchdogOutcome(
                int(returncode) if returncode is not None else None,
                True,
                max(0.0, monotonic() - started),
                termination,
            )
        sleeper(min(max(0.001, float(poll_interval)), max(0.001, deadline - now)))


def ensure_debugger_for_worker(bridge: Any, arch: str, timeout_ms: int) -> dict[str, Any]:
    """Pinned clean-start policy; unit tests guard against target resurrection."""

    result = bridge.RestartDebugger(
        arch=arch,
        timeout_ms=max(1000, int(timeout_ms)),
        reload_target=False,
    )
    return result if isinstance(result, dict) else {"ok": False, "error": str(result)}


def _load_headless_module() -> Any:
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    import headless_smoke  # type: ignore

    return headless_smoke


def _load_corpus_manifest() -> dict[str, Any]:
    path = TOOLS_DIR / "corpus_manifest.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_case_executable(spec: CaseSpec, arch: str, headless: Any) -> str:
    if spec.target == "watch":
        path = Path(headless._ensure_watch_target_exe(arch)).resolve()
    elif spec.target.startswith("corpus:"):
        fixture_id = spec.target.split(":", 1)[1]
        manifest = _load_corpus_manifest()
        fixture = next(
            (item for item in manifest.get("fixtures", []) if item.get("id") == fixture_id),
            None,
        )
        if not isinstance(fixture, dict):
            raise RuntimeError(f"Corpus fixture does not exist: {fixture_id}")
        template = str((fixture.get("build") or {}).get("output") or "")
        path = (REPO_ROOT / template.format(arch=arch)).resolve()
    elif spec.target == "managed:exception":
        path = (REPO_ROOT / "tools" / "bin" / "e2e" / arch / "managed_exception.exe").resolve()
    elif spec.target == "managed:probe":
        path = (
            REPO_ROOT / "tools" / "bin" / "e2e" / arch / "managed_probe_fixture.exe"
        ).resolve()
    else:
        raise RuntimeError(f"Unsupported target selector: {spec.target}")
    if not path.is_file():
        raise FileNotFoundError(
            f"Live case target is missing: {path}. Run the appropriate corpus or managed fixture build first."
        )
    return str(path)


def _run_minidump_adapter(bridge: Any, exe_path: str, artifact_dir: Path, arch: str) -> dict[str, Any]:
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
    )
    if not isinstance(init, dict) or not init.get("ok"):
        return {"ok": False, "init": init, "error": "InitDebuggee failed"}
    entry = bridge.RunUntil(target="entry", timeout_ms=8000, poll_ms=100)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    dump_path = artifact_dir / f"analysis-{arch}.dmp"
    if dump_path.exists():
        dump_path.unlink()
    written = bridge.WriteMiniDump(
        output_path=str(dump_path),
        dump_type="analysis",
        overwrite=False,
        timeout_ms=120000,
    )
    verified = bridge.VerifyMiniDump(str(dump_path), compute_sha256=True)
    observed_arch = str((verified or {}).get("architecture") or "").lower()
    ok = bool(
        isinstance(entry, dict)
        and entry.get("ok")
        and isinstance(written, dict)
        and written.get("ok")
        and isinstance(verified, dict)
        and verified.get("valid")
        and observed_arch == arch
        and dump_path.is_file()
        and dump_path.stat().st_size > 0
    )
    return {
        "ok": ok,
        "init": init,
        "entry": entry,
        "write": written,
        "verify": verified,
        "path": str(dump_path),
        "error": None if ok else "Minidump did not pass architecture-aware verification.",
    }


def _main_module_record(bridge: Any, exe_path: str) -> dict[str, Any]:
    payload = bridge.GetModuleList()
    modules = payload.get("modules", []) if isinstance(payload, dict) else []
    wanted = Path(exe_path).name.casefold()
    return next(
        (
            dict(item)
            for item in modules
            if isinstance(item, dict)
            and str(item.get("name") or item.get("path") or "").split("\\")[-1].casefold()
            == wanted
        ),
        {},
    )


def _bridge_mutation_ok(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if "success" in payload:
        return bool(payload.get("success")) and bool(payload.get("ok", True))
    return bool(payload.get("ok"))


def _raw_guarded_bridge_request(
    bridge: Any,
    method: str,
    endpoint: str,
    *,
    params: Optional[dict[str, Any]] = None,
    data: Optional[dict[str, Any]] = None,
    headers: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    """Issue one non-retried authenticated request for adversarial guard tests."""

    session = bridge._get_http_session()
    kwargs = {
        "params": dict(params or {}) or None,
        "headers": dict(headers or {}),
        "timeout": 5.0,
        "allow_redirects": False,
    }
    if method.upper() == "POST":
        kwargs["data"] = dict(data or {})
        response = session.post(bridge._bridge_url(endpoint), **kwargs)
    else:
        response = session.get(bridge._bridge_url(endpoint), **kwargs)
    try:
        payload = response.json()
    except Exception:
        text = str(getattr(response, "text", ""))
        try:
            payload = json.loads(text)
        except Exception:
            payload = text
    error_code = ""
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            error_code = str(error.get("code") or "")
    return {
        "status": int(response.status_code),
        "ok": 200 <= int(response.status_code) < 300,
        "errorCode": error_code,
        "payload": payload,
    }


def _session_identity_headers(bridge: Any) -> tuple[dict[str, str], Optional[dict[str, Any]]]:
    request_id = f"live-cas-{uuid.uuid4()}"
    headers, error = bridge._guard_headers("session", request_id=request_id)
    if error is not None:
        return {}, error.as_dict()
    return dict(headers), None


def _raw_http_bytes(bridge: Any, request: bytes, timeout: float = 5.0) -> dict[str, Any]:
    """Send one deliberately raw HTTP request, including duplicate headers."""

    parsed = urlsplit(str(getattr(bridge, "x64dbg_server_url", "") or ""))
    host = parsed.hostname or "127.0.0.1"
    port = int(parsed.port or 8888)
    chunks: list[bytes] = []
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            except ConnectionResetError:
                return {
                    "status": 0,
                    "ok": False,
                    "errorCode": "connection_reset",
                    "payload": None,
                    "rawBytes": 0,
                }
            if not chunk:
                break
            chunks.append(chunk)
    raw = b"".join(chunks)
    head, separator, body = raw.partition(b"\r\n\r\n")
    first_line = head.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
    try:
        status = int(first_line.split(" ", 2)[1])
    except Exception:
        status = 0
    try:
        payload = json.loads(body.decode("utf-8", errors="replace")) if separator else body.decode("latin1", errors="replace")
    except Exception:
        payload = body.decode("utf-8", errors="replace") if separator else ""
    error_code = ""
    if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
        error_code = str(payload["error"].get("code") or "")
    return {
        "status": status,
        "ok": 200 <= status < 300,
        "errorCode": error_code,
        "payload": payload,
        "rawBytes": len(raw),
    }


def _run_http_parser_adversarial_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir, arch
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
    )
    if not isinstance(init, dict) or not init.get("ok"):
        return {"ok": False, "init": init, "error": "InitDebuggee failed"}
    token = bridge._discover_bridge_auth_token()
    if not token:
        return {"ok": False, "init": init, "error": "Bridge token unavailable"}
    parsed = urlsplit(str(getattr(bridge, "x64dbg_server_url", "") or ""))
    host = parsed.netloc or "127.0.0.1:8888"
    auth = f"X-MCP-Auth-Token: {token}".encode("ascii")
    base = b"Host: " + host.encode("ascii", errors="ignore") + b"\r\n" + auth + b"\r\n"
    session_headers, session_header_error = _session_identity_headers(bridge)
    if session_header_error:
        return {
            "ok": False,
            "init": init,
            "error": session_header_error,
        }
    # ``_guard_headers`` already carries the authentication token.  Do not
    # prepend ``base`` here: duplicate auth headers are intentionally rejected
    # by the native parser and would make the self-unload guard test exercise
    # authentication failure instead of the guarded route.
    guarded = (
        b"Host: " + host.encode("ascii", errors="ignore") + b"\r\n"
        + b"".join(
        f"{key}: {value}\r\n".encode("ascii", errors="strict")
        for key, value in session_headers.items()
        )
    )

    def request(raw: bytes) -> dict[str, Any]:
        return _raw_http_bytes(bridge, raw)

    authenticated_hello = request(b"GET /Bridge/Hello HTTP/1.1\r\n" + base + b"\r\n")
    duplicate_length = request(
        b"POST /ExecCommand HTTP/1.1\r\n" + base
        + b"Content-Length: 0\r\nContent-Length: 0\r\n\r\n"
    )
    transfer_encoding = request(
        b"POST /ExecCommand HTTP/1.1\r\n" + base
        + b"Transfer-Encoding: chunked\r\n\r\n"
    )
    trailing_bytes = request(
        b"POST /ExecCommand HTTP/1.1\r\n" + base
        + b"Content-Length: 1\r\n\r\naZ"
    )
    malformed_authenticated = request(
        b"BROKENLINE\r\n" + base + b"\r\n"
    )
    # The same malformed request without a token must be rejected by the
    # header-only auth path, before request-target/query decoding.
    unauthenticated_malformed = request(
        b"BROKEN /%FF%FF HTTP/1.1\r\nHost: " + host.encode("ascii", errors="ignore") + b"\r\n\r\n"
    )
    self_unload_aliases = {
        alias: request(
            (
                f"GET /ExecCommand?cmd={alias}%20MCPx64dbg HTTP/1.1\r\n"
            ).encode("ascii")
            + guarded
            + b"\r\n"
        )
        for alias in ("plugunload", "pluginunload", "unloadplugin")
    }
    hello_after_self_unload = request(
        b"GET /Bridge/Hello HTTP/1.1\r\n" + base + b"\r\n"
    )
    cases = {
        "authenticatedHello": authenticated_hello,
        "duplicateLength": duplicate_length,
        "transferEncoding": transfer_encoding,
        "trailingBytes": trailing_bytes,
        "malformedAuthenticated": malformed_authenticated,
        "unauthenticatedMalformed": unauthenticated_malformed,
        "selfUnloadAliases": self_unload_aliases,
        "helloAfterSelfUnload": hello_after_self_unload,
    }
    ok = bool(
        authenticated_hello.get("status") == 200
        and duplicate_length.get("status") == 400
        and duplicate_length.get("errorCode") == "duplicate_content_length"
        and transfer_encoding.get("status") == 400
        and transfer_encoding.get("errorCode") == "transfer_encoding_unsupported"
        and trailing_bytes.get("status") == 400
        and trailing_bytes.get("errorCode") == "trailing_bytes"
        and malformed_authenticated.get("status") == 400
        and malformed_authenticated.get("errorCode") == "malformed_request_line"
        and unauthenticated_malformed.get("status") == 401
        and unauthenticated_malformed.get("errorCode") == "authentication_required"
        and all(
            item.get("status") == 409
            and item.get("errorCode") == "bridge_self_unload_forbidden"
            for item in self_unload_aliases.values()
        )
        and hello_after_self_unload.get("status") == 200
    )
    return {"ok": ok, "init": init, "cases": cases,
            "error": None if ok else "HTTP parser adversarial contract failed"}


def _run_dispatcher_concurrency_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    """Exercise the real socket dispatcher without debugger-side polling hacks."""

    del artifact_dir
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
    )
    if not isinstance(init, dict) or not init.get("ok"):
        return {"ok": False, "init": init, "arch": arch, "error": "InitDebuggee failed"}
    token = bridge._discover_bridge_auth_token()
    parsed = urlsplit(str(getattr(bridge, "x64dbg_server_url", "") or ""))
    host = parsed.hostname or "127.0.0.1"
    port = int(parsed.port or 8888)
    session_headers, header_error = _session_identity_headers(bridge)
    if not token or header_error:
        return {
            "ok": False,
            "init": init,
            "arch": arch,
            "error": header_error or "Bridge token unavailable",
        }

    def raw_request(path: str, headers: Optional[dict[str, str]] = None,
                    timeout: float = 5.0) -> dict[str, Any]:
        merged = {
            "Host": f"{host}:{port}",
            "X-MCP-Auth-Token": token,
        }
        if headers:
            merged.update({str(key): str(value) for key, value in headers.items()})
        raw = (
            f"GET {path} HTTP/1.1\r\n"
            + "".join(f"{key}: {value}\r\n" for key, value in merged.items())
            + "Connection: close\r\n\r\n"
        ).encode("ascii", errors="strict")
        return _raw_http_bytes(bridge, raw, timeout=timeout)

    wait_results: list[dict[str, Any]] = []
    wait_threads: list[threading.Thread] = []

    def wait_worker() -> None:
        try:
            wait_results.append(raw_request("/Debug/WaitForPause?timeoutMs=750", session_headers, 4.0))
        except Exception as exc:  # pragma: no cover - live-only diagnostic
            wait_results.append({"status": 0, "errorCode": type(exc).__name__, "error": str(exc)})

    for _ in range(4):
        thread = threading.Thread(target=wait_worker, daemon=True)
        wait_threads.append(thread)
        thread.start()
    time.sleep(0.10)

    hello_started = time.monotonic()
    hello = raw_request("/Bridge/Hello", timeout=3.0)
    hello_latency = time.monotonic() - hello_started
    pause_started = time.monotonic()
    pause = bridge.DebugPause()
    pause_latency = time.monotonic() - pause_started
    for thread in wait_threads:
        thread.join(timeout=5.0)

    # Hold all ordinary reader slots with deliberately incomplete headers.  A
    # new complete connection must receive the bounded 503 instead of creating
    # an unbounded thread or hanging the accept loop.  Closing the partial
    # sockets immediately after the probe proves shutdown/cancellation too.
    partial_sockets: list[socket.socket] = []
    overload = {"status": 0, "errorCode": "not_attempted"}
    try:
        partial = f"GET /Bridge/Hello HTTP/1.1\r\nHost: {host}:{port}\r\n".encode("ascii")
        for _ in range(40):
            try:
                sock = socket.create_connection((host, port), timeout=1.0)
                sock.settimeout(1.0)
                sock.sendall(partial)
                partial_sockets.append(sock)
            except OSError:
                break
            time.sleep(0.01)
        time.sleep(0.15)
        # The overload response is intentionally probed with an empty input
        # stream.  This avoids leaving unread request bytes in the kernel receive
        # buffer while the bounded accept path rejects the connection, which on
        # Windows would correctly appear as a TCP reset rather than an HTTP
        # response.  The response itself is independent of request parsing.
        overload = _raw_http_bytes(bridge, b"", timeout=3.0)
    finally:
        for sock in partial_sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    waits_ok = len(wait_results) == 4 and all(item.get("status") == 200 for item in wait_results)
    ok = bool(
        waits_ok
        and hello.get("status") == 200
        and hello_latency < 1.5
        and pause_latency < 1.5
        and overload.get("status") == 503
        and overload.get("errorCode") == "request_queue_full"
    )
    return {
        "ok": ok,
        "arch": arch,
        "init": init,
        "waitResults": wait_results,
        "hello": hello,
        "pause": pause,
        "helloLatencySeconds": round(hello_latency, 4),
        "pauseLatencySeconds": round(pause_latency, 4),
        "overload": overload,
        "partialSocketCount": len(partial_sockets),
        "error": None if ok else "Concurrent dispatcher contract failed",
    }


def _run_session_identity_cas_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
    )
    result: dict[str, Any] = {"ok": False, "init": init, "arch": arch}
    if not isinstance(init, dict) or not init.get("ok"):
        result["error"] = "InitDebuggee failed"
        return result

    state = bridge._get_debug_session_state(include_history=False, history_limit=0)
    hello = bridge.BridgeHello(refresh=True)
    module = _main_module_record(bridge, exe_path)
    try:
        module_base = int(str(module.get("base") or "0"), 0)
    except ValueError:
        module_base = 0
    original = bridge.ReadMemory(
        addr=f"0x{module_base:X}", size=2, ty="hex", max_chars=0
    ) if module_base else {}
    original_hex = str((original or {}).get("hex") or "").replace(" ", "").upper()
    headers, header_error = _session_identity_headers(bridge)
    result.update(
        {
            "state": state,
            "hello": hello,
            "module": module,
            "original": original,
            "headerError": header_error,
        }
    )
    required_header_names = {
        "X-MCP-Bridge-Id",
        "X-MCP-Session-Id",
        "X-MCP-Session-Generation",
        "X-MCP-Debuggee-Pid",
        "X-MCP-Debuggee-SHA256",
        "X-MCP-Event-Seq",
    }
    if (
        header_error
        or not module_base
        or len(original_hex) != 4
        or not required_header_names.issubset(headers)
    ):
        result["error"] = "A complete v4 session identity or readable module base is unavailable."
        return result

    form = {
        "addr": f"0x{module_base:X}",
        "data": original_hex,
        "expected": original_hex,
    }

    def request_with(
        name: str,
        *,
        remove: Sequence[str] = (),
        replace: Optional[dict[str, str]] = None,
        method: str = "POST",
        endpoint: str = "Memory/Write",
        params: Optional[dict[str, Any]] = None,
        body: Optional[dict[str, Any]] = None,
        extra: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        candidate = dict(headers)
        for key in remove:
            candidate.pop(key, None)
        candidate.update(dict(replace or {}))
        candidate.update(dict(extra or {}))
        response = _raw_guarded_bridge_request(
            bridge,
            method,
            endpoint,
            params=params,
            data=form if body is None else body,
            headers=candidate,
        )
        response["name"] = name
        return response

    guards = [
        request_with("missing_bridge", remove=("X-MCP-Bridge-Id",)),
        request_with("wrong_bridge", replace={"X-MCP-Bridge-Id": "not-this-bridge"}),
        request_with(
            "missing_session",
            remove=(
                "X-MCP-Session-Id",
                "X-MCP-Session-Generation",
                "X-MCP-Debuggee-Pid",
            ),
        ),
        request_with("wrong_session", replace={"X-MCP-Session-Id": str(uuid.uuid4())}),
        request_with("missing_hash", remove=("X-MCP-Debuggee-SHA256",)),
        request_with("wrong_hash", replace={"X-MCP-Debuggee-SHA256": "00" * 32}),
        request_with("missing_event", remove=("X-MCP-Event-Seq",)),
        request_with(
            "stale_event",
            replace={
                "X-MCP-Event-Seq": str(int(headers["X-MCP-Event-Seq"]) + 1)
            },
        ),
    ]
    accepted = request_with("accepted")

    changed_hex = ("00" if original_hex[:2] != "00" else "FF") + original_hex[2:]
    rollback_form = {
        "addr": f"0x{module_base:X}",
        "data": changed_hex,
        "expected": original_hex,
        "transactionFault": "verify_readback",
    }
    rollback = request_with(
        "forced_rollback",
        body=rollback_form,
        extra={"X-MCP-Test-Intent": "rollback-gate-v1"},
    )
    after_rollback = bridge.ReadMemory(
        addr=f"0x{module_base:X}", size=2, ty="hex", max_chars=0
    )

    register_name = "rip" if arch == "x64" else "eip"
    register_before = bridge.RegisterGet(register_name)
    register_success = request_with(
        "register_same_value",
        method="GET",
        endpoint="Register/Set",
        params={"register": register_name, "value": str(register_before)},
        body={},
    )

    # Exercise the native coordinator lease path independently of the legacy
    # identity/CAS matrix: replay acquisition, prove an unleased mutation is
    # rejected, renew with the nonce-bound token, perform a guarded mutation,
    # and release before session turnover.
    lease_acquire = bridge._acquire_mutation_lease(5000)
    lease_replay = bridge._acquire_mutation_lease(5000)
    lease_blocked = request_with("lease_blocked")
    lease_headers, lease_header_error = _session_identity_headers(bridge)
    lease_guarded = _raw_guarded_bridge_request(
        bridge,
        "POST",
        "Memory/Write",
        data=form,
        headers=lease_headers,
    ) if lease_header_error is None else {"status": 0, "ok": False}
    lease_renew = bridge._renew_mutation_lease(5000)
    lease_release = bridge._release_mutation_lease()

    # Exercise the Python workflow ownership layer against the real native
    # breakpoint database.  Use a nearby code address so the test creates its
    # own software breakpoint rather than claiming x64dbg's startup entry BP.
    workflow_addr = f"0x{module_base + 0x10:X}" if module_base else ""
    workflow_id = f"live-breakpoint-{arch}"
    bp_lease_one = (
        bridge.AcquireBreakpointLease(
            workflow_addr,
            workflow_id=workflow_id,
            breakpoint_type="normal",
            lease_ms=5000,
        )
        if workflow_addr
        else {"ok": False, "errorCode": "no_module_base"}
    )
    bp_lease_two = (
        bridge.AcquireBreakpointLease(
            workflow_addr,
            workflow_id=workflow_id,
            breakpoint_type="normal",
            lease_ms=5000,
        )
        if bp_lease_one.get("ok")
        else {"ok": False, "errorCode": "first_lease_failed"}
    )
    bp_release_one = (
        bridge.ReleaseBreakpointLease(bp_lease_one.get("leaseId", ""))
        if bp_lease_one.get("ok")
        else {"ok": False, "errorCode": "first_lease_failed"}
    )
    bp_release_two = (
        bridge.ReleaseBreakpointLease(bp_lease_two.get("leaseId", ""))
        if bp_lease_two.get("ok")
        else {"ok": False, "errorCode": "second_lease_failed"}
    )
    bp_remaining = bridge.GetBreakpointList("all") if workflow_addr else {}
    bp_remaining_items = (
        bp_remaining.get("breakpoints", [])
        if isinstance(bp_remaining, dict)
        else []
    )
    bp_owned_absent = not any(
        isinstance(item, dict)
        and str(item.get("addr") or "").lower()
        == workflow_addr.lower()
        for item in bp_remaining_items
    )

    first_headers = dict(headers)
    first_hash = str(headers["X-MCP-Debuggee-SHA256"]).upper()
    first_session = str(headers["X-MCP-Session-Id"])
    first_stop = bridge.DebugStop()
    second_init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
    )
    second_state = bridge._get_debug_session_state(
        include_history=False, history_limit=0
    ) if isinstance(second_init, dict) and second_init.get("ok") else {}
    second_module = _main_module_record(bridge, exe_path) if second_state else {}
    try:
        second_base = int(str(second_module.get("base") or "0"), 0)
    except ValueError:
        second_base = 0
    turnover_form = {
        "addr": f"0x{second_base:X}",
        "data": original_hex,
        "expected": original_hex,
    }
    stale_session = _raw_guarded_bridge_request(
        bridge,
        "POST",
        "Memory/Write",
        data=turnover_form,
        headers=first_headers,
    ) if second_base else {"status": 0, "ok": False, "errorCode": "no_second_base"}
    second_headers, second_header_error = _session_identity_headers(bridge) if second_state else ({}, {"code": "no_second_session"})

    expected_codes = {
        "missing_bridge": (428, "missing_bridge_guard"),
        "wrong_bridge": (409, "stale_bridge"),
        "missing_session": (428, "missing_session_guard"),
        "wrong_session": (409, "stale_mutation_guard"),
        "missing_hash": (428, "missing_target_identity"),
        "wrong_hash": (409, "stale_mutation_guard"),
        "missing_event": (428, "missing_event_guard"),
        "stale_event": (409, "stale_mutation_guard"),
    }
    guards_ok = all(
        (item.get("status"), item.get("errorCode")) == expected_codes[item["name"]]
        for item in guards
    )
    rollback_payload = rollback.get("payload") if isinstance(rollback, dict) else {}
    after_hex = str((after_rollback or {}).get("hex") or "").replace(" ", "").upper()
    second_hash = str(second_headers.get("X-MCP-Debuggee-SHA256") or "").upper()
    second_session = str(second_headers.get("X-MCP-Session-Id") or "")
    ok = bool(
        int((hello.get("identity") or {}).get("protocolVersion") or 0) >= 4
        and len(first_hash) == 64
        and guards_ok
        and accepted.get("status") == 200
        and register_success.get("status") == 200
        and isinstance(lease_acquire, dict)
        and lease_acquire.get("ok") is True
        and isinstance(lease_replay, dict)
        and lease_replay.get("ok") is True
        and lease_blocked.get("status") == 409
        and lease_blocked.get("errorCode") == "lease_required"
        and lease_header_error is None
        and lease_guarded.get("status") == 200
        and isinstance(lease_renew, dict)
        and lease_renew.get("ok") is True
        and isinstance(lease_release, dict)
        and lease_release.get("ok") is True
        and bp_lease_one.get("ok") is True
        and bp_lease_two.get("ok") is True
        and bp_lease_two.get("referenceCount") == 2
        and bp_release_one.get("ok") is True
        and bp_release_one.get("deleted") is False
        and bp_release_two.get("ok") is True
        and bp_release_two.get("deleted") is True
        and bp_owned_absent
        and rollback.get("status") == 500
        and isinstance(rollback_payload, dict)
        and rollback_payload.get("faultInjected") is True
        and rollback_payload.get("rollbackAttempted") is True
        and rollback_payload.get("rollbackSucceeded") is True
        and after_hex == original_hex
        and isinstance(second_init, dict)
        and second_init.get("ok")
        and second_header_error is None
        and second_hash == first_hash
        and second_session
        and second_session != first_session
        and stale_session.get("status") == 409
        and stale_session.get("errorCode") == "stale_mutation_guard"
    )
    result.update(
        {
            "ok": ok,
            "guards": guards,
            "accepted": accepted,
            "register": {"before": register_before, "response": register_success},
            "lease": {
                "acquire": lease_acquire,
                "replay": lease_replay,
                "blocked": lease_blocked,
                "guardHeaderError": lease_header_error,
                "guarded": lease_guarded,
                "renew": lease_renew,
                "release": lease_release,
            },
            "breakpointLease": {
                "addr": workflow_addr,
                "acquire": bp_lease_one,
                "acquireReplay": bp_lease_two,
                "releaseFirst": bp_release_one,
                "releaseFinal": bp_release_two,
                "remaining": bp_remaining,
                "ownedAbsent": bp_owned_absent,
            },
            "rollback": rollback,
            "afterRollback": after_rollback,
            "turnover": {
                "firstStop": first_stop,
                "secondInit": second_init,
                "secondState": second_state,
                "firstSessionId": first_session,
                "secondSessionId": second_session,
                "sameHash": second_hash == first_hash,
                "staleRequest": stale_session,
            },
            "error": None if ok else "One or more v4 identity/CAS/rollback invariants failed.",
        }
    )
    return result


def _run_breakpoint_ownership_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
    )
    if not isinstance(init, dict) or not init.get("ok"):
        return {"ok": False, "arch": arch, "init": init, "error": "InitDebuggee failed"}
    bridge.DebugPause()
    paused = bridge.WaitForPause(timeout_ms=5000, poll_ms=50)
    hello = bridge.BridgeHello(refresh=True)
    module = _main_module_record(bridge, exe_path)
    try:
        base = int(str(module.get("base") or "0"), 0)
    except ValueError:
        base = 0
    if not base:
        return {
            "ok": False,
            "arch": arch,
            "init": init,
            "pause": paused,
            "hello": hello,
            "module": module,
            "error": "Main module base unavailable",
        }

    def present(addr: str, payload: Optional[dict[str, Any]] = None) -> bool:
        current = payload if isinstance(payload, dict) else bridge.GetBreakpointList("all")
        return any(
            isinstance(item, dict)
            and str(item.get("addr") or "").casefold() == addr.casefold()
            for item in current.get("breakpoints", [])
        )

    def acquire_release(
        offset: int,
        kind: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        addr = f"0x{base + offset:X}"
        workflow = f"live-{kind}-{arch}"
        cleanup_before = None
        if kind == "hardware":
            cleanup_before = bridge.DeleteHardwareBreakpoint(addr)
        elif kind == "memory":
            cleanup_before = bridge.DeleteMemoryBreakpoint(addr)
        else:
            cleanup_before = bridge.DebugDeleteBreakpoint(addr)
        acquired = bridge.AcquireBreakpointLease(
            addr,
            workflow_id=workflow,
            breakpoint_type=kind,
            lease_ms=5000,
            **kwargs,
        )
        renewed = (
            bridge.RenewBreakpointLease(acquired.get("leaseId", ""), lease_ms=5000)
            if acquired.get("ok")
            else {"ok": False, "errorCode": "acquire_failed"}
        )
        before_release = bridge.GetBreakpointList("all")
        released = (
            bridge.ReleaseBreakpointLease(acquired.get("leaseId", ""))
            if acquired.get("ok")
            else {"ok": False, "errorCode": "acquire_failed"}
        )
        after_release = bridge.GetBreakpointList("all")
        return {
            "addr": addr,
            "cleanupBefore": cleanup_before,
            "acquire": acquired,
            "renew": renewed,
            "presentBeforeRelease": present(addr, before_release),
            "release": released,
            "absentAfterRelease": not present(addr, after_release),
            "beforeRelease": before_release,
            "afterRelease": after_release,
            "ok": bool(
                acquired.get("ok")
                and renewed.get("ok")
                and present(addr, before_release)
                and released.get("ok")
                and released.get("deleted") is True
                and not present(addr, after_release)
            ),
        }

    normal_addr = f"0x{base + 0x10:X}"
    normal_cleanup_before = bridge.DebugDeleteBreakpoint(normal_addr)
    normal_one = bridge.AcquireBreakpointLease(
        normal_addr,
        workflow_id=f"normal-owner-{arch}",
        breakpoint_type="normal",
        lease_ms=5000,
    )
    normal_conflict = (
        bridge.AcquireBreakpointLease(
            normal_addr,
            workflow_id=f"foreign-owner-{arch}",
            breakpoint_type="normal",
            lease_ms=5000,
        )
        if normal_one.get("ok")
        else {"ok": False, "errorCode": "first_acquire_failed"}
    )
    normal_two = (
        bridge.AcquireBreakpointLease(
            normal_addr,
            workflow_id=f"normal-owner-{arch}",
            breakpoint_type="normal",
            lease_ms=5000,
        )
        if normal_one.get("ok")
        else {"ok": False, "errorCode": "first_acquire_failed"}
    )
    normal_release_one = (
        bridge.ReleaseBreakpointLease(normal_one.get("leaseId", ""))
        if normal_one.get("ok")
        else {"ok": False}
    )
    normal_release_two = (
        bridge.ReleaseBreakpointLease(normal_two.get("leaseId", ""))
        if normal_two.get("ok")
        else {"ok": False}
    )
    normal_after = bridge.GetBreakpointList("all")
    normal_ok = bool(
        normal_one.get("ok")
        and normal_conflict.get("ok") is False
        and normal_conflict.get("errorCode") == "BREAKPOINT_LEASE_CONFLICT"
        and normal_two.get("referenceCount") == 2
        and normal_release_one.get("deleted") is False
        and normal_release_two.get("deleted") is True
        and not present(normal_addr, normal_after)
    )

    conditional = acquire_release(
        0x20,
        "conditional",
        condition="1",
        name=f"mcp-owned-conditional-{arch}",
    )
    hardware = acquire_release(0x30, "hardware")
    memory = acquire_release(
        0x40,
        "memory",
        size=1,
        access_type="write",
        name=f"mcp-owned-memory-{arch}",
    )

    expiry_addr = f"0x{base + 0x50:X}"
    expiry_cleanup_before = bridge.DebugDeleteBreakpoint(expiry_addr)
    expiry_acquire = bridge.AcquireBreakpointLease(
        expiry_addr,
        workflow_id=f"expiry-{arch}",
        breakpoint_type="normal",
        lease_ms=1000,
    )
    time.sleep(1.15)
    expiry_list = bridge.ListBreakpointLeases()
    expiry_after = bridge.GetBreakpointList("all")
    expiry_ok = bool(
        expiry_acquire.get("ok")
        and not present(expiry_addr, expiry_after)
        and not any(
            isinstance(item, dict)
            and str(item.get("addr") or "").casefold() == expiry_addr.casefold()
            for item in expiry_list.get("leases", [])
        )
    )

    ok = bool(
        init.get("ok")
        and isinstance(paused, dict)
        and paused.get("paused")
        and isinstance(hello, dict)
        and hello.get("ok")
        and normal_ok
        and conditional.get("ok")
        and hardware.get("ok")
        and memory.get("ok")
        and expiry_ok
    )
    return {
        "ok": ok,
        "arch": arch,
        "init": init,
        "pause": paused,
        "hello": hello,
        "module": module,
        "normal": {
            "addr": normal_addr,
            "cleanupBefore": normal_cleanup_before,
            "acquire": normal_one,
            "conflict": normal_conflict,
            "acquireReplay": normal_two,
            "releaseFirst": normal_release_one,
            "releaseFinal": normal_release_two,
            "absentAfterRelease": not present(normal_addr, normal_after),
            "ok": normal_ok,
        },
        "conditional": conditional,
        "hardware": hardware,
        "memory": memory,
        "expiry": {
            "addr": expiry_addr,
            "cleanupBefore": expiry_cleanup_before,
            "acquire": expiry_acquire,
            "listAfterExpiry": expiry_list,
            "absentAfterExpiry": not present(expiry_addr, expiry_after),
            "ok": expiry_ok,
        },
        "error": None if ok else "Breakpoint ownership/expiry contract failed.",
    }


def _annotation_module_matches(expected: str, observed: Any) -> bool:
    def normalize(value: Any) -> tuple[str, str]:
        name = str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].casefold()
        return name, Path(name).stem.casefold()

    expected_name, expected_stem = normalize(expected)
    observed_name, observed_stem = normalize(observed)
    return bool(
        expected_name
        and observed_name
        and (expected_name == observed_name or expected_stem == observed_stem)
    )


def _resolved_path(path: Path | str) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _path_is_within(path: Path, root: Path) -> bool:
    path_key = os.path.normcase(str(path))
    root_key = os.path.normcase(str(root))
    try:
        return os.path.commonpath((path_key, root_key)) == root_key
    except ValueError:
        return False


def _generated_fixture_guard(
    module: dict[str, Any], fixture_path: Path | str, artifact_dir: Path
) -> dict[str, Any]:
    """Fail closed before deleting any debugger-database annotation."""

    reported = str(module.get("path") or "") if isinstance(module, dict) else ""
    if not reported:
        return {
            "ok": False,
            "errorCode": "ANNOTATION_CLEANUP_PATH_UNAVAILABLE",
            "error": "The loaded module did not report an authoritative path.",
        }
    expected_path = _resolved_path(fixture_path)
    reported_path = _resolved_path(reported)
    roots = (
        _resolved_path(TOOLS_DIR / "bin" / "e2e"),
        _resolved_path(artifact_dir),
    )
    same_path = os.path.normcase(str(expected_path)) == os.path.normcase(str(reported_path))
    allowed_root = next((root for root in roots if _path_is_within(reported_path, root)), None)
    ok = bool(same_path and allowed_root is not None)
    return {
        "ok": ok,
        "fixturePath": str(expected_path),
        "reportedModulePath": str(reported_path),
        "allowedRoots": [str(root) for root in roots],
        "matchedRoot": str(allowed_root) if allowed_root is not None else None,
        "errorCode": None if ok else "ANNOTATION_CLEANUP_PATH_REJECTED",
        "error": None
        if ok
        else "Annotation cleanup is restricted to the generated e2e or current artifact tree.",
    }


def _collect_annotation_page_set(
    bridge: Any, module_name: str, method_name: str, field: str
) -> dict[str, Any]:
    method = getattr(bridge, method_name)
    records: list[dict[str, Any]] = []
    try:
        if method_name == "LabelList":
            payload = method()
            pages = [payload]
        else:
            pages = []
            offset = 0
            for _ in range(1000):
                payload = method(module=module_name, offset=offset, limit=500)
                pages.append(payload)
                if not isinstance(payload, dict) or not payload.get("hasMore"):
                    break
                next_offset = payload.get("nextOffset")
                try:
                    next_value = int(next_offset)
                except (TypeError, ValueError):
                    return {
                        "ok": False,
                        "records": [],
                        "error": f"{method_name} returned an invalid nextOffset.",
                        "response": payload,
                    }
                if next_value <= offset:
                    return {
                        "ok": False,
                        "records": [],
                        "error": f"{method_name} pagination did not advance.",
                        "response": payload,
                    }
                offset = next_value
            else:
                return {
                    "ok": False,
                    "records": [],
                    "error": f"{method_name} exceeded the pagination safety limit.",
                }
    except Exception as exc:
        return {"ok": False, "records": [], "error": str(exc), "method": method_name}

    for payload in pages:
        if not isinstance(payload, dict) or not isinstance(payload.get(field), list):
            return {
                "ok": False,
                "records": [],
                "error": f"{method_name} did not return a {field} array.",
                "response": payload,
            }
        records.extend(
            dict(item)
            for item in payload[field]
            if isinstance(item, dict)
            and _annotation_module_matches(module_name, item.get("module"))
        )
    records.sort(
        key=lambda item: (
            int(str(item.get("rvaStart") or item.get("rva") or "0"), 0),
            int(str(item.get("rvaEnd") or "0"), 0),
        )
    )
    return {"ok": True, "records": records}


def _annotation_snapshot(bridge: Any, module_name: str) -> dict[str, Any]:
    specs = {
        "labels": ("LabelList", "labels"),
        "comments": ("CommentList", "comments"),
        "bookmarks": ("BookmarkList", "bookmarks"),
        "functions": ("FunctionList", "functions"),
    }
    result: dict[str, Any] = {"ok": True}
    for kind, (method_name, field) in specs.items():
        collected = _collect_annotation_page_set(bridge, module_name, method_name, field)
        result[kind] = collected.get("records", [])
        if not collected.get("ok"):
            result["ok"] = False
            result.setdefault("errors", []).append({"kind": kind, **collected})
    result["counts"] = {kind: len(result[kind]) for kind in specs}
    return result


def _target_annotation_absence(bridge: Any, address: str) -> dict[str, Any]:
    checks = {
        "label": bridge.LabelGet(address),
        "comment": bridge.CommentGet(address),
        "bookmark": bridge.BookmarkGet(address),
    }
    # Comment/Get may expose x64dbg's derived disassembly annotation (for
    # example an immediate character literal) even when the authoritative
    # Comment/List store is empty. Portable evidence cleanup is concerned with
    # user annotations, which are proven by the paginated list above.
    portable_ok = bool(
        isinstance(checks["label"], dict)
        and checks["label"].get("found") is False
        and isinstance(checks["bookmark"], dict)
        and checks["bookmark"].get("found") is False
    )
    return {
        "ok": portable_ok,
        "portableOk": portable_ok,
        "derivedCommentIgnored": bool(
            isinstance(checks["comment"], dict)
            and checks["comment"].get("found") is True
        ),
        **checks,
    }


def _clear_fixture_annotations(
    bridge: Any,
    module: dict[str, Any],
    fixture_path: Path | str,
    artifact_dir: Path,
    target_address: str,
) -> dict[str, Any]:
    """Delete all four portable annotation types and prove the module is empty."""

    guard = _generated_fixture_guard(module, fixture_path, artifact_dir)
    result: dict[str, Any] = {"ok": False, "guard": guard, "deletes": []}
    if not guard.get("ok"):
        result["error"] = guard.get("error")
        return result
    module_name = str(module.get("name") or Path(str(module.get("path") or "")).name)
    try:
        base = int(str(module.get("base") or "0"), 0)
    except ValueError:
        base = 0
    if not module_name or not base:
        result["error"] = "The module name/base required for annotation cleanup is missing."
        return result

    before = _annotation_snapshot(bridge, module_name)
    result["before"] = before
    if not before.get("ok"):
        result["error"] = "Could not enumerate annotations before cleanup."
        return result

    delete_specs = {
        "labels": ("LabelDelete", "rva"),
        "comments": ("CommentDelete", "rva"),
        "bookmarks": ("BookmarkDelete", "rva"),
        "functions": ("FunctionDelete", "rvaStart"),
    }
    delete_ok = True
    for kind, (method_name, rva_field) in delete_specs.items():
        method = getattr(bridge, method_name)
        for record in before[kind]:
            try:
                rva = int(str(record.get(rva_field) or "0"), 0)
                address = f"0x{base + rva:X}"
                response = method(address)
                success = _bridge_mutation_ok(response)
            except Exception as exc:
                address = ""
                response = {"ok": False, "error": str(exc)}
                success = False
            result["deletes"].append(
                {
                    "kind": kind[:-1] if kind != "functions" else "function",
                    "address": address,
                    "success": success,
                    "response": response,
                }
            )
            delete_ok = delete_ok and success

    after = _annotation_snapshot(bridge, module_name)
    target = _target_annotation_absence(bridge, target_address)
    zero_counts = {"labels": 0, "comments": 0, "bookmarks": 0, "functions": 0}
    result.update({"after": after, "target": target})
    result["ok"] = bool(
        delete_ok
        and after.get("ok")
        and after.get("counts") == zero_counts
        and target.get("ok")
    )
    if not result["ok"]:
        result["error"] = "Authoritative annotation cleanup proof failed."
    return result


def _seed_annotation_proof(
    bridge: Any,
    module_name: str,
    address: str,
    rva: int,
    label_text: str,
    comment_text: str,
) -> dict[str, Any]:
    snapshot = _annotation_snapshot(bridge, module_name)
    label = bridge.LabelGet(address)
    comment = bridge.CommentGet(address)
    bookmark = bridge.BookmarkGet(address)
    expected_counts = {"labels": 1, "comments": 1, "bookmarks": 1, "functions": 0}

    def one(kind: str, text: Optional[str] = None) -> bool:
        records = snapshot.get(kind)
        if not isinstance(records, list) or len(records) != 1:
            return False
        record = records[0]
        try:
            record_rva = int(str(record.get("rva") or "0"), 0)
        except ValueError:
            return False
        return bool(
            record_rva == rva
            and record.get("manual") is True
            and (text is None or str(record.get("text") or "") == text)
        )

    ok = bool(
        snapshot.get("ok")
        and snapshot.get("counts") == expected_counts
        and one("labels", label_text)
        and one("comments", comment_text)
        and one("bookmarks")
        and isinstance(label, dict)
        and label.get("found") is True
        and label.get("label") == label_text
        and isinstance(comment, dict)
        and comment.get("found") is True
        and comment.get("comment") == comment_text
        and isinstance(bookmark, dict)
        and bookmark.get("found") is True
        and bookmark.get("manual") is True
    )
    return {
        "ok": ok,
        "snapshot": snapshot,
        "label": label,
        "comment": comment,
        "bookmark": bookmark,
    }


def _evidence_counts() -> dict[str, int]:
    return {
        "labels": 1,
        "comments": 1,
        "bookmarks": 1,
        "functions": 0,
        "breakpoints": 0,
        "patches": 0,
        "nativeTraceHits": 0,
        "apiCallsites": 0,
    }


def _hex_value_equals(value: Any, expected: int) -> bool:
    try:
        return int(str(value), 0) == expected
    except (TypeError, ValueError):
        return False


def _evidence_document_contract(
    document: Any,
    *,
    fixture_path: Path | str,
    arch: str,
    runtime_base: int,
    target_rva: int,
    label_text: str,
    comment_text: str,
) -> dict[str, Any]:
    expected_counts = _evidence_counts()
    result: dict[str, Any] = {"ok": False, "expectedCounts": expected_counts}
    if not isinstance(document, dict):
        result["error"] = "Export did not return an evidence document."
        return result
    evidence = document.get("evidence")
    image = document.get("image")
    if not isinstance(evidence, dict) or not isinstance(image, dict):
        result["error"] = "Evidence or image metadata is missing."
        return result
    source = Path(fixture_path)
    try:
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest().upper()
    except OSError as exc:
        result["error"] = f"Could not hash the generated fixture: {exc}"
        return result

    expected_fields = set(expected_counts)
    arrays_exact = set(evidence) == expected_fields and all(
        isinstance(evidence.get(field), list)
        and len(evidence[field]) == expected_counts[field]
        for field in expected_fields
    )
    label = evidence.get("labels", [{}])[0] if expected_counts["labels"] else {}
    comment = evidence.get("comments", [{}])[0] if expected_counts["comments"] else {}
    bookmark = evidence.get("bookmarks", [{}])[0] if expected_counts["bookmarks"] else {}
    entries_exact = bool(
        isinstance(label, dict)
        and _hex_value_equals(label.get("rva"), target_rva)
        and label.get("text") == label_text
        and label.get("manual") is True
        and isinstance(comment, dict)
        and _hex_value_equals(comment.get("rva"), target_rva)
        and comment.get("text") == comment_text
        and comment.get("manual") is True
        and isinstance(bookmark, dict)
        and _hex_value_equals(bookmark.get("rva"), target_rva)
        and bookmark.get("manual") is True
    )
    image_exact = bool(
        str(image.get("name") or "").casefold() == source.name.casefold()
        and str(image.get("sha256") or "").upper() == source_hash
        and str(image.get("arch") or "").casefold() == arch.casefold()
        and _hex_value_equals(image.get("runtimeImageBase"), runtime_base)
    )
    ok = bool(
        document.get("schema") == "x64dbg-mcp-evidence"
        and document.get("version") == 1
        and document.get("counts") == expected_counts
        and arrays_exact
        and entries_exact
        and image_exact
    )
    result.update(
        {
            "ok": ok,
            "actualCounts": document.get("counts"),
            "arraysExact": arrays_exact,
            "entriesExact": entries_exact,
            "imageExact": image_exact,
            "sourceSha256": source_hash,
        }
    )
    if not ok:
        result["error"] = "The exported document is not the exact 1/1/1/0 fixture evidence set."
    return result


def _evidence_record_contract(
    record: Any,
    *,
    kind: str,
    target_rva: int,
    target_address: int,
    label_text: str,
    comment_text: str,
    operation: Optional[str] = None,
    reason: Optional[str] = None,
) -> bool:
    if not isinstance(record, dict):
        return False
    ok = bool(
        record.get("kind") == kind
        and _hex_value_equals(record.get("rva"), target_rva)
        and _hex_value_equals(record.get("address"), target_address)
        and record.get("manual") is True
    )
    if kind == "label":
        ok = ok and record.get("text") == label_text
    elif kind == "comment":
        ok = ok and record.get("text") == comment_text
    if operation is not None:
        ok = ok and record.get("operation") == operation
    if reason is not None:
        ok = ok and record.get("reason") == reason
    return bool(ok)


def _evidence_plan_contract(
    payload: Any,
    *,
    phase: str,
    target_rva: int,
    target_address: int,
    label_text: str,
    comment_text: str,
) -> bool:
    if not isinstance(payload, dict):
        return False
    plan = payload.get("plan")
    validation = payload.get("validation")
    if not isinstance(plan, dict) or not isinstance(validation, dict):
        return False
    common = bool(
        payload.get("ok") is True
        and validation.get("ok") is True
        and validation.get("valid") is True
        and validation.get("schema") == "x64dbg-mcp-evidence"
        and validation.get("version") == 1
        and validation.get("counts") == _evidence_counts()
        and plan.get("identity", {}).get("hashMatches") is True
        and plan.get("identity", {}).get("hashMismatchAllowed") is False
        and plan.get("selected")
        == {
            "labels": True,
            "comments": True,
            "bookmarks": True,
            "functions": False,
            "breakpoints": False,
            "patches": False,
        }
        and plan.get("conflicts") == []
        and plan.get("ignoredCounts")
        == {"functions": 0, "breakpoints": 0, "patches": 0}
        and plan.get("warnings") == []
        and int(plan.get("eventSeq") or 0) > 0
        and plan.get("transactional") is False
        and plan.get("guard") == "session identity + event sequence CAS"
    )
    kinds = ("label", "comment", "bookmark")
    if phase in {"dry-run", "apply"}:
        records = plan.get("actions")
        expected_operation = "create"
        common = common and plan.get("noops") == []
    elif phase == "repeat":
        records = plan.get("noops")
        expected_operation = None
        common = common and plan.get("actions") == []
    else:
        return False
    if not isinstance(records, list) or len(records) != 3:
        return False
    by_kind = {str(item.get("kind")): item for item in records if isinstance(item, dict)}
    if set(by_kind) != set(kinds):
        return False
    for kind in kinds:
        if not _evidence_record_contract(
            by_kind[kind],
            kind=kind,
            target_rva=target_rva,
            target_address=target_address,
            label_text=label_text,
            comment_text=comment_text,
            operation=expected_operation,
            reason="already_equal" if phase == "repeat" else None,
        ):
            return False
    if phase == "dry-run":
        common = bool(
            common
            and payload.get("dryRun") is True
            and payload.get("canApply") is True
            and payload.get("wouldMutate") == 3
        )
    else:
        common = common and payload.get("dryRun") is False
    return bool(common)


def _evidence_apply_contract(
    payload: Any,
    *,
    target_rva: int,
    target_address: int,
    label_text: str,
    comment_text: str,
) -> bool:
    if not _evidence_plan_contract(
        payload,
        phase="apply",
        target_rva=target_rva,
        target_address=target_address,
        label_text=label_text,
        comment_text=comment_text,
    ):
        return False
    applied = payload.get("applied")
    if not isinstance(applied, list) or len(applied) != 3:
        return False
    expected_endpoints = {
        "label": "Label/Set",
        "comment": "Comment/Set",
        "bookmark": "Bookmark/Set",
    }
    observed: dict[str, dict[str, Any]] = {}
    for item in applied:
        if isinstance(item, dict) and isinstance(item.get("action"), dict):
            observed[str(item["action"].get("kind"))] = item
    return bool(
        payload.get("appliedCount") == 3
        and payload.get("failures") == []
        and payload.get("verificationFailures") == []
        and payload.get("partial") is False
        and set(observed) == set(expected_endpoints)
        and all(
            observed[kind].get("endpoint") == endpoint
            and observed[kind].get("verified") is True
            for kind, endpoint in expected_endpoints.items()
        )
    )


def _evidence_repeat_contract(
    payload: Any,
    *,
    target_rva: int,
    target_address: int,
    label_text: str,
    comment_text: str,
) -> bool:
    return bool(
        _evidence_plan_contract(
            payload,
            phase="repeat",
            target_rva=target_rva,
            target_address=target_address,
            label_text=label_text,
            comment_text=comment_text,
        )
        and payload.get("applied") == []
        and payload.get("appliedCount") == 0
        and payload.get("failures") == []
        and payload.get("verificationFailures") == []
        and payload.get("partial") is False
    )


def _run_strict_evidence_roundtrip(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = artifact_dir / f"evidence-{arch}.json"
    copy_path = artifact_dir / f"evidence-copy-{arch}.exe"
    for path in (evidence_path, copy_path):
        if path.exists():
            path.unlink()

    result: dict[str, Any] = {
        "ok": False,
        "evidencePath": str(evidence_path),
        "copyPath": str(copy_path),
    }
    active_cleanup: Optional[tuple[dict[str, Any], str, str]] = None

    def reject(message: str) -> dict[str, Any]:
        result["error"] = message
        return result

    try:
        first_init = bridge.InitDebuggee(
            exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off"
        )
        first_entry = bridge.RunUntil(target="entry", timeout_ms=10000, poll_ms=100)
        first_module = _main_module_record(bridge, exe_path)
        result.update(
            {"firstInit": first_init, "firstEntry": first_entry, "firstModule": first_module}
        )
        if not (
            isinstance(first_init, dict)
            and first_init.get("ok") is True
            and isinstance(first_entry, dict)
            and first_entry.get("ok") is True
        ):
            return reject("The source fixture did not reach its entry point.")
        try:
            base = int(str(first_module.get("base") or "0"), 0)
            entry = int(str(first_module.get("entry") or "0"), 0)
            size = int(str(first_module.get("size") or "0"), 0)
        except ValueError:
            base = entry = size = 0
        annotation_address = entry + 0x20
        if not (base and entry and size and base <= annotation_address < base + size):
            return reject("Main module identity is incomplete.")
        source_guard = _generated_fixture_guard(first_module, exe_path, artifact_dir)
        result["sourceGuard"] = source_guard
        if not source_guard.get("ok"):
            return reject(str(source_guard.get("error") or "Source cleanup guard rejected the fixture."))

        target_rva = annotation_address - base
        address_hex = f"0x{annotation_address:X}"
        label_text = f"mcp_evidence_%41_{arch}"
        comment_text = (
            f"evidence {arch} literal %41 Unicode: Привет/分析; " + ("roundtrip-" * 28)
        )
        module_name = str(
            first_module.get("name") or Path(str(first_module.get("path") or "")).name
        )
        active_cleanup = (first_module, str(exe_path), address_hex)
        source_baseline = _clear_fixture_annotations(
            bridge, first_module, exe_path, artifact_dir, address_hex
        )
        result["sourceBaselineClear"] = source_baseline
        if not source_baseline.get("ok"):
            return reject("The source annotation baseline could not be proven empty.")

        label = bridge.LabelSet(address_hex, label_text, manual=True)
        comment = bridge.CommentSet(address_hex, comment_text, manual=True)
        bookmark = bridge.BookmarkSet(address_hex, manual=True)
        seed_proof = _seed_annotation_proof(
            bridge,
            module_name,
            address_hex,
            target_rva,
            label_text,
            comment_text,
        )
        result["annotations"] = {"label": label, "comment": comment, "bookmark": bookmark}
        result["seedProof"] = seed_proof
        seed_ok = bool(
            _bridge_mutation_ok(label)
            and _bridge_mutation_ok(comment)
            and _bridge_mutation_ok(bookmark)
            and seed_proof.get("ok")
        )

        exported: dict[str, Any] = {}
        export_contract: dict[str, Any] = {"ok": False, "error": "Seed proof failed."}
        document: Any = None
        if seed_ok:
            exported = bridge.ExportAnalysisEvidence(
                output_path=str(evidence_path),
                overwrite=False,
                include_breakpoints=False,
                include_patches=False,
            )
            document = exported.get("document") if isinstance(exported, dict) else None
            export_contract = _evidence_document_contract(
                document,
                fixture_path=exe_path,
                arch=arch,
                runtime_base=base,
                target_rva=target_rva,
                label_text=label_text,
                comment_text=comment_text,
            )
            file_document: Any = None
            try:
                file_document = json.loads(evidence_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                export_contract["fileError"] = str(exc)
            export_contract["fileMatchesDocument"] = file_document == document
            export_contract["ok"] = bool(
                isinstance(exported, dict)
                and exported.get("ok") is True
                and export_contract.get("ok")
                and export_contract["fileMatchesDocument"]
            )
        result["export"] = exported
        result["exportContract"] = export_contract

        # Do not leave the first-session database dirty even when export validation fails.
        source_clear = _clear_fixture_annotations(
            bridge, first_module, exe_path, artifact_dir, address_hex
        )
        result["sourcePostExportClear"] = source_clear
        if source_clear.get("ok"):
            active_cleanup = None
        if not source_clear.get("ok"):
            return reject("The source annotations were not cleared after export.")
        first_stop = bridge.DebugStop()
        result["firstStop"] = first_stop
        if not (isinstance(first_stop, dict) and first_stop.get("ok") is True):
            return reject("The source debug session did not stop cleanly.")
        if not seed_ok:
            return reject("The exact label/comment/bookmark seed could not be proven.")
        if not export_contract.get("ok"):
            return reject("The exact 1/1/1/0 evidence export contract failed.")

        shutil.copy2(exe_path, copy_path)
        second_init = bridge.InitDebuggee(
            str(copy_path),
            timeout_ms=20000,
            retries=2,
            stop_first=True,
            use_scyllahide="off",
        )
        second_entry = bridge.RunUntil(target="entry", timeout_ms=10000, poll_ms=100)
        second_module = _main_module_record(bridge, str(copy_path))
        result.update(
            {
                "secondInit": second_init,
                "secondEntry": second_entry,
                "secondModule": second_module,
            }
        )
        if not (
            isinstance(second_init, dict)
            and second_init.get("ok") is True
            and isinstance(second_entry, dict)
            and second_entry.get("ok") is True
        ):
            return reject("The rebased evidence copy did not reach its entry point.")
        try:
            second_base = int(str(second_module.get("base") or "0"), 0)
        except ValueError:
            second_base = 0
        if not second_base:
            return reject("The rebased evidence-copy module base is unavailable.")
        second_address_value = second_base + target_rva
        second_address = f"0x{second_address_value:X}"
        result["baseChanged"] = base != second_base
        result["rebasedAddress"] = second_address
        active_cleanup = (second_module, str(copy_path), second_address)

        second_baseline = _clear_fixture_annotations(
            bridge, second_module, str(copy_path), artifact_dir, second_address
        )
        result["secondBaselineClear"] = second_baseline
        if not second_baseline.get("ok"):
            return reject("The destination annotation baseline could not be proven empty.")

        encoded = json.dumps(document, ensure_ascii=False)
        import_options = {
            "evidence_json": encoded,
            "allow_hash_mismatch": False,
            "overwrite_existing": False,
            "apply_labels": True,
            "apply_comments": True,
            "apply_bookmarks": True,
            "apply_functions": False,
            "apply_breakpoints": False,
            "apply_patches": False,
        }
        dry_run = bridge.ImportAnalysisEvidence(dry_run=True, **import_options)
        result["dryRun"] = dry_run
        dry_ok = _evidence_plan_contract(
            dry_run,
            phase="dry-run",
            target_rva=target_rva,
            target_address=second_address_value,
            label_text=label_text,
            comment_text=comment_text,
        )
        result["dryRunContract"] = {"ok": dry_ok}
        if not dry_ok:
            return reject("Dry-run was not the exact three-create mutation plan.")

        applied = bridge.ImportAnalysisEvidence(dry_run=False, **import_options)
        result["apply"] = applied
        apply_ok = _evidence_apply_contract(
            applied,
            target_rva=target_rva,
            target_address=second_address_value,
            label_text=label_text,
            comment_text=comment_text,
        )
        result["applyContract"] = {"ok": apply_ok}
        if not apply_ok:
            return reject("Apply was not the exact three verified mutations.")

        label_check = bridge.LabelGet(second_address)
        comment_check = bridge.CommentGet(second_address)
        bookmark_check = bridge.BookmarkGet(second_address)
        verification = {
            "address": second_address,
            "label": label_check,
            "comment": comment_check,
            "bookmark": bookmark_check,
        }
        verification["ok"] = bool(
            isinstance(label_check, dict)
            and label_check.get("found") is True
            and label_check.get("label") == label_text
            and isinstance(comment_check, dict)
            and comment_check.get("found") is True
            and comment_check.get("comment") == comment_text
            and isinstance(bookmark_check, dict)
            and bookmark_check.get("found") is True
            and bookmark_check.get("manual") is True
        )
        result["verification"] = verification

        repeated = bridge.ImportAnalysisEvidence(dry_run=False, **import_options)
        result["repeat"] = repeated
        repeat_ok = _evidence_repeat_contract(
            repeated,
            target_rva=target_rva,
            target_address=second_address_value,
            label_text=label_text,
            comment_text=comment_text,
        )
        result["repeatContract"] = {"ok": repeat_ok}
        final_clear = _clear_fixture_annotations(
            bridge, second_module, str(copy_path), artifact_dir, second_address
        )
        result["finalClear"] = final_clear
        if final_clear.get("ok"):
            active_cleanup = None
        ok = bool(verification["ok"] and repeat_ok and final_clear.get("ok"))
        result["ok"] = ok
        result["error"] = None if ok else "Analysis-evidence roundtrip did not verify exactly."
        return result
    finally:
        if active_cleanup is not None:
            module, fixture, target = active_cleanup
            try:
                result["safetyCleanup"] = _clear_fixture_annotations(
                    bridge, module, fixture, artifact_dir, target
                )
            except Exception as exc:
                result["safetyCleanup"] = {"ok": False, "error": str(exc)}


def _run_evidence_roundtrip_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    return _run_strict_evidence_roundtrip(bridge, exe_path, artifact_dir, arch)


def _run_dll_overlay_dump_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    init = bridge.InitDebuggee(
        exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off"
    )
    entry = bridge.RunUntil(target="entry", timeout_ms=10000, poll_ms=100)
    modules_payload = bridge.GetModuleList()
    modules = modules_payload.get("modules", []) if isinstance(modules_payload, dict) else []
    module = next(
        (
            dict(item)
            for item in modules
            if isinstance(item, dict)
            and str(item.get("name") or "").casefold() == "fixture_module.dll"
        ),
        {},
    )
    artifact_dir.mkdir(parents=True, exist_ok=True)
    output = artifact_dir / f"fixture_module-{arch}.dump.dll"
    if output.exists():
        output.unlink()
    dumped = bridge.DumpLoadedModule(
        "fixture_module.dll", str(output), overwrite=False, verify=True
    )
    source_path = str(module.get("path") or dumped.get("sourcePath") or "")
    verified = bridge.VerifyPEDump(
        str(output), source_path=source_path, require_imports=True
    ) if output.is_file() else {"ok": False, "error": "dump missing"}
    ok = bool(
        init.get("ok")
        and entry.get("ok")
        and module
        and dumped.get("ok")
        and dumped.get("verified")
        and output.is_file()
        and output.stat().st_size > 0
        and verified.get("ok")
        and verified.get("verified")
        and str((verified.get("layout") or {}).get("arch") or "").casefold() == arch
    )
    return {
        "ok": ok,
        "init": init,
        "entry": entry,
        "module": module,
        "dump": dumped,
        "verify": verified,
        "path": str(output),
        "error": None if ok else "Loaded-DLL overlay dump failed verification.",
    }


_FIXTURE_EXCEPTION_EXACT = 0xE0424242
_FIXTURE_EXCEPTION_MASKED = 0xE0429999
_FIXTURE_EXCEPTION_WILDCARD = 0xA1234567
_EXCEPTION_HISTORY_REQUIRED_FIELDS = frozenset(
    {
        "historySeq",
        "seq",
        "eventSeq",
        "bridgeInstanceId",
        "sessionId",
        "sessionGeneration",
        "policyVersion",
        "tickMs",
        "lastUpdateMs",
        "timestamp100ns",
        "lastUpdateTimestamp100ns",
        "processId",
        "threadId",
        "exceptionCode",
        "chance",
        "firstChance",
        "address",
        "ip",
        "action",
        "source",
        "ruleId",
        "matchedSelector",
        "autoContinue",
        "continuationSource",
        "continuationClaimed",
        "commandSubmitted",
        "dispositionSubmitted",
        "resumeRequested",
        "resumeSubmitted",
        "command",
        "status",
        "disposition",
        "requestedDisposition",
        "appliedDisposition",
        "outcome",
    }
)


def _integer(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, str):
            return int(value.strip(), 0)
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _uint32(value: Any) -> int:
    return _integer(value) & 0xFFFFFFFF


def _session_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    direct = payload.get("session")
    if isinstance(direct, dict):
        return direct
    state = payload.get("state")
    if isinstance(state, dict):
        nested = state.get("session")
        if isinstance(nested, dict):
            return nested
    # RunUntil and wait adapters can expose the authoritative native session
    # beside a compact generic state. Prefer that richer nested snapshot.
    for key in ("waitInfo", "waitState"):
        wait = payload.get(key)
        if isinstance(wait, dict) and isinstance(wait.get("state"), dict):
            wait_state = dict(wait["state"])
            nested = wait_state.get("session")
            if isinstance(nested, dict):
                return nested
            if str(wait_state.get("sessionId") or ""):
                return wait_state
    if isinstance(state, dict):
        return state
    return payload


def _exit_code(payload: Any) -> int:
    if not isinstance(payload, dict):
        return -1
    candidates = [payload.get("exitCode")]
    session = _session_payload(payload)
    candidates.append(session.get("exitCode"))
    wait = payload.get("waitInfo")
    if isinstance(wait, dict) and isinstance(wait.get("state"), dict):
        candidates.append(wait["state"].get("exitCode"))
    for candidate in candidates:
        if candidate is None or candidate == "":
            continue
        return _uint32(candidate)
    return -1


def _history_records(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    records = payload.get("history")
    if not isinstance(records, list):
        return []
    return [dict(item) for item in records if isinstance(item, dict)]


def _history_record_contract(record: dict[str, Any]) -> dict[str, Any]:
    missing = sorted(_EXCEPTION_HISTORY_REQUIRED_FIELDS - set(record))
    invalid: list[str] = []
    history_seq = _integer(record.get("historySeq"))
    if history_seq <= 0 or _integer(record.get("seq")) != history_seq:
        invalid.append("historySeq/seq")
    for field in (
        "eventSeq",
        "sessionGeneration",
        "policyVersion",
        "tickMs",
        "lastUpdateMs",
        "timestamp100ns",
        "lastUpdateTimestamp100ns",
        "processId",
        "threadId",
    ):
        if _integer(record.get(field)) <= 0:
            invalid.append(field)
    for field in ("exceptionCode", "address", "ip"):
        if _integer(record.get(field)) <= 0:
            invalid.append(field)
    if _integer(record.get("lastUpdateMs")) < _integer(record.get("tickMs")):
        invalid.append("lastUpdateMs<tickMs")
    if _integer(record.get("lastUpdateTimestamp100ns")) < _integer(
        record.get("timestamp100ns")
    ):
        invalid.append("lastUpdateTimestamp100ns<timestamp100ns")
    for field in (
        "bridgeInstanceId",
        "sessionId",
        "chance",
        "action",
        "source",
        "continuationSource",
        "status",
        "disposition",
        "requestedDisposition",
        "appliedDisposition",
        "outcome",
    ):
        if not isinstance(record.get(field), str) or not str(record.get(field)):
            invalid.append(field)
    if str(record.get("chance") or "") not in {"first", "second"}:
        invalid.append("chance:value")
    if str(record.get("action") or "") not in {"pause", "handled", "not_handled"}:
        invalid.append("action:value")
    if str(record.get("continuationSource") or "") not in {"none", "policy", "manual"}:
        invalid.append("continuationSource:value")
    if str(record.get("requestedDisposition") or "") not in {
        "pause",
        "handled",
        "not_handled",
    }:
        invalid.append("requestedDisposition:value")
    if str(record.get("appliedDisposition") or "") not in {
        "none",
        "pending",
        "handled",
        "not_handled",
    }:
        invalid.append("appliedDisposition:value")
    for field in (
        "firstChance",
        "autoContinue",
        "continuationClaimed",
        "commandSubmitted",
        "dispositionSubmitted",
        "resumeRequested",
        "resumeSubmitted",
    ):
        if not isinstance(record.get(field), bool):
            invalid.append(field)
    for field in ("ruleId", "matchedSelector", "command"):
        if not isinstance(record.get(field), str):
            invalid.append(field)
    return {
        "ok": not missing and not invalid,
        "missing": missing,
        "invalid": invalid,
        "historySeq": history_seq,
    }


def _history_contract(
    payload: Any,
    *,
    expected_codes: Sequence[int],
    expected_session_id: str = "",
    expected_generation: int = 0,
    expected_process_id: int = 0,
) -> dict[str, Any]:
    records = _history_records(payload)
    meta = payload.get("meta") if isinstance(payload, dict) else None
    wanted = [_uint32(code) for code in expected_codes]
    selected = [
        record
        for record in records
        if _uint32(record.get("exceptionCode")) in set(wanted)
    ]
    shapes = [_history_record_contract(record) for record in selected]
    observed_codes = [_uint32(record.get("exceptionCode")) for record in selected]
    sequences = [_integer(record.get("historySeq")) for record in selected]
    session_ids = {str(record.get("sessionId") or "") for record in selected}
    bridge_ids = {str(record.get("bridgeInstanceId") or "") for record in selected}
    generations = {_integer(record.get("sessionGeneration")) for record in selected}
    process_ids = {_integer(record.get("processId")) for record in selected}
    meta_generation = _integer(meta.get("sessionGeneration")) if isinstance(meta, dict) else 0
    meta_process_id = _integer(meta.get("processId")) if isinstance(meta, dict) else 0
    meta_ok = bool(
        isinstance(meta, dict)
        and str(meta.get("bridgeInstanceId") or "")
        and str(meta.get("sessionId") or "")
        and _integer(meta.get("sessionGeneration")) > 0
        and _integer(meta.get("eventSeq")) > 0
        and (
            not expected_session_id
            or str(meta.get("sessionId") or "") == expected_session_id
        )
        and (not expected_generation or meta_generation == expected_generation)
        and (
            not expected_process_id
            or meta_process_id in {0, expected_process_id}
        )
    )
    ok = bool(
        isinstance(payload, dict)
        and payload.get("ok") is True
        and observed_codes == wanted
        and len(sequences) == len(set(sequences))
        and sequences == sorted(sequences)
        and all(item.get("ok") for item in shapes)
        and len(session_ids) == (1 if selected else 0)
        and len(bridge_ids) == (1 if selected else 0)
        and (not selected or bridge_ids == {str(meta.get("bridgeInstanceId") or "")})
        and (not expected_session_id or session_ids == {expected_session_id})
        and (not expected_generation or generations == {expected_generation})
        and (not expected_process_id or process_ids == {expected_process_id})
        and meta_ok
    )
    return {
        "ok": ok,
        "expectedCodes": [f"0x{code:08x}" for code in wanted],
        "observedCodes": [f"0x{code:08x}" for code in observed_codes],
        "records": selected,
        "recordContracts": shapes,
        "historySeqs": sequences,
        "sessionIds": sorted(session_ids),
        "bridgeInstanceIds": sorted(bridge_ids),
        "sessionGenerations": sorted(generations),
        "processIds": sorted(process_ids),
        "metaContract": {"ok": meta_ok, "meta": meta},
        "unrelatedRecordCount": len(records) - len(selected),
    }


def _history_cursor_contract(
    bridge: Any, expected_records: Sequence[dict[str, Any]]
) -> dict[str, Any]:
    expected = [dict(record) for record in expected_records]
    pages: list[dict[str, Any]] = []
    cursor = 0
    ok = True
    expected_oldest = _integer(expected[0].get("historySeq")) if expected else 0
    expected_latest = _integer(expected[-1].get("historySeq")) if expected else 0
    # ClearExceptionHistory advances the retained-history floor instead of
    # reusing sequence numbers. ``dropped`` is a cumulative watermark and a
    # cursor before that floor is correctly reported as truncated.
    expected_dropped = max(0, expected_oldest - 1)
    expected_bridge_id = str(expected[0].get("bridgeInstanceId") or "") if expected else ""
    expected_session_id = str(expected[0].get("sessionId") or "") if expected else ""
    expected_generation = _integer(expected[0].get("sessionGeneration")) if expected else 0
    for index, record in enumerate(expected):
        expected_seq = _integer(record.get("historySeq"))
        page = bridge.GetExceptionHistory(after_seq=cursor, limit=1)
        records = _history_records(page)
        observed_seq = _integer(records[0].get("historySeq")) if len(records) == 1 else 0
        meta = page.get("meta") if isinstance(page, dict) else None
        expected_has_more = index + 1 < len(expected)
        page_ok = bool(
            isinstance(page, dict)
            and page.get("ok") is True
            and len(records) == 1
            and observed_seq == expected_seq
            and _integer(page.get("afterSeq")) == cursor
            and _integer(page.get("limit")) == 1
            and _integer(page.get("returned")) == 1
            and bool(page.get("hasMore")) is expected_has_more
            and _integer(page.get("nextAfterSeq")) == expected_seq
            and _integer(page.get("oldestAvailableSeq")) == expected_oldest
            and _integer(page.get("latestSeq")) == expected_latest
            and _integer(page.get("dropped")) == expected_dropped
            and page.get("cursorTruncated")
            is (cursor < max(0, expected_oldest - 1))
            and observed_seq > cursor
            and isinstance(meta, dict)
            and str(meta.get("bridgeInstanceId") or "") == expected_bridge_id
            and str(meta.get("sessionId") or "") == expected_session_id
            and _integer(meta.get("sessionGeneration")) == expected_generation
            and _integer(meta.get("eventSeq")) > 0
        )
        pages.append(
            {
                "afterSeq": cursor,
                "expectedSeq": expected_seq,
                "observedSeq": observed_seq,
                "page": page,
                "ok": page_ok,
            }
        )
        ok = ok and page_ok
        cursor = expected_seq
    tail = bridge.GetExceptionHistory(after_seq=cursor, limit=1)
    tail_meta = tail.get("meta") if isinstance(tail, dict) else None
    tail_ok = bool(
        isinstance(tail, dict)
        and tail.get("ok") is True
        and _history_records(tail) == []
        and _integer(tail.get("afterSeq")) == cursor
        and _integer(tail.get("nextAfterSeq")) == cursor
        and _integer(tail.get("limit")) == 1
        and _integer(tail.get("returned")) == 0
        and tail.get("hasMore") is False
        and _integer(tail.get("oldestAvailableSeq")) == expected_oldest
        and _integer(tail.get("latestSeq")) == expected_latest
        and _integer(tail.get("dropped")) == expected_dropped
        and tail.get("cursorTruncated") is False
        and isinstance(tail_meta, dict)
        and str(tail_meta.get("bridgeInstanceId") or "") == expected_bridge_id
        and str(tail_meta.get("sessionId") or "") == expected_session_id
        and _integer(tail_meta.get("sessionGeneration")) == expected_generation
    )
    return {"ok": bool(ok and tail_ok), "pages": pages, "tail": tail}


def _launch_exception_fixture(
    bridge: Any, exe_path: str, mode: str
) -> dict[str, Any]:
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
        arguments=[mode],
    )
    entry = (
        bridge.RunUntil(
            target="entry",
            timeout_ms=10000,
            poll_ms=100,
        )
        if isinstance(init, dict) and init.get("ok") is True
        else {"ok": False, "error": "launch failed"}
    )
    # RunUntil returns a compact state snapshot that does not necessarily carry
    # the native session identity.  InitDebuggee does, so resolve every identity
    # field independently instead of treating any non-empty RunUntil state as a
    # complete session object.
    entry_session = _session_payload(entry)
    init_session = _session_payload(init)
    session_id = str(
        entry_session.get("sessionId")
        or init_session.get("sessionId")
        or ""
    )
    generation = _integer(
        entry_session.get("generation")
        or entry_session.get("sessionGeneration")
        or init_session.get("generation")
        or init_session.get("sessionGeneration")
    )
    process_id = _integer(
        entry_session.get("processId")
        or entry_session.get("debuggeePid")
        or entry_session.get("pid")
        or init_session.get("processId")
        or init_session.get("debuggeePid")
        or init_session.get("pid")
    )
    return {
        "ok": bool(
            isinstance(init, dict)
            and init.get("ok") is True
            and isinstance(entry, dict)
            and entry.get("ok") is True
        ),
        "init": init,
        "entry": entry,
        "sessionId": session_id,
        "generation": generation,
        "processId": process_id,
    }


def _clear_exception_history_baseline(bridge: Any) -> dict[str, Any]:
    cleared = bridge.ClearExceptionHistory()
    observed = bridge.GetExceptionHistory(after_seq=0, limit=256)
    return {
        "ok": bool(
            isinstance(cleared, dict)
            and cleared.get("ok") is True
            and isinstance(observed, dict)
            and observed.get("ok") is True
            and _history_records(observed) == []
        ),
        "clear": cleared,
        "observed": observed,
    }


def _set_exception_rules(
    bridge: Any,
    rules: Sequence[dict[str, Any]],
    *,
    first_default: str = "pause",
    second_default: str = "pause",
) -> dict[str, Any]:
    return bridge.SetExceptionPolicy(
        json.dumps(list(rules), ensure_ascii=False),
        enabled=True,
        first_chance_default=first_default,
        second_chance_default=second_default,
        replace=True,
    )


def _exception_meta_contract(
    payload: Any,
    *,
    expected_session_id: str,
    expected_generation: int,
) -> dict[str, Any]:
    meta = payload.get("meta") if isinstance(payload, dict) else None
    ok = bool(
        isinstance(meta, dict)
        and str(meta.get("bridgeInstanceId") or "")
        and str(meta.get("sessionId") or "") == expected_session_id
        and _integer(meta.get("sessionGeneration")) == expected_generation
        and _integer(meta.get("eventSeq")) > 0
    )
    return {"ok": ok, "meta": meta}


def _canonical_expected_policy_rule(rule: dict[str, Any]) -> dict[str, Any]:
    raw_codes = rule.get("codes", rule.get("code", "*"))
    codes = raw_codes if isinstance(raw_codes, list) else [raw_codes]
    return {
        "ruleId": str(rule.get("ruleId") or ""),
        "codes": [str(item).casefold() for item in codes],
        "chance": str(rule.get("chance") or "any").casefold(),
        "action": str(rule.get("action") or "pause").casefold(),
        "priority": _integer(rule.get("priority")),
        "enabled": bool(rule.get("enabled", True)),
    }


def _policy_roundtrip_contract(
    set_payload: Any,
    get_payload: Any,
    *,
    expected_rules: Sequence[dict[str, Any]],
    expected_first_default: str,
    expected_second_default: str,
    expected_session_id: str,
    expected_generation: int,
) -> dict[str, Any]:
    set_policy = _policy_snapshot(set_payload)
    get_policy = _policy_snapshot(get_payload)
    expected = [_canonical_expected_policy_rule(rule) for rule in expected_rules]
    observed = []
    for rule in list(get_policy.get("rules") or []):
        if not isinstance(rule, dict):
            observed.append({"invalid": rule})
            continue
        observed.append(
            {
                "ruleId": str(rule.get("ruleId") or ""),
                "codes": [str(item).casefold() for item in list(rule.get("codes") or [])],
                "chance": str(rule.get("chance") or "").casefold(),
                "action": str(rule.get("action") or "").casefold(),
                "priority": _integer(rule.get("priority")),
                "enabled": bool(rule.get("enabled")),
            }
        )
    set_meta = _exception_meta_contract(
        set_payload,
        expected_session_id=expected_session_id,
        expected_generation=expected_generation,
    )
    get_meta = _exception_meta_contract(
        get_payload,
        expected_session_id=expected_session_id,
        expected_generation=expected_generation,
    )
    version = _integer(get_policy.get("version"))
    ok = bool(
        isinstance(set_payload, dict)
        and set_payload.get("ok") is True
        and isinstance(get_payload, dict)
        and get_payload.get("ok") is True
        and set_policy == get_policy
        and get_policy.get("enabled") is True
        and version > 0
        and _integer(set_policy.get("version")) == version
        and str(get_policy.get("firstChanceDefault") or "") == expected_first_default
        and str(get_policy.get("secondChanceDefault") or "") == expected_second_default
        and _integer(get_policy.get("ruleCount")) == len(expected)
        and observed == expected
        and set_meta.get("ok")
        and get_meta.get("ok")
    )
    return {
        "ok": ok,
        "expectedRules": expected,
        "observedRules": observed,
        "setPolicy": set_policy,
        "getPolicy": get_policy,
        "setMeta": set_meta,
        "getMeta": get_meta,
    }


def _run_first_chance_policy_subcase(
    bridge: Any,
    exe_path: str,
    *,
    action: str,
    expected_exit_code: int,
    rule_id: str,
    fixture_mode: str = "handled",
) -> dict[str, Any]:
    launch = _launch_exception_fixture(bridge, exe_path, fixture_mode)
    policy = _set_exception_rules(
        bridge,
        [
            {
                "ruleId": rule_id,
                "code": f"0x{_FIXTURE_EXCEPTION_EXACT:08x}",
                "chance": "first",
                "action": action,
                "priority": 100,
            }
        ],
    ) if launch.get("ok") else {"ok": False, "error": "launch failed"}
    baseline = (
        _clear_exception_history_baseline(bridge)
        if isinstance(policy, dict) and policy.get("ok") is True
        else {"ok": False, "error": "policy failed"}
    )
    run = bridge.DebugRun() if baseline.get("ok") else {"ok": False}
    exited = bridge.WaitForExit(timeout_ms=15000, poll_ms=100) if baseline.get("ok") else {}
    history = bridge.GetExceptionHistory(after_seq=0, limit=256) if baseline.get("ok") else {}
    contract = _history_contract(
        history,
        expected_codes=[_FIXTURE_EXCEPTION_EXACT],
        expected_session_id=str(launch.get("sessionId") or ""),
        expected_generation=_integer(launch.get("generation")),
        expected_process_id=_integer(launch.get("processId")),
    )
    record = contract["records"][0] if len(contract["records"]) == 1 else {}
    expected_command = "con 1" if action == "not_handled" else "con"
    semantics_ok = bool(
        record.get("firstChance") is True
        and record.get("action") == action
        and record.get("source") == "rule"
        and record.get("ruleId") == rule_id
        and str(record.get("matchedSelector") or "").casefold()
        == f"0x{_FIXTURE_EXCEPTION_EXACT:08x}"
        and record.get("autoContinue") is True
        and record.get("continuationClaimed") is True
        and record.get("commandSubmitted") is True
        and record.get("dispositionSubmitted") is True
        and record.get("resumeRequested") is True
        and record.get("resumeSubmitted") is True
        and record.get("command") == expected_command
        and record.get("continuationSource") == "policy"
        and record.get("status") == "auto_resumed"
        and record.get("disposition") == action
        and record.get("requestedDisposition") == action
        and record.get("appliedDisposition") == action
        and record.get("outcome") == "applied"
    )
    observed_exit = _exit_code(exited)
    ok = bool(
        launch.get("ok")
        and isinstance(policy, dict)
        and policy.get("ok") is True
        and baseline.get("ok")
        and isinstance(exited, dict)
        and exited.get("exited") is True
        and observed_exit == _uint32(expected_exit_code)
        and contract.get("ok")
        and semantics_ok
    )
    return {
        "ok": ok,
        "launch": launch,
        "policy": policy,
        "baseline": baseline,
        "run": run,
        "exit": exited,
        "expectedExitCode": _uint32(expected_exit_code),
        "fixtureMode": fixture_mode,
        "observedExitCode": observed_exit,
        "history": history,
        "historyContract": contract,
        "semanticsOk": semantics_ok,
    }


def _run_exception_policy_first_chance_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir, arch
    not_handled = _run_first_chance_policy_subcase(
        bridge,
        exe_path,
        action="not_handled",
        expected_exit_code=0,
        rule_id="first-pass-to-seh",
    )
    handled = _run_first_chance_policy_subcase(
        bridge,
        exe_path,
        action="handled",
        expected_exit_code=68,
        rule_id="first-swallow-before-seh",
    )
    veh_continued = _run_first_chance_policy_subcase(
        bridge,
        exe_path,
        action="not_handled",
        expected_exit_code=0,
        rule_id="first-pass-to-veh",
        fixture_mode="first-chance",
    )
    ok = bool(
        not_handled.get("ok") and handled.get("ok") and veh_continued.get("ok")
    )
    return {
        "ok": ok,
        "notHandledToSeh": not_handled,
        "handledByDebugger": handled,
        "notHandledToVehContinue": veh_continued,
        "error": None if ok else "First-chance disposition exit oracles failed.",
    }


def _run_exception_policy_precedence_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir, arch
    launch = _launch_exception_fixture(bridge, exe_path, "policy-sequence")
    rules = [
        {
            "ruleId": "wildcard-fallback",
            "code": "*",
            "chance": "first",
            "action": "not_handled",
            "priority": 10000,
        },
        {
            "ruleId": "masked-family",
            "code": "0xe0420000/0xffff0000",
            "chance": "first",
            "action": "not_handled",
            "priority": 1000,
        },
        {
            "ruleId": "exact-code",
            "code": "0xe0424242",
            "chance": "first",
            "action": "not_handled",
            "priority": -1000,
        },
    ]
    policy = _set_exception_rules(bridge, rules) if launch.get("ok") else {"ok": False}
    policy_readback = (
        bridge.GetExceptionPolicy()
        if isinstance(policy, dict) and policy.get("ok") is True
        else {}
    )
    policy_roundtrip = _policy_roundtrip_contract(
        policy,
        policy_readback,
        expected_rules=rules,
        expected_first_default="pause",
        expected_second_default="pause",
        expected_session_id=str(launch.get("sessionId") or ""),
        expected_generation=_integer(launch.get("generation")),
    )
    baseline = (
        _clear_exception_history_baseline(bridge)
        if isinstance(policy, dict) and policy.get("ok") is True
        else {"ok": False}
    )
    run = bridge.DebugRun() if baseline.get("ok") else {"ok": False}
    exited = bridge.WaitForExit(timeout_ms=15000, poll_ms=100) if baseline.get("ok") else {}
    history = bridge.GetExceptionHistory(after_seq=0, limit=256) if baseline.get("ok") else {}
    contract = _history_contract(
        history,
        expected_codes=[
            _FIXTURE_EXCEPTION_EXACT,
            _FIXTURE_EXCEPTION_MASKED,
            _FIXTURE_EXCEPTION_WILDCARD,
        ],
        expected_session_id=str(launch.get("sessionId") or ""),
        expected_generation=_integer(launch.get("generation")),
        expected_process_id=_integer(launch.get("processId")),
    )
    expected_matches = [
        ("exact-code", "0xe0424242"),
        ("masked-family", "0xe0420000/0xffff0000"),
        ("wildcard-fallback", "*"),
    ]
    precedence_ok = bool(
        len(contract["records"]) == len(expected_matches)
        and all(
            record.get("firstChance") is True
            and record.get("action") == "not_handled"
            and record.get("source") == "rule"
            and record.get("ruleId") == expected_rule
            and str(record.get("matchedSelector") or "").casefold() == expected_selector
            and record.get("autoContinue") is True
            and record.get("continuationClaimed") is True
            and record.get("commandSubmitted") is True
            and record.get("dispositionSubmitted") is True
            and record.get("resumeRequested") is True
            and record.get("resumeSubmitted") is True
            and record.get("command") == "con 1"
            and record.get("continuationSource") == "policy"
            and record.get("status") == "auto_resumed"
            and record.get("requestedDisposition") == "not_handled"
            and record.get("appliedDisposition") == "not_handled"
            and record.get("outcome") == "applied"
            for record, (expected_rule, expected_selector) in zip(
                contract["records"], expected_matches
            )
        )
    )
    cursor = (
        _history_cursor_contract(bridge, contract["records"])
        if contract.get("ok")
        else {"ok": False, "error": "history contract failed"}
    )
    observed_exit = _exit_code(exited)
    ok = bool(
        launch.get("ok")
        and isinstance(policy, dict)
        and policy.get("ok") is True
        and policy_roundtrip.get("ok")
        and baseline.get("ok")
        and isinstance(exited, dict)
        and exited.get("exited") is True
        and observed_exit == 0
        and contract.get("ok")
        and precedence_ok
        and cursor.get("ok")
    )
    return {
        "ok": ok,
        "launch": launch,
        "policy": policy,
        "policyReadback": policy_readback,
        "policyRoundtrip": policy_roundtrip,
        "baseline": baseline,
        "run": run,
        "exit": exited,
        "observedExitCode": observed_exit,
        "history": history,
        "historyContract": contract,
        "precedenceOk": precedence_ok,
        "cursorContract": cursor,
        "error": None if ok else "Exception selector precedence/history cursor failed.",
    }


def _run_exception_policy_second_chance_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir, arch
    launch = _launch_exception_fixture(bridge, exe_path, "unhandled")
    policy = _set_exception_rules(
        bridge,
        [],
        first_default="not_handled",
        second_default="pause",
    ) if launch.get("ok") else {"ok": False}
    policy_readback = (
        bridge.GetExceptionPolicy()
        if isinstance(policy, dict) and policy.get("ok") is True
        else {}
    )
    policy_roundtrip = _policy_roundtrip_contract(
        policy,
        policy_readback,
        expected_rules=[],
        expected_first_default="not_handled",
        expected_second_default="pause",
        expected_session_id=str(launch.get("sessionId") or ""),
        expected_generation=_integer(launch.get("generation")),
    )
    baseline = (
        _clear_exception_history_baseline(bridge)
        if isinstance(policy, dict) and policy.get("ok") is True
        else {"ok": False}
    )
    run = bridge.DebugRun() if baseline.get("ok") else {"ok": False}
    paused = bridge.WaitForPause(timeout_ms=15000, poll_ms=100) if baseline.get("ok") else {}
    history = bridge.GetExceptionHistory(after_seq=0, limit=256) if baseline.get("ok") else {}
    contract = _history_contract(
        history,
        expected_codes=[_FIXTURE_EXCEPTION_EXACT, _FIXTURE_EXCEPTION_EXACT],
        expected_session_id=str(launch.get("sessionId") or ""),
        expected_generation=_integer(launch.get("generation")),
        expected_process_id=_integer(launch.get("processId")),
    )
    first = contract["records"][0] if len(contract["records"]) == 2 else {}
    second = contract["records"][1] if len(contract["records"]) == 2 else {}
    paused_session = _session_payload(paused)
    semantics_ok = bool(
        first.get("firstChance") is True
        and first.get("source") == "first_chance_default"
        and first.get("ruleId") == ""
        and first.get("action") == "not_handled"
        and first.get("autoContinue") is True
        and first.get("continuationClaimed") is True
        and first.get("commandSubmitted") is True
        and first.get("dispositionSubmitted") is True
        and first.get("resumeRequested") is True
        and first.get("resumeSubmitted") is True
        and first.get("command") == "con 1"
        and first.get("continuationSource") == "policy"
        and first.get("status") == "auto_resumed"
        and first.get("requestedDisposition") == "not_handled"
        and first.get("appliedDisposition") == "not_handled"
        and first.get("outcome") == "applied"
        and second.get("firstChance") is False
        and second.get("source") == "second_chance_default"
        and second.get("ruleId") == ""
        and second.get("action") == "pause"
        and second.get("autoContinue") is False
        and second.get("continuationClaimed") is False
        and second.get("commandSubmitted") is False
        and second.get("dispositionSubmitted") is False
        and second.get("resumeRequested") is False
        and second.get("resumeSubmitted") is False
        and second.get("command") == ""
        and second.get("continuationSource") == "none"
        and second.get("status") == "paused"
        and second.get("disposition") == "default"
        and second.get("requestedDisposition") == "pause"
        and second.get("appliedDisposition") == "none"
        and second.get("outcome") == "paused"
        and isinstance(paused, dict)
        and paused.get("paused") is True
        and str(paused.get("stopReason") or paused_session.get("stopReason") or "").casefold()
        == "exception"
        and _uint32(
            paused.get("exceptionCode")
            or paused_session.get("exceptionCode")
        )
        == _FIXTURE_EXCEPTION_EXACT
        and bool(
            paused.get("exceptionFirstChance")
            if "exceptionFirstChance" in paused
            else paused_session.get("exceptionFirstChance")
        )
        is False
    )
    cursor = (
        _history_cursor_contract(bridge, contract["records"])
        if contract.get("ok")
        else {"ok": False}
    )
    ok = bool(
        launch.get("ok")
        and isinstance(policy, dict)
        and policy.get("ok") is True
        and policy_roundtrip.get("ok")
        and baseline.get("ok")
        and contract.get("ok")
        and semantics_ok
        and cursor.get("ok")
    )
    return {
        "ok": ok,
        "launch": launch,
        "policy": policy,
        "policyReadback": policy_readback,
        "policyRoundtrip": policy_roundtrip,
        "baseline": baseline,
        "run": run,
        "pause": paused,
        "history": history,
        "historyContract": contract,
        "semanticsOk": semantics_ok,
        "cursorContract": cursor,
        "error": None if ok else "Second-chance pause semantics failed.",
    }


def _policy_snapshot(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    policy = payload.get("policy")
    return dict(policy) if isinstance(policy, dict) else {}


def _run_exception_policy_lifecycle_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir, arch
    launch = _launch_exception_fixture(bridge, exe_path, "handled")
    policy = _set_exception_rules(bridge, []) if launch.get("ok") else {"ok": False}
    baseline = (
        _clear_exception_history_baseline(bridge)
        if isinstance(policy, dict) and policy.get("ok") is True
        else {"ok": False}
    )
    run_to_exception = bridge.DebugRun() if baseline.get("ok") else {"ok": False}
    paused = bridge.WaitForPause(timeout_ms=15000, poll_ms=100) if baseline.get("ok") else {}
    paused_session = _session_payload(paused)
    event_seq = _integer(paused.get("eventSeq") if isinstance(paused, dict) else 0)
    if event_seq <= 0:
        event_seq = _integer(paused_session.get("exceptionEventSeq") or paused_session.get("eventSeq"))
    stale = (
        bridge.ContinueException(
            disposition="pass", expected_event_seq=event_seq - 1, resume=False
        )
        if event_seq > 1
        else {"ok": False, "errorCode": "EVENT_IDENTITY_UNAVAILABLE"}
    )
    stale_code = str(
        stale.get("errorCode") or stale.get("code") or ""
    ).casefold() if isinstance(stale, dict) else ""
    stale_rejected_ok = bool(
        isinstance(stale, dict)
        and stale.get("ok") is False
        and stale_code
        in {
            "stale_event",
            "stale_exception_event",
            "stale_mutation_guard",
        }
    )
    first = (
        bridge.ContinueException(
            disposition="pass", expected_event_seq=event_seq, resume=False
        )
        if event_seq > 0 and stale_rejected_ok
        else {"ok": False, "errorCode": "EVENT_IDENTITY_UNAVAILABLE"}
    )
    duplicate = (
        bridge.ContinueException(
            disposition="pass", expected_event_seq=event_seq, resume=False
        )
        if event_seq > 0
        else {"ok": False, "errorCode": "EVENT_IDENTITY_UNAVAILABLE"}
    )
    duplicate_code = str(
        duplicate.get("errorCode") or duplicate.get("code") or ""
    ).casefold() if isinstance(duplicate, dict) else ""
    exactly_once_ok = bool(
        isinstance(first, dict)
        and first.get("ok") is True
        and isinstance(duplicate, dict)
        and duplicate.get("ok") is False
        and duplicate_code == "exception_already_claimed"
    )
    history = bridge.GetExceptionHistory(after_seq=0, limit=256) if baseline.get("ok") else {}
    contract = _history_contract(
        history,
        expected_codes=[_FIXTURE_EXCEPTION_EXACT],
        expected_session_id=str(launch.get("sessionId") or ""),
        expected_generation=_integer(launch.get("generation")),
        expected_process_id=_integer(launch.get("processId")),
    )
    record = contract["records"][0] if len(contract["records"]) == 1 else {}
    manual_history_ok = bool(
        record.get("firstChance") is True
        and record.get("action") == "pause"
        and record.get("autoContinue") is False
        and record.get("continuationClaimed") is True
        and record.get("commandSubmitted") is True
        and record.get("dispositionSubmitted") is True
        and record.get("resumeRequested") is False
        and record.get("resumeSubmitted") is False
        and record.get("command") == "con 1"
        and record.get("continuationSource") == "manual"
        and record.get("status") == "disposition_applied"
        and record.get("disposition") == "not_handled"
        and record.get("requestedDisposition") == "not_handled"
        and record.get("appliedDisposition") == "not_handled"
        and record.get("outcome") == "applied"
    )
    history_clear = (
        bridge.ClearExceptionHistory()
        if exactly_once_ok and contract.get("ok") and manual_history_ok
        else {"ok": False}
    )
    history_after_clear = (
        bridge.GetExceptionHistory(after_seq=0, limit=256)
        if isinstance(history_clear, dict) and history_clear.get("ok") is True
        else {}
    )
    history_clear_ok = bool(
        isinstance(history_clear, dict)
        and history_clear.get("ok") is True
        and _integer(history_clear.get("cleared")) >= 1
        and isinstance(history_after_clear, dict)
        and history_after_clear.get("ok") is True
        and _history_records(history_after_clear) == []
    )
    resume = bridge.DebugRun() if history_clear_ok else {"ok": False}
    exited = bridge.WaitForExit(timeout_ms=15000, poll_ms=100) if history_clear_ok else {}
    first_session_id = str(launch.get("sessionId") or "")
    first_generation = _integer(launch.get("generation"))
    observed_exit = _exit_code(exited)

    relaunch = _launch_exception_fixture(bridge, exe_path, "handled")
    fresh_policy = bridge.GetExceptionPolicy() if relaunch.get("ok") else {}
    fresh_history = (
        bridge.GetExceptionHistory(after_seq=0, limit=256) if relaunch.get("ok") else {}
    )
    fresh_snapshot = _policy_snapshot(fresh_policy)
    fresh_policy_meta = _exception_meta_contract(
        fresh_policy,
        expected_session_id=str(relaunch.get("sessionId") or ""),
        expected_generation=_integer(relaunch.get("generation")),
    )
    fresh_history_meta = _exception_meta_contract(
        fresh_history,
        expected_session_id=str(relaunch.get("sessionId") or ""),
        expected_generation=_integer(relaunch.get("generation")),
    )
    fresh_records = _history_records(fresh_history)
    fresh_history_isolated = all(
        str(record.get("exceptionCode") or "").casefold() == "0x80000003"
        and str(record.get("source") or "").casefold() == "policy_disabled"
        and str(record.get("sessionId") or "")
        == str(relaunch.get("sessionId") or "")
        for record in fresh_records
    )
    relaunch_isolated = bool(
        relaunch.get("ok")
        and str(relaunch.get("sessionId") or "")
        and str(relaunch.get("sessionId") or "") != first_session_id
        and _integer(relaunch.get("generation")) > first_generation
        and isinstance(fresh_policy, dict)
        and fresh_policy.get("ok") is True
        and fresh_snapshot.get("enabled") is False
        and list(fresh_snapshot.get("rules") or []) == []
        and fresh_snapshot.get("firstChanceDefault") == "pause"
        and fresh_snapshot.get("secondChanceDefault") == "pause"
        and fresh_policy_meta.get("ok")
        and isinstance(fresh_history, dict)
        and fresh_history.get("ok") is True
        and fresh_history_meta.get("ok")
        and fresh_history_isolated
    )
    seeded_policy = _set_exception_rules(
        bridge,
        [
            {
                "ruleId": "clear-me",
                "code": "0xe0424242",
                "chance": "first",
                "action": "pause",
            }
        ],
    ) if relaunch_isolated else {"ok": False}
    seed_run = (
        bridge.DebugRun()
        if isinstance(seeded_policy, dict) and seeded_policy.get("ok") is True
        else {"ok": False}
    )
    seed_pause = (
        bridge.WaitForPause(timeout_ms=15000, poll_ms=100)
        if isinstance(seeded_policy, dict) and seeded_policy.get("ok") is True
        else {}
    )
    seeded_history = (
        bridge.GetExceptionHistory(after_seq=0, limit=256)
        if isinstance(seed_pause, dict) and seed_pause.get("paused") is True
        else {}
    )
    seeded_contract = _history_contract(
        seeded_history,
        expected_codes=[_FIXTURE_EXCEPTION_EXACT],
        expected_session_id=str(relaunch.get("sessionId") or ""),
        expected_generation=_integer(relaunch.get("generation")),
        expected_process_id=_integer(relaunch.get("processId")),
    )
    seeded_record = (
        seeded_contract["records"][0]
        if len(seeded_contract.get("records") or []) == 1
        else {}
    )
    seeded_nonempty_ok = bool(
        isinstance(seed_pause, dict)
        and seed_pause.get("paused") is True
        and seeded_contract.get("ok")
        and seeded_record.get("ruleId") == "clear-me"
        and seeded_record.get("action") == "pause"
        and seeded_record.get("continuationSource") == "none"
        and seeded_record.get("outcome") == "paused"
    )
    cleared_policy = (
        bridge.ClearExceptionPolicy(clear_history=True)
        if seeded_nonempty_ok
        else {"ok": False}
    )
    post_clear_policy = (
        bridge.GetExceptionPolicy()
        if isinstance(cleared_policy, dict) and cleared_policy.get("ok") is True
        else {}
    )
    post_clear_history = (
        bridge.GetExceptionHistory(after_seq=0, limit=256)
        if isinstance(cleared_policy, dict) and cleared_policy.get("ok") is True
        else {}
    )
    post_clear_snapshot = _policy_snapshot(post_clear_policy)
    explicit_clear_ok = bool(
        isinstance(cleared_policy, dict)
        and cleared_policy.get("ok") is True
        and _integer(cleared_policy.get("historyCleared")) >= 1
        and isinstance(post_clear_policy, dict)
        and post_clear_policy.get("ok") is True
        and post_clear_snapshot.get("enabled") is False
        and list(post_clear_snapshot.get("rules") or []) == []
        and isinstance(post_clear_history, dict)
        and post_clear_history.get("ok") is True
        and _history_records(post_clear_history) == []
    )
    ok = bool(
        launch.get("ok")
        and isinstance(policy, dict)
        and policy.get("ok") is True
        and baseline.get("ok")
        and isinstance(paused, dict)
        and paused.get("paused") is True
        and stale_rejected_ok
        and exactly_once_ok
        and history_clear_ok
        and isinstance(exited, dict)
        and exited.get("exited") is True
        and observed_exit == 0
        and contract.get("ok")
        and manual_history_ok
        and relaunch_isolated
        and explicit_clear_ok
    )
    return {
        "ok": ok,
        "launch": launch,
        "policy": policy,
        "baseline": baseline,
        "runToException": run_to_exception,
        "pause": paused,
        "eventSeq": event_seq,
        "staleDisposition": stale,
        "staleRejectedOk": stale_rejected_ok,
        "firstManualDisposition": first,
        "duplicateManualDisposition": duplicate,
        "exactlyOnceOk": exactly_once_ok,
        "resume": resume,
        "exit": exited,
        "observedExitCode": observed_exit,
        "history": history,
        "historyContract": contract,
        "manualHistoryOk": manual_history_ok,
        "historyClear": history_clear,
        "historyAfterClear": history_after_clear,
        "historyClearOk": history_clear_ok,
        "relaunch": relaunch,
        "freshPolicy": fresh_policy,
        "freshHistory": fresh_history,
        "freshPolicyMeta": fresh_policy_meta,
        "freshHistoryMeta": fresh_history_meta,
        "relaunchIsolated": relaunch_isolated,
        "seededPolicy": seeded_policy,
        "seedRun": seed_run,
        "seedPause": seed_pause,
        "seededHistory": seeded_history,
        "seededHistoryContract": seeded_contract,
        "seededNonemptyOk": seeded_nonempty_ok,
        "clearPolicy": cleared_policy,
        "postClearPolicy": post_clear_policy,
        "postClearHistory": post_clear_history,
        "explicitClearOk": explicit_clear_ok,
        "error": None if ok else "Exception policy/history lifecycle contract failed.",
    }


def _run_heap_resource_trace_adapter(
    bridge: Any,
    exe_path: str,
    artifact_dir: Path,
    arch: str,
    *,
    resource_matrix: bool = False,
) -> dict[str, Any]:
    del artifact_dir
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
        arguments=["--resource-matrix"] if resource_matrix else [],
    )
    entry = (
        {
            "ok": True,
            "skipped": True,
            "reason": "resource matrix uses an exported post-loader anchor",
        }
        if init.get("ok") and resource_matrix
        else bridge.RunUntil(target="entry", timeout_ms=10000, poll_ms=100)
        if init.get("ok")
        else {"ok": False, "error": "InitDebuggee failed"}
    )
    module = _main_module_record(bridge, exe_path) if entry.get("ok") else {}
    module_name = str(module.get("name") or Path(exe_path).name)
    capture = (
        bridge.CaptureSymbolicBreakpoint(
            target=(
                f"{module_name}!fixture_resource_matrix"
                if resource_matrix
                else f"{module_name}!fixture_heap_alloc"
            ),
            timeout_ms=30000 if resource_matrix else 15000,
            delete_after_hit=True,
            resume=True,
            source="release-matrix",
            symbol_name=(
                "fixture_resource_matrix"
                if resource_matrix
                else "fixture_heap_alloc"
            ),
        )
        if entry.get("ok")
        else {"ok": False, "error": "entry failed"}
    )
    start = (
        bridge.StartHeapTrace(
            label=(
                "heap-resource-family-matrix-live"
                if resource_matrix
                else "heap-resource-lifecycle-live"
            ),
            families_json=json.dumps(
                (
                    ["win32_heap", "crt", "virtual_memory", "com_task",
                     "local_memory", "global_memory", "cpp"]
                    if resource_matrix
                    else
                    ["win32_heap", "nt_heap", "crt", "virtual_memory",
                     "com_task", "local_memory", "global_memory", "cpp"]
                )
            ),
            min_allocation_size=1,
            # The fixture deliberately allocates 32/64/96/80 bytes.  A
            # larger CRT/stdio buffer is incidental to its checkpoint output
            # and must not become a false leak in the lifecycle oracle.
            max_allocation_size=512,
            # This fixture has a bounded, preloaded target set. Avoid spending
            # the trace loop enumerating every loaded module while a secondary
            # thread is waiting to exercise cross-thread ownership.
            subscribe_modules=not resource_matrix,
        )
        if capture.get("ok")
        else {"ok": False, "error": "fixture allocator entry was not captured"}
    )
    heap_trace_id = str(start.get("heapTraceId") or "")
    # Win32 HeapAlloc/CRT/new are commonly inlined or forwarded to
    # RtlAllocateHeap by the platform runtime.  The matrix oracle therefore
    # asserts the four stable direct families and keeps the underlying
    # HeapAlloc lifecycle covered by the dedicated base case.
    expected_allocations = 5 if resource_matrix else 3
    expected_reallocations = 3 if resource_matrix else 1
    expected_frees = 5 if resource_matrix else 3
    expected_anomalies = 1 if resource_matrix else 0
    run = (
        bridge.RunHeapTrace(
            heap_trace_id,
            timeout_ms=160000 if resource_matrix else 45000,
            expected_allocations=expected_allocations,
            expected_reallocations=expected_reallocations,
            expected_frees=expected_frees,
            expected_anomalies=expected_anomalies,
            stop_when_live_zero=True,
            require_complete=True,
            # One logical call per wait keeps the native return-hook drain
            # boundary deterministic; batching can leave a wrapper return
            # paused after the lifecycle oracle is already satisfied.
            calls_per_iteration=1,
            max_logical_events=64,
            stop_on_complete=True,
        )
        if heap_trace_id
        else {"ok": False, "error": "heap trace identity missing"}
    )
    state = (
        bridge.GetHeapState(heap_trace_id)
        if heap_trace_id
        else {"ok": False}
    )
    stop = run.get("stop") if isinstance(run, dict) else None
    api_trace_id = str(start.get("apiTraceId") or "")
    if not isinstance(stop, dict):
        stop = (
            bridge.StopApiTrace(api_trace_id, delete_breakpoints=True)
            if api_trace_id
            else {"ok": False, "error": "missing api trace identity"}
        )
    expected_sizes = (
        [128, 160, 24, 48, 80, 40, 64, 96]
        if resource_matrix
        else [32, 64, 96, 80]
    )
    observed_sizes = [
        int(item.get("sizeDecimal") or item.get("requestedSize") or 0)
        for item in list(state.get("events") or [])
        if isinstance(item, dict)
        and item.get("op") in {"alloc", "realloc"}
    ]
    statuses = [
        str(item.get("status") or "")
        for item in list(state.get("events") or [])
        if isinstance(item, dict)
    ]
    realloc_events = [
        item for item in list(state.get("recentReallocations") or [])
        if isinstance(item, dict)
    ]
    free_events = [
        item for item in list(state.get("recentFrees") or [])
        if isinstance(item, dict)
    ]
    tracked_free_events = [
        item for item in free_events
        if item.get("status") == "freed" and item.get("wasKnown") is True
    ]
    lineage_ok = bool(
        realloc_events
        and realloc_events[-1].get("parentAllocationId")
        and realloc_events[-1].get("oldAddr")
        and realloc_events[-1].get("newAddr")
        and (
            resource_matrix
            or int(realloc_events[-1].get("requestedSize") or 0) == 80
        )
    )
    lifecycle_ok = bool(
        state.get("ok")
        and state.get("schema") == "heap-resource-lifecycle-v2"
        and int(state.get("allocCount") or 0) == expected_allocations
        and int(state.get("reallocCount") or 0) == expected_reallocations
        and int(state.get("freeCount") or 0) == expected_frees
        and int(state.get("liveAllocations") or 0) == 0
        and int(state.get("leakCount") or 0) == 0
        and int(state.get("failedOperationCount") or 0) == 0
        and int(sum((state.get("anomalyCounts") or {}).values()))
        == expected_anomalies
        and state.get("evidenceComplete") is True
        and len(tracked_free_events) >= expected_frees
        and lineage_ok
        and all(
            item.get("status") == "freed"
            for item in tracked_free_events[-expected_frees:]
        )
    )
    family_calls = state.get("familyCalls") if isinstance(state, dict) else {}
    def _family_call_count(value: Any) -> int:
        if isinstance(value, dict):
            for key in ("calls", "count", "total"):
                if key in value:
                    try:
                        return int(value.get(key) or 0)
                    except (TypeError, ValueError):
                        return 0
            total = 0
            for item in value.values():
                try:
                    total += int(item or 0)
                except (TypeError, ValueError):
                    continue
            return total
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0
    observed_families = {
        str(key)
        for key, value in (family_calls or {}).items()
        if _family_call_count(value) > 0
    }
    required_families = (
        {
            "virtual_memory",
            "local_memory",
            "global_memory",
            "com_task",
        }
        if resource_matrix
        else set()
    )
    family_matrix_ok = bool(
        not resource_matrix
        or required_families.issubset(observed_families)
        and int((state.get("anomalyCounts") or {}).get("cross_thread_free") or 0) >= 1
    )
    ok = bool(
        init.get("ok")
        and entry.get("ok")
        and capture.get("ok")
        and start.get("ok")
        and run.get("ok")
        and lifecycle_ok
        and family_matrix_ok
        and stop.get("ok")
        and not (stop.get("breakpointRemovalFailures") or [])
    )
    return {
        "ok": ok,
        "arch": arch,
        "init": init,
        "entry": entry,
        "module": module,
        "capture": capture,
        "start": start,
        "run": run,
        "state": state,
        "stop": stop,
        "expectedSizes": expected_sizes,
        "observedSizes": observed_sizes,
        "eventStatuses": statuses,
        "lineageOk": lineage_ok,
        "lifecycleOk": lifecycle_ok,
        "resourceMatrix": resource_matrix,
        "observedFamilies": sorted(observed_families),
        "familyMatrixOk": family_matrix_ok,
        "error": None if ok else "Full heap/resource lifecycle oracle failed.",
    }


def _run_api_trace_exception_unwind_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir, arch
    launch = _launch_exception_fixture(bridge, exe_path, "unhandled")
    policy = (
        _set_exception_rules(
            bridge,
            [],
            first_default="not_handled",
            second_default="pause",
        )
        if launch.get("ok")
        else {"ok": False, "error": "launch failed"}
    )
    baseline = (
        _clear_exception_history_baseline(bridge)
        if policy.get("ok") is True
        else {"ok": False, "error": "policy failed"}
    )
    started = (
        bridge.StartApiTrace(
            modules_json=json.dumps(["kernelbase.dll"]),
            filter_json=json.dumps(["raiseexception"]),
            arg_count=4,
            label="exception-unwind-live",
            max_targets=16,
            capture_returns=True,
            capture_callstack=False,
            max_out_bytes=0,
            subscribe_modules=False,
            discover_dynamic_resolvers=False,
        )
        if baseline.get("ok")
        else {"ok": False, "error": "baseline failed"}
    )
    trace_id = str(started.get("traceId") or "")
    run = (
        bridge.RunApiTrace(
            trace_id,
            timeout_ms=30000,
            max_calls=2,
            drain_returns=True,
        )
        if trace_id
        else {"ok": False, "error": "trace identity missing"}
    )
    native_before = (
        bridge.GetNativeApiTraceEvidence(trace_id, after_seq=0, limit=200)
        if trace_id
        else {"ok": False}
    )
    paused = bridge.GetDebugState() if trace_id else {"ok": False}
    paused_session = _session_payload(paused)
    event_seq = _integer(
        paused.get("eventSeq")
        if isinstance(paused, dict)
        else 0
    )
    if event_seq <= 0:
        event_seq = _integer(
            paused_session.get("exceptionEventSeq")
            or paused_session.get("eventSeq")
        )
    paused_state = str(
        paused_session.get("state")
        or paused.get("state")
        or ""
    ).casefold()
    continued = (
        bridge.ContinueException(
            disposition="pass",
            expected_event_seq=event_seq,
            resume=True,
        )
        if event_seq > 0 and paused_state not in {"exited", "not_debugging"}
        else {
            "ok": paused_state in {"exited", "not_debugging"},
            "skipped": True,
            "reason": "second-chance disposition already completed",
        }
    )
    exited = bridge.WaitForExit(timeout_ms=15000, poll_ms=100)
    native_after = (
        bridge.GetNativeApiTraceEvidence(trace_id, after_seq=0, limit=200)
        if trace_id
        else {"ok": False}
    )
    stop = (
        bridge.StopApiTrace(trace_id, delete_breakpoints=True)
        if trace_id
        else {"ok": False}
    )
    events = (
        native_after.get("events", [])
        if isinstance(native_after, dict)
        else []
    )
    exception_events = [
        item for item in events if isinstance(item, dict)
        and item.get("kind") in {"exception", "exception_unwind"}
    ]
    entry_events = [
        item for item in events if isinstance(item, dict)
        and item.get("kind") == "entry"
    ]
    first_chance_events = [
        item for item in exception_events
        if item.get("kind") == "exception"
        and item.get("exceptionFirstChance") is True
    ]
    unwind_events = [
        item for item in exception_events
        if item.get("kind") == "exception_unwind"
        and item.get("exceptionFirstChance") is False
    ]
    native_unwound = int(
        (native_after.get("exceptionUnwoundPendingCalls") or 0)
        if isinstance(native_after, dict)
        else 0
    )
    native_return_hooks_ok = bool(
        started.get("nativeReturnHooks") is True
        and native_after.get("nativeReturnHooks") is True
        and int(native_after.get("returnHooksInstalled") or 0) >= 1
        and int(native_after.get("returnHooksRemoved") or 0) >= 1
        and int(native_after.get("returnHookFailures") or 0) == 0
        and not (native_after.get("ownedReturnBreakpoints") or [])
    )
    ok = bool(
        launch.get("ok")
        and policy.get("ok") is True
        and baseline.get("ok")
        and started.get("ok")
        and run.get("ok")
        and entry_events
        and first_chance_events
        and unwind_events
        and all(
            _uint32(item.get("exceptionCode"))
            == _FIXTURE_EXCEPTION_EXACT
            for item in exception_events
        )
        and native_unwound >= 1
        and native_return_hooks_ok
        and continued.get("ok") is True
        and isinstance(exited, dict)
        and exited.get("exited") is True
        and _exit_code(exited) == 99
        and stop.get("ok") is True
        and not (stop.get("breakpointRemovalFailures") or [])
    )
    return {
        "ok": ok,
        "launch": launch,
        "policy": policy,
        "baseline": baseline,
        "start": started,
        "run": run,
        "paused": paused,
        "continued": continued,
        "exit": exited,
        "nativeBefore": native_before,
        "nativeAfter": native_after,
        "entryCount": len(entry_events),
        "firstChanceCount": len(first_chance_events),
        "unwindCount": len(unwind_events),
        "exceptionUnwoundPendingCalls": native_unwound,
        "nativeReturnHooksOk": native_return_hooks_ok,
        "stop": stop,
        "error": None if ok else "Native API exception-unwind contract failed.",
    }


def _run_api_trace_managed_exception_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir, arch
    launch = _launch_exception_fixture(bridge, exe_path, "managed")
    policy = (
        _set_exception_rules(
            bridge,
            [],
            first_default="not_handled",
            second_default="pause",
        )
        if launch.get("ok")
        else {"ok": False, "error": "launch failed"}
    )
    baseline = (
        _clear_exception_history_baseline(bridge)
        if policy.get("ok") is True
        else {"ok": False, "error": "policy failed"}
    )
    started = (
        bridge.StartApiTrace(
            modules_json=json.dumps(["kernelbase.dll"]),
            filter_json=json.dumps(["raiseexception"]),
            arg_count=4,
            label="managed-exception-live",
            max_targets=8,
            capture_returns=True,
            capture_callstack=False,
            max_out_bytes=0,
            subscribe_modules=False,
            discover_dynamic_resolvers=False,
        )
        if baseline.get("ok")
        else {"ok": False, "error": "baseline failed"}
    )
    trace_id = str(started.get("traceId") or "")
    run = (
        bridge.RunApiTrace(
            trace_id,
            timeout_ms=30000,
            max_calls=1,
            drain_returns=True,
        )
        if trace_id
        else {"ok": False, "error": "trace identity missing"}
    )
    paused = bridge.GetDebugState() if trace_id else {"ok": False}
    paused_session = _session_payload(paused)
    event_seq = _integer(
        paused.get("eventSeq")
        if isinstance(paused, dict)
        else 0
    )
    if event_seq <= 0:
        event_seq = _integer(
            paused_session.get("exceptionEventSeq")
            or paused_session.get("eventSeq")
        )
    paused_state = str(
        paused_session.get("state")
        or paused.get("state")
        or ""
    ).casefold()
    continued = (
        bridge.ContinueException(
            disposition="pass",
            expected_event_seq=event_seq,
            resume=True,
        )
        if event_seq > 0
        and paused_state not in {"exited", "not_debugging"}
        else {"ok": True, "skipped": True}
    )
    exited = bridge.WaitForExit(timeout_ms=15000, poll_ms=100)
    native = (
        bridge.GetNativeApiTraceEvidence(trace_id, after_seq=0, limit=200)
        if trace_id
        else {"ok": False}
    )
    stop = (
        bridge.StopApiTrace(trace_id, delete_breakpoints=True)
        if trace_id
        else {"ok": False}
    )
    events = native.get("events", []) if isinstance(native, dict) else []
    managed_events = [
        item for item in events
        if isinstance(item, dict) and item.get("managedException") is True
    ]
    managed_exception_events = [
        item for item in managed_events
        if item.get("kind") in {"exception", "exception_unwind"}
    ]
    hresult_ok = any(
        _uint32(item.get("managedHResult")) == 0x80131500
        for item in managed_exception_events
    )
    params_ok = any(
        any(_uint32(value) == 0x80131500 for value in (item.get("exceptionParameters") or []))
        and len(item.get("exceptionParameters") or []) >= 2
        for item in managed_exception_events
    )
    managed_correlation_ok = bool(
        managed_exception_events
        and hresult_ok
        and params_ok
        and all(int(item.get("callId") or 0) > 0 for item in managed_exception_events)
    )
    ok = bool(
        launch.get("ok")
        and policy.get("ok") is True
        and baseline.get("ok")
        and started.get("ok")
        and run.get("ok")
        and managed_correlation_ok
        and continued.get("ok") is True
        and isinstance(exited, dict)
        and exited.get("exited") is True
        and _exit_code(exited) == 0
        and stop.get("ok") is True
        and not (stop.get("breakpointRemovalFailures") or [])
    )
    return {
        "ok": ok,
        "launch": launch,
        "policy": policy,
        "baseline": baseline,
        "start": started,
        "run": run,
        "paused": paused,
        "continued": continued,
        "exit": exited,
        "native": native,
        "managedEventCount": len(managed_exception_events),
        "managedCorrelationOk": managed_correlation_ok,
        "managedRuntimeValues": sorted(
            {
                str(item.get("managedRuntime") or "")
                for item in managed_exception_events
            }
        ),
        "stop": stop,
        "error": None if ok else "Managed exception correlation contract failed.",
    }


def _run_real_managed_exception_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    static = bridge.InspectManagedAssembly(
        path=exe_path,
        include_il=True,
        max_types=1000,
        max_methods=5000,
    )
    main_methods = [
        item
        for item in (static.get("methods", []) if isinstance(static, dict) else [])
        if isinstance(item, dict)
        and str(item.get("name") or "") == "Main"
        and str(item.get("token") or "") == "0x06000001"
        and item.get("hasBody") is True
    ]
    static_ok = bool(
        isinstance(static, dict)
        and static.get("ok") is True
        and static.get("isManaged") is True
        and str((static.get("runtime") or {}).get("executionArchitecture") or "") == arch
        and len(main_methods) == 1
        and str(main_methods[0].get("ilSha256") or "")
    )
    token = (
        bridge.ResolveManagedToken("0x06000001", path=exe_path)
        if static_ok
        else {"ok": False, "error": "static managed inspection failed"}
    )
    artifact_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = artifact_dir / "managed-evidence.json"
    evidence = (
        bridge.ExportManagedEvidence(
            output_path=str(evidence_path),
            path=exe_path,
            overwrite=True,
            include_il=True,
        )
        if static_ok
        else {"ok": False, "error": "static managed inspection failed"}
    )
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
        arguments=[],
    )
    runtime_state = (
        bridge.GetManagedRuntimeState()
        if init.get("ok")
        else {"ok": False, "error": "InitDebuggee failed"}
    )
    policy = (
        _set_exception_rules(
            bridge,
            [],
            first_default="not_handled",
            # CLR startup intentionally probes guarded runtime paths with
            # exceptions before managed user code exists. Let the runtime own
            # both chances; the fixture catches its target managed exception.
            second_default="not_handled",
        )
        if init.get("ok")
        else {"ok": False, "error": "InitDebuggee failed"}
    )
    baseline = (
        _clear_exception_history_baseline(bridge)
        if policy.get("ok") is True
        else {"ok": False, "error": "policy failed"}
    )
    # A managed PE entry is the CLR bootstrap thunk, not the managed Main.
    # Install the native RaiseException trace while the process is still at
    # its deterministic initial pause, before clr.dll starts executing.
    entry = {
        "ok": baseline.get("ok") is True,
        "skipped": True,
        "reason": "managed PE uses the CLR bootstrap entrypoint",
    }
    started = (
        bridge.StartApiTrace(
            modules_json=json.dumps(["kernelbase.dll"]),
            filter_json=json.dumps(["raiseexception"]),
            arg_count=4,
            label="real-managed-exception-live",
            max_targets=8,
            capture_returns=True,
            capture_callstack=False,
            max_out_bytes=0,
            subscribe_modules=False,
            discover_dynamic_resolvers=False,
        )
        if baseline.get("ok")
        else {"ok": False, "error": "exception baseline failed"}
    )
    trace_id = str(started.get("traceId") or "")
    run = (
        bridge.RunApiTrace(
            trace_id,
            timeout_ms=60000,
            max_calls=64,
            drain_returns=True,
        )
        if trace_id
        else {"ok": False, "error": "trace identity missing"}
    )
    exited = bridge.WaitForExit(timeout_ms=20000, poll_ms=100)
    native = (
        bridge.GetNativeApiTraceEvidence(trace_id, after_seq=0, limit=300)
        if trace_id
        else {"ok": False}
    )
    managed_history = (
        bridge.GetManagedExceptionHistory(trace_id, after_seq=0, limit=300)
        if trace_id
        else {"ok": False}
    )
    stop = (
        bridge.StopApiTrace(trace_id, delete_breakpoints=True)
        if trace_id
        else {"ok": False}
    )
    events = native.get("events", []) if isinstance(native, dict) else []
    managed_events = [
        item for item in events
        if isinstance(item, dict)
        and item.get("managedException") is True
        and item.get("kind") == "exception"
    ]
    runtime_values = {
        str(item.get("managedRuntime") or "")
        for item in managed_events
    }
    managed_correlation_ok = bool(
        managed_events
        and runtime_values.intersection({"clr", "coreclr"})
        and any(_uint32(item.get("managedHResult")) == 0x80131509 for item in managed_events)
        and all(int(item.get("callId") or 0) > 0 for item in managed_events)
        and all(len(item.get("exceptionParameters") or []) >= 2 for item in managed_events)
    )
    history_events = (
        managed_history.get("events", [])
        if isinstance(managed_history, dict)
        else []
    )
    history_ok = bool(
        managed_history.get("ok") is True
        and len(history_events) == len(managed_events)
        and any(_uint32(item.get("managedHResult")) == 0x80131509 for item in history_events)
    )
    standalone = subprocess.run(
        [exe_path],
        cwd=str(Path(exe_path).parent),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
        creationflags=0x08000000 if os.name == "nt" else 0,
    )
    standalone_ok = bool(
        standalone.returncode == 0
        and "MANAGED_CLR_OK type=System.InvalidOperationException" in standalone.stdout
        and "hresult=0x80131509" in standalone.stdout.casefold()
    )
    ok = bool(
        static_ok
        and token.get("ok") is True
        and token.get("jitNativeAddress") is None
        and token.get("jitMappingSupported") is False
        and evidence.get("ok") is True
        and evidence_path.is_file()
        and init.get("ok")
        and runtime_state.get("ok") is True
        and runtime_state.get("isManaged") is True
        and entry.get("ok")
        and policy.get("ok") is True
        and started.get("ok")
        and run.get("ok")
        and managed_correlation_ok
        and history_ok
        and standalone_ok
        and isinstance(exited, dict)
        and exited.get("exited") is True
        and _exit_code(exited) == 0
        and stop.get("ok") is True
        and not (stop.get("breakpointRemovalFailures") or [])
    )
    return {
        "ok": ok,
        "static": static,
        "staticOk": static_ok,
        "token": token,
        "evidence": evidence,
        "evidencePath": str(evidence_path),
        "init": init,
        "runtimeState": runtime_state,
        "entry": entry,
        "policy": policy,
        "baseline": baseline,
        "start": started,
        "run": run,
        "exit": exited,
        "native": native,
        "managedHistory": managed_history,
        "managedHistoryOk": history_ok,
        "managedEventCount": len(managed_events),
        "managedCorrelationOk": managed_correlation_ok,
        "managedRuntimeValues": sorted(runtime_values),
        "standalone": {
            "ok": standalone_ok,
            "exitCode": standalone.returncode & 0xFFFFFFFF,
            "stdout": standalone.stdout,
            "stderr": standalone.stderr,
        },
        "stop": stop,
        "error": None if ok else "Real managed .NET exception correlation failed.",
    }


def _run_managed_runtime_probe_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    static = bridge.InspectManagedAssembly(path=exe_path, include_il=True)
    work_methods = [
        item
        for item in (static.get("methods", []) if isinstance(static, dict) else [])
        if isinstance(item, dict)
        and item.get("name") == "ManagedWork"
        and item.get("token") == "0x06000001"
        and item.get("hasBody") is True
    ]
    static_ok = bool(
        isinstance(static, dict)
        and static.get("ok") is True
        and static.get("isManaged") is True
        and (static.get("runtime") or {}).get("executionArchitecture") == arch
        and len(work_methods) == 1
    )
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=30000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
        arguments=[],
        stdin={"mode": "pipe", "capacityBytes": 4096},
        stdout={"mode": "pipe"},
        stderr={"mode": "pipe"},
        capture_limit_bytes=65536,
    )
    native = _native_launch_payload(init)
    launch_id = str(native.get("launchId") or "")
    identity = _launch_identity_contract(native, arch)
    policy = (
        _set_exception_rules(
            bridge,
            [],
            first_default="not_handled",
            second_default="not_handled",
        )
        if init.get("ok")
        else {"ok": False, "error": "InitDebuggee failed"}
    )

    marker = b"MANAGED_PROBE_READY tid=1 value=41"
    readfile_capture = (
        bridge.CaptureSymbolicBreakpoint(
            target="kernelbase.dll!ReadFile",
            timeout_ms=30000,
            delete_after_hit=False,
            resume=True,
            source="managed-runtime-probe",
            symbol_name="ReadFile",
        )
        if policy.get("ok") is True and launch_id
        else {"ok": False, "error": "launch/policy failed"}
    )
    readfile_addr = str(readfile_capture.get("resolvedAddr") or "")
    capture_attempts: list[dict[str, Any]] = []
    capture: dict[str, Any] = {"ok": False, "error": "ManagedWork stack was not observed."}
    current_read_hit: Any = readfile_capture
    def _breakpoint_event(payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return {}
        nested = payload.get("event")
        return dict(nested) if isinstance(nested, dict) else payload

    for attempt in range(16):
        current_event = _breakpoint_event(current_read_hit)
        if current_event.get("hit") is not True:
            break
        candidate = bridge.CaptureManagedRuntimeState(
            metadata_token="0x06000001",
            module=Path(exe_path).name,
            pause_if_running=False,
            resume_after=False,
            max_threads=64,
            max_frames=128,
            max_modules=1024,
            max_maps=1024,
            timeout_ms=30000,
        )
        candidate_methods = [
            method
            for resolution in (
                candidate.get("resolutions", [])
                if isinstance(candidate, dict)
                else []
            )
            if isinstance(resolution, dict)
            for method in resolution.get("methods", [])
            if isinstance(method, dict)
            and method.get("metadataToken") == "0x06000001"
            and method.get("name") == "ManagedWork"
        ]
        capture_attempts.append(
            {
                "attempt": attempt + 1,
                "eventSeq": current_event.get("eventSeq"),
                "rip": current_event.get("rip"),
                "ok": candidate.get("ok") if isinstance(candidate, dict) else False,
                "runtimeCount": len(candidate.get("runtimes", []))
                if isinstance(candidate, dict)
                else 0,
                "tokenFound": bool(candidate_methods),
                "errorCode": (
                    candidate.get("errorCode")
                    or (
                        candidate.get("error", {}).get("code")
                        if isinstance(candidate.get("error"), dict)
                        else None
                    )
                )
                if isinstance(candidate, dict)
                else None,
                "error": (
                    candidate.get("error", {}).get("message")
                    if isinstance(candidate.get("error"), dict)
                    else candidate.get("error")
                )
                if isinstance(candidate, dict)
                else None,
            }
        )
        if candidate_methods:
            capture = candidate
            break
        bridge.DebugRun()
        current_read_hit = bridge.WaitForBreakpointDetailed(
            addr=readfile_addr,
            timeout_ms=15000,
            poll_ms=50,
        )

    paused = bridge.GetDebugStateLean()
    pause = {
        "ok": bool(isinstance(paused, dict) and paused.get("paused")),
        "skipped": True,
        "reason": "persistent ReadFile breakpoint produced a coherent pause",
    }
    initial_stream = (
        bridge.ReadLaunchStream(
            launch_id,
            stream="stdout",
            cursor=0,
            max_bytes=4096,
            wait_ms=0,
        )
        if launch_id
        else {"ok": False}
    )
    initial_bytes = b""
    if isinstance(initial_stream, dict) and initial_stream.get("ok") is True:
        initial_bytes = base64.b64decode(
            str(initial_stream.get("dataBase64") or "").encode("ascii"),
            validate=True,
        )
    marker_seen = marker in initial_bytes
    runtime_state = (
        bridge.GetManagedRuntimeState()
        if isinstance(paused, dict) and paused.get("paused")
        else {"ok": False, "error": "managed fixture was not paused"}
    )
    readfile_delete = (
        bridge.DebugDeleteBreakpoint(readfile_addr)
        if readfile_addr and capture.get("ok") is True
        else {"ok": False, "skipped": True}
    )
    resolutions = [
        item
        for item in (capture.get("resolutions", []) if isinstance(capture, dict) else [])
        if isinstance(item, dict)
    ]
    resolved_methods = [
        method
        for resolution in resolutions
        for method in resolution.get("methods", [])
        if isinstance(method, dict)
    ]
    exact_methods = [
        method
        for method in resolved_methods
        if method.get("metadataToken") == "0x06000001"
        and method.get("name") == "ManagedWork"
        and str(method.get("compilationType") or "") in {"Jit", "Ngen"}
        and _integer(method.get("nativeCode")) > 0
        and _integer(method.get("ilToNativeMapCount")) > 0
    ]
    runtime_summary_ok = bool(
        capture.get("ok") is True
        and capture.get("identityVerified") is True
        and len(capture.get("runtimes", [])) == 1
        and len(exact_methods) == 1
        and any(
            _integer((runtime.get("counts") or {}).get("appDomains")) >= 1
            and _integer((runtime.get("counts") or {}).get("threads")) >= 1
            and _integer((runtime.get("counts") or {}).get("activeStackMethods")) >= 2
            for runtime in capture.get("runtimes", [])
            if isinstance(runtime, dict)
        )
    )
    artifact_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = artifact_dir / "managed-runtime-evidence.json"
    if evidence_path.exists():
        evidence_path.unlink()
    evidence = (
        bridge.ExportManagedRuntimeEvidence(
            output_path=str(evidence_path),
            metadata_token="0x06000001",
            module=Path(exe_path).name,
            overwrite=False,
            timeout_ms=45000,
        )
        if runtime_summary_ok
        else {"ok": False, "error": "runtime capture failed"}
    )
    metadata_path = artifact_dir / "managed-dynamic-metadata.json"
    if metadata_path.exists():
        metadata_path.unlink()
    dynamic_metadata = (
        bridge.ExportManagedAssemblyMetadata(
            output_path=str(metadata_path),
            module="ManagedProbeDynamicPayload",
            overwrite=False,
            timeout_ms=45000,
        )
        if runtime_summary_ok
        else {"ok": False, "error": "runtime capture failed"}
    )
    dynamic_metadata_document: dict[str, Any] = {}
    if metadata_path.is_file():
        try:
            loaded_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if isinstance(loaded_metadata, dict):
                dynamic_metadata_document = loaded_metadata
        except Exception:
            dynamic_metadata_document = {}
    metadata_payload = b""
    try:
        metadata_payload = base64.b64decode(
            str((dynamic_metadata_document.get("metadata") or {}).get("base64") or ""),
            validate=True,
        )
    except Exception:
        metadata_payload = b""
    dynamic_metadata_ok = bool(
        dynamic_metadata.get("ok") is True
        and metadata_path.is_file()
        and dynamic_metadata_document.get("schema") == "managed-assembly-metadata-v1"
        and (
            bool((dynamic_metadata_document.get("module") or {}).get("isDynamic"))
            or bool((dynamic_metadata_document.get("module") or {}).get("isMemoryOnly"))
            or not bool((dynamic_metadata_document.get("module") or {}).get("isPeFile"))
        )
        and metadata_payload.startswith(b"BSJB")
        and hashlib.sha256(metadata_payload).hexdigest().upper()
        == str((dynamic_metadata_document.get("metadata") or {}).get("sha256") or "").upper()
    )
    managed_breakpoint = (
        bridge.SetManagedMethodBreakpoint(
            metadata_token="0x06000001",
            module=Path(exe_path).name,
            name="managed-runtime-probe:ManagedWork",
            singleshoot=True,
            timeout_ms=45000,
        )
        if runtime_summary_ok
        else {"ok": False, "error": "runtime capture failed"}
    )
    first_input = (
        bridge.WriteLaunchStdin(
            launch_id,
            base64.b64encode(b"first\n").decode("ascii"),
            wait_ms=1000,
        )
        if managed_breakpoint.get("ok") is True
        else {"ok": False}
    )
    run_to_second = (
        bridge.DebugRun()
        if first_input.get("ok") is True
        else {"ok": False}
    )
    hit = (
        bridge.WaitForBreakpointDetailed(
            addr=str(managed_breakpoint.get("address") or ""),
            name="managed-runtime-probe:ManagedWork",
            timeout_ms=30000,
            poll_ms=50,
        )
        if first_input.get("ok") is True
        else {"ok": False}
    )
    hit_state = hit.get("state") if isinstance(hit, dict) and isinstance(hit.get("state"), dict) else {}
    hit_rip = str(
        hit.get("rip")
        or hit.get("addr")
        or hit_state.get("ip")
        or hit_state.get("address")
        or ""
    ).casefold()
    expected_rip = str(managed_breakpoint.get("address") or "").casefold()
    hit_ok = bool(
        isinstance(hit, dict)
        and hit.get("hit") is True
        and _integer(hit_rip) == _integer(expected_rip)
    )
    second_input = (
        bridge.WriteLaunchStdin(
            launch_id,
            base64.b64encode(b"second\n").decode("ascii"),
            wait_ms=1000,
            close_after_write=True,
        )
        if hit_ok
        else {"ok": False}
    )
    final_run = bridge.DebugRun() if second_input.get("ok") is True else {"ok": False}
    exited = (
        bridge.WaitForExit(timeout_ms=30000, poll_ms=50)
        if second_input.get("ok") is True
        else {"ok": False}
    )
    failure_stop: Any = None
    if not (isinstance(exited, dict) and exited.get("exited") is True):
        if launch_id:
            try:
                bridge.CloseLaunchStdin(launch_id)
            except Exception:
                pass
        try:
            failure_stop = bridge.DebugStop()
            bridge.WaitForExit(timeout_ms=10000, poll_ms=50)
        except Exception:
            pass
    stdout = (
        _drain_launch_stream(
            bridge, launch_id, "stdout", wait_ms=250, max_pages=16
        )
        if launch_id
        else {}
    )
    stderr = (
        _drain_launch_stream(
            bridge, launch_id, "stderr", wait_ms=250, max_pages=16
        )
        if launch_id
        else {}
    )
    stdout_data = stdout.get("data") if isinstance(stdout.get("data"), bytes) else b""
    output_ok = bool(
        stdout.get("ok")
        and stderr.get("ok")
        and marker in stdout_data
        and b"MANAGED_PROBE_READY tid=1 value=99" in stdout_data
        and b"MANAGED_PROBE_RESUME input=first" in stdout_data
        and b"MANAGED_PROBE_RESUME input=second" in stdout_data
        and b"MANAGED_PROBE_OK result=42 second=100" in stdout_data
        and not (stderr.get("data") or b"")
    )
    cleanup = _finish_launch_resources(bridge, launch_id) if launch_id else {}
    stdout.pop("data", None)
    stderr.pop("data", None)
    ok = bool(
        static_ok
        and init.get("ok") is True
        and identity.get("ok")
        and policy.get("ok") is True
        and _breakpoint_event(readfile_capture).get("hit") is True
        and marker_seen
        and isinstance(paused, dict)
        and paused.get("paused") is True
        and runtime_state.get("ok") is True
        and runtime_state.get("isManaged") is True
        and runtime_summary_ok
        and evidence.get("ok") is True
        and evidence_path.is_file()
        and dynamic_metadata_ok
        and managed_breakpoint.get("ok") is True
        and first_input.get("ok") is True
        and hit_ok
        and second_input.get("ok") is True
        and isinstance(exited, dict)
        and exited.get("exited") is True
        and _exit_code(exited) == 0
        and output_ok
        and cleanup.get("ok")
    )
    return {
        "ok": ok,
        "static": static,
        "staticOk": static_ok,
        "init": init,
        "identity": identity,
        "policy": policy,
        "readFileCapture": readfile_capture,
        "readFileAddress": readfile_addr,
        "readFileDelete": readfile_delete,
        "captureAttempts": capture_attempts,
        "initialStream": initial_stream,
        "markerSeen": marker_seen,
        "pause": pause,
        "paused": paused,
        "runtimeState": runtime_state,
        "capture": capture,
        "runtimeSummaryOk": runtime_summary_ok,
        "resolvedMethod": exact_methods[0] if len(exact_methods) == 1 else None,
        "evidence": evidence,
        "evidencePath": str(evidence_path),
        "dynamicMetadata": dynamic_metadata,
        "dynamicMetadataPath": str(metadata_path),
        "dynamicMetadataOk": dynamic_metadata_ok,
        "managedBreakpoint": managed_breakpoint,
        "firstInput": first_input,
        "runToSecond": run_to_second,
        "breakpointHit": hit,
        "breakpointHitOk": hit_ok,
        "secondInput": second_input,
        "finalRun": final_run,
        "exit": exited,
        "failureStop": failure_stop,
        "stdout": stdout,
        "stderr": stderr,
        "outputOk": output_ok,
        "cleanup": cleanup,
        "error": None if ok else "Managed runtime/JIT sidecar contract failed.",
    }


def _run_dynamic_api_trace_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir, arch
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
    )
    entry = (
        bridge.RunUntil(target="entry", timeout_ms=10000, poll_ms=100)
        if init.get("ok")
        else {"ok": False, "error": "InitDebuggee failed"}
    )
    target_module = (
        _main_module_record(bridge, exe_path) if entry.get("ok") else {}
    )
    target_module_name = str(
        target_module.get("name") or Path(exe_path).name
    )
    target_capture = (
        bridge.CaptureSymbolicBreakpoint(
            target=f"{target_module_name}!dynamic_api_target",
            timeout_ms=15000,
            delete_after_hit=True,
            resume=True,
            source="release-matrix",
            symbol_name="dynamic_api_target",
        )
        if entry.get("ok")
        else {"ok": False, "error": "entry stop failed"}
    )
    started = (
        bridge.StartApiTrace(
            modules_json=json.dumps(["kernelbase.dll"]),
            filter_json=json.dumps(["getprocaddress", "getsystemmetrics"]),
            arg_count=6,
            label="dynamic-resolver-live",
            max_targets=64,
            capture_returns=True,
            capture_callstack=False,
            max_out_bytes=0,
            subscribe_modules=False,
            discover_dynamic_resolvers=True,
        )
        if target_capture.get("ok")
        else {"ok": False, "error": "dynamic API target capture failed"}
    )
    trace_id = str(started.get("traceId") or "")
    run = (
        bridge.RunApiTrace(
            trace_id,
            timeout_ms=30000,
            # The fixture makes exactly one resolver call followed by the
            # dynamically subscribed API call.  Stop at that boundary so CRT
            # shutdown/COM loader traffic cannot leave an unrelated system
            # resolver frame pending at the test deadline.
            max_calls=2,
            drain_returns=True,
        )
        if trace_id
        else {"ok": False, "error": "API trace identity missing"}
    )
    log = (
        bridge.GetApiTraceLog(trace_id, offset=0, limit=100)
        if trace_id
        else {"ok": False}
    )
    native = (
        bridge.GetNativeApiTraceEvidence(trace_id, after_seq=0, limit=500)
        if trace_id
        else {"ok": False}
    )
    stop = (
        bridge.StopApiTrace(trace_id, delete_breakpoints=True)
        if trace_id
        else {"ok": False}
    )
    calls = log.get("calls", []) if isinstance(log, dict) else []
    names = [str(item.get("func") or "").casefold() for item in calls]
    resolved_calls = [
        item
        for item in calls
        if str(item.get("func") or "").casefold() == "getsystemmetrics"
    ]
    resolver_calls = [
        item
        for item in calls
        if "getprocaddress" in str(item.get("func") or "").casefold()
    ]
    decoded_return_ok = bool(
        resolver_calls
        and all(
            isinstance(item.get("returnDecoded"), dict)
            and item.get("returnDecoded", {}).get("raw")
            == item.get("returnValue")
            for item in resolver_calls
        )
        and any(
            isinstance(item.get("returnDecoded"), dict)
            and item.get("returnDecoded", {}).get("resolved") is True
            for item in resolver_calls
        )
    )
    subscription_records = [
        item.get("dynamicTargetSubscription")
        for item in resolver_calls
        if isinstance(item.get("dynamicTargetSubscription"), dict)
    ]
    module_init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
    )
    module_entry = (
        bridge.RunUntil(target="entry", timeout_ms=10000, poll_ms=100)
        if module_init.get("ok")
        else {"ok": False, "error": "module subscription InitDebuggee failed"}
    )
    # Late-module mode intentionally starts at entry.  A symbolic capture at
    # dynamic_api_prepare would spend its budget walking TLS callbacks before
    # user code; RunApiTrace already classifies and skips those system stops.
    module_target_capture = {
        "ok": True,
        "skipped": True,
        "reason": "late-module trace starts at entry",
    }
    module_start = (
        bridge.StartApiTrace(
            modules_json=json.dumps(["kernelbase.dll", "user32.dll"]),
            filter_json=json.dumps(["loadlibraryw", "getsystemmetrics"]),
            arg_count=6,
            label="late-module-live",
            max_targets=64,
            capture_returns=True,
            capture_callstack=False,
            max_out_bytes=0,
            subscribe_modules=True,
            discover_dynamic_resolvers=False,
        )
        if module_entry.get("ok")
        else {
            "ok": False,
            "error": "module subscription entry stop failed",
        }
    )
    module_trace_id = str(module_start.get("traceId") or "")
    module_run = (
        bridge.RunApiTrace(
            module_trace_id,
            timeout_ms=30000,
            max_calls=2,
            drain_returns=True,
        )
        if module_trace_id
        else {"ok": False, "error": "module subscription trace identity missing"}
    )
    module_log = (
        bridge.GetApiTraceLog(module_trace_id, offset=0, limit=100)
        if module_trace_id
        else {"ok": False}
    )
    module_native = (
        bridge.GetNativeApiTraceEvidence(
            module_trace_id,
            after_seq=0,
            limit=500,
        )
        if module_trace_id
        else {"ok": False}
    )
    module_stop = (
        bridge.StopApiTrace(module_trace_id, delete_breakpoints=True)
        if module_trace_id
        else {"ok": False}
    )
    module_calls = (
        module_log.get("calls", []) if isinstance(module_log, dict) else []
    )
    module_resolved_calls = [
        item
        for item in module_calls
        if str(item.get("func") or "").casefold() == "getsystemmetrics"
    ]
    module_decoded_return_ok = bool(
        module_calls
        and all(
            isinstance(item.get("returnDecoded"), dict)
            and item.get("returnDecoded", {}).get("raw")
            == item.get("returnValue")
            for item in module_calls
        )
        and any(
            isinstance(item.get("returnDecoded"), dict)
            and item.get("returnDecoded", {}).get("moduleBase")
            for item in module_calls
            if str(item.get("func") or "").casefold().startswith("loadlibrary")
        )
    )
    native_return_hooks_ok = bool(
        started.get("nativeReturnHooks") is True
        and native.get("nativeReturnHooks") is True
        and int(native.get("returnHooksInstalled") or 0) >= 1
        and int(native.get("returnHooksRemoved") or 0) >= 1
        and int(native.get("returnHookFailures") or 0) == 0
        and not (native.get("ownedReturnBreakpoints") or [])
    )
    native_dynamic_entries = [
        item
        for item in (native.get("events") or [])
        if isinstance(item, dict)
        and item.get("kind") == "entry"
        and str(item.get("apiFunction") or "").casefold()
        == "getsystemmetrics"
    ]
    native_dynamic_returns = [
        item
        for item in (native.get("events") or [])
        if isinstance(item, dict)
        and item.get("kind") == "return"
        and str(item.get("apiFunction") or "").casefold()
        == "getsystemmetrics"
        and item.get("matchedReturn") is True
    ]
    native_dynamic_entry_ok = bool(
        native_dynamic_entries and native_dynamic_returns
    )
    module_native_return_hooks_ok = bool(
        module_start.get("nativeReturnHooks") is True
        and module_native.get("nativeReturnHooks") is True
        and int(module_native.get("returnHooksInstalled") or 0) >= 1
        and int(module_native.get("returnHooksRemoved") or 0) >= 1
        and int(module_native.get("returnHookFailures") or 0) == 0
        and not (module_native.get("ownedReturnBreakpoints") or [])
    )
    module_native_events = (
        module_native.get("events") or []
        if isinstance(module_native, dict)
        else []
    )
    module_native_dynamic_entries = [
        item
        for item in module_native_events
        if isinstance(item, dict)
        and item.get("kind") == "entry"
        and str(item.get("apiFunction") or "").casefold()
        == "getsystemmetrics"
    ]
    module_native_dynamic_returns = [
        item
        for item in module_native_events
        if isinstance(item, dict)
        and item.get("kind") == "return"
        and str(item.get("apiFunction") or "").casefold()
        == "getsystemmetrics"
        and item.get("matchedReturn") is True
    ]
    module_native_dynamic_entry_ok = bool(
        module_native_dynamic_entries and module_native_dynamic_returns
    )
    ok = bool(
        init.get("ok")
        and entry.get("ok")
        and target_capture.get("ok")
        and started.get("ok")
        and run.get("ok")
        and int(run.get("dynamicTargetsAdded") or 0) >= 1
        and not int(run.get("subscriptionFailures") or 0)
        and resolver_calls
        and resolved_calls
        and decoded_return_ok
        and any(
            int(item.get("added") or 0) >= 1
            and item.get("source") == "getprocaddress-return"
            for item in subscription_records
        )
        and native.get("ok")
        and native_return_hooks_ok
        and native_dynamic_entry_ok
        and stop.get("ok")
        and not (stop.get("breakpointRemovalFailures") or [])
        and module_init.get("ok")
        and module_entry.get("ok")
        and module_target_capture.get("ok")
        and module_start.get("ok")
        and module_run.get("ok")
        and int(module_run.get("moduleTargetsAdded") or 0) >= 1
        and not int(module_run.get("subscriptionFailures") or 0)
        and module_resolved_calls
        and module_decoded_return_ok
        and module_native.get("ok")
        and module_native_return_hooks_ok
        and module_native_dynamic_entry_ok
        and module_stop.get("ok")
        and not (module_stop.get("breakpointRemovalFailures") or [])
    )
    return {
        "ok": ok,
        "init": init,
        "entry": entry,
        "targetCapture": target_capture,
        "start": started,
        "run": run,
        "log": log,
        "native": native,
        "nativeReturnHooksOk": native_return_hooks_ok,
        "nativeDynamicEntryCount": len(native_dynamic_entries),
        "nativeDynamicReturnCount": len(native_dynamic_returns),
        "nativeDynamicEntryOk": native_dynamic_entry_ok,
        "stop": stop,
        "callNames": names,
        "resolverCallCount": len(resolver_calls),
        "resolvedCallCount": len(resolved_calls),
        "decodedReturnOk": decoded_return_ok,
        "subscriptionRecords": subscription_records,
        "moduleSubscription": {
            "init": module_init,
            "entry": module_entry,
            "targetCapture": module_target_capture,
            "start": module_start,
            "run": module_run,
            "log": module_log,
            "native": module_native,
            "nativeReturnHooksOk": module_native_return_hooks_ok,
            "nativeDynamicEntryCount": len(module_native_dynamic_entries),
            "nativeDynamicReturnCount": len(module_native_dynamic_returns),
            "nativeDynamicEntryOk": module_native_dynamic_entry_ok,
            "stop": module_stop,
            "resolvedCallCount": len(module_resolved_calls),
            "decodedReturnOk": module_decoded_return_ok,
        },
        "error": None if ok else "Dynamic API resolver trace contract failed.",
    }


def _run_memory_pe_discovery_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
    )
    entry = (
        bridge.RunUntil(target="entry", timeout_ms=10000, poll_ms=100)
        if init.get("ok")
        else {"ok": False, "error": "debuggee initialization failed"}
    )
    module = _main_module_record(bridge, exe_path) if entry.get("ok") else {}
    module_base = int(str(module.get("base") or "0"), 0)
    module_size = int(str(module.get("size") or "0"), 0)
    manifest_path = artifact_dir / f"memory-map-{arch}.json"
    manifest = bridge.DumpMemoryMapManifest(
        output_path=str(manifest_path),
        include_hashes=True,
        hash_bytes_per_region=256,
        max_regions=2048,
    )
    scan = bridge.ScanMemoryForPEImages(
        max_regions=2048,
        max_candidates=128,
        header_bytes=65536,
    )
    manifest_body = manifest.get("manifest") if isinstance(manifest, dict) else {}
    regions = (
        manifest_body.get("regions", [])
        if isinstance(manifest_body, dict)
        else []
    )
    main_region = next(
        (
            item
            for item in regions
            if isinstance(item, dict)
            and int(str(item.get("base") or "0"), 0) == module_base
            and int(item.get("size") or 0) > 0
        ),
        {},
    )
    raw_size = min(int(main_region.get("size") or 0), module_size, 0x10000)
    raw_path = artifact_dir / f"main-header-{arch}.bin"
    raw_dump = (
        bridge.DumpModuleRaw(
            base=f"0x{module_base:X}",
            size=raw_size,
            output_path=str(raw_path),
            chunk_size=0x1000,
            overwrite=True,
        )
        if module_base and raw_size
        else {"ok": False, "error": "main module memory region was not found"}
    )
    reconstructed_path = artifact_dir / f"main-reconstructed-{arch}.exe"
    reconstructed = (
        bridge.DumpPeFromMemory(
            base=f"0x{module_base:X}",
            output_path=str(reconstructed_path),
            image_size=module_size,
            header_template_path=exe_path,
            reverse_relocations=True,
            verify=True,
            overwrite=True,
        )
        if module_base and module_size
        else {"ok": False, "error": "main module identity was not resolved"}
    )
    iat_inspection = bridge.InspectRuntimeIAT(
        module=str(module.get("name") or ""), limit=5000, resolve_symbols=False
    )
    iat_validation = bridge.ValidateIAT(
        module=str(module.get("name") or ""), require_resolved=True, min_imports=1
    )
    fixed_dump_path = artifact_dir / f"main-imports-fixed-{arch}.exe"
    fixed_imports = (
        bridge.FixDumpImports(
            dump_path=str(reconstructed_path),
            output_path=str(fixed_dump_path),
            overwrite=True,
        )
        if reconstructed.get("ok")
        else {"ok": False, "error": "reconstruction failed"}
    )
    # Validate and smoke-run the reconstructed image before the optional IAT
    # cleanup.  FixDumpImports intentionally clears the runtime IAT when an
    # OriginalFirstThunk is available; that artifact is structurally useful
    # for re-import analysis, but is not expected to execute as-is.
    dump_validation = (
        bridge.ValidateDump(
            dump_path=str(reconstructed_path),
            run_isolated=True,
            arguments_json="[]",
            timeout_ms=5000,
            expected_exit_code=0,
            network_policy="deny",
            crash_report_path=str(artifact_dir / f"reconstruction-crash-{arch}.json"),
        )
        if fixed_imports.get("ok")
        else {"ok": False, "error": "import repair failed"}
    )
    candidates = scan.get("candidates", []) if isinstance(scan, dict) else []
    main_candidate = next(
        (
            item
            for item in candidates
            if isinstance(item, dict)
            and int(str(item.get("base") or "0"), 0) == module_base
        ),
        {},
    )
    raw_prefix = raw_path.read_bytes()[:2] if raw_path.is_file() else b""
    expected_arch = "x64" if arch == "x64" else "x86"
    ok = bool(
        init.get("ok")
        and entry.get("ok")
        and module_base
        and module_size
        and manifest.get("ok")
        and manifest.get("output", {}).get("written")
        and manifest_path.is_file()
        and main_region
        and main_region.get("sampleSha256")
        and scan.get("ok")
        and main_candidate
        and main_candidate.get("architecture") == expected_arch
        and int(main_candidate.get("sizeOfImage") or 0) == module_size
        and raw_dump.get("ok")
        and int(raw_dump.get("sizeOnDisk") or 0) == raw_size
        and raw_prefix == b"MZ"
        and reconstructed.get("ok")
        and reconstructed.get("architecture") == expected_arch
        and reconstructed.get("verification", {}).get("structural")
        and reconstructed.get("reloadable")
        and reconstructed_path.is_file()
        and iat_inspection.get("ok")
        and int(iat_inspection.get("count") or 0) > 0
        and iat_validation.get("ok")
        and fixed_imports.get("ok")
        and fixed_imports.get("verified")
        and fixed_dump_path.is_file()
        and dump_validation.get("ok")
        and dump_validation.get("execution", {}).get("success")
    )
    return {
        "ok": ok,
        "init": init,
        "entry": entry,
        "module": module,
        "manifest": manifest,
        "mainRegion": main_region,
        "scan": scan,
        "mainCandidate": main_candidate,
        "rawDump": raw_dump,
        "rawPrefix": raw_prefix.hex().upper(),
        "reconstructed": reconstructed,
        "iatInspection": iat_inspection,
        "iatValidation": iat_validation,
        "fixedImports": fixed_imports,
        "dumpValidation": dump_validation,
        "error": None if ok else "Memory/PE discovery live oracle failed.",
    }


def _run_native_coverage_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
        arguments=["0"],
    )
    entry = bridge.RunUntil(target="entry", timeout_ms=10000, poll_ms=100)
    module = _main_module_record(bridge, exe_path)
    module_name = str(module.get("name") or Path(exe_path).name)
    base = int(str(module.get("base") or "0"), 0)
    size = int(str(module.get("size") or "0"), 0)
    capture = bridge.CaptureSymbolicBreakpoint(
        target=f"{module_name}!coverage_target",
        timeout_ms=15000,
        delete_after_hit=True,
        resume=True,
        source="release-matrix",
        symbol_name="coverage_target",
    )
    coverage_exception_policy = (
        _set_exception_rules(
            bridge,
            [
                {
                    "ruleId": "coverage-fixture-seh",
                    "code": "0xE0424242",
                    "chance": "first",
                    "action": "not_handled",
                    "priority": 100,
                    "enabled": True,
                }
            ],
            first_default="pause",
            second_default="pause",
        )
        if capture.get("ok")
        else {"ok": False, "error": "coverage target capture failed"}
    )
    started = bridge.StartNativeTrace(
        mode="coverage",
        range_start=f"0x{base:X}" if base else "",
        range_size=size,
        # The fixture's CRT/SEH path reaches the final SMC version at roughly
        # 12k steps on current x64dbg builds.  Stop at a bounded ceiling before
        # the normal loader/debug-break tail can produce unrelated events.
        max_steps=15000,
        max_events=1,
        max_unique=10000,
        stop_on_limit=True,
        auto_resume_exceptions=True,
    )
    trace_id = str(started.get("traceId") or "")
    run = bridge.RunNativeTrace(
        trace_id=trace_id,
        condition="0",
        step_mode="into",
        max_steps=15000,
        timeout_ms=60000,
        event_limit=0,
        hit_limit=5000,
    ) if trace_id else {"ok": False, "error": "trace identity missing"}
    evidence = run.get("evidence") if isinstance(run.get("evidence"), dict) else {}
    hits = {
        int(str(item.get("ip") or "0"), 0)
        for item in evidence.get("hits", [])
        if isinstance(item, dict) and item.get("ip")
    }
    symbols_payload = bridge.QuerySymbols(module_name, offset=0, limit=5000)
    symbols = symbols_payload.get("symbols", []) if isinstance(symbols_payload, dict) else []
    exported = {
        str(item.get("name") or ""): base + int(str(item.get("rva") or "0"), 0)
        for item in symbols
        if isinstance(item, dict) and str(item.get("type") or "").casefold() == "export"
    }
    # x86 can exit the short fixture before the symbol query.  In that case
    # the live module list is legitimately gone; resolve the same PE export
    # directory from the identity-verified input file and keep the oracle in
    # hash+RVA space.
    if not exported:
        parse_layout = getattr(bridge, "_parse_pe_layout", None)
        try:
            static_layout = (
                parse_layout(exe_path) if callable(parse_layout) else {}
            )
            exported = {
                str(item.get("name") or ""): base
                + int(str(item.get("rva") or "0"), 0)
                for item in (static_layout.get("exports") or [])
                if isinstance(item, dict) and item.get("name")
            }
        except Exception:
            exported = {}
    # CB_TRACEEXECUTE starts after the instruction that stopped on the entry
    # breakpoint. Prove coverage_target separately through the exact resolved
    # breakpoint address; the native hit map must then prove the logical blocks
    # executed after that entry instruction.
    entry_name = "coverage_target"
    expected_names = {
        "block_entry",
        "block_zero",
        "block_even",
        "block_le10",
        "block_loop",
        "block_switch_0",
        "block_indirect_even",
        "block_exception_raise",
        "block_exception_handler",
        "coverage_loop",
        "coverage_switch",
        "coverage_indirect",
        "coverage_exception",
        "coverage_self_modify",
        "coverage_smc_entry",
        "block_final",
    }
    unexpected_names = {
        "block_odd",
        "block_gt10",
        "block_indirect_odd",
        "block_switch_1",
        "block_switch_2",
        "block_switch_3",
        "block_switch_4",
        "block_switch_5",
        "block_switch_6",
        "block_switch_7",
    }
    missing_symbols = sorted(
        name
        for name in expected_names | unexpected_names | {entry_name}
        if not exported.get(name)
    )
    captured_entry = int(str(capture.get("resolvedAddr") or "0"), 0)
    entry_capture_matches = bool(
        exported.get(entry_name) and captured_entry == exported.get(entry_name)
    )
    missing = sorted(name for name in expected_names if exported.get(name) not in hits)
    unexpected = sorted(name for name in unexpected_names if exported.get(name) in hits)
    clear = bridge.ClearNativeTrace(trace_id) if trace_id else {"ok": False}
    supports_bb_adapter = all(
        callable(getattr(bridge, name, None))
        for name in (
            "StartTraceRecord",
            "RunTraceRecord",
            "GetBasicBlockCoverage",
            "StopTraceRecord",
        )
    )
    # The bounded selector trace intentionally runs hundreds of instructions
    # and may leave RIP in a CRT/loader module.  Start the BB session from a
    # deterministic entry point so its main-module reconstruction is a real
    # execution proof rather than an accidental post-trace tail.
    if supports_bb_adapter:
        bb_reinit = bridge.InitDebuggee(
            exe_path,
            timeout_ms=20000,
            retries=2,
            stop_first=True,
            use_scyllahide="off",
            arguments=["0"],
        )
        bb_entry = (
            bridge.RunUntil(target="entry", timeout_ms=10000, poll_ms=100)
            if bb_reinit.get("ok")
            else {"ok": False, "error": "basic block debuggee reinitialization failed"}
        )
        bb_capture = (
            bridge.CaptureSymbolicBreakpoint(
                target=f"{module_name}!coverage_target",
                timeout_ms=15000,
                delete_after_hit=True,
                resume=True,
                source="release-matrix-bb",
                symbol_name="coverage_target",
            )
            if bb_entry.get("ok")
            else {"ok": False, "error": "basic block entry wait failed"}
        )
        bb_exception_policy = (
            _set_exception_rules(
                bridge,
                [
                    {
                        "ruleId": "coverage-fixture-seh-bb",
                        "code": "0xE0424242",
                        "chance": "first",
                        "action": "not_handled",
                        "priority": 100,
                        "enabled": True,
                    }
                ],
                first_default="pause",
                second_default="pause",
            )
            if bb_capture.get("ok")
            else {"ok": False, "error": "basic block target capture failed"}
        )
        bb_record = bridge.StartTraceRecord(
            mode="hitcount",
            label="release-matrix-basic-blocks",
            max_steps=15000,
            stop_on_limit=True,
        )
        bb_trace_id = str(bb_record.get("traceId") or "")
        bb_run = (
            bridge.RunTraceRecord(
                bb_trace_id,
                timeout_ms=60000,
                max_hits=15000,
            )
            if bb_trace_id
            else {"ok": False, "error": "basic block trace identity missing"}
        )
        bb_exception_history = (
            bridge.GetExceptionHistory(after_seq=0, limit=256)
            if callable(getattr(bridge, "GetExceptionHistory", None))
            else {"ok": True, "skipped": True}
        )
        bb_native_exception_events = []
        read_native_events = getattr(bridge, "_read_native_trace_events", None)
        if bb_trace_id and callable(read_native_events):
            try:
                raw_events = read_native_events(
                    str(bb_record.get("nativeTraceId") or ""),
                    max_items=50000,
                )
                if isinstance(raw_events, tuple) and len(raw_events) >= 2:
                    bb_native_exception_events = [
                        item
                        for item in raw_events[1]
                        if isinstance(item, dict)
                        and item.get("exceptionTransition")
                    ]
            except Exception:
                bb_native_exception_events = []
        bb_coverage = (
            bridge.GetBasicBlockCoverage(bb_trace_id, limit=500)
            if bb_trace_id
            else {"ok": False}
        )
        supports_artifacts = all(
            callable(getattr(bridge, name, None))
            for name in (
                "ExportCoverageArtifact",
                "MergeCoverageArtifacts",
                "DiffCoverageArtifacts",
            )
        )
        coverage_artifact_path = artifact_dir / f"coverage-{arch}.json"
        coverage_export = (
            bridge.ExportCoverageArtifact(
                bb_trace_id,
                output_path=str(coverage_artifact_path),
                limit=500,
            )
            if supports_artifacts and bb_trace_id
            else {"ok": True, "skipped": True}
        )
        exported_artifact = (
            coverage_export.get("artifact")
            if isinstance(coverage_export, dict)
            else None
        )
        coverage_merge = (
            bridge.MergeCoverageArtifacts(
                json.dumps([exported_artifact, exported_artifact], ensure_ascii=False)
            )
            if supports_artifacts and isinstance(exported_artifact, dict)
            else {"ok": True, "skipped": True}
        )
        coverage_diff = (
            bridge.DiffCoverageArtifacts(
                json.dumps(exported_artifact, ensure_ascii=False),
                json.dumps(coverage_merge.get("artifact"), ensure_ascii=False),
            )
            if supports_artifacts
            and isinstance(exported_artifact, dict)
            and isinstance(coverage_merge, dict)
            and isinstance(coverage_merge.get("artifact"), dict)
            else {"ok": True, "skipped": True}
        )
        artifact_ok = bool(
            (not supports_artifacts)
            or (
                coverage_export.get("ok")
                and isinstance(coverage_export.get("output"), dict)
                and coverage_export.get("output", {}).get("written")
                and coverage_export.get("artifactSha256")
                and coverage_merge.get("ok")
                and coverage_merge.get("artifactSha256")
                and coverage_diff.get("ok")
                and isinstance(coverage_diff.get("summary"), dict)
                and coverage_diff.get("summary", {}).get("addedBlocks") == 0
                and coverage_diff.get("summary", {}).get("removedBlocks") == 0
            )
        )
        bb_stop = (
            bridge.StopTraceRecord(bb_trace_id)
            if bb_trace_id
            else {"ok": False}
        )
        bb_blocks = (
            bb_coverage.get("blocks")
            if isinstance(bb_coverage, dict)
            and isinstance(bb_coverage.get("blocks"), list)
            else []
        )
        bb_edges = (
            bb_coverage.get("edges")
            if isinstance(bb_coverage, dict)
            and isinstance(bb_coverage.get("edges"), list)
            else []
        )
        smc_rva = (
            exported.get("coverage_smc_entry", 0) - base
            if exported.get("coverage_smc_entry") and base
            else -1
        )
        loop_rva = (
            exported.get("block_loop", 0) - base
            if exported.get("block_loop") and base
            else -1
        )
        smc_blocks = [
            item
            for item in bb_blocks
            if isinstance(item, dict)
            and int(str(item.get("startRva") or "-1"), 0) == smc_rva
        ]
        loop_blocks = [
            item
            for item in bb_blocks
            if isinstance(item, dict)
            and int(str(item.get("startRva") or "-1"), 0) == loop_rva
        ]
        returned_block_keys = {
            str(item.get("stableKey") or "")
            for item in bb_blocks
            if isinstance(item, dict)
        }
        no_dangling_edges = all(
            isinstance(item, dict)
            and str(item.get("from") or "") in returned_block_keys
            and str(item.get("to") or "") in returned_block_keys
            for item in bb_edges
        )
        # x32dbg's conditional instruction tracer does not reliably preserve
        # a compiler-SEH trace command across the dispatcher transition.  The
        # x86 first/second-chance contract has its own live release cases; this
        # CFG oracle therefore requires exception edges on x64 and keeps the
        # x86 gate focused on exact blocks, typed branches, loop counts and
        # versioned SMC.
        exception_edge_required = str(arch).lower() != "x86"
        exact_cfg_oracle = {
            "ok": bool(
                bb_coverage.get("reconstructionSchema") == "basic-block-edge-v2"
                and len(smc_blocks) == 2
                and all(item.get("selfModified") is True for item in smc_blocks)
                and {int(item.get("codeVersion") or 0) for item in smc_blocks}
                == {1, 2}
                and sum(int(item.get("hits") or 0) for item in loop_blocks) == 3
                and int(bb_coverage.get("versionedBlockCount") or 0) >= 2
                and f"0x{smc_rva:x}" in (bb_coverage.get("selfModifyingRvas") or [])
                and int(bb_coverage.get("indirectEdgeCount") or 0) >= 1
                and (
                    not exception_edge_required
                    or int(bb_coverage.get("exceptionEdgeCount") or 0) >= 1
                )
                and int(bb_coverage.get("executedInstructionHits") or 0)
                > int(bb_coverage.get("executedBlockHits") or 0)
                and no_dangling_edges
            ),
            "smcRva": f"0x{smc_rva:x}" if smc_rva >= 0 else None,
            "smcBlocks": smc_blocks,
            "loopRva": f"0x{loop_rva:x}" if loop_rva >= 0 else None,
            "loopBlocks": loop_blocks,
            "noDanglingEdges": no_dangling_edges,
            "indirectEdgeCount": int(
                bb_coverage.get("indirectEdgeCount") or 0
            ),
            "exceptionEdgeCount": int(
                bb_coverage.get("exceptionEdgeCount") or 0
            ),
            "exceptionEdgeRequired": exception_edge_required,
        }
        bb_ok = bool(
            bb_reinit.get("ok")
            and bb_entry.get("ok")
            and bb_capture.get("ok")
            and bb_exception_policy.get("ok")
            and bb_record.get("ok")
            and bb_run.get("ok")
            and bb_coverage.get("ok")
            and bb_coverage.get("coverageModel") == "basic-block-edge-v1"
            and int(bb_coverage.get("blockCount") or 0) >= 1
            and int(bb_coverage.get("coveredInstructions") or 0) >= 1
            and exact_cfg_oracle.get("ok")
            and artifact_ok
            and bb_stop.get("ok")
        )
    else:
        bb_reinit = {"ok": True, "skipped": True, "reason": "TraceRecord API unavailable"}
        bb_entry = {"ok": True, "skipped": True}
        bb_capture = {"ok": True, "skipped": True}
        bb_exception_policy = {"ok": True, "skipped": True}
        bb_record = {"ok": True, "skipped": True}
        bb_trace_id = ""
        bb_run = {"ok": True, "skipped": True}
        bb_exception_history = {"ok": True, "skipped": True}
        bb_native_exception_events = []
        bb_coverage = {"ok": True, "skipped": True}
        coverage_export = {"ok": True, "skipped": True}
        coverage_merge = {"ok": True, "skipped": True}
        coverage_diff = {"ok": True, "skipped": True}
        coverage_artifact_path = None
        artifact_ok = True
        bb_stop = {"ok": True, "skipped": True}
        exact_cfg_oracle = {"ok": True, "skipped": True}
        bb_ok = True
    # A second, instruction-mode trace keeps a deliberately tiny bounded ring
    # with stopOnLimit=false.  This proves the new watermark/cursor contract
    # instead of only the legacy offset coverage path.
    supports_ring_probe = all(
        callable(getattr(bridge, name, None))
        for name in ("GetNativeTrace", "StartNativeTrace", "RunNativeTrace")
    )
    probe_reinit = (
        bridge.InitDebuggee(
            exe_path,
            timeout_ms=20000,
            retries=2,
            stop_first=True,
            use_scyllahide="off",
            arguments=["0"],
        )
        if supports_ring_probe
        else {"ok": True, "skipped": True}
    )
    probe_entry = (
        bridge.RunUntil(target="entry", timeout_ms=10000, poll_ms=100)
        if supports_ring_probe and probe_reinit.get("ok")
        else {"ok": True, "skipped": True}
    )
    ring_started = (
        bridge.StartNativeTrace(
            mode="instruction",
            # Capture the current thread regardless of which loader/system
            # module owns RIP after the first trace; this keeps the ring probe
            # independent of the fixture's post-trace location.
            range_start="",
            range_size=0,
            max_steps=100,
            max_events=4,
            max_unique=64,
            stop_on_limit=False,
            enrich_events=True,
        )
        if supports_ring_probe and probe_reinit.get("ok") and probe_entry.get("ok")
        else {"ok": True, "skipped": True}
    )
    ring_trace_id = str(ring_started.get("traceId") or "")
    ring_run = (
        bridge.RunNativeTrace(
            trace_id=ring_trace_id,
            condition="0",
            step_mode="into",
            max_steps=100,
            timeout_ms=30000,
            event_limit=4,
            hit_limit=64,
        )
        if ring_trace_id
        else {"ok": False, "error": "ring trace identity missing"}
    )
    ring_page = (
        bridge.GetNativeTrace(
            ring_trace_id,
            event_offset=0,
            event_limit=4,
            hit_offset=0,
            hit_limit=64,
            event_after_seq=1,
            hit_after_revision=1,
        )
        if ring_trace_id
        else {}
    )
    wrong_ring_clear = (
        bridge.ClearNativeTrace(f"{ring_trace_id}-stale")
        if ring_trace_id
        else {"ok": False}
    )
    ring_clear = (
        bridge.ClearNativeTrace(ring_trace_id)
        if ring_trace_id
        else {"ok": True, "skipped": True}
    )
    supports_race_probe = all(
        callable(getattr(bridge, name, None))
        for name in (
            "StartNativeTrace",
            "GetNativeTrace",
            "WaitNativeTrace",
            "StopNativeTrace",
            "ClearNativeTrace",
        )
    )
    race_started = (
        bridge.StartNativeTrace(
            mode="instruction",
            range_start="",
            range_size=0,
            max_steps=1_000_000,
            max_events=32,
            max_unique=64,
            stop_on_limit=False,
        )
        if supports_race_probe
        else {"ok": True, "skipped": True}
    )
    race_trace_id = str(race_started.get("traceId") or "")
    race_wait_result: dict[str, Any] = {}
    race_reader_results: list[dict[str, Any]] = []

    def race_waiter() -> None:
        try:
            race_wait_result.update(
                bridge.WaitNativeTrace(
                    trace_id=race_trace_id,
                    timeout_ms=5000,
                    poll_ms=20,
                )
            )
        except Exception as exc:  # pragma: no cover - live-only diagnostic
            race_wait_result.update({"ok": False, "error": str(exc)})

    def race_reader() -> None:
        try:
            for _ in range(15):
                page = bridge.GetNativeTrace(
                    race_trace_id,
                    event_limit=8,
                    hit_limit=8,
                    event_after_seq=0,
                    hit_after_revision=0,
                )
                race_reader_results.append(page if isinstance(page, dict) else {"ok": False})
        except Exception as exc:  # pragma: no cover - live-only diagnostic
            race_reader_results.append({"ok": False, "error": str(exc)})

    race_wait_thread = (
        threading.Thread(target=race_waiter, daemon=True)
        if supports_race_probe and race_trace_id
        else None
    )
    if race_wait_thread:
        race_wait_thread.start()
    race_reader_threads = (
        [
            threading.Thread(target=race_reader, daemon=True)
            for _ in range(4)
        ]
        if supports_race_probe and race_trace_id
        else []
    )
    for reader_thread in race_reader_threads:
        reader_thread.start()
    time.sleep(0.15)
    clear_while_active = (
        bridge.ClearNativeTrace(race_trace_id)
        if supports_race_probe and race_trace_id
        else {"ok": True, "skipped": True}
    )
    stop_race = (
        bridge.StopNativeTrace(race_trace_id)
        if supports_race_probe and race_trace_id
        else {"ok": True, "skipped": True}
    )
    if race_wait_thread:
        race_wait_thread.join(timeout=8.0)
    for reader_thread in race_reader_threads:
        reader_thread.join(timeout=8.0)
    clear_after_race = (
        bridge.ClearNativeTrace(race_trace_id)
        if supports_race_probe and race_trace_id
        else {"ok": True, "skipped": True}
    )
    overflow_started = (
        bridge.StartNativeTrace(
            mode="instruction",
            range_start="",
            range_size=0,
            max_steps=1000,
            max_events=64,
            max_unique=64,
            stop_on_limit=False,
        )
        if supports_race_probe
        else {"ok": True, "skipped": True}
    )
    overflow_trace_id = str(overflow_started.get("traceId") or "")
    overflow_run = (
        bridge.RunNativeTrace(
            trace_id=overflow_trace_id,
            condition="0",
            step_mode="into",
            max_steps=1000,
            timeout_ms=5000,
            event_limit=0,
            hit_limit=0,
        )
        if overflow_trace_id
        else {"ok": True, "skipped": True}
    )
    overflow_evidence = (
        overflow_run.get("evidence")
        if isinstance(overflow_run, dict)
        and isinstance(overflow_run.get("evidence"), dict)
        else {}
    )
    overflow_clear = (
        bridge.ClearNativeTrace(overflow_trace_id)
        if overflow_trace_id
        else {"ok": True, "skipped": True}
    )
    overflow_ok = bool(
        (not supports_race_probe)
        or (
            overflow_trace_id
            and int(overflow_evidence.get("eventCount") or 0) == 64
            and int(overflow_evidence.get("droppedEvents") or 0) >= 900
            and int(overflow_evidence.get("latestEventSeq") or 0)
            > int(overflow_evidence.get("oldestEventSeq") or 0)
            and overflow_clear.get("ok")
        )
    )
    wrong_clear_error = wrong_ring_clear.get("error") if isinstance(wrong_ring_clear, dict) else None
    wrong_clear_code = (
        wrong_clear_error.get("code")
        if isinstance(wrong_clear_error, dict)
        else str(wrong_ring_clear.get("errorCode") or "")
        if isinstance(wrong_ring_clear, dict)
        else ""
    )
    wrong_clear_ok = bool(
        ring_trace_id
        and isinstance(wrong_ring_clear, dict)
        and not wrong_ring_clear.get("ok")
        and wrong_clear_code == "trace_not_found"
    )
    active_clear_error = (
        clear_while_active.get("error")
        if isinstance(clear_while_active, dict)
        else None
    )
    active_clear_code = (
        active_clear_error.get("code")
        if isinstance(active_clear_error, dict)
        else str(clear_while_active.get("errorCode") or "")
        if isinstance(clear_while_active, dict)
        else ""
    )
    reader_race_ok = bool(
        (not supports_race_probe)
        or (
            race_trace_id
        and len(race_reader_results) == 60
        and all(item.get("ok") is True for item in race_reader_results)
        and race_wait_thread is not None
        and not race_wait_thread.is_alive()
        )
    )
    clear_wait_ok = bool(
        (not supports_race_probe)
        or (
            race_trace_id
        and isinstance(clear_while_active, dict)
        and not clear_while_active.get("ok")
        and active_clear_code == "trace_active"
        and isinstance(stop_race, dict)
        and stop_race.get("ok")
        and isinstance(race_wait_result, dict)
        and race_wait_result.get("ok")
        and not race_wait_result.get("timedOut")
        and isinstance(clear_after_race, dict)
        and clear_after_race.get("ok")
        )
    )
    race_ok = bool(reader_race_ok and clear_wait_ok)
    enriched_events = (
        ring_page.get("events")
        if isinstance(ring_page, dict) and isinstance(ring_page.get("events"), list)
        else []
    )
    enrichment_ok = bool(
        ring_page.get("enrichEvents") is True
        and enriched_events
        and any(
            isinstance(event, dict)
            and event.get("module")
            and event.get("instruction")
            and int(event.get("instructionSize") or 0) > 0
            and event.get("bytes")
            for event in enriched_events
        )
    )
    ring_ok = bool(
        (not supports_ring_probe)
        or (
            probe_reinit.get("ok")
        and probe_entry.get("ok")
        and ring_started.get("ok")
        and ring_run.get("ok")
        and isinstance(ring_page, dict)
        and ring_page.get("eventCursorExclusive") is True
        and int(ring_page.get("oldestEventSeq") or 0) >= 0
        and int(ring_page.get("latestEventSeq") or 0)
        >= int(ring_page.get("oldestEventSeq") or 0)
        and ring_page.get("hitCursorExclusive") is True
        and int(ring_page.get("latestHitRevision") or 0)
        >= int(ring_page.get("oldestHitRevision") or 0)
        and wrong_clear_ok
        and enrichment_ok
        and ring_clear.get("ok")
        and race_ok
        and overflow_ok
        )
    )
    ok = bool(
        init.get("ok")
        and entry.get("ok")
        and capture.get("ok")
        and coverage_exception_policy.get("ok")
        and entry_capture_matches
        and started.get("ok")
        and run.get("ok")
        and int(evidence.get("matchedSteps") or 0) > 0
        and not missing_symbols
        and not missing
        and not unexpected
        and clear.get("ok")
        and bb_ok
        and ring_ok
    )
    return {
        "ok": ok,
        "init": init,
        "entry": entry,
        "module": module,
        "capture": capture,
        "exceptionPolicy": coverage_exception_policy,
        "start": started,
        "run": run,
        "capturedEntry": {
            "symbol": entry_name,
            "expected": f"0x{exported.get(entry_name, 0):X}",
            "actual": f"0x{captured_entry:X}",
            "matches": entry_capture_matches,
        },
        "expectedExports": {name: f"0x{exported.get(name, 0):X}" for name in sorted(expected_names)},
        "missingExportSymbols": missing_symbols,
        "missingExpected": missing,
        "unexpectedCovered": unexpected,
        "clear": clear,
        "basicBlockRecord": bb_record,
        "basicBlockReinit": bb_reinit,
        "basicBlockEntry": bb_entry,
        "basicBlockCapture": bb_capture,
        "basicBlockExceptionPolicy": bb_exception_policy,
        "basicBlockRun": bb_run,
        "basicBlockExceptionHistory": bb_exception_history,
        "basicBlockNativeExceptionEvents": bb_native_exception_events,
        "basicBlockCoverage": bb_coverage,
        "exactCfgOracle": exact_cfg_oracle,
        "coverageArtifact": {
            "path": str(coverage_artifact_path) if coverage_artifact_path else None,
            "export": coverage_export,
            "merge": coverage_merge,
            "diff": coverage_diff,
            "ok": artifact_ok,
        },
        "basicBlockStop": bb_stop,
        "basicBlockOk": bb_ok,
        "ringTrace": {
            "reinit": probe_reinit,
            "entry": probe_entry,
            "start": ring_started,
            "run": ring_run,
            "pageAfterSeq": ring_page,
            "wrongClear": wrong_ring_clear,
            "wrongClearOk": wrong_clear_ok,
            "enrichmentOk": enrichment_ok,
            "clear": ring_clear,
            "ok": ring_ok,
        },
        "readerRace": {
            "start": race_started,
            "readerCount": len(race_reader_results),
            "readerOk": reader_race_ok,
            "clearWhileActive": clear_while_active,
            "stop": stop_race,
            "wait": race_wait_result,
            "clearAfter": clear_after_race,
            "clearWaitOk": clear_wait_ok,
            "ok": race_ok,
        },
        "highRateOverflow": {
            "start": overflow_started,
            "run": overflow_run,
            "evidence": overflow_evidence,
            "clear": overflow_clear,
            "ok": overflow_ok,
        },
        "error": None if ok else "Native coverage did not match the selector-zero path.",
    }


def execute_scenario_with_cleanup(
    bridge: Any,
    scenario: Callable[[Any, str], Any],
    exe_path: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run one adapter and always request a bounded debug-session stop."""

    result: dict[str, Any]
    cleanup: dict[str, Any] = {"attempted": False}
    try:
        raw = scenario(bridge, exe_path)
        if not isinstance(raw, dict):
            result = {
                "ok": False,
                "error": "Scenario returned a non-object result.",
                "resultType": type(raw).__name__,
                "rawResult": repr(raw),
            }
        else:
            result = dict(raw)
        if result.get("skipped"):
            result["ok"] = False
            result.setdefault("error", "Live release cases cannot pass by being skipped.")
            result["skipRejected"] = True
        return result, cleanup
    except Exception as exc:
        result = {
            "ok": False,
            "error": str(exc),
            "exceptionType": type(exc).__name__,
            "traceback": traceback.format_exc(),
        }
        return result, cleanup
    finally:
        cleanup["attempted"] = True
        try:
            cleanup["debugStop"] = bridge.DebugStop()
        except Exception as exc:
            cleanup["debugStopError"] = str(exc)


def _launch_runtime_oracle(name: str) -> dict[str, Any]:
    manifest = _load_corpus_manifest()
    fixture = next(
        (
            item
            for item in manifest.get("fixtures", [])
            if isinstance(item, dict) and item.get("id") == "launch_contract"
        ),
        None,
    )
    if not isinstance(fixture, dict):
        raise RuntimeError("launch_contract corpus fixture is unavailable")
    runtime = next(
        (
            item
            for item in fixture.get("runtime", [])
            if isinstance(item, dict) and item.get("name") == name
        ),
        None,
    )
    if not isinstance(runtime, dict):
        raise RuntimeError(f"launch_contract runtime oracle is unavailable: {name}")
    return dict(runtime)


def _native_launch_payload(init: Any) -> dict[str, Any]:
    if not isinstance(init, dict):
        return {}
    native = init.get("initResult")
    return dict(native) if isinstance(native, dict) else dict(init)


def _launch_identity_contract(native: dict[str, Any], arch: str) -> dict[str, Any]:
    process = native.get("process") if isinstance(native.get("process"), dict) else {}
    expected = (
        process.get("expectedIdentity")
        if isinstance(process.get("expectedIdentity"), dict)
        else {}
    )
    actual = (
        process.get("actualIdentity")
        if isinstance(process.get("actualIdentity"), dict)
        else {}
    )
    expected_sha = str(expected.get("sha256") or "").casefold()
    actual_sha = str(actual.get("sha256") or "").casefold()
    expected_file_id = str(expected.get("fileId") or "").casefold()
    actual_file_id = str(actual.get("fileId") or "").casefold()
    ok = bool(
        native.get("ok") is True
        and native.get("identityVerified") is True
        and native.get("resumed") is True
        and native.get("ownershipCommitted") is True
        and native.get("phase") == "attached_paused"
        and process.get("architecture") == arch
        and _integer(process.get("pid")) > 0
        and _integer(process.get("primaryThreadId")) > 0
        and _integer(process.get("creationTime100ns")) > 0
        and expected.get("available") is True
        and actual.get("available") is True
        and len(expected_sha) == 64
        and expected_sha == actual_sha
        and len(expected_file_id) == 32
        and expected_file_id == actual_file_id
        and _integer(expected.get("size")) > 0
        and _integer(expected.get("size")) == _integer(actual.get("size"))
    )
    return {
        "ok": ok,
        "pid": _integer(process.get("pid")),
        "primaryThreadId": _integer(process.get("primaryThreadId")),
        "creationTime100ns": _integer(process.get("creationTime100ns")),
        "expectedSha256": expected_sha,
        "actualSha256": actual_sha,
        "expectedFileId": expected_file_id,
        "actualFileId": actual_file_id,
        "resumePreviousSuspendCount": _integer(
            native.get("resumePreviousSuspendCount")
        ),
        "debuggerSuspensionObserved": native.get("debuggerSuspensionObserved"),
    }


def _drain_launch_stream(
    bridge: Any,
    launch_id: str,
    stream: str,
    *,
    max_bytes: int = 65536,
    wait_ms: int = 1000,
    max_pages: int = 128,
) -> dict[str, Any]:
    cursor = 0
    chunks: list[bytes] = []
    pages: list[dict[str, Any]] = []
    total_dropped = 0
    cursor_truncated = False
    eof = False
    for _ in range(max_pages):
        payload = bridge.ReadLaunchStream(
            launch_id,
            stream=stream,
            cursor=cursor,
            max_bytes=max_bytes,
            wait_ms=wait_ms,
        )
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            return {
                "ok": False,
                "stream": stream,
                "cursor": cursor,
                "pages": pages,
                "error": payload,
            }
        encoded = payload.get("dataBase64")
        if not isinstance(encoded, str):
            return {
                "ok": False,
                "stream": stream,
                "cursor": cursor,
                "pages": pages,
                "error": "dataBase64 is missing",
            }
        try:
            data = base64.b64decode(encoded.encode("ascii"), validate=True)
        except Exception as exc:
            return {
                "ok": False,
                "stream": stream,
                "cursor": cursor,
                "pages": pages,
                "error": f"invalid base64: {type(exc).__name__}: {exc}",
            }
        if base64.b64encode(data).decode("ascii") != encoded:
            return {
                "ok": False,
                "stream": stream,
                "cursor": cursor,
                "pages": pages,
                "error": "non-canonical base64",
            }
        byte_count = _integer(payload.get("byteCount"), -1)
        next_cursor = _integer(payload.get("nextCursor"), -1)
        if byte_count != len(data) or next_cursor < cursor:
            return {
                "ok": False,
                "stream": stream,
                "cursor": cursor,
                "pages": pages,
                "error": "byteCount/nextCursor contract mismatch",
                "payload": {
                    key: value
                    for key, value in payload.items()
                    if key != "dataBase64"
                },
            }
        page = {
            key: value
            for key, value in payload.items()
            if key not in {"dataBase64", "meta"}
        }
        page["dataSha256"] = hashlib.sha256(data).hexdigest()
        pages.append(page)
        chunks.append(data)
        total_dropped = max(total_dropped, _integer(payload.get("totalDroppedBytes")))
        cursor_truncated = cursor_truncated or payload.get("cursorTruncated") is True
        cursor = next_cursor
        eof = payload.get("eof") is True
        if eof:
            break
        if not data and next_cursor == _integer(payload.get("requestedCursor")):
            continue
    data = b"".join(chunks)
    return {
        "ok": eof,
        "stream": stream,
        "eof": eof,
        "cursor": cursor,
        "byteCount": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "data": data,
        "totalDroppedBytes": total_dropped,
        "cursorTruncated": cursor_truncated,
        "pages": pages,
    }


def _finish_launch_resources(bridge: Any, launch_id: str) -> dict[str, Any]:
    before = bridge.GetLaunchState(launch_id)
    closed = bridge.CloseLaunchResources(launch_id)
    after = bridge.GetLaunchState(launch_id)
    ok = bool(
        isinstance(before, dict)
        and before.get("ok") is True
        and isinstance(closed, dict)
        and closed.get("ok") is True
        and closed.get("released") is True
        and isinstance(after, dict)
        and after.get("ok") is False
        and str(after.get("errorCode") or "").casefold() == "launch_not_found"
    )
    return {"ok": ok, "before": before, "closed": closed, "after": after}


def _run_launch_to_exit(
    bridge: Any,
    *,
    timeout_ms: int = 20000,
) -> dict[str, Any]:
    entry = bridge.RunUntil(target="entry", timeout_ms=10000, poll_ms=50)
    run = bridge.DebugRun() if isinstance(entry, dict) and entry.get("ok") else None
    exited = (
        bridge.WaitForExit(timeout_ms=timeout_ms, poll_ms=50)
        if isinstance(entry, dict) and entry.get("ok")
        else {}
    )
    return {
        "ok": bool(
            isinstance(entry, dict)
            and entry.get("ok") is True
            and isinstance(exited, dict)
            and exited.get("exited") is True
        ),
        "entry": entry,
        "run": run,
        "exit": exited,
        "exitCode": _exit_code(exited),
    }


def _run_launch_argv_env_cwd_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir
    oracle = _launch_runtime_oracle("typed-argv-env-cwd")
    environment = dict(oracle.get("env") or {})
    environment["X64DBG_MCP_E2E_ENV_DELETE"] = None
    environment["X64DBG_MCP_E2E_ENV_ABSENT"] = None
    working_directory = str((REPO_ROOT / str(oracle.get("cwd") or "")).resolve())
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=30000,
        retries=1,
        stop_first=True,
        use_scyllahide="off",
        arguments=list(oracle.get("args") or []),
        working_directory=working_directory,
        environment=environment,
        inherit_environment=True,
        stdin={"mode": "null"},
        stdout={"mode": "pipe"},
        stderr={"mode": "pipe"},
        capture_limit_bytes=4096,
    )
    native = _native_launch_payload(init)
    launch_id = str(native.get("launchId") or "")
    identity = _launch_identity_contract(native, arch)
    execution = _run_launch_to_exit(bridge) if launch_id else {"ok": False}
    stdout = _drain_launch_stream(bridge, launch_id, "stdout") if launch_id else {}
    stderr = _drain_launch_stream(bridge, launch_id, "stderr") if launch_id else {}
    expected_stdout = base64.b64decode(str(oracle.get("stdoutBase64") or ""))
    expected_stderr = base64.b64decode(str(oracle.get("stderrBase64") or ""))
    streams_ok = bool(
        stdout.get("ok")
        and stderr.get("ok")
        and stdout.get("data") == expected_stdout
        and stderr.get("data") == expected_stderr
        and stdout.get("sha256") == oracle.get("expectedStdoutSha256")
        and stderr.get("sha256") == oracle.get("expectedStderrSha256")
    )
    cleanup = _finish_launch_resources(bridge, launch_id) if launch_id else {}
    stdout.pop("data", None)
    stderr.pop("data", None)
    return {
        "ok": bool(
            isinstance(init, dict)
            and init.get("ok") is True
            and identity.get("ok")
            and execution.get("ok")
            and execution.get("exitCode") == _uint32(oracle.get("expectedExitCode"))
            and streams_ok
            and cleanup.get("ok")
        ),
        "init": init,
        "identity": identity,
        "execution": execution,
        "stdout": stdout,
        "stderr": stderr,
        "streamsExact": streams_ok,
        "cleanup": cleanup,
    }


def _run_launch_bytes_stdio_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir
    oracle = _launch_runtime_oracle("typed-stream-binary")
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=30000,
        retries=1,
        stop_first=True,
        use_scyllahide="off",
        arguments=list(oracle.get("args") or []),
        stdin={
            "mode": "bytes",
            "dataBase64": str(oracle.get("stdinBase64") or ""),
            "closeAfterWrite": True,
        },
        stdout={"mode": "pipe"},
        stderr={"mode": "pipe"},
        capture_limit_bytes=4096,
    )
    native = _native_launch_payload(init)
    launch_id = str(native.get("launchId") or "")
    identity = _launch_identity_contract(native, arch)
    execution = _run_launch_to_exit(bridge) if launch_id else {"ok": False}
    stdout = _drain_launch_stream(bridge, launch_id, "stdout") if launch_id else {}
    stderr = _drain_launch_stream(bridge, launch_id, "stderr") if launch_id else {}
    expected_stdout = base64.b64decode(str(oracle.get("stdoutBase64") or ""))
    expected_stderr = base64.b64decode(str(oracle.get("stderrBase64") or ""))
    streams_ok = bool(
        stdout.get("ok")
        and stderr.get("ok")
        and stdout.get("data") == expected_stdout
        and stderr.get("data") == expected_stderr
        and stdout.get("sha256") == oracle.get("expectedStdoutSha256")
        and stderr.get("sha256") == oracle.get("expectedStderrSha256")
    )
    cleanup = _finish_launch_resources(bridge, launch_id) if launch_id else {}
    stdout.pop("data", None)
    stderr.pop("data", None)
    return {
        "ok": bool(
            isinstance(init, dict)
            and init.get("ok") is True
            and identity.get("ok")
            and execution.get("ok")
            and execution.get("exitCode") == _uint32(oracle.get("expectedExitCode"))
            and streams_ok
            and cleanup.get("ok")
        ),
        "init": init,
        "identity": identity,
        "execution": execution,
        "stdout": stdout,
        "stderr": stderr,
        "streamsExact": streams_ok,
        "cleanup": cleanup,
    }


def _run_launch_pipe_stdio_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir
    oracle = _launch_runtime_oracle("typed-stream-binary")
    stdin_bytes = base64.b64decode(str(oracle.get("stdinBase64") or ""))
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=30000,
        retries=1,
        stop_first=True,
        use_scyllahide="off",
        arguments=list(oracle.get("args") or []),
        stdin={"mode": "pipe", "capacityBytes": 4096},
        stdout={"mode": "pipe"},
        stderr={"mode": "pipe"},
        capture_limit_bytes=4096,
    )
    native = _native_launch_payload(init)
    launch_id = str(native.get("launchId") or "")
    identity = _launch_identity_contract(native, arch)
    entry = (
        bridge.RunUntil(target="entry", timeout_ms=10000, poll_ms=50)
        if launch_id
        else {}
    )
    run = (
        bridge.DebugRun()
        if isinstance(entry, dict) and entry.get("ok") is True
        else None
    )
    split = max(1, len(stdin_bytes) // 3)
    write_one = (
        bridge.WriteLaunchStdin(
            launch_id,
            base64.b64encode(stdin_bytes[:split]).decode("ascii"),
            wait_ms=1000,
        )
        if run is not None
        else {}
    )
    write_two = (
        bridge.WriteLaunchStdin(
            launch_id,
            base64.b64encode(stdin_bytes[split:]).decode("ascii"),
            wait_ms=1000,
        )
        if isinstance(write_one, dict) and write_one.get("ok") is True
        else {}
    )
    close_stdin = (
        bridge.CloseLaunchStdin(launch_id)
        if isinstance(write_two, dict) and write_two.get("ok") is True
        else {}
    )
    exited = (
        bridge.WaitForExit(timeout_ms=20000, poll_ms=50)
        if isinstance(close_stdin, dict) and close_stdin.get("ok") is True
        else {}
    )
    stdout = _drain_launch_stream(bridge, launch_id, "stdout") if launch_id else {}
    stderr = _drain_launch_stream(bridge, launch_id, "stderr") if launch_id else {}
    expected_stdout = base64.b64decode(str(oracle.get("stdoutBase64") or ""))
    expected_stderr = base64.b64decode(str(oracle.get("stderrBase64") or ""))
    streams_ok = bool(
        stdout.get("ok")
        and stderr.get("ok")
        and stdout.get("data") == expected_stdout
        and stderr.get("data") == expected_stderr
    )
    writes_ok = bool(
        isinstance(write_one, dict)
        and write_one.get("ok") is True
        and _integer(write_one.get("acceptedBytes")) == split
        and isinstance(write_two, dict)
        and write_two.get("ok") is True
        and _integer(write_two.get("acceptedBytes")) == len(stdin_bytes) - split
        and isinstance(close_stdin, dict)
        and close_stdin.get("ok") is True
        and close_stdin.get("closed") is True
    )
    cleanup = _finish_launch_resources(bridge, launch_id) if launch_id else {}
    stdout.pop("data", None)
    stderr.pop("data", None)
    return {
        "ok": bool(
            isinstance(init, dict)
            and init.get("ok") is True
            and identity.get("ok")
            and isinstance(entry, dict)
            and entry.get("ok") is True
            and writes_ok
            and isinstance(exited, dict)
            and exited.get("exited") is True
            and _exit_code(exited) == _uint32(oracle.get("expectedExitCode"))
            and streams_ok
            and cleanup.get("ok")
        ),
        "init": init,
        "identity": identity,
        "entry": entry,
        "run": run,
        "writeOne": write_one,
        "writeTwo": write_two,
        "closeStdin": close_stdin,
        "exit": exited,
        "stdout": stdout,
        "stderr": stderr,
        "writesExact": writes_ok,
        "streamsExact": streams_ok,
        "cleanup": cleanup,
    }


def _run_launch_file_stdio_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    oracle = _launch_runtime_oracle("typed-stream-binary")
    stdin_bytes = base64.b64decode(str(oracle.get("stdinBase64") or ""))
    expected_stdout = base64.b64decode(str(oracle.get("stdoutBase64") or ""))
    expected_stderr = base64.b64decode(str(oracle.get("stderrBase64") or ""))
    artifact_dir.mkdir(parents=True, exist_ok=True)
    stdin_path = artifact_dir / "stdin.bin"
    stdout_path = artifact_dir / "stdout-truncate.bin"
    stderr_path = artifact_dir / "stderr-append.bin"
    stderr_prefix = b"MCP_APPEND_PREFIX\x00\xff\n"
    stdin_path.write_bytes(stdin_bytes)
    stdout_path.write_bytes(b"MUST_BE_TRUNCATED")
    stderr_path.write_bytes(stderr_prefix)
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=30000,
        retries=1,
        stop_first=True,
        use_scyllahide="off",
        arguments=list(oracle.get("args") or []),
        stdin={"mode": "file", "path": str(stdin_path)},
        stdout={
            "mode": "file",
            "path": str(stdout_path),
            "fileMode": "truncate",
        },
        stderr={
            "mode": "file",
            "path": str(stderr_path),
            "fileMode": "append",
        },
        capture_limit_bytes=4096,
    )
    native = _native_launch_payload(init)
    launch_id = str(native.get("launchId") or "")
    identity = _launch_identity_contract(native, arch)
    execution = _run_launch_to_exit(bridge) if launch_id else {"ok": False}
    actual_stdout = stdout_path.read_bytes() if stdout_path.is_file() else b""
    actual_stderr = stderr_path.read_bytes() if stderr_path.is_file() else b""
    descriptors = native.get("streams") if isinstance(native.get("streams"), dict) else {}
    descriptor_modes = {
        name: str((descriptors.get(name) or {}).get("mode") or "")
        for name in ("stdin", "stdout", "stderr")
    }
    uncaptured = (
        bridge.ReadLaunchStream(launch_id, "stdout", 0, 64, 0)
        if launch_id
        else {}
    )
    files_ok = bool(
        actual_stdout == expected_stdout
        and actual_stderr == stderr_prefix + expected_stderr
        and descriptor_modes
        == {"stdin": "file", "stdout": "file", "stderr": "file"}
        and isinstance(uncaptured, dict)
        and uncaptured.get("ok") is False
    )
    cleanup = _finish_launch_resources(bridge, launch_id) if launch_id else {}
    return {
        "ok": bool(
            isinstance(init, dict)
            and init.get("ok") is True
            and identity.get("ok")
            and execution.get("ok")
            and execution.get("exitCode") == _uint32(oracle.get("expectedExitCode"))
            and files_ok
            and cleanup.get("ok")
        ),
        "init": init,
        "identity": identity,
        "execution": execution,
        "paths": {
            "stdin": str(stdin_path),
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
        },
        "descriptorModes": descriptor_modes,
        "stdoutByteCount": len(actual_stdout),
        "stderrByteCount": len(actual_stderr),
        "stdoutSha256": hashlib.sha256(actual_stdout).hexdigest(),
        "stderrSha256": hashlib.sha256(actual_stderr).hexdigest(),
        "filesExact": files_ok,
        "uncapturedRead": uncaptured,
        "cleanup": cleanup,
    }


def _run_launch_bounded_burst_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir
    capture_limit = 65536
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=30000,
        retries=1,
        stop_first=True,
        use_scyllahide="off",
        arguments=["--case", "burst"],
        stdin={"mode": "null"},
        stdout={"mode": "pipe"},
        stderr={"mode": "pipe"},
        capture_limit_bytes=capture_limit,
    )
    native = _native_launch_payload(init)
    launch_id = str(native.get("launchId") or "")
    identity = _launch_identity_contract(native, arch)
    execution = _run_launch_to_exit(bridge, timeout_ms=30000) if launch_id else {"ok": False}
    stdout = (
        _drain_launch_stream(
            bridge, launch_id, "stdout", max_bytes=1024 * 1024, wait_ms=1000
        )
        if launch_id
        else {}
    )
    stderr = (
        _drain_launch_stream(
            bridge, launch_id, "stderr", max_bytes=1024 * 1024, wait_ms=1000
        )
        if launch_id
        else {}
    )
    stdout_data = stdout.get("data") if isinstance(stdout.get("data"), bytes) else b""
    stderr_data = stderr.get("data") if isinstance(stderr.get("data"), bytes) else b""
    stdout_newest = max(
        (_integer(page.get("newestCursor")) for page in stdout.get("pages", [])),
        default=0,
    )
    stderr_newest = max(
        (_integer(page.get("newestCursor")) for page in stderr.get("pages", [])),
        default=0,
    )
    bounded_ok = bool(
        stdout.get("ok")
        and stderr.get("ok")
        and len(stdout_data) == capture_limit
        and len(stderr_data) == capture_limit
        and stdout.get("cursorTruncated") is True
        and stderr.get("cursorTruncated") is True
        and _integer(stdout.get("totalDroppedBytes")) > 0
        and _integer(stderr.get("totalDroppedBytes")) > 0
        and stdout_newest > 2 * 1024 * 1024
        and stderr_newest > 2 * 1024 * 1024
        and stdout_data.endswith(b"channel=stdout\n")
        and stderr_data.endswith(b"channel=stderr\n")
    )
    cleanup = _finish_launch_resources(bridge, launch_id) if launch_id else {}
    stdout.pop("data", None)
    stderr.pop("data", None)
    return {
        "ok": bool(
            isinstance(init, dict)
            and init.get("ok") is True
            and identity.get("ok")
            and execution.get("ok")
            and execution.get("exitCode") == 0
            and bounded_ok
            and cleanup.get("ok")
        ),
        "init": init,
        "identity": identity,
        "execution": execution,
        "stdout": stdout,
        "stderr": stderr,
        "boundedExact": bounded_ok,
        "cleanup": cleanup,
    }


def _run_launch_explicit_inherit_adapter(
    bridge: Any, exe_path: str, artifact_dir: Path, arch: str
) -> dict[str, Any]:
    del artifact_dir
    init = bridge.InitDebuggee(
        exe_path,
        timeout_ms=20000,
        retries=1,
        stop_first=True,
        use_scyllahide="off",
        arguments=["--case", "quick"],
        stdin={"mode": "inherit"},
        stdout={"mode": "inherit"},
        stderr={"mode": "inherit"},
        capture_limit_bytes=4096,
    )
    native = _native_launch_payload(init)
    launch_id = str(native.get("launchId") or "")
    if isinstance(init, dict) and init.get("ok") is True and launch_id:
        identity = _launch_identity_contract(native, arch)
        descriptors = (
            native.get("streams") if isinstance(native.get("streams"), dict) else {}
        )
        modes = {
            name: str((descriptors.get(name) or {}).get("mode") or "")
            for name in ("stdin", "stdout", "stderr")
        }
        execution = _run_launch_to_exit(bridge)
        cleanup = _finish_launch_resources(bridge, launch_id)
        ok = bool(
            identity.get("ok")
            and modes
            == {"stdin": "inherit", "stdout": "inherit", "stderr": "inherit"}
            and execution.get("ok")
            and execution.get("exitCode") == 0
            and cleanup.get("ok")
        )
        return {
            "ok": ok,
            "outcome": "inherited",
            "init": init,
            "identity": identity,
            "descriptorModes": modes,
            "execution": execution,
            "cleanup": cleanup,
        }

    error_code = str(native.get("errorCode") or init.get("errorCode") or "").casefold()
    state = init.get("state") if isinstance(init, dict) and isinstance(init.get("state"), dict) else {}
    failed_closed = bool(
        error_code == "inherited_handle_invalid"
        and not launch_id
        and state.get("debugging") is False
        and not state.get("processExists")
    )
    return {
        "ok": failed_closed,
        "outcome": "failed_closed",
        "init": init,
        "errorCode": error_code,
        "noDebugSession": state.get("debugging") is False,
        "noProcess": not state.get("processExists"),
    }


def _build_case_scenario(
    spec: CaseSpec,
    headless: Any,
    artifact_dir: Path,
    arch: str,
) -> Callable[[Any, str], Any]:
    """Resolve a matrix case to exactly one tested adapter."""

    special_adapters: dict[str, Callable[[Any, str], Any]] = {
        "__launch_argv_env_cwd__": lambda mod, path: _run_launch_argv_env_cwd_adapter(
            mod, path, artifact_dir, arch
        ),
        "__launch_bytes_stdio__": lambda mod, path: _run_launch_bytes_stdio_adapter(
            mod, path, artifact_dir, arch
        ),
        "__launch_pipe_stdio__": lambda mod, path: _run_launch_pipe_stdio_adapter(
            mod, path, artifact_dir, arch
        ),
        "__launch_file_stdio__": lambda mod, path: _run_launch_file_stdio_adapter(
            mod, path, artifact_dir, arch
        ),
        "__launch_bounded_burst__": lambda mod, path: _run_launch_bounded_burst_adapter(
            mod, path, artifact_dir, arch
        ),
        "__launch_explicit_inherit__": lambda mod, path: _run_launch_explicit_inherit_adapter(
            mod, path, artifact_dir, arch
        ),
        "__minidump_analysis__": lambda mod, path: _run_minidump_adapter(
            mod, path, artifact_dir, arch
        ),
        "__session_identity_cas__": lambda mod, path: _run_session_identity_cas_adapter(
            mod, path, artifact_dir, arch
        ),
        "__breakpoint_ownership__": lambda mod, path: _run_breakpoint_ownership_adapter(
            mod, path, artifact_dir, arch
        ),
        "__http_parser_adversarial__": lambda mod, path: _run_http_parser_adversarial_adapter(
            mod, path, artifact_dir, arch
        ),
        "__dispatcher_concurrency__": lambda mod, path: _run_dispatcher_concurrency_adapter(
            mod, path, artifact_dir, arch
        ),
        "__api_trace_dynamic_resolver__": lambda mod, path: _run_dynamic_api_trace_adapter(
            mod, path, artifact_dir, arch
        ),
        "__api_trace_exception_unwind__": lambda mod, path: _run_api_trace_exception_unwind_adapter(
            mod, path, artifact_dir, arch
        ),
        "__api_trace_managed_exception__": lambda mod, path: _run_real_managed_exception_adapter(
            mod, path, artifact_dir, arch
        ),
        "__managed_runtime_probe__": lambda mod, path: _run_managed_runtime_probe_adapter(
            mod, path, artifact_dir, arch
        ),
        "__heap_resource_trace__": lambda mod, path: _run_heap_resource_trace_adapter(
            mod, path, artifact_dir, arch
        ),
        "__heap_resource_families__": lambda mod, path: _run_heap_resource_trace_adapter(
            mod, path, artifact_dir, arch, resource_matrix=True
        ),
        "__evidence_roundtrip__": lambda mod, path: _run_evidence_roundtrip_adapter(
            mod, path, artifact_dir, arch
        ),
        "__dll_overlay_dump__": lambda mod, path: _run_dll_overlay_dump_adapter(
            mod, path, artifact_dir, arch
        ),
        "__memory_pe_discovery__": lambda mod, path: _run_memory_pe_discovery_adapter(
            mod, path, artifact_dir, arch
        ),
        "__native_coverage__": lambda mod, path: _run_native_coverage_adapter(
            mod, path, artifact_dir, arch
        ),
        "__exception_policy_first_chance__": lambda mod, path: _run_exception_policy_first_chance_adapter(
            mod, path, artifact_dir, arch
        ),
        "__exception_policy_precedence__": lambda mod, path: _run_exception_policy_precedence_adapter(
            mod, path, artifact_dir, arch
        ),
        "__exception_policy_second_chance__": lambda mod, path: _run_exception_policy_second_chance_adapter(
            mod, path, artifact_dir, arch
        ),
        "__exception_policy_lifecycle__": lambda mod, path: _run_exception_policy_lifecycle_adapter(
            mod, path, artifact_dir, arch
        ),
    }
    scenario = special_adapters.get(spec.scenario)
    if scenario is not None:
        return scenario
    scenario = headless.SCENARIOS.get(spec.scenario)
    if not callable(scenario):
        raise RuntimeError(f"Smoke scenario is unavailable: {spec.scenario}")
    return scenario


def _worker_main(args: argparse.Namespace) -> int:
    started_monotonic = time.monotonic()
    started_at = _utc_now()
    worker_path = Path(args.worker_out).resolve()
    artifact_dir = Path(args.worker_artifact_dir).resolve()
    spec = next((item for item in CASE_SPECS if item.name == args.worker_case), None)
    payload: dict[str, Any] = {
        "schemaVersion": WORKER_SCHEMA_VERSION,
        "case": args.worker_case,
        "arch": args.worker_arch,
        "startedAt": started_at,
        "workerPid": os.getpid(),
        "ok": False,
    }
    bridge = None
    ensure: dict[str, Any] = {}
    session_cleanup: dict[str, Any] = {"attempted": False}
    try:
        if spec is None:
            raise RuntimeError(f"Unknown worker case: {args.worker_case}")
        headless = _load_headless_module()
        bridge = headless.load_bridge(args.bridge)
        ensure = ensure_debugger_for_worker(
            bridge,
            args.worker_arch,
            min(int(spec.timeout_seconds * 500), 60000),
        )
        payload["ensure"] = ensure
        if not ensure.get("ok"):
            raise RuntimeError(f"RestartDebugger failed: {ensure.get('error') or ensure}")
        active = getattr(bridge, "_get_active_debugger_info", lambda: {})() or {}
        payload["activeDebugger"] = active
        exe_path = _resolve_case_executable(spec, args.worker_arch, headless)
        payload["exePath"] = exe_path
        scenario = _build_case_scenario(
            spec, headless, artifact_dir, args.worker_arch
        )
        result, session_cleanup = execute_scenario_with_cleanup(
            bridge, scenario, exe_path
        )
        payload["result"] = result
        payload["ok"] = bool(result.get("ok")) and not bool(result.get("skipped"))
    except Exception as exc:
        payload["ok"] = False
        payload["error"] = str(exc)
        payload["exceptionType"] = type(exc).__name__
        payload["traceback"] = traceback.format_exc()
        if bridge is not None and not session_cleanup.get("attempted"):
            session_cleanup["attempted"] = True
            try:
                session_cleanup["debugStop"] = bridge.DebugStop()
            except Exception as cleanup_exc:
                session_cleanup["debugStopError"] = str(cleanup_exc)
    finally:
        payload["sessionCleanup"] = session_cleanup
        payload["finishedAt"] = _utc_now()
        payload["durationSeconds"] = round(
            max(0.0, time.monotonic() - started_monotonic), 3
        )
        _atomic_write_json(worker_path, payload)
    return 0 if payload.get("ok") else 1


def _case_failure(message: str, failure_type: str, details: Any = None) -> dict[str, Any]:
    failure: dict[str, Any] = {"message": message, "type": failure_type}
    if details is not None:
        failure["details"] = details
    return failure


def _finalize_report(report: dict[str, Any]) -> dict[str, Any]:
    testcases = list(report.get("testcases") or [])
    failures = sum(1 for item in testcases if item.get("status") == "failure")
    errors = sum(1 for item in testcases if item.get("status") == "error")
    reported_skips = sum(1 for item in testcases if item.get("reportedSkipped"))
    report.update(
        {
            "tests": len(testcases),
            "failures": failures,
            "errors": errors,
            # Skips are still represented for diagnostics, but every one is a
            # failure and therefore can never make the aggregate green.
            "skipped": reported_skips,
            "time": round(sum(float(item.get("time") or 0.0) for item in testcases), 3),
            "ok": bool(testcases) and failures == 0 and errors == 0 and reported_skips == 0,
            "finishedAt": _utc_now(),
        }
    )
    return report


def _new_report(run_id: str, args: argparse.Namespace, runs: Sequence[tuple[str, CaseSpec]]) -> dict[str, Any]:
    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "name": "x64dbg MCP live release matrix",
        "runId": run_id,
        "startedAt": _utc_now(),
        "properties": {
            "repoRoot": str(REPO_ROOT),
            "bridge": str(Path(args.bridge).resolve()),
            "requestedArch": args.arch,
            "selectedCases": [f"{arch}.{spec.name}" for arch, spec in runs],
            "python": sys.version,
            "platform": sys.platform,
            "hardTimeoutOverrideSeconds": args.timeout_seconds,
        },
        "tests": len(runs),
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "time": 0.0,
        "ok": False,
        "testcases": [],
    }


def _worker_command(
    args: argparse.Namespace,
    arch: str,
    spec: CaseSpec,
    worker_out: Path,
    artifact_dir: Path,
) -> list[str]:
    return [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        "--worker-case",
        spec.name,
        "--worker-arch",
        arch,
        "--worker-out",
        str(worker_out),
        "--worker-artifact-dir",
        str(artifact_dir),
        "--bridge",
        str(Path(args.bridge).resolve()),
    ]


def _run_parent_case(
    args: argparse.Namespace,
    arch: str,
    spec: CaseSpec,
    run_dir: Path,
) -> dict[str, Any]:
    case_id = f"{arch}.{spec.name}"
    case_dir = run_dir / "cases" / case_id
    artifact_dir = case_dir / "artifacts"
    case_dir.mkdir(parents=True, exist_ok=True)
    worker_out = case_dir / "worker.json"
    stdout_path = case_dir / "stdout.log"
    stderr_path = case_dir / "stderr.log"
    expected_debugger_name = "x64dbg.exe" if arch == "x64" else "x32dbg.exe"
    before = snapshot_processes()
    existing = debugger_processes(before)
    if existing:
        return {
            "name": case_id,
            "classname": f"x64dbgMCP.live.{arch}",
            "arch": arch,
            "case": spec.name,
            "time": 0.0,
            "status": "error",
            "failure": _case_failure(
                "A debugger appeared before the isolated case started.",
                "PREEXISTING_DEBUGGER",
                [asdict(item) for item in existing],
            ),
            "cleanup": {"ok": False, "notAttempted": True},
        }
    observed_roots: dict[tuple[int, str, int], ProcessIdentity] = {}
    observed_descendants: dict[tuple[int, str, int], ProcessIdentity] = {}
    monitor_errors: list[str] = []

    def monitor() -> None:
        try:
            current = snapshot_processes()
            roots = [
                item
                for item in current
                if item.name.casefold() == expected_debugger_name.casefold()
                and item.creation_time > 0
            ]
            for item in roots:
                observed_roots[item.key] = item
            for item in descendant_processes(current, [root.pid for root in roots]):
                if item.creation_time > 0:
                    observed_descendants[item.key] = item
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            if not monitor_errors or monitor_errors[-1] != message:
                monitor_errors.append(message)

    command = _worker_command(args, arch, spec, worker_out, artifact_dir)
    creationflags = 0x00000200 if os.name == "nt" else 0  # CREATE_NEW_PROCESS_GROUP
    timeout = float(args.timeout_seconds or spec.timeout_seconds)
    outcome = WatchdogOutcome(None, False, 0.0, None)
    lifecycle_error: Optional[dict[str, Any]] = None
    process: Any = None
    cleanup: dict[str, Any] = {
        "ok": False,
        "errorCode": "CLEANUP_NOT_ATTEMPTED",
    }
    try:
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            process = subprocess.Popen(
                command,
                cwd=str(REPO_ROOT),
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                creationflags=creationflags,
                start_new_session=os.name != "nt",
            )
            outcome = wait_with_watchdog(
                process,
                timeout,
                poll_interval=0.1,
                on_poll=monitor,
            )
    except Exception as exc:
        lifecycle_error = {
            "message": str(exc),
            "type": type(exc).__name__,
            "traceback": traceback.format_exc(),
        }
        termination = None
        if process is not None and process.poll() is None:
            termination = _terminate_worker_tree(int(process.pid))
        outcome = WatchdogOutcome(
            process.poll() if process is not None else None,
            False,
            outcome.elapsed_seconds,
            termination,
        )
    finally:
        # This path is independent of the worker's own finally block.  It also
        # runs after worker crashes, malformed reports and watchdog failures.
        monitor()
        try:
            cleanup = cleanup_owned_processes(
                observed_roots.values(), observed_descendants.values()
            )
        except Exception as exc:
            cleanup = {
                "ok": False,
                "errorCode": "CLEANUP_EXCEPTION",
                "error": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc(),
            }
        if monitor_errors:
            cleanup["ok"] = False
            cleanup["monitorErrors"] = monitor_errors
    worker: dict[str, Any] = {}
    if worker_out.is_file():
        try:
            loaded = json.loads(worker_out.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                worker = loaded
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            worker = {"ok": False, "error": f"Invalid worker report: {exc}"}
    status = "success"
    failure = None
    reported_skipped = bool((worker.get("result") or {}).get("skipped")) if isinstance(worker.get("result"), dict) else False
    if lifecycle_error is not None:
        status = "error"
        failure = _case_failure(
            "The parent could not complete the isolated worker lifecycle.",
            "WORKER_LIFECYCLE_ERROR",
            lifecycle_error,
        )
    elif outcome.timed_out:
        status = "error"
        failure = _case_failure(
            f"Hard timeout after {timeout:.3f} seconds.",
            "HARD_TIMEOUT",
            outcome.termination,
        )
    elif outcome.returncode != 0 or not worker.get("ok") or reported_skipped:
        status = "failure"
        failure = _case_failure(
            str(
                worker.get("error")
                or ((worker.get("result") or {}).get("error") if isinstance(worker.get("result"), dict) else "")
                or f"Worker exited with code {outcome.returncode}."
            ),
            "SKIP_REJECTED" if reported_skipped else "LIVE_ASSERTION_FAILED",
            worker,
        )
    if not cleanup.get("ok"):
        status = "error"
        failure = _case_failure(
            "PID-safe debugger cleanup did not complete.",
            "CLEANUP_FAILED",
            cleanup,
        )
    testcase: dict[str, Any] = {
        "name": case_id,
        "classname": f"x64dbgMCP.live.{arch}",
        "arch": arch,
        "case": spec.name,
        "description": spec.description,
        "time": round(outcome.elapsed_seconds, 3),
        "status": status,
        "timeoutSeconds": timeout,
        "timedOut": outcome.timed_out,
        "returncode": outcome.returncode,
        "reportedSkipped": reported_skipped,
        "workerReport": str(worker_out),
        "systemOut": str(stdout_path),
        "systemErr": str(stderr_path),
        "worker": worker,
        "cleanup": cleanup,
    }
    if failure is not None:
        testcase["failure"] = failure
    return testcase


class _RunLock:
    def __init__(self) -> None:
        self.path = Path(tempfile.gettempdir()) / "x64dbg-mcp-live-release-matrix.lock"
        self.owned = False

    def __enter__(self) -> "_RunLock":
        payload = json.dumps({"pid": os.getpid(), "startedAt": _utc_now()}).encode("utf-8")
        try:
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            stale = True
            try:
                existing = json.loads(self.path.read_text(encoding="utf-8"))
                existing_pid = int(existing.get("pid") or 0)
                stale = lookup_process_identity(existing_pid) is None
            except Exception:
                stale = True
            if not stale:
                raise RuntimeError(f"Another live release matrix owns {self.path}")
            try:
                self.path.unlink()
            except OSError:
                pass
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        self.owned = True
        return self

    def __exit__(self, *_: Any) -> None:
        if self.owned:
            try:
                self.path.unlink()
            except OSError:
                pass
        self.owned = False


def _take_over_existing_debuggers(existing: Sequence[ProcessIdentity]) -> dict[str, Any]:
    snapshot = snapshot_processes()
    descendants = descendant_processes(snapshot, [item.pid for item in existing])
    return cleanup_owned_processes(existing, descendants)


def _parent_main(args: argparse.Namespace) -> int:
    try:
        runs = select_case_runs(args.arch, args.case)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    run_id = args.run_id or f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
    run_dir = Path(args.out_dir or (DEFAULT_RESULTS_ROOT / run_id)).resolve()
    report_path = Path(args.out).resolve() if args.out else run_dir / "report.json"
    run_dir.mkdir(parents=True, exist_ok=True)
    report = _new_report(run_id, args, runs)
    _atomic_write_json(report_path, report)
    try:
        with _RunLock():
            existing = debugger_processes()
            if existing:
                if not args.take_over_existing_debugger:
                    failure = _case_failure(
                        "Existing x32dbg/x64dbg session detected; refusing to disrupt it.",
                        "PREEXISTING_DEBUGGER",
                        [asdict(item) for item in existing],
                    )
                    report["preflightFailure"] = failure
                    report["testcases"].append(
                        {
                            "name": "preflight.exclusive_debugger",
                            "classname": "x64dbgMCP.live.preflight",
                            "time": 0.0,
                            "status": "error",
                            "failure": failure,
                        }
                    )
                    _finalize_report(report)
                    _atomic_write_json(report_path, report)
                    return 2
                takeover = _take_over_existing_debuggers(existing)
                report["takeOverCleanup"] = takeover
                if not takeover.get("ok"):
                    failure = _case_failure(
                        "Could not safely take over the existing debugger session.",
                        "TAKEOVER_CLEANUP_FAILED",
                        takeover,
                    )
                    report["preflightFailure"] = failure
                    report["testcases"].append(
                        {
                            "name": "preflight.takeover_cleanup",
                            "classname": "x64dbgMCP.live.preflight",
                            "time": 0.0,
                            "status": "error",
                            "failure": failure,
                        }
                    )
                    _finalize_report(report)
                    _atomic_write_json(report_path, report)
                    return 2
            for arch, spec in runs:
                testcase = _run_parent_case(args, arch, spec, run_dir)
                report["testcases"].append(testcase)
                _finalize_report(report)
                _atomic_write_json(report_path, report)
    except Exception as exc:
        runner_error = {
            "message": str(exc),
            "type": type(exc).__name__,
            "traceback": traceback.format_exc(),
        }
        report["runnerError"] = runner_error
        report["testcases"].append(
            {
                "name": "runner.internal_error",
                "classname": "x64dbgMCP.live.runner",
                "time": 0.0,
                "status": "error",
                "failure": runner_error,
            }
        )
        _finalize_report(report)
        _atomic_write_json(report_path, report)
        print(json.dumps({"ok": False, "report": str(report_path), "error": str(exc)}, ensure_ascii=False))
        return 2
    _finalize_report(report)
    _atomic_write_json(report_path, report)
    print(
        json.dumps(
            {
                "ok": report["ok"],
                "report": str(report_path),
                "tests": report["tests"],
                "failures": report["failures"],
                "errors": report["errors"],
                "skipped": report["skipped"],
                "time": report["time"],
            },
            ensure_ascii=False,
        )
    )
    return 0 if report["ok"] else 1


def _list_payload() -> dict[str, Any]:
    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "architectures": list(ARCHITECTURES),
        "cases": [asdict(spec) for spec in CASE_SPECS],
        "runCountAll": len(CASE_SPECS) * len(ARCHITECTURES),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run isolated x86/x64 live x64dbg MCP release cases."
    )
    parser.add_argument("--arch", choices=["all", "x86", "x64"], default="all")
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Case name (repeatable/comma-separated), optionally prefixed with x86. or x64.",
    )
    parser.add_argument("--list", action="store_true", help="List cases without touching x64dbg.")
    parser.add_argument("--bridge", default=str(DEFAULT_BRIDGE))
    parser.add_argument("--out-dir")
    parser.add_argument("--out", help="Exact JSON report path; defaults to <out-dir>/report.json.")
    parser.add_argument("--run-id")
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        help="Override every per-case hard deadline (primarily for diagnosis).",
    )
    parser.add_argument(
        "--take-over-existing-debugger",
        action="store_true",
        help="Explicitly authorize PID-safe termination of a pre-existing x32dbg/x64dbg session.",
    )
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--worker-case", help=argparse.SUPPRESS)
    parser.add_argument("--worker-arch", choices=["x86", "x64"], help=argparse.SUPPRESS)
    parser.add_argument("--worker-out", help=argparse.SUPPRESS)
    parser.add_argument("--worker-artifact-dir", help=argparse.SUPPRESS)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.list:
        print(json.dumps(_list_payload(), ensure_ascii=False, indent=2))
        return 0
    if args.timeout_seconds is not None and args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")
    if args.worker:
        missing = [
            name
            for name in ("worker_case", "worker_arch", "worker_out", "worker_artifact_dir")
            if not getattr(args, name)
        ]
        if missing:
            parser.error(f"worker mode is missing: {', '.join(missing)}")
        return _worker_main(args)
    return _parent_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
