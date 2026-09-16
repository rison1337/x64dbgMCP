"""Live x64dbg gate for PID-bound hollowed-child identity and dump recovery."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import queue
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_hollow_live", MODULE_PATH)
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


def _pump(stream, output: list[str], events: queue.Queue[str]) -> None:
    try:
        for line in iter(stream.readline, ""):
            output.append(line)
            events.put(line)
    finally:
        stream.close()


def _start_hollowed_child(arch: str) -> dict[str, Any]:
    directory = REPO_ROOT / "tools" / "bin" / "e2e" / arch
    parent_path = directory / "process_hollowing.exe"
    host_path = directory / "hollow_host.exe"
    payload_path = directory / "hollow_payload.exe"
    environment = os.environ.copy()
    environment["X64DBG_MCP_E2E_HOLLOW_HOLD_MS"] = "30000"
    environment["X64DBG_MCP_E2E_HOLLOW_BREAK"] = "1"
    process = subprocess.Popen(
        [str(parent_path), str(host_path), str(payload_path), "12000"],
        cwd=str(directory),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert process.stdout is not None and process.stderr is not None
    stdout: list[str] = []
    stderr: list[str] = []
    events: queue.Queue[str] = queue.Queue()
    threading.Thread(target=_pump, args=(process.stdout, stdout, events), daemon=True).start()
    threading.Thread(target=_pump, args=(process.stderr, stderr, queue.Queue()), daemon=True).start()
    deadline = time.monotonic() + 10.0
    child_pid = 0
    event_line = ""
    while time.monotonic() < deadline and process.poll() is None:
        try:
            line = events.get(timeout=0.25)
        except queue.Empty:
            continue
        if "HOLLOW_EVENT" not in line:
            continue
        event_line = line.strip()
        for token in event_line.split():
            if token.startswith("childPid="):
                child_pid = int(token.split("=", 1)[1], 10)
                break
        if child_pid:
            break
    if not child_pid:
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError(
            f"{arch} hollow parent did not publish a child PID: "
            f"stdout={''.join(stdout)!r} stderr={''.join(stderr)!r}"
        )
    return {
        "process": process,
        "stdout": stdout,
        "stderr": stderr,
        "event": event_line,
        "childPid": child_pid,
        "directory": directory,
        "parentPath": parent_path,
        "hostPath": host_path,
        "payloadPath": payload_path,
    }


def _smoke(path: Path) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["X64DBG_MCP_E2E_HOLLOW_HOLD_MS"] = "10"
    completed = subprocess.run(
        [str(path)],
        cwd=str(path.parent),
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )
    return {
        "ok": completed.returncode == 42
        and "HOLLOW_PAYLOAD_OK identity=payload" in completed.stdout,
        "exitCode": completed.returncode & 0xFFFFFFFF,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _terminate_fixture_process(pid: int, expected_path: Path) -> dict[str, Any]:
    """Terminate only the exact corpus image published by this live gate."""

    if os.name != "nt" or int(pid) <= 0:
        return {"ok": True, "skipped": True, "reason": "not-applicable"}
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    open_process.restype = ctypes.c_void_p
    query_image = kernel32.QueryFullProcessImageNameW
    query_image.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    query_image.restype = ctypes.c_int
    terminate_process = kernel32.TerminateProcess
    terminate_process.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    terminate_process.restype = ctypes.c_int
    wait_for_single = kernel32.WaitForSingleObject
    wait_for_single.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    wait_for_single.restype = ctypes.c_ulong
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int

    process_query_limited_information = 0x1000
    process_terminate = 0x0001
    handle = open_process(
        process_query_limited_information | process_terminate, 0, int(pid)
    )
    if not handle:
        error = ctypes.get_last_error()
        # The debugger may already have terminated the corpus child.
        if error in (87, 1168):
            return {"ok": True, "skipped": True, "reason": "already-exited"}
        return {"ok": False, "error": f"OpenProcess({pid}) failed: {error}"}
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.c_ulong(len(buffer))
        if not query_image(handle, 0, buffer, ctypes.byref(length)):
            return {
                "ok": False,
                "error": f"QueryFullProcessImageNameW({pid}) failed: "
                f"{ctypes.get_last_error()}",
            }
        observed = Path(buffer.value)
        expected = expected_path.resolve()
        if os.path.normcase(str(observed.resolve())) != os.path.normcase(str(expected)):
            return {
                "ok": False,
                "error": "cleanup identity mismatch",
                "observedPath": str(observed),
                "expectedPath": str(expected),
            }
        if not terminate_process(handle, 0xEE):
            return {
                "ok": False,
                "error": f"TerminateProcess({pid}) failed: {ctypes.get_last_error()}",
            }
        wait_for_single(handle, 5000)
        return {"ok": True, "terminated": True, "pid": int(pid)}
    finally:
        close_handle(handle)


def _one_arch(module: Any, arch: str, artifact_root: Path) -> dict[str, Any]:
    fixture = _start_hollowed_child(arch)
    parent: subprocess.Popen[str] = fixture["process"]
    child_pid = int(fixture["childPid"])
    artifact_root.mkdir(parents=True, exist_ok=True)
    dump_path = artifact_root / f"hollow_payload-{arch}.dump.exe"
    minidump_path = artifact_root / f"hollow_payload-{arch}.dmp"
    try:
        attach = module.AttachToProcess(
            pid=child_pid,
            arch=arch,
            restart_debugger=True,
            stop_first=True,
            timeout_ms=30000,
        )
        if not isinstance(attach, dict) or not attach.get("ok"):
            raise RuntimeError(f"{arch} attach failed: {attach}")
        identity = module.InspectProcessPayload(
            minimum_code_similarity=0.70,
            scan_candidates=True,
            max_candidates=128,
        )
        if not identity.get("ok") or not identity.get("likelyHollowed"):
            raise RuntimeError(f"{arch} hollow identity was not confirmed: {identity}")
        if int(identity.get("pid") or 0) != child_pid:
            raise RuntimeError(f"{arch} identity PID mismatch: {identity}")
        selected = (identity.get("selection") or {}).get("selected") or {}
        base = str(selected.get("base") or (identity.get("mainModule") or {}).get("runtimeBase") or "")
        if not base:
            raise RuntimeError(f"{arch} payload base was not selected: {identity}")
        rebuilt = module.DumpPeFromMemory(
            base=base,
            output_path=str(dump_path),
            header_template_path=str(fixture["payloadPath"]),
            verify_template_identity=True,
            minimum_template_similarity=0.70,
            reset_mutable_sections_from_template=True,
            reverse_relocations=True,
            source_layout="memory",
            verify=True,
            overwrite=True,
        )
        if not rebuilt.get("ok") or not rebuilt.get("reloadable"):
            raise RuntimeError(f"{arch} payload reconstruction failed: {rebuilt}")
        pause = module.WaitForPause(timeout_ms=30000, poll_ms=100)
        if not isinstance(pause, dict) or not pause.get("paused"):
            raise RuntimeError(f"{arch} payload did not reach its live gate pause: {pause}")
        minidump = module.WriteMiniDump(
            output_path=str(minidump_path),
            dump_type="analysis",
            overwrite=True,
            pause_if_running=False,
            resume_after=False,
            timeout_ms=120000,
        )
        if not minidump.get("ok"):
            raise RuntimeError(f"{arch} payload minidump failed: {minidump}")
        stop = module.DebugStop()
        smoke = _smoke(dump_path)
        if not smoke["ok"]:
            raise RuntimeError(f"{arch} reconstructed payload smoke failed: {smoke}")
        return {
            "ok": True,
            "arch": arch,
            "fixture": {
                "event": fixture["event"],
                "parentPid": parent.pid,
                "childPid": child_pid,
                "host": {"path": str(fixture["hostPath"]), "sha256": _sha256(fixture["hostPath"])},
                "payload": {"path": str(fixture["payloadPath"]), "sha256": _sha256(fixture["payloadPath"])},
            },
            "attach": attach,
            "identity": identity,
            "rebuild": rebuilt,
            "dump": {"path": str(dump_path), "sha256": _sha256(dump_path)},
            "minidump": minidump,
            "smoke": smoke,
            "stop": stop,
        }
    finally:
        try:
            module.DebugStop()
        except Exception:
            pass
        _terminate_fixture_process(child_pid, fixture["hostPath"])
        if parent.poll() is None:
            parent.kill()
        try:
            parent.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=("x64", "x86", "all"), default="all")
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "tools" / "dump_outputs" / "stage5e-hollowing-live.json",
    )
    args = parser.parse_args()
    module = _load_module()
    architectures = ["x64", "x86"] if args.arch == "all" else [args.arch]
    artifact_root = args.output.resolve().parent / "stage5e-hollowing-live"
    report: dict[str, Any] = {
        "schema": "stage5e-process-hollowing-live-v1",
        "ok": False,
        "architectures": architectures,
        "results": [],
    }
    try:
        for arch in architectures:
            report["results"].append(_one_arch(module, arch, artifact_root))
        report["ok"] = all(item.get("ok") for item in report["results"])
    except Exception as exc:
        report["error"] = str(exc)
        report["traceback"] = traceback.format_exc()
    args.output.resolve().parent.mkdir(parents=True, exist_ok=True)
    canonical = json.dumps(report, ensure_ascii=False, sort_keys=True).encode("utf-8")
    report["reportSha256"] = hashlib.sha256(canonical).hexdigest().upper()
    args.output.resolve().write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
