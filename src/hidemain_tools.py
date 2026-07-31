"""Optional HideMain/EbloDDG integration for the x64dbg MCP server.

HideMain originally shipped as a legacy x64 kernel anti-anti-debug driver.  Its
SSDT/code-cave build is detected and blocked fail-closed after a confirmed
PatchGuard 0x109 crash.  Only the non-kernel-patching protocol-v2 build may be
started or receive new Hide requests; cleanup/status remain available.

Protocol v2 adds an authoritative status/capability query while preserving the
existing Hide/Unhide IOCTL numbers.
"""

from __future__ import annotations

import atexit
import configparser
import ctypes
import functools
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


SERVICE_NAME = "EbloDDG"
DEVICE_PATH = r"\\.\EbloDDG"
DRIVER_FILE = "EbloDDG.sys"
PLUGIN_FILE = "EbloDDGPlugin.dp64"
CLI_FILE = "EbloDDGCLI.exe"
UPSTREAM_PLUGIN_SHA256 = "4286C436AD7C429A5FF678C5518D9900574D7909809947DB7FCBEA3D59E072BF"
MCP_FIXED_PLUGIN_SHA256 = "A7889FC3416524F39A5F24C1CEFA3CB86D0E942A2C27A6F3F52CC84E43C67839"
SAFE_DRIVER_MARKER = b"EbloDDG.SafeV2.NoKernelPatching"
LEGACY_DRIVER_MARKERS = (
    b"FindCaveAddress",
    b"HookInline (cave)",
    b"SSDT write",
    b"SsdtHook",
)

FILE_DEVICE_UNKNOWN = 0x22
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
IOCTL_HIDE_PID = (
    (FILE_DEVICE_UNKNOWN << 16) | (FILE_ANY_ACCESS << 14) | (0x800 << 2) | METHOD_BUFFERED
)
IOCTL_UNHIDE_PID = (
    (FILE_DEVICE_UNKNOWN << 16) | (FILE_ANY_ACCESS << 14) | (0x801 << 2) | METHOD_BUFFERED
)
IOCTL_QUERY_STATUS = (
    (FILE_DEVICE_UNKNOWN << 16) | (FILE_ANY_ACCESS << 14) | (0x802 << 2) | METHOD_BUFFERED
)
PROTOCOL_MAGIC_V2 = 0x32484445
PROTOCOL_STATUS_V2 = struct.Struct("<IHHQQ")
CAPABILITY_SAFE_KERNEL_NO_PATCHING = 1 << 0
CAPABILITY_TARGET_SELECTION = 1 << 1
CAPABILITY_PEB_BEING_DEBUGGED = 1 << 2
PROTOCOL_REQUIRED_CAPABILITIES = (
    CAPABILITY_SAFE_KERNEL_NO_PATCHING
    | CAPABILITY_TARGET_SELECTION
    | CAPABILITY_PEB_BEING_DEBUGGED
)

_SERVICE_STATES = {
    1: "stopped",
    2: "start_pending",
    3: "stop_pending",
    4: "running",
    5: "continue_pending",
    6: "pause_pending",
    7: "paused",
}

_PROTOCOL_LOCK = threading.RLock()


def _protocol_locked(fn: Callable) -> Callable:
    """Serialize service mutations and the driver's single-target protocol."""

    @functools.wraps(fn)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        with _PROTOCOL_LOCK:
            return fn(*args, **kwargs)

    return wrapped


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _same_file_content(left: str, right: str) -> bool:
    try:
        return os.path.getsize(left) == os.path.getsize(right) and _sha256(left) == _sha256(right)
    except OSError:
        return False


def _driver_binary_info(path: str) -> Dict[str, Any]:
    """Classify a driver without executing it.

    Safe v2 exports a marker that is deliberately retained in the PE image.  Any
    unknown image fails closed: the legacy build modifies ntoskrnl module padding
    and the SSDT, which caused bugcheck 0x109/arg4=0x1E on the test host.
    """
    exists = bool(path and os.path.isfile(path))
    payload: Dict[str, Any] = {
        "path": path,
        "exists": exists,
        "size": os.path.getsize(path) if exists else 0,
        "sha256": _sha256(path) if exists else "",
        "embeddedSignature": _pe_has_embedded_signature(path) if exists else False,
        "variant": "absent",
        "safeMarker": False,
        "legacyKernelPatchMarkers": [],
    }
    if not exists:
        return payload
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        payload.update(variant="unreadable", error=str(exc))
        return payload
    safe = SAFE_DRIVER_MARKER in data
    legacy = [marker.decode("ascii") for marker in LEGACY_DRIVER_MARKERS if marker in data]
    payload.update(
        safeMarker=safe,
        legacyKernelPatchMarkers=legacy,
        variant=(
            "safe-v2-no-kernel-patching"
            if safe and not legacy
            else "legacy-kernel-patching-v1"
            if legacy
            else "unknown"
        ),
    )
    return payload


def _driver_load_policy(path: str) -> Dict[str, Any]:
    binary = _driver_binary_info(path)
    allowed = bool(
        binary.get("exists")
        and binary.get("safeMarker")
        and not binary.get("legacyKernelPatchMarkers")
    )
    if allowed:
        reason = "Safe v2 marker present; no legacy SSDT/code-cave markers found."
    elif binary.get("legacyKernelPatchMarkers"):
        reason = (
            "Blocked legacy EbloDDG build: it patches ntoskrnl module padding and "
            "the SSDT and caused CRITICAL_STRUCTURE_CORRUPTION (0x109/arg4=0x1E)."
        )
    elif binary.get("exists"):
        reason = "Blocked unknown EbloDDG build: the safe v2 no-kernel-patching marker is absent."
    else:
        reason = "Driver image was not found."
    return {
        "allowed": allowed,
        "failClosed": True,
        "binary": binary,
        "reason": reason,
    }


def _plugin_binary_info(path: str) -> Dict[str, Any]:
    exists = bool(path and os.path.isfile(path))
    sha256 = _sha256(path) if exists else ""
    if sha256 == MCP_FIXED_PLUGIN_SHA256:
        variant = "safe-v2-plugin-v5"
        known_issues: List[str] = []
    elif sha256 == UPSTREAM_PLUGIN_SHA256:
        variant = "upstream-v1"
        known_issues = [
            "The upstream plugin ignores its disabled flag in process/thread callbacks.",
            "Its legacy create callbacks can observe PID 0 on newer x64dbg builds.",
        ]
    else:
        variant = "unknown" if exists else "absent"
        known_issues = (
            ["Unknown plugin build; enabled-state and callback compatibility were not verified."]
            if exists
            else []
        )
    return {
        "exists": exists,
        "sha256": sha256,
        "variant": variant,
        "knownIssues": known_issues,
    }


def _pe_has_embedded_signature(path: str) -> bool:
    """Return whether the PE security directory contains an embedded signature."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(4096)
        if len(data) < 0x40 or data[:2] != b"MZ":
            return False
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data):
            with open(path, "rb") as handle:
                handle.seek(pe_offset)
                data = handle.read(512)
            optional_offset = 24
        else:
            optional_offset = pe_offset + 24
        if optional_offset + 2 > len(data):
            return False
        magic = struct.unpack_from("<H", data, optional_offset)[0]
        directory_offset = optional_offset + (112 if magic == 0x20B else 96 if magic == 0x10B else 0)
        if not directory_offset or directory_offset + (8 * 5) > len(data):
            return False
        cert_offset, cert_size = struct.unpack_from("<II", data, directory_offset + (8 * 4))
        return cert_offset > 0 and cert_size > 0
    except (OSError, ValueError, struct.error):
        return False


def _authenticode_status(path: str) -> Dict[str, Any]:
    """Verify the exact embedded signature through Windows Authenticode policy."""
    if os.name != "nt" or not path or not os.path.isfile(path):
        return {"ok": False, "status": "NotFound", "path": path}
    script = (
        "$s=Get-AuthenticodeSignature -LiteralPath $env:HIDEMAIN_VERIFY_PATH;"
        "[pscustomobject]@{Status=[string]$s.Status;Message=$s.StatusMessage;"
        "Thumbprint=if($s.SignerCertificate){$s.SignerCertificate.Thumbprint}else{''}}"
        "|ConvertTo-Json -Compress"
    )
    try:
        child_env = os.environ.copy()
        child_env["HIDEMAIN_VERIFY_PATH"] = path
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            creationflags=0x08000000,
            env=child_env,
        )
        stdout = _decode_process_output(completed.stdout or b"").strip()
        payload = json.loads(stdout) if stdout else {}
        status = str(payload.get("Status") or "UnknownError")
        return {
            "ok": completed.returncode == 0 and status.lower() == "valid",
            "status": status,
            "message": str(payload.get("Message") or ""),
            "thumbprint": str(payload.get("Thumbprint") or ""),
            "returncode": int(completed.returncode),
            "path": path,
        }
    except Exception as exc:
        return {"ok": False, "status": "VerificationError", "path": path, "error": str(exc)}


def _candidate_distribution_roots(explicit: str = "") -> List[str]:
    candidates: List[str] = []
    home = str(Path.home())
    for raw in (
        explicit,
        os.getenv("HIDEMAIN_ROOT"),
        os.getenv("HIDEMAIN_HOME"),
        os.path.join(home, "Downloads", "hidemain"),
    ):
        value = os.path.abspath(os.path.expandvars(os.path.expanduser(str(raw or "").strip()))) if raw else ""
        if value and value not in candidates:
            candidates.append(value)
    return candidates


def _find_distribution_root(explicit: str = "") -> Dict[str, Any]:
    checked: List[str] = []
    for base in _candidate_distribution_roots(explicit):
        nested = [
            base,
            os.path.join(base, "Hide-main"),
            os.path.join(base, "Hide-main", "Hide-main"),
        ]
        for candidate in nested:
            candidate = os.path.abspath(candidate)
            if candidate in checked:
                continue
            checked.append(candidate)
            assets = {
                "driver": os.path.join(candidate, DRIVER_FILE),
                "plugin": os.path.join(candidate, PLUGIN_FILE),
                "cli": os.path.join(candidate, CLI_FILE),
            }
            if any(os.path.isfile(path) for path in assets.values()):
                return {"ok": True, "root": candidate, "assets": assets, "checked": checked}
    return {
        "ok": False,
        "root": "",
        "assets": {},
        "checked": checked,
        "error": "HideMain distribution was not found. Set HIDEMAIN_ROOT to its directory.",
    }


def _read_registry_dword(path: str, name: str) -> Optional[int]:
    if os.name != "nt":
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            value, _ = winreg.QueryValueEx(key, name)
        return int(value)
    except (OSError, ValueError, TypeError):
        return None


def _read_service_image_path() -> str:
    if os.name != "nt":
        return ""
    try:
        import winreg

        path = rf"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            value, _ = winreg.QueryValueEx(key, "ImagePath")
        normalized = os.path.expandvars(str(value or "").strip().strip('"'))
        if normalized.startswith("\\??\\"):
            normalized = normalized[4:]
        if normalized.lower().startswith("\\systemroot\\"):
            normalized = os.path.join(
                os.environ.get("SystemRoot", r"C:\Windows"), normalized[12:]
            )
        return normalized
    except OSError:
        return ""


_DEVICE_GUARD_CACHE: Dict[str, Any] = {}


def _device_guard_status() -> Dict[str, Any]:
    """Authoritatively query the VBS / HVCI *running* state via Win32_DeviceGuard.

    The registry HVCI flag alone is not sufficient: a machine can run
    Virtualization-Based Security (Secure Kernel) with that key cleared, and
    loading a legacy kernel-patching driver there triggers a SECURE_KERNEL_ERROR
    bug check (0x18B, an immediate system crash).  ``VirtualizationBasedSecurityStatus
    == 2`` means VBS is enabled *and running*; ``SecurityServicesRunning`` containing
    ``2`` means HVCI/Memory-Integrity is live.  A successful result is cached because
    the state cannot change without a reboot; failures are not cached.
    """
    if os.name != "nt":
        return {"vbsRunning": None, "hvciRunning": None, "vbsStatus": None, "source": "non-windows"}
    if _DEVICE_GUARD_CACHE:
        return dict(_DEVICE_GUARD_CACHE)
    script = (
        "$d=Get-CimInstance -ClassName Win32_DeviceGuard "
        "-Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction Stop;"
        "[pscustomobject]@{Vbs=[int]$d.VirtualizationBasedSecurityStatus;"
        "Running=@($d.SecurityServicesRunning)}|ConvertTo-Json -Compress"
    )
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
            creationflags=0x08000000,
        )
        stdout = _decode_process_output(completed.stdout or b"").strip()
        payload = json.loads(stdout) if stdout else {}
        vbs_status = int(payload.get("Vbs") or 0)
        running = payload.get("Running")
        if isinstance(running, int):
            running = [running]
        running_ids = [int(x) for x in (running or [])]
        result = {
            "vbsStatus": vbs_status,
            "vbsRunning": vbs_status == 2,
            "hvciRunning": 2 in running_ids,
            "credentialGuardRunning": 1 in running_ids,
            "securityServicesRunning": running_ids,
            "source": "cim",
        }
        _DEVICE_GUARD_CACHE.update(result)
        return dict(result)
    except Exception as exc:
        return {
            "vbsStatus": None,
            "vbsRunning": None,
            "hvciRunning": None,
            "credentialGuardRunning": None,
            "source": "error",
            "error": str(exc),
        }


def _windows_security_status() -> Dict[str, Any]:
    hvci = _read_registry_dword(
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        "Enabled",
    )
    vbs = _read_registry_dword(
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "EnableVirtualizationBasedSecurity",
    )
    vulnerable_blocklist = _read_registry_dword(
        r"SYSTEM\CurrentControlSet\Control\CI\Config",
        "VulnerableDriverBlocklistEnable",
    )
    device_guard = _device_guard_status()
    vbs_running = device_guard.get("vbsRunning")
    hvci_running = device_guard.get("hvciRunning")
    blockers: List[str] = []
    if vbs_running:
        blockers.append(
            "Virtualization-Based Security (Secure Kernel) is running; loading the "
            "legacy kernel-patching driver triggers a SECURE_KERNEL_ERROR bug check "
            "(0x18B, an immediate system crash)."
        )
    if hvci_running or hvci == 1:
        blockers.append("Memory Integrity/HVCI is enabled; the legacy inline-hook driver is incompatible.")
    if vulnerable_blocklist == 1:
        blockers.append("The Microsoft vulnerable-driver blocklist is enabled.")
    # The authoritative running-state signals decide whether kernel patching is
    # fatal here; the registry flags are kept for diagnostics only.
    kernel_patching_blocked = bool(vbs_running or hvci_running or hvci == 1)
    return {
        "hvciConfigured": None if hvci is None else bool(hvci),
        "vbsConfigured": None if vbs is None else bool(vbs),
        "vbsRunning": vbs_running,
        "hvciRunning": hvci_running,
        "vbsStatus": device_guard.get("vbsStatus"),
        "deviceGuard": device_guard,
        "kernelPatchingBlocked": kernel_patching_blocked,
        "vulnerableDriverBlocklistConfigured": (
            None if vulnerable_blocklist is None else bool(vulnerable_blocklist)
        ),
        "blockers": blockers,
    }


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _decode_process_output(data: bytes) -> str:
    for encoding in ("utf-8", "cp866", "cp1251", "mbcs"):
        try:
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


def _run_sc(arguments: List[str], timeout_sec: float = 15.0) -> Dict[str, Any]:
    if os.name != "nt":
        return {"ok": False, "returncode": -1, "error": "HideMain driver management is Windows-only."}
    started = time.time()
    try:
        completed = subprocess.run(
            ["sc.exe", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=max(1.0, float(timeout_sec)),
            creationflags=0x08000000,
        )
        stdout = _decode_process_output(completed.stdout or b"").strip()
        stderr = _decode_process_output(completed.stderr or b"").strip()
        return {
            "ok": completed.returncode == 0,
            "returncode": int(completed.returncode),
            "stdout": stdout,
            "stderr": stderr,
            "elapsedMs": round((time.time() - started) * 1000, 2),
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": -1,
            "error": str(exc),
            "elapsedMs": round((time.time() - started) * 1000, 2),
        }


def _query_service_status_api() -> Dict[str, Any]:
    """Query the SCM without depending on localized ``sc.exe`` output."""
    if os.name != "nt":
        return {"ok": False, "exists": False, "error": "Windows-only service query."}

    class SERVICE_STATUS_PROCESS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", ctypes.c_uint32),
            ("dwCurrentState", ctypes.c_uint32),
            ("dwControlsAccepted", ctypes.c_uint32),
            ("dwWin32ExitCode", ctypes.c_uint32),
            ("dwServiceSpecificExitCode", ctypes.c_uint32),
            ("dwCheckPoint", ctypes.c_uint32),
            ("dwWaitHint", ctypes.c_uint32),
            ("dwProcessId", ctypes.c_uint32),
            ("dwServiceFlags", ctypes.c_uint32),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    open_manager = advapi32.OpenSCManagerW
    open_manager.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    open_manager.restype = ctypes.c_void_p
    open_service = advapi32.OpenServiceW
    open_service.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
    open_service.restype = ctypes.c_void_p
    query_status = advapi32.QueryServiceStatusEx
    query_status.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    query_status.restype = ctypes.c_int
    close_handle = advapi32.CloseServiceHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int

    manager = open_manager(None, None, 0x0001)  # SC_MANAGER_CONNECT
    if not manager:
        code = ctypes.get_last_error()
        return {"ok": False, "exists": False, "winerror": code, "error": _format_windows_error(code)}

    service = None
    try:
        service = open_service(manager, SERVICE_NAME, 0x0004)  # SERVICE_QUERY_STATUS
        if not service:
            code = ctypes.get_last_error()
            if code == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
                return {"ok": True, "exists": False, "stateCode": 0, "pid": 0}
            return {"ok": False, "exists": False, "winerror": code, "error": _format_windows_error(code)}

        status = SERVICE_STATUS_PROCESS()
        needed = ctypes.c_uint32(0)
        queried = query_status(
            service,
            0,  # SC_STATUS_PROCESS_INFO
            ctypes.cast(ctypes.byref(status), ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.sizeof(status),
            ctypes.byref(needed),
        )
        if not queried:
            code = ctypes.get_last_error()
            return {"ok": False, "exists": True, "winerror": code, "error": _format_windows_error(code)}
        return {
            "ok": True,
            "exists": True,
            "stateCode": int(status.dwCurrentState),
            "pid": int(status.dwProcessId),
            "serviceType": int(status.dwServiceType),
            "win32ExitCode": int(status.dwWin32ExitCode),
        }
    finally:
        if service:
            close_handle(service)
        close_handle(manager)


def _query_service() -> Dict[str, Any]:
    api = _query_service_status_api()
    result = _run_sc(["queryex", SERVICE_NAME], timeout_sec=5.0)
    combined = "\n".join(
        value for value in (str(result.get("stdout") or ""), str(result.get("stderr") or ""), str(result.get("error") or "")) if value
    )
    absent = bool(api.get("ok") and not api.get("exists")) or (
        result.get("returncode") != 0
        and ("1060" in combined or "does not exist" in combined.lower())
    )
    state_code = int(api.get("stateCode") or 0) if api.get("ok") else 0
    if not state_code:
        state_match = re.search(r"\bSTATE\s*:\s*(\d+)", combined, flags=re.IGNORECASE)
        if not state_match:
            state_match = re.search(
                r":\s*(\d+)\s+(?:STOPPED|START_PENDING|STOP_PENDING|RUNNING|CONTINUE_PENDING|PAUSE_PENDING|PAUSED)\b",
                combined,
                flags=re.IGNORECASE,
            )
        if state_match:
            state_code = int(state_match.group(1))
    pid = int(api.get("pid") or 0) if api.get("ok") else 0
    if not pid:
        pid_match = re.search(r"\bPID\s*:\s*(\d+)", combined, flags=re.IGNORECASE)
        if pid_match:
            pid = int(pid_match.group(1))
    image_path = _read_service_image_path()
    exists = bool(api.get("exists")) if api.get("ok") else bool(
        image_path or result.get("returncode") == 0
    )
    return {
        "ok": bool(api.get("ok") or result.get("ok") or absent),
        "exists": not absent and exists,
        "name": SERVICE_NAME,
        "stateCode": state_code,
        "state": _SERVICE_STATES.get(state_code, "absent" if absent else "unknown"),
        "running": state_code == 4,
        "pid": pid,
        "imagePath": image_path,
        "statusApi": api,
        "query": result,
    }


def _wait_service_state(wanted: str, timeout_ms: int = 10000) -> Dict[str, Any]:
    deadline = time.time() + max(0, int(timeout_ms)) / 1000.0
    last = _query_service()
    while time.time() < deadline and last.get("state") != wanted:
        time.sleep(0.15)
        last = _query_service()
    return last


def _format_windows_error(code: int) -> str:
    if not code:
        return "Unknown Windows error"
    try:
        return ctypes.FormatError(code).strip()
    except Exception:
        return f"Windows error {code}"


def _open_device() -> Dict[str, Any]:
    if os.name != "nt":
        return {"ok": False, "handle": None, "winerror": 0, "error": "Windows-only device."}
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    handle = create_file(DEVICE_PATH, 0xC0000000, 0x00000003, None, 3, 0x80, None)
    invalid = ctypes.c_void_p(-1).value
    if handle in (None, invalid):
        code = ctypes.get_last_error()
        return {"ok": False, "handle": None, "winerror": code, "error": _format_windows_error(code)}
    return {"ok": True, "handle": handle, "winerror": 0}


def _close_handle(handle: Any) -> None:
    if os.name != "nt" or not handle:
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        kernel32.CloseHandle(handle)
    except Exception:
        pass


def _probe_device() -> Dict[str, Any]:
    opened = _open_device()
    handle = opened.pop("handle", None)
    if handle:
        _close_handle(handle)
    opened["path"] = DEVICE_PATH
    opened["available"] = bool(opened.get("ok"))
    return opened


def _query_driver_protocol() -> Dict[str, Any]:
    """Query safe-v2 status; legacy v1 returns unsupported without mutation."""
    opened = _open_device()
    handle = opened.pop("handle", None)
    if not handle:
        return {
            "ok": False,
            "supported": False,
            "device": opened,
            "error": f"Could not open {DEVICE_PATH}: {opened.get('error') or 'device unavailable'}",
        }
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        device_io = kernel32.DeviceIoControl
        device_io.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        device_io.restype = ctypes.c_int
        output = (ctypes.c_ubyte * PROTOCOL_STATUS_V2.size)()
        returned = ctypes.c_uint32(0)
        call_ok = bool(
            device_io(
                handle,
                IOCTL_QUERY_STATUS,
                None,
                0,
                ctypes.byref(output),
                ctypes.sizeof(output),
                ctypes.byref(returned),
                None,
            )
        )
        winerror = 0 if call_ok else ctypes.get_last_error()
        if not call_ok or returned.value < PROTOCOL_STATUS_V2.size:
            return {
                "ok": False,
                "supported": False,
                "ioctl": f"0x{IOCTL_QUERY_STATUS:08X}",
                "deviceIoControl": call_ok,
                "bytesReturned": int(returned.value),
                "winerror": int(winerror),
                "error": _format_windows_error(winerror) if winerror else "Driver did not return a v2 status payload.",
            }
        magic, version, size, capabilities, target_pid = PROTOCOL_STATUS_V2.unpack(
            bytes(output)
        )
        valid = bool(
            magic == PROTOCOL_MAGIC_V2
            and version == 2
            and size == PROTOCOL_STATUS_V2.size
            and (capabilities & PROTOCOL_REQUIRED_CAPABILITIES)
            == PROTOCOL_REQUIRED_CAPABILITIES
        )
        return {
            "ok": valid,
            "supported": valid,
            "ioctl": f"0x{IOCTL_QUERY_STATUS:08X}",
            "deviceIoControl": True,
            "bytesReturned": int(returned.value),
            "magic": f"0x{magic:08X}",
            "version": int(version),
            "size": int(size),
            "capabilitiesValue": int(capabilities),
            "capabilities": {
                "safeKernelNoPatching": bool(capabilities & CAPABILITY_SAFE_KERNEL_NO_PATCHING),
                "targetSelection": bool(capabilities & CAPABILITY_TARGET_SELECTION),
                "pebBeingDebuggedSanitization": bool(capabilities & CAPABILITY_PEB_BEING_DEBUGGED),
            },
            "targetPid": int(target_pid),
            "authoritative": valid,
            "error": None if valid else "Driver returned an invalid or unsafe protocol-v2 status payload.",
        }
    finally:
        _close_handle(handle)


def _device_ioctl(pid: int, hide: bool) -> Dict[str, Any]:
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        return {
            "ok": False,
            "error": "The HideMain protocol uses a pointer-sized PID and requires 64-bit Python.",
        }
    target_pid = int(pid or 0)
    if target_pid <= 4 or target_pid > 0xFFFFFFFF:
        return {"ok": False, "error": f"Invalid PID: {pid}"}
    opened = _open_device()
    handle = opened.pop("handle", None)
    if not handle:
        return {
            "ok": False,
            "pid": target_pid,
            "action": "hide" if hide else "unhide",
            "device": opened,
            "error": f"Could not open {DEVICE_PATH}: {opened.get('error') or 'device unavailable'}",
        }
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        device_io = kernel32.DeviceIoControl
        device_io.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        device_io.restype = ctypes.c_int
        input_pid = ctypes.c_void_p(target_pid)
        output_success = ctypes.c_ubyte(0)
        returned = ctypes.c_uint32(0)
        code = IOCTL_HIDE_PID if hide else IOCTL_UNHIDE_PID
        call_ok = bool(
            device_io(
                handle,
                code,
                ctypes.byref(input_pid),
                ctypes.sizeof(input_pid),
                ctypes.byref(output_success),
                ctypes.sizeof(output_success),
                ctypes.byref(returned),
                None,
            )
        )
        winerror = 0 if call_ok else ctypes.get_last_error()
        protocol_ok = (
            call_ok
            and returned.value == ctypes.sizeof(output_success)
            and bool(output_success.value)
        )
        return {
            "ok": protocol_ok,
            "pid": target_pid,
            "action": "hide" if hide else "unhide",
            "ioctl": f"0x{code:08X}",
            "deviceIoControl": call_ok,
            "driverSuccess": bool(output_success.value),
            "bytesReturned": int(returned.value),
            "winerror": int(winerror),
            "error": None if protocol_ok else (_format_windows_error(winerror) if winerror else "Driver rejected the request."),
            "authoritativeStatus": False,
        }
    finally:
        _close_handle(handle)


def _plugin_enabled(path: str) -> Optional[bool]:
    if not os.path.isfile(path):
        return None
    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
        return parser.getboolean("Settings", "Enabled", fallback=True)
    except (OSError, ValueError, configparser.Error):
        return None


def _write_plugin_enabled(path: str, enabled: bool) -> Dict[str, Any]:
    parser = configparser.ConfigParser()
    if os.path.isfile(path):
        try:
            parser.read(path, encoding="utf-8")
        except (OSError, configparser.Error):
            parser = configparser.ConfigParser()
    if not parser.has_section("Settings"):
        parser.add_section("Settings")
    parser.set("Settings", "Enabled", "1" if enabled else "0")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp_path = path + ".tmp"
    try:
        with open(temp_path, "w", encoding="utf-8", newline="\n") as handle:
            parser.write(handle)
        os.replace(temp_path, path)
        return {"ok": True, "path": path, "enabled": bool(enabled)}
    except OSError as exc:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except OSError:
            pass
        return {"ok": False, "path": path, "enabled": bool(enabled), "error": str(exc)}


def _resolve_plugin_paths(g: Dict[str, Any]) -> Dict[str, Any]:
    resolver = g.get("_resolve_debugger_install_dir")
    install_dir = str(resolver("x64") or "") if callable(resolver) else ""
    plugin_dir = os.path.join(install_dir, "plugins") if install_dir else ""
    return {
        "installDir": install_dir,
        "pluginDir": plugin_dir,
        "pluginPath": os.path.join(plugin_dir, PLUGIN_FILE) if plugin_dir else "",
        "configPath": os.path.join(plugin_dir, "EbloDDG.ini") if plugin_dir else "",
    }


def _active_target(g: Dict[str, Any], pid: int = 0) -> Dict[str, Any]:
    infer_pid = g.get("_infer_debuggee_pid")
    build_state = g.get("_build_debug_state")
    process_exists = g.get("_process_exists")
    image_for_pid = g.get("_get_process_image_path")
    detect_arch = g.get("_detect_pe_arch")
    inference_error = ""
    active_pid = 0
    session_verified = False
    if callable(build_state):
        try:
            state = build_state(
                include_console=False,
                include_callstack=False,
                max_console_chars=0,
            )
            if isinstance(state, dict):
                session_verified = True
                if state.get("debugging"):
                    active_pid = int(state.get("debuggeePid") or 0)
        except Exception as exc:
            inference_error = str(exc)
    if not session_verified:
        try:
            active_pid = int(infer_pid() or 0) if callable(infer_pid) else 0
        except Exception as exc:
            active_pid = 0
            inference_error = str(exc)
    target_pid = int(pid or active_pid or 0)
    try:
        image_path = (
            str(image_for_pid(target_pid) or "")
            if target_pid and callable(image_for_pid)
            else ""
        )
    except Exception:
        image_path = ""
    try:
        arch = (
            str(detect_arch(image_path) or "")
            if image_path and callable(detect_arch)
            else ""
        )
    except Exception:
        arch = ""
    try:
        exists = (
            bool(process_exists(target_pid))
            if target_pid and callable(process_exists)
            else bool(target_pid)
        )
    except Exception:
        exists = False
    return {
        "pid": target_pid,
        "activeDebuggeePid": active_pid,
        "isActiveDebuggee": bool(target_pid and active_pid and target_pid == active_pid),
        "exists": exists,
        "imagePath": image_path,
        "arch": arch,
        "sessionVerified": session_verified,
        "inferenceError": inference_error or None,
    }


def register(mcp, g: Dict[str, Any]) -> None:
    remember_runtime: Optional[Callable] = g.get("_remember_runtime")
    get_runtime: Optional[Callable] = g.get("_get_runtime_value")
    log_event: Optional[Callable] = g.get("_log_event")

    def _remember(record: Optional[Dict[str, Any]]) -> None:
        if callable(remember_runtime):
            remember_runtime(lastHideMain=record)

    def _last_record() -> Optional[Dict[str, Any]]:
        value = get_runtime("lastHideMain") if callable(get_runtime) else None
        return dict(value) if isinstance(value, dict) else None

    def _log(kind: str, **fields: Any) -> None:
        if callable(log_event):
            log_event(kind, **fields)

    _armed_exit_pids: set = set()

    def _cleanup_tracked(reason: str, clear_on_failure: bool = False) -> Dict[str, Any]:
        previous = _last_record()
        if not previous or not int(previous.get("pid") or 0):
            return {"ok": True, "skipped": True, "reason": "No MCP-tracked HideMain target."}
        target_pid = int(previous["pid"])
        result = _device_ioctl(target_pid, hide=False)
        # A protocol-level rejection means another controller already changed the
        # single global target, so retaining our stale ownership record is worse.
        rejected = bool(
            result.get("deviceIoControl") and not result.get("driverSuccess")
        )
        if result.get("ok") or rejected or clear_on_failure:
            _remember(None)
        _log(
            "hidemain_cleanup",
            ok=result.get("ok"),
            pid=target_pid,
            reason=reason,
            recordCleared=bool(result.get("ok") or rejected or clear_on_failure),
            error=result.get("error"),
        )
        return {**result, "reason": reason, "previous": previous}

    def _arm_exit_cleanup(pid: int) -> Dict[str, Any]:
        """Hold a process handle and clear the driver target on natural exit."""
        if os.name != "nt" or int(pid or 0) <= 4:
            return {"ok": False, "armed": False, "error": "Process exit watch is unavailable."}
        with _PROTOCOL_LOCK:
            if int(pid) in _armed_exit_pids:
                # A watcher thread already holds a handle for this PID; re-hiding
                # the same target must not leak another thread + process handle.
                return {"ok": True, "armed": True, "alreadyArmed": True, "pid": int(pid)}
            _armed_exit_pids.add(int(pid))
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        open_process.restype = ctypes.c_void_p
        wait_for_single = kernel32.WaitForSingleObject
        wait_for_single.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        wait_for_single.restype = ctypes.c_uint32
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        handle = open_process(0x00100000, 0, int(pid))  # SYNCHRONIZE
        if not handle:
            code = ctypes.get_last_error()
            with _PROTOCOL_LOCK:
                _armed_exit_pids.discard(int(pid))
            return {
                "ok": False,
                "armed": False,
                "winerror": code,
                "error": _format_windows_error(code),
            }

        def wait_for_exit() -> None:
            try:
                wait_result = int(wait_for_single(handle, 0xFFFFFFFF))
            finally:
                close_handle(handle)
                with _PROTOCOL_LOCK:
                    _armed_exit_pids.discard(int(pid))
            if wait_result != 0:  # WAIT_OBJECT_0
                return
            with _PROTOCOL_LOCK:
                current = _last_record()
                if not current or int(current.get("pid") or 0) != int(pid):
                    return
                cleanup = _cleanup_tracked("process_exit", clear_on_failure=True)
                _log(
                    "hidemain_process_exit_cleanup",
                    ok=cleanup.get("ok"),
                    pid=int(pid),
                    error=cleanup.get("error"),
                )

        watcher = threading.Thread(
            target=wait_for_exit,
            name=f"HideMainExit-{int(pid)}",
            daemon=True,
        )
        watcher.start()
        return {"ok": True, "armed": True, "pid": int(pid)}

    def _cleanup_at_exit() -> None:
        try:
            with _PROTOCOL_LOCK:
                _cleanup_tracked("mcp_exit", clear_on_failure=True)
        except Exception:
            pass

    server_mode = bool(
        os.getenv("X64DBG_STDIO_BROKER_CHILD") == "1"
        or len(sys.argv) == 1
        or (len(sys.argv) > 1 and sys.argv[1] in ("serve", "--serve"))
    )
    if server_mode:
        atexit.register(_cleanup_at_exit)

    @mcp.tool()
    def GetHideMainStatus(pid: int = 0, root: str = "") -> dict:
        """Inspect HideMain artifacts, Windows compatibility, driver/device state, plugin deployment, and the selected debuggee.

        This call never installs or starts the kernel driver.  Safe protocol v2
        reports authoritative capabilities/target state; legacy v1 is diagnosed
        but is never allowed to load.
        """
        distribution = _find_distribution_root(root)
        assets: Dict[str, Any] = {}
        for name, path in (distribution.get("assets") or {}).items():
            if name == "driver":
                assets[name] = _driver_binary_info(path)
                continue
            exists = os.path.isfile(path)
            assets[name] = {
                "path": path,
                "exists": exists,
                "size": os.path.getsize(path) if exists else 0,
                "sha256": _sha256(path) if exists else "",
                "embeddedSignature": _pe_has_embedded_signature(path) if exists else False,
            }
        service = _query_service()
        service_driver_path = str(service.get("imagePath") or "")
        service["driver"] = _driver_binary_info(service_driver_path)
        distribution_driver_path = str((distribution.get("assets") or {}).get("driver") or "")
        policy_driver_path = (
            service_driver_path if service.get("exists") else distribution_driver_path
        )
        load_policy = _driver_load_policy(policy_driver_path)
        device = _probe_device()
        protocol_status = (
            _query_driver_protocol()
            if device.get("available")
            else {
                "ok": False,
                "supported": False,
                "authoritative": False,
                "reason": "Driver device is not available.",
            }
        )
        security = _windows_security_status()
        plugin = _resolve_plugin_paths(g)
        plugin_path = str(plugin.get("pluginPath") or "")
        config_path = str(plugin.get("configPath") or "")
        plugin_binary = _plugin_binary_info(plugin_path)
        target = _active_target(g, pid)
        warnings = [
            "HideMain safe-v2 sanitizes supported anti-debug state for the selected x64 target; it does not cloak the process from Task Manager, tasklist, Get-Process, WMI, or SystemProcessInformation.",
        ]
        if not load_policy.get("allowed"):
            warnings.append(str(load_policy.get("reason") or "Driver load is blocked by fail-closed policy."))
        if service.get("running") and not protocol_status.get("ok"):
            warnings.append("The running EbloDDG driver did not return valid safe-v2 protocol status; only stop/unhide operations are allowed.")
        driver_asset = assets.get("driver") or {}
        service_driver = service.get("driver") or {}
        if service_driver.get("exists") and not service_driver.get("embeddedSignature"):
            warnings.append("The installed driver service points to a driver without an embedded Authenticode signature.")
        elif (
            not service_driver.get("exists")
            and driver_asset.get("exists")
            and not driver_asset.get("embeddedSignature")
        ):
            warnings.append("The supplied driver has no embedded Authenticode signature.")
        if ((load_policy.get("binary") or {}).get("variant") == "legacy-kernel-patching-v1"):
            warnings.extend(security.get("blockers") or [])
        last = _last_record()
        return {
            "ok": True,
            "name": "HideMain/EbloDDG",
            "experimental": True,
            "semantics": {
                "purpose": "selected-target anti-debug state sanitization",
                "driverSuccessMeaning": "Safe-v2 sanitized PEB.BeingDebugged and selected the target PID.",
                "processEnumerationCloaking": False,
            },
            "capabilities": {
                "safeKernelNoPatching": bool((protocol_status.get("capabilities") or {}).get("safeKernelNoPatching")),
                "pebBeingDebuggedSanitization": bool((protocol_status.get("capabilities") or {}).get("pebBeingDebuggedSanitization")),
                "legacyHeapDebugFlagSanitization": False,
                "processDebugPortMasking": False,
                "processDebugObjectMasking": False,
                "threadHideFromDebuggerVirtualization": False,
                "smbiosSpoofing": False,
                "systemProcessInformationFiltering": False,
                "eprocessActiveProcessLinksManipulation": False,
                "targetLocalPluginRequiredForExtendedMasking": True,
            },
            "distribution": distribution,
            "assets": assets,
            "service": service,
            "device": device,
            "plugin": {
                **plugin,
                "installed": bool(plugin_binary.get("exists")),
                "configuredEnabled": _plugin_enabled(config_path),
                "binary": plugin_binary,
                "stockPluginKnownIssues": plugin_binary.get("knownIssues") or [],
                "operationalNotes": [
                    "Configuration changes require an x64dbg restart to affect a loaded plugin.",
                ],
            },
            "security": {**security, "elevated": _is_admin()},
            "loadPolicy": load_policy,
            "target": target,
            "protocol": {
                "version": int(protocol_status.get("version") or 1),
                "pointerSize": ctypes.sizeof(ctypes.c_void_p),
                "hideIoctl": f"0x{IOCTL_HIDE_PID:08X}",
                "unhideIoctl": f"0x{IOCTL_UNHIDE_PID:08X}",
                "queryStatusIoctl": f"0x{IOCTL_QUERY_STATUS:08X}",
                "queryStatusSupported": bool(protocol_status.get("supported")),
                "status": protocol_status,
            },
            "protection": {
                "authoritative": bool(protocol_status.get("authoritative")),
                "lastMcpOperation": last,
                "reportedTargetPid": int(protocol_status.get("targetPid") or 0),
                "driverReady": bool(device.get("available") and protocol_status.get("ok") and load_policy.get("allowed")),
                "targetCompatible": bool(
                    target.get("pid") and target.get("arch") == "x64"
                ),
                "ready": bool(
                    device.get("available")
                    and protocol_status.get("ok")
                    and load_policy.get("allowed")
                    and target.get("pid")
                    and target.get("arch") == "x64"
                ),
            },
            "warnings": warnings,
        }

    @mcp.tool()
    @_protocol_locked
    def ManageHideMainDriver(
        action: str = "status",
        root: str = "",
        driver_path: str = "",
        allow_system_changes: bool = False,
        allow_unsigned: bool = False,
        acknowledge_kernel_risk: bool = False,
        replace_existing: bool = False,
        timeout_ms: int = 10000,
    ) -> dict:
        """Manage the EbloDDG kernel-driver service.

        Actions: status, install, start, stop, restart, remove.  Every mutating
        action requires ``allow_system_changes=true`` and elevation.  Starting an
        unsigned build additionally requires both ``allow_unsigned=true`` and
        ``acknowledge_kernel_risk=true``.  This tool never changes HVCI, Secure
        Boot, test-signing, BCD, or other Windows security policy.
        """
        requested = str(action or "status").strip().lower()
        if requested == "status":
            return GetHideMainStatus(root=root)
        if requested not in {"install", "start", "stop", "restart", "remove"}:
            return {"ok": False, "error": f"Unknown action: {action}"}
        if not allow_system_changes:
            return {
                "ok": False,
                "action": requested,
                "requiresConfirmation": True,
                "error": "Set allow_system_changes=true for driver-service mutations.",
            }
        if not _is_admin():
            return {
                "ok": False,
                "action": requested,
                "requiresElevation": True,
                "error": "Driver-service mutations require an elevated MCP process.",
            }

        distribution = _find_distribution_root(root)
        source_driver = os.path.abspath(str(driver_path or "").strip()) if driver_path else str((distribution.get("assets") or {}).get("driver") or "")
        existing = _query_service()

        def _start() -> Dict[str, Any]:
            current = _query_service()
            if not current.get("exists"):
                return {"ok": False, "error": "EbloDDG service is not installed."}
            active_path = str(current.get("imagePath") or source_driver or "")
            load_policy = _driver_load_policy(active_path)
            if not load_policy.get("allowed"):
                return {
                    "ok": False,
                    "blocked": True,
                    "failClosed": True,
                    "loadPolicy": load_policy,
                    "error": load_policy.get("reason"),
                }
            embedded = _pe_has_embedded_signature(active_path) if active_path and os.path.isfile(active_path) else False
            signature = (
                _authenticode_status(active_path)
                if embedded
                else {"ok": False, "status": "NotSigned", "path": active_path}
            )
            if not signature.get("ok") and not allow_unsigned:
                return {
                    "ok": False,
                    "requiresUnsignedAcknowledgement": True,
                    "signature": signature,
                    "error": "The driver does not have a valid trusted signature. Set allow_unsigned=true only in a disposable test VM.",
                }
            if not acknowledge_kernel_risk:
                return {
                    "ok": False,
                    "requiresKernelRiskAcknowledgement": True,
                    "error": "Set acknowledge_kernel_risk=true to acknowledge general kernel-driver/BSOD risk.",
                }
            if current.get("running"):
                device = _probe_device()
                return {
                    "ok": bool(device.get("available")),
                    "alreadyRunning": True,
                    "service": current,
                    "device": device,
                    "signature": signature,
                    "error": (
                        None
                        if device.get("available")
                        else "The service is running, but its device cannot be opened."
                    ),
                }
            call = _run_sc(["start", SERVICE_NAME], timeout_sec=max(1, timeout_ms / 1000.0))
            final = _wait_service_state("running", timeout_ms) if call.get("ok") else _query_service()
            device = _probe_device()
            return {
                "ok": bool(final.get("running") and device.get("available")),
                "command": call,
                "service": final,
                "device": device,
                "signature": signature,
                "error": None if final.get("running") and device.get("available") else "Driver did not reach a usable running state.",
            }

        if requested == "install":
            if not source_driver or not os.path.isfile(source_driver):
                return {"ok": False, "action": requested, "distribution": distribution, "error": "EbloDDG.sys was not found."}
            source_policy = _driver_load_policy(source_driver)
            if not source_policy.get("allowed"):
                return {
                    "ok": False,
                    "action": requested,
                    "blocked": True,
                    "failClosed": True,
                    "loadPolicy": source_policy,
                    "error": source_policy.get("reason"),
                }
            if existing.get("exists"):
                current_path = os.path.abspath(str(existing.get("imagePath") or "")) if existing.get("imagePath") else ""
                same = bool(current_path and os.path.isfile(current_path) and _same_file_content(current_path, source_driver))
                if not same and not replace_existing:
                    return {
                        "ok": False,
                        "action": requested,
                        "service": existing,
                        "conflict": True,
                        "error": "An EbloDDG service already points to different driver content; set replace_existing=true to replace it.",
                    }
                if same:
                    return {"ok": True, "action": requested, "alreadyInstalled": True, "service": existing}

            resolver = g.get("_resolve_debugger_install_dir")
            install_dir = str(resolver("x64") or "") if callable(resolver) else ""
            stable_dir = os.path.join(os.path.dirname(install_dir), "hidemain") if install_dir else os.path.join(os.path.dirname(source_driver), "installed")
            os.makedirs(stable_dir, exist_ok=True)
            deployed_driver = os.path.join(stable_dir, DRIVER_FILE)
            cleanup = None
            stop_call = None
            if existing.get("exists") and replace_existing:
                if existing.get("running"):
                    cleanup = _cleanup_tracked("driver_replace")
                    stop_call = _run_sc(
                        ["stop", SERVICE_NAME],
                        timeout_sec=max(1, timeout_ms / 1000.0),
                    )
                    stopped = (
                        _wait_service_state("stopped", timeout_ms)
                        if stop_call.get("ok")
                        else _query_service()
                    )
                    if stopped.get("state") != "stopped":
                        return {
                            "ok": False,
                            "action": requested,
                            "cleanup": cleanup,
                            "stop": stop_call,
                            "service": stopped,
                            "error": "Could not stop the existing driver; its image was not replaced.",
                        }

            temp_driver = f"{deployed_driver}.new-{os.getpid()}"
            backup_driver = f"{deployed_driver}.mcp-backup"
            had_deployed = os.path.isfile(deployed_driver)
            try:
                if had_deployed:
                    shutil.copy2(deployed_driver, backup_driver)
                shutil.copy2(source_driver, temp_driver)
                os.replace(temp_driver, deployed_driver)
            except OSError as exc:
                for temporary in (temp_driver,):
                    try:
                        if os.path.exists(temporary):
                            os.remove(temporary)
                    except OSError:
                        pass
                return {
                    "ok": False,
                    "action": requested,
                    "cleanup": cleanup,
                    "stop": stop_call,
                    "driverPath": deployed_driver,
                    "error": f"Could not deploy the driver image: {exc}",
                }

            if existing.get("exists") and replace_existing:
                call = _run_sc(
                    ["config", SERVICE_NAME, "type=", "kernel", "start=", "demand", "error=", "normal", "binPath=", deployed_driver],
                    timeout_sec=max(1, timeout_ms / 1000.0),
                )
            else:
                call = _run_sc(
                    ["create", SERVICE_NAME, "type=", "kernel", "start=", "demand", "error=", "normal", "binPath=", deployed_driver, "DisplayName=", "EbloDDG HideMain"],
                    timeout_sec=max(1, timeout_ms / 1000.0),
                )
            if not call.get("ok"):
                try:
                    if had_deployed and os.path.isfile(backup_driver):
                        os.replace(backup_driver, deployed_driver)
                    elif not had_deployed and os.path.isfile(deployed_driver):
                        os.remove(deployed_driver)
                except OSError:
                    pass
            else:
                try:
                    if os.path.isfile(backup_driver):
                        os.remove(backup_driver)
                except OSError:
                    pass
            final = _query_service()
            deployed_exists = os.path.isfile(deployed_driver)
            payload = {
                "ok": bool(call.get("ok") and final.get("exists")),
                "action": requested,
                "driverPath": deployed_driver,
                "sha256": _sha256(deployed_driver) if deployed_exists else "",
                "embeddedSignature": (
                    _pe_has_embedded_signature(deployed_driver)
                    if deployed_exists
                    else False
                ),
                "command": call,
                "service": final,
                "cleanup": cleanup,
                "stop": stop_call,
                "startAttempted": False,
            }
            _log("hidemain_driver_install", ok=payload["ok"], driverPath=deployed_driver)
            return payload

        if requested == "start":
            result = _start()
            result["action"] = requested
            _log("hidemain_driver_start", ok=result.get("ok"), error=result.get("error"))
            return result

        if requested == "restart":
            cleanup = _cleanup_tracked("driver_restart")
            if existing.get("running"):
                stop_call = _run_sc(["stop", SERVICE_NAME], timeout_sec=max(1, timeout_ms / 1000.0))
                stopped = (
                    _wait_service_state("stopped", timeout_ms)
                    if stop_call.get("ok")
                    else _query_service()
                )
                if stopped.get("state") != "stopped":
                    result = {
                        "ok": False,
                        "action": requested,
                        "cleanup": cleanup,
                        "stop": stop_call,
                        "service": stopped,
                        "error": "Driver stop failed; restart was aborted.",
                    }
                    _log("hidemain_driver_restart", ok=False, error=result["error"])
                    return result
                _remember(None)
            else:
                stop_call = {"ok": True, "skipped": True}
            _remember(None)
            result = _start()
            result.update(action=requested, stop=stop_call, cleanup=cleanup)
            _log("hidemain_driver_restart", ok=result.get("ok"), error=result.get("error"))
            return result

        if requested == "stop":
            cleanup = _cleanup_tracked("driver_stop")
            call = _run_sc(["stop", SERVICE_NAME], timeout_sec=max(1, timeout_ms / 1000.0))
            final = _wait_service_state("stopped", timeout_ms) if call.get("ok") else _query_service()
            ok = bool(final.get("state") in ("stopped", "absent"))
            if ok:
                _remember(None)
            result = {"ok": ok, "action": requested, "cleanup": cleanup, "command": call, "service": final}
            _log("hidemain_driver_stop", ok=ok)
            return result

        # remove
        cleanup = _cleanup_tracked("driver_remove")
        stop_call = None
        if existing.get("running"):
            stop_call = _run_sc(["stop", SERVICE_NAME], timeout_sec=max(1, timeout_ms / 1000.0))
            stopped = (
                _wait_service_state("stopped", timeout_ms)
                if stop_call.get("ok")
                else _query_service()
            )
            if stopped.get("state") != "stopped":
                result = {
                    "ok": False,
                    "action": requested,
                    "cleanup": cleanup,
                    "stop": stop_call,
                    "service": stopped,
                    "error": "Driver stop failed; remove was aborted.",
                }
                _log("hidemain_driver_remove", ok=False)
                return result
            _remember(None)
        call = _run_sc(["delete", SERVICE_NAME], timeout_sec=max(1, timeout_ms / 1000.0))
        final = _query_service()
        result = {
            "ok": bool(call.get("ok") and not final.get("exists")),
            "action": requested,
            "cleanup": cleanup,
            "stop": stop_call,
            "command": call,
            "service": final,
        }
        if result["ok"]:
            _remember(None)
        _log("hidemain_driver_remove", ok=result["ok"])
        return result

    @mcp.tool()
    def ConfigureHideMainPlugin(
        action: str = "status",
        root: str = "",
        enabled: bool = True,
        overwrite: bool = False,
    ) -> dict:
        """Inspect, install, remove, enable, or disable the optional stock dp64 plugin.

        The stock plugin is x64-only and has known lifecycle bugs; direct MCP IOCTL
        control is preferred.  Install/remove/enable changes take effect after an
        x64dbg restart and never restart the debugger automatically.
        """
        requested = str(action or "status").strip().lower()
        paths = _resolve_plugin_paths(g)
        plugin_path = str(paths.get("pluginPath") or "")
        config_path = str(paths.get("configPath") or "")
        if requested == "status":
            binary = _plugin_binary_info(plugin_path)
            return {
                "ok": True,
                **paths,
                "installed": bool(binary.get("exists")),
                "configuredEnabled": _plugin_enabled(config_path),
                "binary": binary,
                "restartRequired": False,
            }
        if requested not in {"install", "remove", "enable", "disable"}:
            return {"ok": False, "error": f"Unknown plugin action: {action}"}
        if not plugin_path:
            return {"ok": False, **paths, "error": "x64dbg x64 installation was not found."}
        if requested == "install":
            distribution = _find_distribution_root(root)
            source = str((distribution.get("assets") or {}).get("plugin") or "")
            if not source or not os.path.isfile(source):
                return {"ok": False, "distribution": distribution, "error": f"{PLUGIN_FILE} was not found."}
            if os.path.isfile(plugin_path) and not _same_file_content(source, plugin_path) and not overwrite:
                return {"ok": False, **paths, "conflict": True, "error": "A different plugin is already installed; set overwrite=true to replace it."}
            os.makedirs(os.path.dirname(plugin_path), exist_ok=True)
            changed = not os.path.isfile(plugin_path) or not _same_file_content(source, plugin_path)
            if changed:
                shutil.copy2(source, plugin_path)
            config_existed = os.path.isfile(config_path)
            previous_enabled = _plugin_enabled(config_path)
            config = _write_plugin_enabled(config_path, enabled)
            config_changed = not config_existed or previous_enabled != bool(enabled)
            result = {
                "ok": bool(config.get("ok")),
                **paths,
                "installed": True,
                "changed": changed,
                "configChanged": config_changed,
                "config": config,
                "binary": _plugin_binary_info(plugin_path),
                "restartRequired": bool(changed or config_changed),
            }
            _log("hidemain_plugin_install", ok=result["ok"], path=plugin_path)
            return result
        if requested == "remove":
            try:
                existed = os.path.isfile(plugin_path)
                if existed:
                    os.remove(plugin_path)
                result = {"ok": True, **paths, "removed": existed, "restartRequired": existed}
            except OSError as exc:
                result = {"ok": False, **paths, "error": str(exc), "restartRequired": True}
            _log("hidemain_plugin_remove", ok=result["ok"], path=plugin_path)
            return result
        write = _write_plugin_enabled(config_path, requested == "enable")
        result = {**write, **paths, "installed": os.path.isfile(plugin_path), "restartRequired": True}
        _log("hidemain_plugin_config", ok=result.get("ok"), enabled=requested == "enable")
        return result

    def _validate_target(pid: int, require_active_debuggee: bool) -> Dict[str, Any]:
        target = _active_target(g, pid)
        if not target.get("pid"):
            return {"ok": False, "target": target, "error": "No target PID was provided or inferred."}
        if require_active_debuggee and not target.get("isActiveDebuggee"):
            return {
                "ok": False,
                "target": target,
                "error": "Refusing an arbitrary PID: target is not the active x64dbg debuggee.",
            }
        if not target.get("exists"):
            return {"ok": False, "target": target, "error": "Target process no longer exists."}
        if int(target.get("pid") or 0) == os.getpid():
            return {"ok": False, "target": target, "error": "Refusing to target the MCP server process."}
        debugger_info = g.get("_get_active_debugger_info")
        active_debugger = debugger_info() if callable(debugger_info) else {}
        if int(target.get("pid") or 0) == int((active_debugger or {}).get("pid") or 0):
            return {"ok": False, "target": target, "error": "Refusing to target the debugger process itself."}
        if target.get("arch") != "x64":
            error = (
                "HideMain safe-v2 supports x64 targets only."
                if target.get("arch")
                else "Could not verify that the target is x64; refusing the IOCTL."
            )
            return {
                "ok": False,
                "target": target,
                "unsupported": True,
                "error": error,
            }
        return {"ok": True, "target": target}

    @mcp.tool()
    @_protocol_locked
    def HideDebuggeeWithHideMain(pid: int = 0, require_active_debuggee: bool = True) -> dict:
        """Mask supported anti-debug signals for the active x64 debuggee.

        The legacy HideMain name does not mean removing the process from normal
        Windows process enumeration.
        """
        if not require_active_debuggee:
            return {
                "ok": False,
                "error": "Arbitrary-PID hiding is not exposed; select the process as the active x64dbg debuggee.",
            }
        validated = _validate_target(pid, True)
        if not validated.get("ok"):
            return validated
        target = validated["target"]
        service = _query_service()
        load_policy = _driver_load_policy(str(service.get("imagePath") or ""))
        if not load_policy.get("allowed"):
            return {
                "ok": False,
                "blocked": True,
                "failClosed": True,
                "target": target,
                "loadPolicy": load_policy,
                "error": load_policy.get("reason"),
            }
        protocol_before = _query_driver_protocol()
        if not protocol_before.get("ok"):
            return {
                "ok": False,
                "blocked": True,
                "failClosed": True,
                "target": target,
                "protocol": protocol_before,
                "error": "Safe HideMain protocol v2 could not be verified; no hide IOCTL was sent.",
            }
        previous = _last_record()
        replaced = None
        if previous and int(previous.get("pid") or 0) not in (0, int(target["pid"])):
            replaced = _device_ioctl(int(previous["pid"]), hide=False)
            # HideMain has one global target and the stock plugin can change it
            # behind MCP's back. A rejected stale cleanup must not wedge the new
            # active target: the following successful Hide explicitly replaces it.
        result = _device_ioctl(int(target["pid"]), hide=True)
        protocol_after = _query_driver_protocol()
        authoritative = bool(
            result.get("ok")
            and protocol_after.get("ok")
            and protocol_after.get("authoritative")
            and int(protocol_after.get("targetPid") or 0) == int(target["pid"])
        )
        rollback = None
        if result.get("ok") and not authoritative:
            # The byte may already have been changed even if status verification
            # failed. Restore it fail-closed instead of claiming protection.
            rollback = _device_ioctl(int(target["pid"]), hide=False)

        accepted = authoritative
        payload = {
            **result,
            "ok": authoritative,
            "processEnumerationCloaking": False,
            "driverSuccessMeaning": "Safe-v2 sanitized PEB.BeingDebugged and selected the target PID.",
            "target": target,
            "protocolBefore": protocol_before,
            "protocol": protocol_after,
            "previous": previous,
            "replaceCleanup": replaced,
            "reconciledOwnership": bool(replaced and not replaced.get("ok")),
            "authoritativeStatus": authoritative,
            "verificationRollback": rollback,
        }
        if result.get("ok") and not authoritative:
            payload["error"] = "Hide IOCTL completed, but protocol-v2 did not confirm the requested target; the operation was rolled back."
        if accepted:
            record = {
                "pid": int(target["pid"]),
                "imagePath": target.get("imagePath"),
                "arch": target.get("arch") or "x64",
                "action": "hide",
                "timestamp": _now_iso(),
                "authoritative": False,
            }
            _remember(record)
            payload["exitCleanup"] = _arm_exit_cleanup(int(target["pid"]))
        _log(
            "hidemain_hide",
            ok=payload.get("ok"),
            pid=target.get("pid"),
            error=payload.get("error"),
        )
        return payload

    @mcp.tool()
    @_protocol_locked
    def UnhideDebuggeeWithHideMain(pid: int = 0, require_active_debuggee: bool = True) -> dict:
        """Clear HideMain's active target for the current x64 debuggee."""
        previous = _last_record()
        target_pid = int(pid or (previous or {}).get("pid") or 0)
        if (
            not require_active_debuggee
            and (not previous or int(previous.get("pid") or 0) != target_pid)
        ):
            return {
                "ok": False,
                "pid": target_pid,
                "error": "Inactive-PID cleanup is restricted to MCP's tracked HideMain target.",
            }
        validated = _validate_target(target_pid, require_active_debuggee)
        if not validated.get("ok"):
            # A stopped debuggee no longer exists, but clearing the driver's stale
            # PID is still worth attempting when it is the MCP-tracked record.
            if not previous or int(previous.get("pid") or 0) != target_pid:
                return validated
        result = _device_ioctl(target_pid, hide=False)
        protocol_after = _query_driver_protocol()
        authoritative = bool(
            result.get("ok")
            and protocol_after.get("ok")
            and protocol_after.get("authoritative")
            and int(protocol_after.get("targetPid") or 0) == 0
        )
        # Legacy cleanup remains possible, but only safe-v2 can make an
        # authoritative postcondition claim.
        operation_ok = authoritative if protocol_after.get("supported") else bool(result.get("ok"))
        payload = {
            **result,
            "ok": operation_ok,
            "target": validated.get("target"),
            "previous": previous,
            "protocol": protocol_after,
            "authoritativeStatus": authoritative,
        }
        if result.get("ok") and protocol_after.get("supported") and not authoritative:
            payload["error"] = "Unhide IOCTL completed, but protocol-v2 did not confirm an empty target."
        rejected = bool(
            payload.get("deviceIoControl") and not payload.get("driverSuccess")
        )
        if payload.get("ok") or (rejected and previous and int(previous.get("pid") or 0) == target_pid):
            _remember(None)
        _log("hidemain_unhide", ok=payload.get("ok"), pid=target_pid, error=payload.get("error"))
        return payload

    @mcp.tool()
    @_protocol_locked
    def EnsureHideMainForDebuggee(
        pid: int = 0,
        mode: str = "auto",
        root: str = "",
        allow_system_changes: bool = False,
        allow_unsigned: bool = False,
        acknowledge_kernel_risk: bool = False,
    ) -> dict:
        """Ensure HideMain protection for the current x64 debuggee.

        ``auto`` only uses an already-available device and otherwise skips safely.
        ``force`` may start an already-installed service, but never installs it;
        service start still requires all explicit safety flags and elevation.
        """
        requested = str(mode or "auto").strip().lower()
        if requested not in {"off", "auto", "force"}:
            return {"ok": False, "error": f"Unknown HideMain mode: {mode}"}
        if requested == "off":
            return {"ok": True, "skipped": True, "mode": requested, "reason": "HideMain policy disabled."}
        validated = _validate_target(pid, True)
        if not validated.get("ok"):
            return {**validated, "mode": requested}
        status = GetHideMainStatus(pid=int(validated["target"]["pid"]), root=root)
        load_policy = status.get("loadPolicy") or {}
        device = status.get("device") or {}
        start = None
        if not device.get("available"):
            if requested == "auto":
                return {
                    "ok": True,
                    "skipped": True,
                    "mode": requested,
                    "reason": "HideMain device is not already available; auto mode does not mutate driver state.",
                    "status": status,
                }
            if not load_policy.get("allowed"):
                return {
                    "ok": False,
                    "blocked": True,
                    "failClosed": True,
                    "mode": requested,
                    "status": status,
                    "error": load_policy.get("reason") or "HideMain driver load is blocked by fail-closed policy.",
                }
            start = ManageHideMainDriver(
                action="start",
                root=root,
                allow_system_changes=allow_system_changes,
                allow_unsigned=allow_unsigned,
                acknowledge_kernel_risk=acknowledge_kernel_risk,
            )
            if not start.get("ok"):
                return {"ok": False, "mode": requested, "status": status, "driverStart": start, "error": start.get("error") or "HideMain driver could not be started."}
        elif not load_policy.get("allowed"):
            return {
                "ok": False,
                "blocked": True,
                "failClosed": True,
                "mode": requested,
                "status": status,
                "error": load_policy.get("reason") or "HideMain driver load is blocked by fail-closed policy.",
            }
        hidden = HideDebuggeeWithHideMain(pid=int(validated["target"]["pid"]), require_active_debuggee=True)
        return {"ok": bool(hidden.get("ok")), "mode": requested, "status": status, "driverStart": start, "hide": hidden, "authoritativeStatus": False}

    def _prepare_hidemain_policy(
        mode: str = "off",
        root: str = "",
        allow_system_changes: bool = False,
        allow_unsigned: bool = False,
        acknowledge_kernel_risk: bool = False,
    ) -> Dict[str, Any]:
        requested = str(mode or "off").strip().lower()
        if requested not in {"off", "auto", "force"}:
            return {"ok": False, "mode": requested, "error": f"Unknown HideMain mode: {mode}"}
        if requested == "off":
            return {"ok": True, "mode": requested, "skipped": True, "reason": "HideMain policy disabled."}
        status = GetHideMainStatus(root=root)
        if (status.get("device") or {}).get("available"):
            return {"ok": True, "mode": requested, "ready": True, "status": status}
        if requested == "auto":
            return {"ok": True, "mode": requested, "skipped": True, "reason": "HideMain is not already running.", "status": status}
        start = ManageHideMainDriver(
            action="start",
            root=root,
            allow_system_changes=allow_system_changes,
            allow_unsigned=allow_unsigned,
            acknowledge_kernel_risk=acknowledge_kernel_risk,
        )
        return {"ok": bool(start.get("ok")), "mode": requested, "ready": bool(start.get("ok")), "status": status, "driverStart": start, "error": start.get("error") if not start.get("ok") else None}

    def _apply_hidemain_policy(
        pid: int,
        mode: str = "off",
        root: str = "",
        allow_system_changes: bool = False,
        allow_unsigned: bool = False,
        acknowledge_kernel_risk: bool = False,
    ) -> Dict[str, Any]:
        requested = str(mode or "off").strip().lower()
        if requested == "off":
            return {"ok": True, "mode": requested, "skipped": True, "reason": "HideMain policy disabled."}
        return EnsureHideMainForDebuggee(
            pid=pid,
            mode=requested,
            root=root,
            allow_system_changes=allow_system_changes,
            allow_unsigned=allow_unsigned,
            acknowledge_kernel_risk=acknowledge_kernel_risk,
        )

    def _cleanup_hidemain_target() -> Dict[str, Any]:
        with _PROTOCOL_LOCK:
            return _cleanup_tracked("debugger_cleanup")

    exported = [
        GetHideMainStatus,
        ManageHideMainDriver,
        ConfigureHideMainPlugin,
        HideDebuggeeWithHideMain,
        UnhideDebuggeeWithHideMain,
        EnsureHideMainForDebuggee,
    ]
    main_module_name = g.get("__name__", "x64dbg")
    for fn in exported:
        try:
            fn.__module__ = main_module_name
        except Exception:
            pass
        g[fn.__name__] = fn
    g["_prepare_hidemain_policy"] = _prepare_hidemain_policy
    g["_apply_hidemain_policy"] = _apply_hidemain_policy
    g["_cleanup_hidemain_target"] = _cleanup_hidemain_target
    _log("hidemain_tools_loaded", count=len(exported))
