import sys
import os
import inspect
import json
import logging
import ctypes
import configparser
import time
import re
import math
import hashlib
import base64
import binascii
import struct
import subprocess
import ipaddress
import atexit
import shutil
import tempfile
import warnings
import uuid
import secrets
from collections import deque
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from threading import Lock, RLock, Thread, local
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, get_args, get_origin, get_type_hints
from urllib.parse import quote, urlencode, urlsplit
import requests

# ``x64dbg.py`` is frequently loaded directly through
# ``spec_from_file_location`` by tests and embedded MCP launchers.  In that
# mode Python does not automatically place the sibling ``src`` directory on
# ``sys.path``, so make local decomposed cores importable without requiring an
# installation step.
_SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))
if _SOURCE_DIR not in sys.path:
    sys.path.insert(0, _SOURCE_DIR)

from coverage_core import reconstruct_basic_block_coverage
from mcp_runtime.contracts import (
    BridgeEnvelope,
    BridgeError,
    json_safe as _json_safe,
)
from mcp_runtime.route_policy import load_route_policy as _load_route_policy_file
from mcp_runtime.pe import (
    detect_pe_arch as _detect_pe_arch,
    dotnet_effective_arch as _dotnet_effective_arch,
)


def _configure_mcp_process_runtime() -> None:
    # Keep the stdio transport quiet. Codex only needs protocol traffic on
    # stdout; warnings and chatty INFO logs on stderr are noise at best and
    # can destabilize fragile host integrations at worst.
    if not sys.warnoptions:
        warnings.filterwarnings("ignore", category=DeprecationWarning)
    try:
        logging.basicConfig(level=logging.ERROR, force=True)
    except TypeError:
        logging.basicConfig(level=logging.ERROR)
    logging.getLogger().setLevel(logging.ERROR)
    for logger_name in (
        "mcp",
        "mcp.server",
        "mcp.server.fastmcp",
        "mcp.server.fastmcp.server",
        "mcp.server.lowlevel.server",
        "FastMCP",
    ):
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.ERROR)
        logger.propagate = True


_configure_mcp_process_runtime()

from mcp.server.fastmcp import FastMCP

DEFAULT_X64DBG_SERVER = "http://127.0.0.1:8888/"
BRIDGE_AUTH_HEADER = "X-MCP-Auth-Token"
BRIDGE_AUTH_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{64}$")
# Target identity is deliberately a full, strict SHA-256 digest.  Keeping a
# separate expression (rather than reusing the bearer-token validator) makes
# the wire contract self-documenting and prevents accidental acceptance of a
# truncated hash in mutation headers.
TARGET_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_BRIDGE_AUTH_LOCK = Lock()
_BRIDGE_AUTH_CACHE: Dict[str, Any] = {}
_ROUTE_POLICY_PATH = Path(__file__).resolve().with_name("route_policy.inc")


def _load_route_policy() -> Tuple[Dict[str, str], str]:
    # Keep this wrapper for tests and operators that patch the historical
    # module-level path; parsing itself is now reusable and independently
    # testable in ``mcp_runtime.route_policy``.
    return _load_route_policy_file(_ROUTE_POLICY_PATH)


_ROUTE_POLICY, _ROUTE_POLICY_ID = _load_route_policy()


def _force_utf8_stdio() -> None:
    # MCP uses stdio transport, so Windows ANSI code pages can crash the
    # server when x64dbg returns mojibake from non-ASCII paths or labels.
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for name, errors in (
        ("stdin", "replace"),
        ("stdout", "replace"),
        ("stderr", "backslashreplace"),
    ):
        stream = getattr(sys, name, None)
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors=errors)
        except Exception:
            continue


_force_utf8_stdio()


def _normalize_loopback_server_url(value: Any) -> str:
    """Return a canonical bridge base URL, or ``""`` when it is unsafe.

    The native bridge is deliberately loopback-only.  Keeping the Python side
    equally strict prevents the per-launch bearer token from being sent through
    a proxy, redirect, URL user-info field, or accidentally configured remote
    host.
    """

    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
        port = parsed.port  # Raises ValueError for malformed/out-of-range ports.
    except (TypeError, ValueError):
        return ""
    if parsed.scheme.casefold() != "http":
        return ""
    if parsed.username is not None or parsed.password is not None:
        return ""
    host = str(parsed.hostname or "").casefold()
    # MCPx64dbg currently binds an AF_INET socket to INADDR_LOOPBACK.  Do not
    # accept ::1 here: doing so advertises a transport the native listener
    # cannot serve and can leave an operator talking to an unrelated listener.
    if host not in {"127.0.0.1", "localhost"}:
        return ""
    if port is None or not (1 <= int(port) <= 65535):
        return ""
    if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        return ""
    return f"http://{host}:{port}/"


def _resolve_server_url_from_args_env() -> str:
    env_url = os.getenv("X64DBG_URL")
    if env_url:
        return _normalize_loopback_server_url(env_url) or DEFAULT_X64DBG_SERVER
    if len(sys.argv) > 1 and isinstance(sys.argv[1], str):
        candidate = str(sys.argv[1]).strip()
        if candidate.casefold().startswith(("http://", "https://")):
            return _normalize_loopback_server_url(candidate) or DEFAULT_X64DBG_SERVER
    return DEFAULT_X64DBG_SERVER


x64dbg_server_url = _resolve_server_url_from_args_env()

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
LOG_PATH = os.path.join(LOG_DIR, "x64dbg-mcp.log")
SERVER_LOCK_PATH = os.path.join(os.path.dirname(__file__), ".x64dbg-mcp-server.lock")

INPUT_WAIT_STACK_MARKERS = (
    "ntdll.ntreadfile",
    "kernelbase.readfile",
    "kernelbase.readconsole",
    "ucrtbase._read",
    "ucrtbase.fgetc",
    "ucrtbase.fgets",
    "ucrtbase.getchar",
    "ucrtbase.scanf",
    "ucrtbase._fread_nolock_s",
    "msvcrt._read",
    "msvcrt.fgetc",
    "msvcrt.fgets",
    "msvcrt.scanf",
    "basic_istream",
    "std::cin",
)

INPUT_PROMPT_KEYWORDS = (
    "enter",
    "password",
    "passcode",
    "input",
    "choice",
    "select",
    "command",
    "option",
    "username",
    "login",
    "press any key",
    "number",
    "key",
)

STARTUP_BREAKPOINT_MARKERS = (
    "tls callback",
    "entry point",
    "entrypoint",
    "point d'entree",
    "точке входа",
    "точка входа",
    "system breakpoint",
)

STARTUP_STACK_MARKERS = (
    "ntdll.ldr",
    "ntdll.ldrinitialize",
    "ntdll.ldrp",
    "ntdll.ldrinitialize",
    "ntdll.rtlcapturestackcontext",
    "ntdll.ldrhotpatchnotify",
    "kernel32.basethreadinitthunk",
)

COMMON_ANTI_DEBUG_APIS = (
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "ntsetinformationthread",
)

ANTI_DEBUG_IMPORT_HINTS = {
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "ntsetinformationthread",
    "ntquerysysteminformation",
    "ntclose",
    "outputdebugstringa",
    "outputdebugstringw",
    "findwindowa",
    "findwindoww",
    "findwindowexa",
    "findwindowexw",
    "blockinput",
    "zwqueryinformationprocess",
    "zwsetinformationthread",
}

STRONG_ANTI_DEBUG_IMPORT_HINTS = {
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "ntsetinformationthread",
    "ntquerysysteminformation",
    "zwqueryinformationprocess",
    "zwsetinformationthread",
    "blockinput",
    "findwindowa",
    "findwindoww",
    "findwindowexa",
    "findwindowexw",
}

WEAK_ANTI_DEBUG_IMPORT_HINTS = {
    "isdebuggerpresent",
    "outputdebugstringa",
    "outputdebugstringw",
    "ntclose",
}

SCYLLA_PROTECTOR_PROFILES = {
    "themida": "Themida x86/x64",
    "obsidium": "Obsidium x86/x64",
    "armadillo": "Armadillo x86",
}

# Research-specific virtualization profiles are deliberately not part of the
# active MCP surface.  Keep an explicit write guard so a stale local INI cannot
# silently re-enable a deferred profile through SetScyllaHideProfile.
SCYLLA_DISABLED_PROFILE_KEYS = frozenset(
    {"disabled", "disable", "off", "none", "vmprotect", "vmp"}
)


def _scylla_profile_key(profile: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(profile or "").strip().lower())


def _is_disabled_scylla_profile(profile: Any) -> bool:
    key = _scylla_profile_key(profile)
    return bool(key) and any(
        key == disabled or key.startswith(disabled)
        for disabled in SCYLLA_DISABLED_PROFILE_KEYS
    )

COMMON_ANTI_DEBUG_BREAKPOINT_TARGETS = (
    ("kernel32.dll", "IsDebuggerPresent"),
    ("kernel32.dll", "CheckRemoteDebuggerPresent"),
    ("kernelbase.dll", "IsDebuggerPresent"),
    ("kernelbase.dll", "CheckRemoteDebuggerPresent"),
    ("ntdll.dll", "NtQueryInformationProcess"),
    ("ntdll.dll", "NtSetInformationThread"),
)

GENERIC_UI_HOST_EXES = {
    "applicationframehost.exe",
    "browser_broker.exe",
    "brave.exe",
    "brave-browser.exe",
    "chrome.exe",
    "firefox.exe",
    "explorer.exe",
    "iexplore.exe",
    "launcher.exe",
    "microsoftedge.exe",
    "msedge.exe",
    "opera.exe",
    "rundll32.exe",
    "dllhost.exe",
    "systemsettings.exe",
    "shellexperiencehost.exe",
    "searchhost.exe",
    "openwith.exe",
}

GENERIC_UI_HOST_CLASSES = {
    "ApplicationFrameWindow",
    "CabinetWClass",
    "SystemSettings",
    "Windows.UI.Core.CoreWindow",
}

GENERIC_UI_HOST_CLASSES_CASEFOLD = {
    item.casefold() for item in GENERIC_UI_HOST_CLASSES
}

NOISE_WINDOW_CLASSES = {
    "pseudoconsolewindow",
    "ime",
    "msctfime ui",
    "gdi+ hook window class",
}

IGNORED_RETARGET_EXES = {
    "x64dbg.exe",
    "x32dbg.exe",
    "conhost.exe",
    "windowsterminal.exe",
    "powershell.exe",
    "pwsh.exe",
    "codex.exe",
}

DEBUG_PROCESS_INFO_CLASSES = {
    0x7: ("ProcessDebugPort", "ptr_zero"),
    0x1E: ("ProcessDebugObjectHandle", "ptr_zero"),
    0x1F: ("ProcessDebugFlags", "ulong_one"),
}

DEBUG_THREAD_INFO_CLASSES = {
    0x11: ("ThreadHideFromDebugger", "status_zero"),
}

_LOG_LOCK = Lock()
_RUNTIME_LOCK = Lock()
_RUNTIME_STATE: Dict[str, Any] = {
    "sessionStartedAt": None,
    "lastDebuggeePid": 0,
    "lastDebuggeeImage": None,
    "lastDebuggeePath": None,
    "boundSession": None,
    "lastState": "unknown",
    "lastRip": None,
    "lastBreakpointHits": {},
    "lastConsoleText": "",
    "traceHistory": [],
    "breakpointCaptureHistory": [],
    "interactionHistory": [],
    "inputHistory": [],
    "memorySnapshots": {},
    "memorySnapshotOrder": [],
    "memorySnapshotSeq": 0,
    "windowCaptures": {},
    "windowCaptureOrder": [],
    "windowCaptureSeq": 0,
    "lastDetailedBreakpoint": None,
    "lastScyllaHide": None,
    # Authoritative identity reported by Bridge/Hello.  Mutations are never
    # allowed to rely on process-name heuristics when this identity is absent.
    "bridgeIdentity": None,
    "lastBridgeHelloAt": None,
    "lastLaunchSpec": None,
    "lastLaunchContext": None,
    "lastUiRetarget": None,
    "lastChildProcessCandidate": None,
    "selectedBridgeInstanceId": "",
    "selectedBridgeDebuggerPid": 0,
    "selectedBridgeAt": None,
    # Full-state snapshots (regs + user-picked memory ranges) keyed by id.
    "stateSnapshots": {},
    "stateSnapshotOrder": [],
    "stateSnapshotSeq": 0,
    # API call traces keyed by session id.
    "apiTraces": {},
    "apiTraceSeq": 0,
    # Heap-tracking sessions keyed by id.
    "heapTraces": {},
    "heapTraceSeq": 0,
    # Trace record sessions keyed by id.
    "traceRecords": {},
    "traceRecordSeq": 0,
    # Workflow-owned breakpoint leases.  Entries are session-bound and never
    # survive a bridge/debuggee turnover; user-created breakpoints are marked
    # preexisting and are therefore never removed by lease cleanup.
    "breakpointLeases": {},
}

# Max number of entries/snapshots to keep per category (oldest dropped).
MAX_STATE_SNAPSHOTS = 32
MAX_API_TRACE_SESSIONS = 8
MAX_API_TRACE_CALLS = 5000  # per session
MAX_HEAP_TRACE_SESSIONS = 4
MAX_TRACE_RECORD_SESSIONS = 4
MAX_TRACE_RECORD_EVENTS = 50000

if os.name == "nt":
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    INPUT_KEYBOARD = 1
    INPUT_MOUSE = 0
    KEYEVENTF_KEYUP = 0x0002
    KEYEVENTF_UNICODE = 0x0004
    KEYEVENTF_SCANCODE = 0x0008
    KEYEVENTF_EXTENDEDKEY = 0x0001
    VK_RETURN = 0x0D
    VK_TAB = 0x09
    VK_ESCAPE = 0x1B
    VK_SPACE = 0x20
    VK_LEFT = 0x25
    VK_UP = 0x26
    VK_RIGHT = 0x27
    VK_DOWN = 0x28
    VK_HOME = 0x24
    VK_END = 0x23
    VK_PRIOR = 0x21
    VK_NEXT = 0x22
    VK_INSERT = 0x2D
    VK_DELETE = 0x2E
    VK_BACK = 0x08
    VK_CONTROL = 0x11
    VK_MENU = 0x12
    VK_SHIFT = 0x10
    SW_RESTORE = 9
    GA_ROOT = 2
    MOUSEEVENTF_MOVE = 0x0001
    MOUSEEVENTF_LEFTDOWN = 0x0002
    MOUSEEVENTF_LEFTUP = 0x0004
    MOUSEEVENTF_RIGHTDOWN = 0x0008
    MOUSEEVENTF_RIGHTUP = 0x0010
    MOUSEEVENTF_WHEEL = 0x0800
    WHEEL_DELTA = 120
    SRCCOPY = 0x00CC0020
    BI_RGB = 0
    DIB_RGB_COLORS = 0
    SYNCHRONIZE = 0x00100000
    PROCESS_ALL_ACCESS = 0x001F0FFF
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    WAIT_OBJECT_0 = 0x00000000
    WAIT_TIMEOUT = 0x00000102
    WAIT_FAILED = 0xFFFFFFFF

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    KEY_EVENT = 0x0001
    SHIFT_PRESSED = 0x0010
    LEFT_CTRL_PRESSED = 0x0008
    LEFT_ALT_PRESSED = 0x0002
    SMTO_ABORTIFHUNG = 0x0002
    SMTO_BLOCK = 0x0001
    WM_GETTEXT = 0x000D
    WM_GETTEXTLENGTH = 0x000E
    WM_SETTEXT = 0x000C
    WM_COMMAND = 0x0111
    WM_CHAR = 0x0102
    WM_LBUTTONDOWN = 0x0201
    WM_LBUTTONUP = 0x0202
    BM_CLICK = 0x00F5
    BM_GETCHECK = 0x00F0
    EM_SETSEL = 0x00B1
    EM_REPLACESEL = 0x00C2
    GWL_STYLE = -16
    GWL_EXSTYLE = -20
    ES_PASSWORD = 0x0020
    BS_PUSHBUTTON = 0x00000000
    BS_DEFPUSHBUTTON = 0x00000001
    BS_CHECKBOX = 0x00000002
    BS_AUTOCHECKBOX = 0x00000003
    BS_RADIOBUTTON = 0x00000004
    BS_3STATE = 0x00000005
    BS_AUTO3STATE = 0x00000006
    BS_GROUPBOX = 0x00000007
    BS_AUTORADIOBUTTON = 0x00000009
    BN_CLICKED = 0
    MK_LBUTTON = 0x0001

    ULONG_PTR = wintypes.WPARAM
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [
            ("wVk", wintypes.WORD),
            ("wScan", wintypes.WORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ULONG_PTR),
        ]

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [
            ("dx", wintypes.LONG),
            ("dy", wintypes.LONG),
            ("mouseData", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ULONG_PTR),
        ]

    class HARDWAREINPUT(ctypes.Structure):
        _fields_ = [
            ("uMsg", wintypes.DWORD),
            ("wParamL", wintypes.WORD),
            ("wParamH", wintypes.WORD),
        ]

    class INPUT_UNION(ctypes.Union):
        _fields_ = [
            ("ki", KEYBDINPUT),
            ("mi", MOUSEINPUT),
            ("hi", HARDWAREINPUT),
        ]

    class INPUT(ctypes.Structure):
        _anonymous_ = ("u",)
        _fields_ = [
            ("type", wintypes.DWORD),
            ("u", INPUT_UNION),
        ]

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ULONG_PTR),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    class CHAR_UNION(ctypes.Union):
        _fields_ = [
            ("UnicodeChar", wintypes.WCHAR),
            ("AsciiChar", ctypes.c_char),
        ]

    class KEY_EVENT_RECORD(ctypes.Structure):
        _fields_ = [
            ("bKeyDown", wintypes.BOOL),
            ("wRepeatCount", wintypes.WORD),
            ("wVirtualKeyCode", wintypes.WORD),
            ("wVirtualScanCode", wintypes.WORD),
            ("uChar", CHAR_UNION),
            ("dwControlKeyState", wintypes.DWORD),
        ]

    class INPUT_RECORD_UNION(ctypes.Union):
        _fields_ = [
            ("KeyEvent", KEY_EVENT_RECORD),
            ("Padding", ctypes.c_byte * 16),
        ]

    class INPUT_RECORD(ctypes.Structure):
        _anonymous_ = ("Event",)
        _fields_ = [
            ("EventType", wintypes.WORD),
            ("Event", INPUT_RECORD_UNION),
        ]

    class COORD(ctypes.Structure):
        _fields_ = [
            ("X", wintypes.SHORT),
            ("Y", wintypes.SHORT),
        ]

    class SMALL_RECT(ctypes.Structure):
        _fields_ = [
            ("Left", wintypes.SHORT),
            ("Top", wintypes.SHORT),
            ("Right", wintypes.SHORT),
            ("Bottom", wintypes.SHORT),
        ]

    class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
        _fields_ = [
            ("dwSize", COORD),
            ("dwCursorPosition", COORD),
            ("wAttributes", wintypes.WORD),
            ("srWindow", SMALL_RECT),
            ("dwMaximumWindowSize", COORD),
        ]

    class RECT(ctypes.Structure):
        _fields_ = [
            ("left", wintypes.LONG),
            ("top", wintypes.LONG),
            ("right", wintypes.LONG),
            ("bottom", wintypes.LONG),
        ]

    class POINT(ctypes.Structure):
        _fields_ = [
            ("x", wintypes.LONG),
            ("y", wintypes.LONG),
        ]

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [
            ("biSize", wintypes.DWORD),
            ("biWidth", wintypes.LONG),
            ("biHeight", wintypes.LONG),
            ("biPlanes", wintypes.WORD),
            ("biBitCount", wintypes.WORD),
            ("biCompression", wintypes.DWORD),
            ("biSizeImage", wintypes.DWORD),
            ("biXPelsPerMeter", wintypes.LONG),
            ("biYPelsPerMeter", wintypes.LONG),
            ("biClrUsed", wintypes.DWORD),
            ("biClrImportant", wintypes.DWORD),
        ]

    class RGBQUAD(ctypes.Structure):
        _fields_ = [
            ("rgbBlue", wintypes.BYTE),
            ("rgbGreen", wintypes.BYTE),
            ("rgbRed", wintypes.BYTE),
            ("rgbReserved", wintypes.BYTE),
        ]

    class BITMAPINFO(ctypes.Structure):
        _fields_ = [
            ("bmiHeader", BITMAPINFOHEADER),
            ("bmiColors", RGBQUAD * 1),
        ]

    user32.SendInput.argtypes = (wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int)
    user32.SendInput.restype = wintypes.UINT
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.GetWindowTextLengthW.argtypes = (wintypes.HWND,)
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.GetWindowTextA.argtypes = (wintypes.HWND, ctypes.c_char_p, ctypes.c_int)
    user32.GetWindowTextA.restype = ctypes.c_int
    user32.GetWindowThreadProcessId.argtypes = (
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    )
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.SetForegroundWindow.argtypes = (wintypes.HWND,)
    user32.SetForegroundWindow.restype = wintypes.BOOL
    user32.BringWindowToTop.argtypes = (wintypes.HWND,)
    user32.BringWindowToTop.restype = wintypes.BOOL
    user32.SetActiveWindow.argtypes = (wintypes.HWND,)
    user32.SetActiveWindow.restype = wintypes.HWND
    user32.SetFocus.argtypes = (wintypes.HWND,)
    user32.SetFocus.restype = wintypes.HWND
    user32.AttachThreadInput.argtypes = (wintypes.DWORD, wintypes.DWORD, wintypes.BOOL)
    user32.AttachThreadInput.restype = wintypes.BOOL
    user32.SetCursorPos.argtypes = (ctypes.c_int, ctypes.c_int)
    user32.SetCursorPos.restype = wintypes.BOOL
    user32.ShowWindow.argtypes = (wintypes.HWND, ctypes.c_int)
    user32.ShowWindow.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = (wintypes.HWND,)
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.EnumWindows.argtypes = (WNDENUMPROC, wintypes.LPARAM)
    user32.EnumWindows.restype = wintypes.BOOL
    user32.EnumChildWindows.argtypes = (wintypes.HWND, WNDENUMPROC, wintypes.LPARAM)
    user32.EnumChildWindows.restype = wintypes.BOOL
    user32.VkKeyScanW.argtypes = (wintypes.WCHAR,)
    user32.VkKeyScanW.restype = ctypes.c_short
    user32.MapVirtualKeyW.argtypes = (wintypes.UINT, wintypes.UINT)
    user32.MapVirtualKeyW.restype = wintypes.UINT
    user32.GetClassNameW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    user32.GetClassNameW.restype = ctypes.c_int
    user32.GetDlgCtrlID.argtypes = (wintypes.HWND,)
    user32.GetDlgCtrlID.restype = ctypes.c_int
    user32.IsWindowEnabled.argtypes = (wintypes.HWND,)
    user32.IsWindowEnabled.restype = wintypes.BOOL
    user32.GetWindowRect.argtypes = (wintypes.HWND, ctypes.POINTER(RECT))
    user32.GetWindowRect.restype = wintypes.BOOL
    user32.GetClientRect.argtypes = (wintypes.HWND, ctypes.POINTER(RECT))
    user32.GetClientRect.restype = wintypes.BOOL
    user32.ClientToScreen.argtypes = (wintypes.HWND, ctypes.POINTER(POINT))
    user32.ClientToScreen.restype = wintypes.BOOL
    user32.GetAncestor.argtypes = (wintypes.HWND, wintypes.UINT)
    user32.GetAncestor.restype = wintypes.HWND
    user32.GetParent.argtypes = (wintypes.HWND,)
    user32.GetParent.restype = wintypes.HWND
    user32.SendMessageW.argtypes = (
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    )
    user32.SendMessageW.restype = wintypes.LPARAM
    user32.PostMessageW.argtypes = (
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    )
    user32.PostMessageW.restype = wintypes.BOOL
    user32.SendMessageTimeoutW.argtypes = (
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
        wintypes.UINT,
        wintypes.UINT,
        ctypes.POINTER(ULONG_PTR),
    )
    user32.SendMessageTimeoutW.restype = wintypes.LPARAM
    user32.SendMessageTimeoutA.argtypes = (
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
        wintypes.UINT,
        wintypes.UINT,
        ctypes.POINTER(ULONG_PTR),
    )
    user32.SendMessageTimeoutA.restype = wintypes.LPARAM
    if hasattr(user32, "GetWindowLongPtrW"):
        user32.GetWindowLongPtrW.argtypes = (wintypes.HWND, ctypes.c_int)
        user32.GetWindowLongPtrW.restype = (
            ctypes.c_longlong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_long
        )
        _get_window_long = user32.GetWindowLongPtrW
    else:
        user32.GetWindowLongW.argtypes = (wintypes.HWND, ctypes.c_int)
        user32.GetWindowLongW.restype = ctypes.c_long
        _get_window_long = user32.GetWindowLongW

    kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.GetShortPathNameW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
    )
    kernel32.GetShortPathNameW.restype = wintypes.DWORD
    kernel32.Process32FirstW.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(PROCESSENTRY32W),
    )
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(PROCESSENTRY32W),
    )
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    if hasattr(ntdll, "NtQueryInformationProcess"):
        ntdll.NtQueryInformationProcess.argtypes = (
            wintypes.HANDLE,
            wintypes.ULONG,
            wintypes.LPVOID,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
        )
        ntdll.NtQueryInformationProcess.restype = ctypes.c_long
    if hasattr(ntdll, "NtRemoveProcessDebug"):
        ntdll.NtRemoveProcessDebug.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        ntdll.NtRemoveProcessDebug.restype = ctypes.c_long
    user32.WaitForInputIdle.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    user32.WaitForInputIdle.restype = wintypes.DWORD
    kernel32.GetCurrentThreadId.restype = wintypes.DWORD
    kernel32.FreeConsole.restype = wintypes.BOOL
    kernel32.AttachConsole.argtypes = (wintypes.DWORD,)
    kernel32.AttachConsole.restype = wintypes.BOOL
    kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.WriteConsoleInputW.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(INPUT_RECORD),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.WriteConsoleInputW.restype = wintypes.BOOL
    kernel32.GetConsoleScreenBufferInfo.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(CONSOLE_SCREEN_BUFFER_INFO),
    )
    kernel32.GetConsoleScreenBufferInfo.restype = wintypes.BOOL
    kernel32.ReadConsoleOutputCharacterW.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        COORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.ReadConsoleOutputCharacterW.restype = wintypes.BOOL
    user32.GetDC.argtypes = (wintypes.HWND,)
    user32.GetDC.restype = wintypes.HDC
    user32.ReleaseDC.argtypes = (wintypes.HWND, wintypes.HDC)
    user32.ReleaseDC.restype = ctypes.c_int
    gdi32.CreateCompatibleDC.argtypes = (wintypes.HDC,)
    gdi32.CreateCompatibleDC.restype = wintypes.HDC
    gdi32.DeleteDC.argtypes = (wintypes.HDC,)
    gdi32.DeleteDC.restype = wintypes.BOOL
    gdi32.CreateCompatibleBitmap.argtypes = (wintypes.HDC, ctypes.c_int, ctypes.c_int)
    gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
    gdi32.SelectObject.argtypes = (wintypes.HDC, wintypes.HGDIOBJ)
    gdi32.SelectObject.restype = wintypes.HGDIOBJ
    gdi32.BitBlt.argtypes = (
        wintypes.HDC,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HDC,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.DWORD,
    )
    gdi32.BitBlt.restype = wintypes.BOOL
    gdi32.DeleteObject.argtypes = (wintypes.HGDIOBJ,)
    gdi32.DeleteObject.restype = wintypes.BOOL
    gdi32.GetDIBits.argtypes = (
        wintypes.HDC,
        wintypes.HBITMAP,
        wintypes.UINT,
        wintypes.UINT,
        wintypes.LPVOID,
        ctypes.POINTER(BITMAPINFO),
        wintypes.UINT,
    )
    gdi32.GetDIBits.restype = ctypes.c_int


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


_RUNTIME_STATE["sessionStartedAt"] = _now_iso()


def _trim_text(value: Any, limit: int = 800) -> Any:
    if not isinstance(value, str):
        return value
    if len(value) <= limit:
        return value
    return value[:limit] + f"... <trimmed {len(value) - limit} chars>"


def _log_event(kind: str, **fields: Any) -> None:
    entry = {
        "ts": _now_iso(),
        "kind": kind,
        "fields": _json_safe(fields),
    }
    with _RUNTIME_LOCK:
        history = list(_RUNTIME_STATE.get("interactionHistory", []))
        history.append(entry)
        if len(history) > 256:
            history = history[-256:]
        _RUNTIME_STATE["interactionHistory"] = history
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with _LOG_LOCK:
            with open(LOG_PATH, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _tail_log(limit: int = 80) -> List[str]:
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as handle:
        return list(deque(handle, maxlen=max(1, limit)))


def _run_powershell_json(script: str, timeout_ms: int = 5000) -> Dict[str, Any]:
    command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        base64.b64encode(script.encode("utf-16le")).decode("ascii"),
    ]
    creationflags = 0x08000000 if os.name == "nt" else 0
    completed = subprocess.run(
        command,
        capture_output=True,
        timeout=max(1, int(timeout_ms)) / 1000.0,
        creationflags=creationflags,
    )
    stdout = (completed.stdout or b"").decode("utf-8", errors="replace").strip()
    stderr = (completed.stderr or b"").decode("utf-8", errors="replace").strip()
    if completed.returncode != 0:
        raise RuntimeError(
            f"PowerShell failed ({completed.returncode}): {stderr or stdout or 'no output'}"
        )
    if not stdout:
        return {"ok": True}
    try:
        return _repair_payload_strings(json.loads(stdout))
    except Exception as exc:
        raise RuntimeError(
            f"PowerShell returned non-JSON output: {stdout[:400]!r}"
        ) from exc


def _text_suspicious_mojibake_score(value: str) -> int:
    if not value:
        return 0
    score = sum(value.count(ch) for ch in ("Р", "С", "Ð", "Ñ"))
    score += len(re.findall(r"(?:Р.|С.|Ð.|Ñ.)", value))
    return score


def _text_cyrillic_score(value: str) -> int:
    if not value:
        return 0
    return sum(1 for ch in value if "\u0400" <= ch <= "\u04ff")


def _repair_text_mojibake(value: str) -> str:
    if not isinstance(value, str) or len(value) < 4:
        return value
    suspicious = _text_suspicious_mojibake_score(value)
    if suspicious < 2:
        return value
    best = value
    best_suspicious = suspicious
    best_cyrillic = _text_cyrillic_score(value)
    for encoding in ("cp1251", "latin1"):
        try:
            repaired = value.encode(encoding).decode("utf-8")
        except Exception:
            continue
        repaired_suspicious = _text_suspicious_mojibake_score(repaired)
        repaired_cyrillic = _text_cyrillic_score(repaired)
        if repaired_suspicious < best_suspicious and repaired_cyrillic >= best_cyrillic:
            best = repaired
            best_suspicious = repaired_suspicious
            best_cyrillic = repaired_cyrillic
    return best


def _repair_payload_strings(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _repair_payload_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_repair_payload_strings(item) for item in value]
    if isinstance(value, str):
        return _repair_text_mojibake(value)
    return value


def _text_suspicious_mojibake_score_v2(value: str) -> int:
    if not value:
        return 0
    markers = ("Р", "С", "Ð", "Ñ", "Ã", "Â", "â")
    score = sum(value.count(ch) for ch in markers)
    score += len(re.findall(r"(?:Р.|С.|Ð.|Ñ.|Ã.|Â.|â.)", value))
    return score


def _looks_path_like_for_repair(value: str) -> bool:
    if not value:
        return False
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return True
    return "\\" in value or "/" in value


def _repair_text_mojibake_v2(value: str) -> str:
    if not isinstance(value, str) or len(value) < 4:
        return value
    suspicious = _text_suspicious_mojibake_score_v2(value)
    path_like = _looks_path_like_for_repair(value)
    if suspicious < 2 and not (path_like and any(ord(ch) >= 128 for ch in value)):
        return value

    best = value
    best_suspicious = suspicious
    best_cyrillic = _text_cyrillic_score(value)
    best_exists = path_like and os.path.exists(best)
    best_parent_exists = bool(os.path.dirname(best)) and os.path.exists(
        os.path.dirname(best)
    )
    for encoding in ("cp1251", "cp866", "cp1252", "latin1"):
        try:
            repaired = value.encode(encoding).decode("utf-8")
        except Exception:
            continue
        repaired_suspicious = _text_suspicious_mojibake_score_v2(repaired)
        repaired_cyrillic = _text_cyrillic_score(repaired)
        repaired_exists = path_like and os.path.exists(repaired)
        repaired_parent_exists = bool(os.path.dirname(repaired)) and os.path.exists(
            os.path.dirname(repaired)
        )
        if repaired_exists and not best_exists:
            best = repaired
            best_suspicious = repaired_suspicious
            best_cyrillic = repaired_cyrillic
            best_exists = repaired_exists
            best_parent_exists = repaired_parent_exists
            continue
        if (
            repaired_parent_exists
            and not best_parent_exists
            and repaired_suspicious <= best_suspicious
        ):
            best = repaired
            best_suspicious = repaired_suspicious
            best_cyrillic = repaired_cyrillic
            best_exists = repaired_exists
            best_parent_exists = repaired_parent_exists
            continue
        if repaired_suspicious < best_suspicious and (
            not path_like or repaired_cyrillic > 0 or repaired_parent_exists
        ):
            best = repaired
            best_suspicious = repaired_suspicious
            best_cyrillic = repaired_cyrillic
            best_exists = repaired_exists
            best_parent_exists = repaired_parent_exists
            continue
        if repaired_suspicious == best_suspicious and repaired_cyrillic > best_cyrillic:
            best = repaired
            best_suspicious = repaired_suspicious
            best_cyrillic = repaired_cyrillic
            best_exists = repaired_exists
            best_parent_exists = repaired_parent_exists
    return best


def _text_suspicious_mojibake_score_v3(value: str) -> int:
    if not value:
        return 0
    markers = ("\u0420", "\u0421", "\u00d0", "\u00d1", "\u0413", "\u0412", "\u0432")
    score = sum(value.count(ch) for ch in markers)
    score += len(
        re.findall(
            r"(?:\u0420.|\u0421.|\u00d0.|\u00d1.|\u0413.|\u0412.|\u0432.)",
            value,
        )
    )
    return score


def _repair_text_mojibake_v3(value: str) -> str:
    if not isinstance(value, str) or len(value) < 4:
        return value
    suspicious = _text_suspicious_mojibake_score_v3(value)
    path_like = _looks_path_like_for_repair(value)
    if suspicious < 2 and not (path_like and any(ord(ch) >= 128 for ch in value)):
        return value

    best = value
    best_suspicious = suspicious
    best_cyrillic = _text_cyrillic_score(value)
    best_exists = path_like and os.path.exists(best)
    best_parent_exists = bool(os.path.dirname(best)) and os.path.exists(
        os.path.dirname(best)
    )
    for encoding in ("cp1251", "cp866", "cp1252", "latin1"):
        try:
            repaired = value.encode(encoding).decode("utf-8")
        except Exception:
            continue
        repaired_suspicious = _text_suspicious_mojibake_score_v3(repaired)
        repaired_cyrillic = _text_cyrillic_score(repaired)
        repaired_exists = path_like and os.path.exists(repaired)
        repaired_parent_exists = bool(os.path.dirname(repaired)) and os.path.exists(
            os.path.dirname(repaired)
        )
        if repaired_exists and not best_exists:
            best = repaired
            best_suspicious = repaired_suspicious
            best_cyrillic = repaired_cyrillic
            best_exists = repaired_exists
            best_parent_exists = repaired_parent_exists
            continue
        if (
            repaired_parent_exists
            and not best_parent_exists
            and repaired_suspicious <= best_suspicious
        ):
            best = repaired
            best_suspicious = repaired_suspicious
            best_cyrillic = repaired_cyrillic
            best_exists = repaired_exists
            best_parent_exists = repaired_parent_exists
            continue
        if repaired_suspicious < best_suspicious and (
            not path_like or repaired_cyrillic > 0 or repaired_parent_exists
        ):
            best = repaired
            best_suspicious = repaired_suspicious
            best_cyrillic = repaired_cyrillic
            best_exists = repaired_exists
            best_parent_exists = repaired_parent_exists
            continue
        if repaired_suspicious == best_suspicious and repaired_cyrillic > best_cyrillic:
            best = repaired
            best_suspicious = repaired_suspicious
            best_cyrillic = repaired_cyrillic
            best_exists = repaired_exists
            best_parent_exists = repaired_parent_exists
    return best


_text_suspicious_mojibake_score = _text_suspicious_mojibake_score_v3
_repair_text_mojibake = _repair_text_mojibake_v3


def _coerce_json_payload(result: Any) -> Any:
    if isinstance(result, (dict, list)):
        return _repair_payload_strings(result)
    if isinstance(result, str):
        try:
            return _repair_payload_strings(json.loads(result))
        except json.JSONDecodeError:
            return None
    return None


def _decode_http_text(response: Any) -> str:
    raw = getattr(response, "content", b"") or b""
    if raw:
        try:
            return _decode_best_effort_bytes(raw).strip()
        except Exception:
            pass
    text = getattr(response, "text", "") or ""
    return _repair_text_mojibake(str(text)).strip()


def _decode_http_json_or_text(response: Any) -> tuple[Optional[Any], str]:
    text = _decode_http_text(response)
    payload = _coerce_json_payload(text)
    return payload, text


def _normalize_hex(addr: Any) -> Optional[str]:
    if addr in (None, ""):
        return None
    try:
        return f"0x{int(str(addr), 0):x}"
    except Exception:
        return str(addr).strip().lower()


def _parse_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value in (None, ""):
        return default
    try:
        return int(str(value), 0)
    except Exception:
        return default


def _require_windows() -> None:
    if os.name != "nt":
        raise RuntimeError("This tool is only available on Windows")


def _list_processes() -> List[Dict[str, Any]]:
    _require_windows()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise OSError(f"CreateToolhelp32Snapshot failed: {ctypes.get_last_error()}")
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        items: List[Dict[str, Any]] = []
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            items.append(
                {
                    "pid": int(entry.th32ProcessID),
                    "ppid": int(entry.th32ParentProcessID),
                    "exe": entry.szExeFile,
                }
            )
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        return items
    finally:
        kernel32.CloseHandle(snapshot)


def _process_exists(pid: int) -> bool:
    if not pid:
        return False
    try:
        return any(int(item["pid"]) == int(pid) for item in _list_processes())
    except Exception:
        return False


def _get_process_info(pid: int) -> Dict[str, Any]:
    if not pid:
        return {}
    try:
        return next(
            (
                item
                for item in _list_processes()
                if int(item.get("pid") or 0) == int(pid)
            ),
            {},
        )
    except Exception:
        return {}


def _get_process_image_path(pid: int) -> str:
    if not pid:
        return ""
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return ""
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(int(size.value))
        if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return _repair_text_mojibake(buf.value)
        return ""
    finally:
        kernel32.CloseHandle(handle)


def _ntstatus_hex(status: Any) -> str:
    parsed = _parse_int(status)
    if parsed is None:
        return str(status or "")
    return f"0x{parsed & 0xFFFFFFFF:08X}"


def _query_process_debug_status(pid: int = 0) -> Dict[str, Any]:
    target_pid = int(pid or 0)
    if not target_pid:
        try:
            target_pid = _infer_debuggee_pid(0)
        except Exception:
            target_pid = int(_get_runtime_value("lastDebuggeePid", 0) or 0)
    if not target_pid:
        return {"ok": False, "pid": 0, "error": "Could not resolve a target PID."}
    if os.name != "nt" or "ntdll" not in globals():
        return {"ok": False, "pid": target_pid, "error": "Windows-only helper."}
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        int(target_pid),
    )
    if not handle:
        return {
            "ok": False,
            "pid": target_pid,
            "imagePath": _get_process_image_path(target_pid),
            "error": f"OpenProcess failed: {ctypes.get_last_error()}",
        }
    try:
        status_entries: Dict[str, Any] = {}

        def _query_handle_value(info_class: int) -> Tuple[int, int]:
            retlen = wintypes.ULONG(0)
            holder = ctypes.c_size_t(0)
            status = int(
                ntdll.NtQueryInformationProcess(
                    handle,
                    info_class,
                    ctypes.byref(holder),
                    ctypes.sizeof(holder),
                    ctypes.byref(retlen),
                )
            )
            return status, int(holder.value or 0)

        def _query_ulong_value(info_class: int) -> Tuple[int, int]:
            retlen = wintypes.ULONG(0)
            holder = wintypes.ULONG(0)
            status = int(
                ntdll.NtQueryInformationProcess(
                    handle,
                    info_class,
                    ctypes.byref(holder),
                    ctypes.sizeof(holder),
                    ctypes.byref(retlen),
                )
            )
            return status, int(holder.value or 0)

        debug_port_status, debug_port = _query_handle_value(0x7)
        debug_object_status, debug_object = _query_handle_value(0x1E)
        debug_flags_status, debug_flags = _query_ulong_value(0x1F)
        status_entries["debugPortStatus"] = _ntstatus_hex(debug_port_status)
        status_entries["debugObjectStatus"] = _ntstatus_hex(debug_object_status)
        status_entries["debugFlagsStatus"] = _ntstatus_hex(debug_flags_status)
        under_debugger = bool(debug_port) or bool(debug_object) or debug_flags == 0
        return {
            "ok": True,
            "pid": target_pid,
            "imagePath": _get_process_image_path(target_pid),
            "debugPort": _normalize_hex(debug_port) or "0x0",
            "debugObjectHandle": _normalize_hex(debug_object) or "0x0",
            "debugFlags": debug_flags,
            "underDebugger": under_debugger,
            "statuses": status_entries,
        }
    finally:
        kernel32.CloseHandle(handle)


def _remove_process_debug_object(pid: int = 0) -> Dict[str, Any]:
    status = _query_process_debug_status(pid=pid)
    if not status.get("ok"):
        return dict(status)
    target_pid = int(status.get("pid") or 0)
    debug_object = _parse_int(status.get("debugObjectHandle"))
    if not debug_object:
        return {
            "ok": True,
            "pid": target_pid,
            "removed": False,
            "status": status,
            "reason": "No debug object handle was present.",
        }
    if os.name != "nt" or "ntdll" not in globals() or not hasattr(
        ntdll, "NtRemoveProcessDebug"
    ):
        return {
            "ok": False,
            "pid": target_pid,
            "removed": False,
            "status": status,
            "error": "NtRemoveProcessDebug is unavailable.",
        }
    handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(target_pid))
    if not handle:
        return {
            "ok": False,
            "pid": target_pid,
            "removed": False,
            "status": status,
            "error": f"OpenProcess failed: {ctypes.get_last_error()}",
        }
    try:
        ntstatus = int(
            ntdll.NtRemoveProcessDebug(handle, ctypes.c_void_p(int(debug_object)))
        )
    finally:
        kernel32.CloseHandle(handle)
    try:
        kernel32.CloseHandle(ctypes.c_void_p(int(debug_object)))
    except Exception:
        pass
    refreshed = _query_process_debug_status(pid=target_pid)
    return {
        "ok": ntstatus == 0,
        "pid": target_pid,
        "removed": ntstatus == 0,
        "ntstatus": _ntstatus_hex(ntstatus),
        "status": status,
        "statusAfter": refreshed,
        "hint": None
        if ntstatus == 0
        else "Target may still be owned by another debugger or the handle was stale.",
    }


def _build_attach_failure_diagnostics(pid: int) -> Dict[str, Any]:
    diagnostics = _query_process_debug_status(pid=pid)
    hint = ""
    if diagnostics.get("underDebugger"):
        hint = (
            "Target appears to already have a debug port/object attached. "
            "Use RemoveProcessDebug or attach to the owning parent instead."
        )
    elif diagnostics.get("ok"):
        hint = "Target is alive but did not transition into an attached pause before timeout."
    return {"processDebug": diagnostics, "hint": hint}


def _detect_process_arch(pid: int) -> Optional[str]:
    image_path = _get_process_image_path(pid)
    if image_path and os.path.exists(image_path):
        detected = _detect_pe_arch(image_path)
        if detected in ("x86", "x64"):
            return detected
    return None


def _resolve_attach_target(pid: int = 0, exe_filter: str = "") -> Dict[str, Any]:
    target_pid = int(pid or 0)
    if target_pid:
        info = _get_process_info(target_pid)
        if not info:
            return {
                "ok": False,
                "error": f"Process {target_pid} was not found.",
                "pid": target_pid,
            }
        image_path = _get_process_image_path(target_pid)
        return {
            "ok": True,
            "pid": target_pid,
            "exe": str(info.get("exe") or ""),
            "imagePath": image_path,
            "arch": _detect_process_arch(target_pid),
            "candidates": [
                {
                    "pid": target_pid,
                    "exe": str(info.get("exe") or ""),
                    "imagePath": image_path,
                }
            ],
        }
    filter_text = _repair_text_mojibake(str(exe_filter or "").strip())
    if not filter_text:
        return {
            "ok": False,
            "error": "Either pid or exe_filter is required.",
            "pid": 0,
        }
    tokens = _normalize_name_tokens(filter_text)
    filter_looks_like_path = (
        any(sep in filter_text for sep in ("\\", "/")) or ":" in filter_text
    )
    matches: List[Dict[str, Any]] = []
    for item in _list_processes():
        pid_value = int(item.get("pid") or 0)
        exe_name = _process_basename(item.get("exe") or "")
        if not pid_value or exe_name in (
            "x64dbg.exe",
            "x32dbg.exe",
            "conhost.exe",
            "openconsole.exe",
        ):
            continue
        image_path = _get_process_image_path(pid_value)
        image_base = _process_basename(image_path or "")
        haystacks = [str(item.get("exe") or "").casefold(), image_base]
        if filter_looks_like_path:
            haystacks.append(str(image_path or "").casefold())
        if tokens and not any(
            token in haystack for token in tokens for haystack in haystacks if haystack
        ):
            continue
        matches.append(
            {
                "pid": pid_value,
                "exe": str(item.get("exe") or ""),
                "imagePath": image_path,
                "ppid": int(item.get("ppid") or 0),
                "arch": _detect_process_arch(pid_value),
                "score": 0,
            }
        )
    if not matches:
        return {
            "ok": False,
            "error": f"No running process matched exe_filter={filter_text!r}.",
            "pid": 0,
            "exeFilter": filter_text,
        }
    filter_base = _process_basename(filter_text)
    exact_path = os.path.normcase(filter_text) if os.path.isabs(filter_text) else ""
    for item in matches:
        exe_name = _process_basename(item.get("exe") or "")
        image_path = str(item.get("imagePath") or "")
        score = 0
        if filter_base and exe_name == filter_base:
            score += 120
        if exact_path and image_path and os.path.normcase(image_path) == exact_path:
            score += 180
        if _text_matches(image_path, filter_text):
            score += 35
        if _text_matches(str(item.get("exe") or ""), filter_text):
            score += 25
        score += min(50, int(item.get("pid") or 0) // 1000)
        item["score"] = score
    matches.sort(
        key=lambda item: (
            int(item.get("score") or 0),
            int(item.get("pid") or 0),
        ),
        reverse=True,
    )
    chosen = matches[0]
    return {
        "ok": True,
        "pid": int(chosen.get("pid") or 0),
        "exe": str(chosen.get("exe") or ""),
        "imagePath": str(chosen.get("imagePath") or ""),
        "arch": str(chosen.get("arch") or ""),
        "exeFilter": filter_text,
        "candidateCount": len(matches),
        "candidates": matches[:10],
    }


def _process_basename(value: str) -> str:
    return os.path.basename(str(value or "")).strip().lower()


def _rect_area(rect: Any) -> int:
    payload = rect if isinstance(rect, dict) else {}
    return max(0, int(payload.get("width") or 0)) * max(
        0, int(payload.get("height") or 0)
    )


def _is_noise_window_node(window: Dict[str, Any]) -> bool:
    if not isinstance(window, dict):
        return False
    class_lower = str(window.get("className") or "").strip().casefold()
    title = str(window.get("title") or "").strip()
    area = _rect_area(window.get("rect") or {})
    if class_lower in NOISE_WINDOW_CLASSES:
        return True
    if "hook window" in class_lower:
        return True
    if class_lower == "pseudoconsolewindow":
        return True
    if area <= 64 and not title:
        return True
    if area <= 256 and class_lower in NOISE_WINDOW_CLASSES:
        return True
    return False


def _is_meaningful_window_node(window: Dict[str, Any]) -> bool:
    return isinstance(window, dict) and not _is_noise_window_node(window)


def _get_short_path(path: str) -> str:
    if os.name != "nt":
        return ""
    candidate = str(path or "").strip()
    if not candidate:
        return ""
    try:
        size = int(kernel32.GetShortPathNameW(candidate, None, 0))
        if size <= 0:
            return ""
        buffer = ctypes.create_unicode_buffer(size + 2)
        written = int(kernel32.GetShortPathNameW(candidate, buffer, len(buffer)))
        if written <= 0:
            return ""
        short_path = _repair_text_mojibake(buffer.value)
        return short_path if short_path and os.path.exists(short_path) else ""
    except Exception:
        return ""


def _stage_ascii_launch_path(exe_path: str) -> str:
    source_path = str(exe_path or "").strip()
    if not source_path or not os.path.exists(source_path):
        return ""
    source_dir = os.path.dirname(source_path)
    base_name = os.path.basename(source_path)
    if not source_dir or not base_name:
        return ""
    if all(ord(ch) < 128 for ch in source_path):
        return source_path
    drive, _tail = os.path.splitdrive(source_dir)
    stage_root = os.path.join(
        drive + os.sep if drive else tempfile.gettempdir(), "x64dbg-mcp-alias"
    )
    alias_name = (
        re.sub(r"[^A-Za-z0-9_.-]+", "_", os.path.basename(source_dir).strip())
        or "target"
    )
    digest = hashlib.sha1(source_dir.encode("utf-8", errors="ignore")).hexdigest()[:10]
    alias_dir = os.path.join(stage_root, f"{alias_name}_{digest}")
    alias_path = os.path.join(alias_dir, base_name)
    if os.path.exists(alias_path):
        return alias_path
    try:
        os.makedirs(stage_root, exist_ok=True)
    except Exception:
        return ""
    try:
        if not os.path.exists(alias_dir):
            completed = subprocess.run(
                ["cmd", "/c", "mklink", "/J", alias_dir, source_dir],
                capture_output=True,
                creationflags=0x08000000 if os.name == "nt" else 0,
                timeout=10,
                check=False,
            )
            if completed.returncode != 0 and not os.path.isdir(alias_dir):
                raise RuntimeError(
                    (completed.stderr or completed.stdout or b"").decode(
                        "utf-8", errors="replace"
                    )
                )
        if os.path.exists(alias_path):
            return alias_path
    except Exception:
        pass
    try:
        staged_dir = os.path.join(stage_root, f"files_{digest}")
        os.makedirs(staged_dir, exist_ok=True)
        staged_name = (
            re.sub(r"[^A-Za-z0-9_.-]+", "_", os.path.splitext(base_name)[0]) or "target"
        )
        staged_path = os.path.join(
            staged_dir, staged_name + os.path.splitext(base_name)[1]
        )
        if not os.path.exists(staged_path):
            shutil.copy2(source_path, staged_path)
        return staged_path if os.path.exists(staged_path) else ""
    except Exception:
        return ""


def _append_unique_launch_path(
    paths: List[str], seen: set[str], candidate: str
) -> None:
    normalized = _repair_text_mojibake(str(candidate or "").strip())
    if not normalized:
        return
    try:
        key = os.path.normcase(os.path.normpath(normalized))
    except Exception:
        key = normalized.casefold()
    if key in seen:
        return
    seen.add(key)
    paths.append(normalized)


def _build_init_launch_paths(exe_path: str) -> List[str]:
    paths: List[str] = []
    seen: set[str] = set()
    if any(ord(ch) > 127 for ch in exe_path):
        _append_unique_launch_path(paths, seen, _get_short_path(exe_path))
        _append_unique_launch_path(paths, seen, _stage_ascii_launch_path(exe_path))
    _append_unique_launch_path(paths, seen, exe_path)
    return paths


def _normalize_name_tokens(value: str) -> List[str]:
    text = str(value or "").strip().casefold()
    if not text:
        return []
    stem = os.path.splitext(os.path.basename(text))[0]
    tokens = [item for item in re.split(r"[^a-z0-9]+", stem) if item]
    if stem and stem not in tokens:
        tokens.append(stem)
    return sorted(set(tokens))


def _collect_descendant_processes(
    parent_pid: int, include_descendants: bool = True
) -> List[Dict[str, Any]]:
    if not parent_pid:
        return []
    processes = _list_processes()
    by_parent: Dict[int, List[Dict[str, Any]]] = {}
    for item in processes:
        by_parent.setdefault(int(item.get("ppid") or 0), []).append(item)
    items: List[Dict[str, Any]] = []
    queue: List[tuple[int, int]] = [(int(parent_pid), 0)]
    seen: set[int] = {int(parent_pid)}
    while queue:
        current_pid, depth = queue.pop(0)
        for child in by_parent.get(current_pid, []):
            child_pid = int(child.get("pid") or 0)
            if not child_pid or child_pid in seen:
                    continue
            seen.add(child_pid)
            enriched = dict(child)
            enriched["depth"] = depth + 1
            items.append(enriched)
            if include_descendants:
                queue.append((child_pid, depth + 1))
    return items


def _resolve_child_watch_parent_pid(parent_pid: int = 0) -> int:
    if parent_pid:
        return int(parent_pid)
    context = _get_runtime_value("lastLaunchContext")
    if isinstance(context, dict):
        source_pid = int(context.get("sourcePid") or 0)
        if source_pid:
            return source_pid
    return int(_get_runtime_value("lastDebuggeePid", 0) or 0)


def _describe_process_candidate(
    item: Dict[str, Any],
    baseline_pids: Optional[set[int]] = None,
    visible_only: bool = True,
) -> Dict[str, Any]:
    pid_value = int(item.get("pid") or 0)
    top_hwnd = (
        _select_preferred_top_window(pid_value, visible_only=visible_only)
        if pid_value
        else 0
    )
    title = _repair_text_mojibake(_get_window_text(top_hwnd)) if top_hwnd else ""
    class_name = _repair_text_mojibake(_get_class_name(top_hwnd)) if top_hwnd else ""
    image_path = _get_process_image_path(pid_value)
    payload = {
        "pid": pid_value,
        "ppid": int(item.get("ppid") or 0),
        "depth": int(item.get("depth") or 1),
        "exe": str(item.get("exe") or ""),
        "imagePath": image_path,
        "isNew": bool(
            pid_value and baseline_pids is not None and pid_value not in baseline_pids
        ),
        "hasWindow": bool(top_hwnd),
        "topWindowHwnd": f"0x{top_hwnd:X}" if top_hwnd else "",
        "topWindowTitle": title,
        "topWindowClass": class_name,
    }
    if top_hwnd:
        payload["windowRect"] = _window_bounds(top_hwnd, client_only=False)
    return payload


def _score_child_process_candidate(
    candidate: Dict[str, Any], exe_filter: str = ""
) -> int:
    score = 0
    pid_value = int(candidate.get("pid") or 0)
    exe_name = _process_basename(candidate.get("exe"))
    title = str(candidate.get("topWindowTitle") or "")
    class_name = str(candidate.get("topWindowClass") or "")
    image_path = str(candidate.get("imagePath") or "")
    depth = int(candidate.get("depth") or 1)
    if pid_value:
        score += 5
    relationship = str(candidate.get("relationship") or "")
    if relationship == "descendant":
        score += 35
    elif relationship == "new_process":
        score += 12
    if bool(candidate.get("isNew")):
        score += 90
    if bool(candidate.get("hasWindow")):
        score += 30
    if depth == 1:
        score += 25
    elif depth == 2:
        score += 10
    area = int(
        ((candidate.get("windowRect") or {}).get("width") or 0)
        * ((candidate.get("windowRect") or {}).get("height") or 0)
    )
    if area >= 120000:
        score += 12
    filter_tokens = _normalize_name_tokens(exe_filter)
    for token in filter_tokens:
        if token in exe_name:
            score += 60
        if token in image_path.casefold():
            score += 40
        if token in title.casefold():
            score += 25
        if token in class_name.casefold():
            score += 10
    context = _get_runtime_value("lastLaunchContext")
    if isinstance(context, dict):
        target_tokens = _normalize_name_tokens(str(context.get("targetBaseName") or ""))
        for token in target_tokens:
            if token in exe_name:
                score += 35
            if token in title.casefold():
                score += 20
        before_pids = {
            int(item)
            for item in list(context.get("processIds") or [])
            if int(item or 0)
        }
        if pid_value and pid_value not in before_pids:
            score += 10
    if exe_name in GENERIC_UI_HOST_EXES:
        score += 15
    if title:
        score += 5
    return score


def _list_child_process_candidates(
    parent_pid: int = 0,
    include_descendants: bool = True,
    only_new: bool = False,
    exe_filter: str = "",
    visible_only: bool = True,
    include_console_hosts: bool = False,
) -> Dict[str, Any]:
    watch_parent = _resolve_child_watch_parent_pid(parent_pid)
    if not watch_parent:
        return {
            "ok": False,
            "error": "Could not resolve a parent PID to watch",
            "parentPid": 0,
            "children": [],
        }
    context = _get_runtime_value("lastLaunchContext")
    baseline_pids = None
    if isinstance(context, dict):
        baseline_pids = {
            int(item)
            for item in list(context.get("processIds") or [])
            if int(item or 0)
        }
    descendants = _collect_descendant_processes(
        watch_parent, include_descendants=include_descendants
    )
    descendant_pids = {int(item.get("pid") or 0) for item in descendants}
    children: List[Dict[str, Any]] = []
    seen_pids: set[int] = set()
    for item in descendants:
        described = _describe_process_candidate(
            item, baseline_pids=baseline_pids, visible_only=visible_only
        )
        exe_name = _process_basename(described.get("exe"))
        if not include_console_hosts and exe_name in ("conhost.exe", "openconsole.exe"):
            continue
        if exe_name in IGNORED_RETARGET_EXES:
            continue
        described["relationship"] = "descendant"
        if only_new and not described.get("isNew"):
            continue
        if exe_filter:
            tokens = _normalize_name_tokens(exe_filter)
            haystack = " ".join(
                [
                    _process_basename(described.get("exe")),
                    str(described.get("imagePath") or "").casefold(),
                    str(described.get("topWindowTitle") or "").casefold(),
                    str(described.get("topWindowClass") or "").casefold(),
                ]
            )
            if tokens and not any(token in haystack for token in tokens):
                continue
        described["score"] = _score_child_process_candidate(
            described, exe_filter=exe_filter
        )
        children.append(described)
        seen_pids.add(int(described.get("pid") or 0))

    context = _get_runtime_value("lastLaunchContext")
    target_tokens = (
        _normalize_name_tokens(str((context or {}).get("targetBaseName") or ""))
        if isinstance(context, dict)
        else []
    )
    for item in _list_processes():
        pid_value = int(item.get("pid") or 0)
        if (
            not pid_value
            or pid_value == watch_parent
            or pid_value in descendant_pids
            or pid_value in seen_pids
        ):
            continue
        described = _describe_process_candidate(
            item, baseline_pids=baseline_pids, visible_only=visible_only
        )
        exe_name = _process_basename(described.get("exe"))
        if not include_console_hosts and exe_name in ("conhost.exe", "openconsole.exe"):
            continue
        if exe_name in IGNORED_RETARGET_EXES:
            continue
        if only_new and not described.get("isNew"):
            continue
        if not described.get("isNew"):
            continue
        token_haystack = " ".join(
            [
                exe_name,
                str(described.get("imagePath") or "").casefold(),
                str(described.get("topWindowTitle") or "").casefold(),
                str(described.get("topWindowClass") or "").casefold(),
            ]
        )
        filter_tokens = _normalize_name_tokens(exe_filter)
        target_match = any(token and token in token_haystack for token in target_tokens)
        filter_match = any(token and token in token_haystack for token in filter_tokens)
        if not (filter_match or target_match or described.get("hasWindow")):
            continue
        described["relationship"] = "new_process"
        described["score"] = _score_child_process_candidate(
            described, exe_filter=exe_filter
        )
        children.append(described)
        seen_pids.add(pid_value)
    retarget_process = _discover_launch_retarget_process_candidate(
        visible_only=visible_only, exe_filter=exe_filter
    )
    retarget_pid = int((retarget_process or {}).get("pid") or 0)
    if retarget_process and retarget_pid and retarget_pid not in seen_pids:
        if not (only_new and not retarget_process.get("isNew")):
            children.append(retarget_process)
            seen_pids.add(retarget_pid)
    children.sort(
        key=lambda item: (
            int(item.get("score") or 0),
            1 if item.get("hasWindow") else 0,
            1 if item.get("isNew") else 0,
            -int(item.get("depth") or 0),
            int(item.get("pid") or 0),
        ),
        reverse=True,
    )
    return {
        "ok": True,
        "parentPid": watch_parent,
        "includeDescendants": bool(include_descendants),
        "onlyNew": bool(only_new),
        "exeFilter": exe_filter,
        "includeConsoleHosts": bool(include_console_hosts),
        "count": len(children),
        "children": children,
    }


def _enumerate_top_windows_global(visible_only: bool = True) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []

    @WNDENUMPROC
    def enum_proc(hwnd: int, _lparam: int) -> bool:
        if int(user32.GetAncestor(hwnd, GA_ROOT)) != int(hwnd):
            return True
        if visible_only and not user32.IsWindowVisible(hwnd):
            return True
        window_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
        pid_value = int(window_pid.value)
        process_info = _get_process_info(pid_value)
        exe_name = str(process_info.get("exe") or "")
        items.append(
            {
                "hwnd": f"0x{int(hwnd):X}",
                "pid": pid_value,
                "ppid": int(process_info.get("ppid") or 0),
                "exe": exe_name,
                "imagePath": _get_process_image_path(pid_value),
                "title": _repair_text_mojibake(_get_window_text(hwnd)),
                "className": _repair_text_mojibake(_get_class_name(hwnd)),
                "visible": bool(user32.IsWindowVisible(hwnd)),
                "enabled": bool(user32.IsWindowEnabled(hwnd)),
                "rect": _window_bounds(hwnd, client_only=False),
            }
        )
        return True

    user32.EnumWindows(enum_proc, 0)
    return items


def _coerce_launch_arguments(arguments: Any) -> tuple[Optional[List[str]], Optional[str]]:
    if arguments is None:
        return [], None
    value = arguments
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return [], None
        try:
            value = json.loads(raw)
        except Exception as exc:
            return None, f"arguments must be a list of strings: {exc}"
    if not isinstance(value, (list, tuple)):
        return None, "arguments must be a list of strings"
    result: List[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            return None, f"arguments[{index}] must be a string"
        if "\x00" in item:
            return None, f"arguments[{index}] contains a NUL character"
        result.append(item)
    return result, None


def _coerce_launch_environment(
    environment: Any,
) -> tuple[Optional[Dict[str, Optional[str]]], Optional[str]]:
    if environment is None:
        return {}, None
    value = environment
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return {}, None
        try:
            value = json.loads(raw)
        except Exception as exc:
            return None, f"environment must be a JSON object: {exc}"
    if not isinstance(value, dict):
        return None, "environment must be an object"
    result: Dict[str, Optional[str]] = {}
    seen_casefold: set[str] = set()
    for raw_key, raw_value in value.items():
        if (
            not isinstance(raw_key, str)
            or not raw_key
            or "=" in raw_key
            or "\x00" in raw_key
        ):
            return None, f"Invalid environment variable name: {raw_key!r}"
        folded_key = raw_key.casefold()
        if folded_key in seen_casefold:
            return None, f"Duplicate case-insensitive environment variable: {raw_key!r}"
        seen_casefold.add(folded_key)
        if raw_value is not None and not isinstance(raw_value, str):
            return None, f"Environment value for {raw_key!r} must be a string or null"
        if isinstance(raw_value, str) and "\x00" in raw_value:
            return None, f"Environment value for {raw_key!r} contains a NUL character"
        try:
            raw_key.encode("utf-16-le", errors="strict")
            if isinstance(raw_value, str):
                raw_value.encode("utf-16-le", errors="strict")
        except UnicodeEncodeError:
            return None, f"Environment entry {raw_key!r} is not valid UTF-16"
        result[raw_key] = raw_value
    # The final inherited block is validated by the native bridge after the
    # case-insensitive merge.  This still rejects an override set that cannot
    # possibly fit in CreateProcessW's 32767 UTF-16-code-unit environment block.
    override_units = 1
    for key, value in result.items():
        if value is not None:
            override_units += len(f"{key}={value}".encode("utf-16-le")) // 2 + 1
    if override_units > 32767:
        return None, "Environment overrides exceed 32767 UTF-16 code units"
    return result, None


_LAUNCH_CONTRACT_VERSION = 2
_DEFAULT_CAPTURE_LIMIT_BYTES = 1024 * 1024
_MIN_CAPTURE_LIMIT_BYTES = 4 * 1024
_MAX_CAPTURE_LIMIT_BYTES = 64 * 1024 * 1024
_MAX_LAUNCH_IO_CHUNK_BYTES = 1024 * 1024
_MAX_LAUNCH_WAIT_MS = 60_000
# The native bridge intentionally caps one blocking HTTP handler slice so a
# status/pause request cannot be starved.  Public Python tools aggregate these
# slices to honour the caller's full wait_ms contract.
_MAX_LAUNCH_NATIVE_WAIT_SLICE_MS = 750
_MAX_WINDOWS_COMMAND_LINE_UNITS = 32_766
_MAX_LAUNCH_ID_LENGTH = 128
_LAUNCH_CHILD_POLICIES = {
    "none",
    "attach-first",
    "attach-all",
    "break-on-create",
}


def _strict_int(value: Any, name: str) -> tuple[Optional[int], Optional[str]]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None, f"{name} must be an integer"
    return int(value), None


def _utf16_code_units(value: str) -> Optional[int]:
    try:
        return len(value.encode("utf-16-le", errors="strict")) // 2
    except UnicodeEncodeError:
        return None


def _normalize_absolute_launch_path(
    value: Any,
    *,
    field_name: str,
    input_file: bool,
) -> tuple[Optional[str], Optional[str]]:
    if not isinstance(value, str) or not value:
        return None, f"{field_name} must be a non-empty string"
    if "\x00" in value:
        return None, f"{field_name} contains a NUL character"
    if _utf16_code_units(value) is None:
        return None, f"{field_name} is not valid UTF-16"
    if not os.path.isabs(value):
        return None, f"{field_name} must be an absolute path"
    normalized = os.path.abspath(value)
    if input_file:
        if not os.path.isfile(normalized):
            return None, f"{field_name} was not found or is not a file: {normalized}"
    else:
        if os.path.isdir(normalized):
            return None, f"{field_name} names a directory: {normalized}"
        parent = os.path.dirname(normalized)
        if not parent or not os.path.isdir(parent):
            return None, f"Parent directory for {field_name} was not found: {parent}"
    return normalized, None


def _decode_canonical_base64(
    value: Any, field_name: str
) -> tuple[Optional[bytes], Optional[str]]:
    if not isinstance(value, str):
        return None, f"{field_name} must be a base64 string"
    try:
        encoded = value.encode("ascii", errors="strict")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, ValueError, base64.binascii.Error):
        return None, f"{field_name} must be canonical RFC 4648 base64"
    # Reject alternate padded spellings even if a future Python decoder starts
    # accepting them.  The bridge contract has one deterministic representation.
    if base64.b64encode(decoded).decode("ascii") != value:
        return None, f"{field_name} must be canonical RFC 4648 base64"
    return decoded, None


def _normalize_launch_stream(
    stream_name: str,
    value: Any,
) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not isinstance(value, dict):
        return None, f"{stream_name} must be an object"
    raw_mode = value.get("mode")
    if not isinstance(raw_mode, str):
        return None, f"{stream_name}.mode must be a string"
    mode = raw_mode.strip().casefold()
    is_stdin = stream_name == "stdin"
    allowed_modes = (
        {"inherit", "null", "file", "bytes", "pipe"}
        if is_stdin
        else {"inherit", "null", "file", "pipe"}
    )
    if mode not in allowed_modes:
        return None, (
            f"{stream_name}.mode must be one of "
            + ", ".join(sorted(allowed_modes))
        )

    allowed_keys = {"mode"}
    normalized: Dict[str, Any] = {"mode": mode}
    if mode == "file":
        allowed_keys.add("path")
        path, path_error = _normalize_absolute_launch_path(
            value.get("path"),
            field_name=f"{stream_name}.path",
            input_file=is_stdin,
        )
        if path_error:
            return None, path_error
        normalized["path"] = path
        if not is_stdin:
            allowed_keys.add("fileMode")
            file_mode = value.get("fileMode", "truncate")
            if not isinstance(file_mode, str) or file_mode.casefold() not in {
                "append",
                "truncate",
            }:
                return None, f"{stream_name}.fileMode must be append or truncate"
            normalized["fileMode"] = file_mode.casefold()
    elif is_stdin and mode == "bytes":
        allowed_keys.update({"data", "dataBase64", "closeAfterWrite"})
        has_raw = "data" in value
        has_base64 = "dataBase64" in value
        if has_raw == has_base64:
            return None, (
                "stdin bytes mode requires exactly one of data (raw bytes) "
                "or dataBase64"
            )
        if has_raw:
            raw_data = value.get("data")
            if not isinstance(raw_data, (bytes, bytearray, memoryview)):
                return None, "stdin.data must be bytes-like"
            decoded = bytes(raw_data)
        else:
            decoded, decode_error = _decode_canonical_base64(
                value.get("dataBase64"), "stdin.dataBase64"
            )
            if decode_error:
                return None, decode_error
            assert decoded is not None
        if len(decoded) > _MAX_LAUNCH_IO_CHUNK_BYTES:
            return None, (
                "stdin bytes payload exceeds the 1048576-byte launch limit"
            )
        close_after_write = value.get("closeAfterWrite", True)
        if not isinstance(close_after_write, bool):
            return None, "stdin.closeAfterWrite must be a boolean"
        if not close_after_write:
            return None, (
                "stdin bytes mode is a finite source and closeAfterWrite must be true; "
                "use mode=pipe for incremental writes"
            )
        normalized.update(
            {
                "dataBase64": base64.b64encode(decoded).decode("ascii"),
                "closeAfterWrite": close_after_write,
            }
        )
    elif is_stdin and mode == "pipe":
        allowed_keys.add("capacityBytes")
        if "capacityBytes" in value:
            capacity, capacity_error = _strict_int(
                value.get("capacityBytes"), "stdin.capacityBytes"
            )
            if capacity_error:
                return None, capacity_error
            assert capacity is not None
            if not _MIN_CAPTURE_LIMIT_BYTES <= capacity <= _MAX_CAPTURE_LIMIT_BYTES:
                return None, (
                    "stdin.capacityBytes must be between 4096 and 67108864"
                )
            normalized["capacityBytes"] = capacity

    unknown = sorted(str(key) for key in value if key not in allowed_keys)
    if unknown:
        return None, f"Unknown {stream_name} fields: {', '.join(unknown)}"
    return normalized, None


def _normalize_launch_streams(
    stdin: Any,
    stdout: Any,
    stderr: Any,
) -> tuple[Optional[Dict[str, Dict[str, Any]]], bool, Optional[str]]:
    supplied = [value is not None for value in (stdin, stdout, stderr)]
    if not any(supplied):
        return {
            "stdin": {"mode": "inherit"},
            "stdout": {"mode": "inherit"},
            "stderr": {"mode": "inherit"},
        }, False, None
    if not all(supplied):
        return None, True, (
            "stdin, stdout, and stderr must all be specified when any stream "
            "is configured explicitly"
        )
    streams: Dict[str, Dict[str, Any]] = {}
    for name, value in (("stdin", stdin), ("stdout", stdout), ("stderr", stderr)):
        normalized, error = _normalize_launch_stream(name, value)
        if error:
            return None, True, error
        assert normalized is not None
        streams[name] = normalized
    return streams, True, None


def _build_launch_spec(
    exe_path: str,
    *,
    arguments: Any = None,
    command_line: str = "",
    working_directory: str = "",
    environment: Any = None,
    inherit_environment: bool = True,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
    child_policy: str = "none",
    capture_limit_bytes: int = _DEFAULT_CAPTURE_LIMIT_BYTES,
) -> Dict[str, Any]:
    target_path = _repair_text_mojibake(str(exe_path or "").strip())
    if not target_path:
        return {"ok": False, "error": "exe_path is required"}
    if "\x00" in target_path:
        return {"ok": False, "error": "exe_path contains a NUL character"}
    if not os.path.isabs(target_path):
        return {"ok": False, "error": "exe_path must be an absolute path"}
    target_path = os.path.abspath(target_path)
    if not os.path.isfile(target_path):
        return {"ok": False, "error": f"Executable was not found: {target_path}"}
    if _utf16_code_units(target_path) is None:
        return {"ok": False, "error": "exe_path is not valid UTF-16"}
    if not isinstance(inherit_environment, bool):
        return {"ok": False, "error": "inherit_environment must be a boolean"}
    if not isinstance(command_line, str):
        return {"ok": False, "error": "command_line must be a string"}
    argv, argv_error = _coerce_launch_arguments(arguments)
    env, env_error = _coerce_launch_environment(environment)
    raw_command_line = command_line
    if argv_error or env_error:
        return {"ok": False, "error": argv_error or env_error}
    if argv and raw_command_line:
        return {
            "ok": False,
            "error": "arguments and command_line are mutually exclusive",
        }
    if "\x00" in raw_command_line:
        return {"ok": False, "error": "command_line contains a NUL character"}
    if _utf16_code_units(raw_command_line) is None:
        return {"ok": False, "error": "command_line is not valid UTF-16"}
    for index, argument in enumerate(argv or []):
        if _utf16_code_units(argument) is None:
            return {"ok": False, "error": f"arguments[{index}] is not valid UTF-16"}
    cwd = _repair_text_mojibake(str(working_directory or "").strip())
    if cwd:
        if "\x00" in cwd:
            return {"ok": False, "error": "working_directory contains a NUL character"}
        if _utf16_code_units(cwd) is None:
            return {"ok": False, "error": "working_directory is not valid UTF-16"}
        if not os.path.isabs(cwd):
            return {"ok": False, "error": "working_directory must be an absolute path"}
        cwd = os.path.abspath(cwd)
        if not os.path.isdir(cwd):
            return {"ok": False, "error": f"Working directory was not found: {cwd}"}
    capture_limit, capture_error = _strict_int(
        capture_limit_bytes, "capture_limit_bytes"
    )
    if capture_error:
        return {"ok": False, "error": capture_error}
    assert capture_limit is not None
    if not _MIN_CAPTURE_LIMIT_BYTES <= capture_limit <= _MAX_CAPTURE_LIMIT_BYTES:
        return {
            "ok": False,
            "error": "capture_limit_bytes must be between 4096 and 67108864",
        }
    if not isinstance(child_policy, str):
        return {"ok": False, "error": "child_policy must be a string"}
    normalized_child_policy = child_policy.strip().casefold()
    if normalized_child_policy not in _LAUNCH_CHILD_POLICIES:
        return {
            "ok": False,
            "error": (
                "child_policy must be none, attach-first, attach-all, or "
                "break-on-create"
            ),
        }
    streams, streams_explicit, stream_error = _normalize_launch_streams(
        stdin, stdout, stderr
    )
    if stream_error:
        return {
            "ok": False,
            "errorCode": "INVALID_STREAM_SPEC",
            "error": stream_error,
        }
    assert streams is not None
    stdout_spec = streams["stdout"]
    stderr_spec = streams["stderr"]
    if stdout_spec.get("mode") == "file" and stderr_spec.get("mode") == "file":
        stdout_key = os.path.normcase(os.path.abspath(str(stdout_spec.get("path") or "")))
        stderr_key = os.path.normcase(os.path.abspath(str(stderr_spec.get("path") or "")))
        if stdout_key == stderr_key:
            return {
                "ok": False,
                "errorCode": "INVALID_STREAM_SPEC",
                "error": (
                    "stdout and stderr cannot name the same file; merged file-handle "
                    "semantics are not part of launch contract v2"
                ),
            }
    rendered_command_line = raw_command_line or subprocess.list2cmdline(list(argv or []))
    executable_token = subprocess.list2cmdline([target_path])
    if raw_command_line:
        full_command_line = f"{executable_token} {raw_command_line}"
    else:
        full_command_line = subprocess.list2cmdline([target_path, *(argv or [])])
    full_command_units = _utf16_code_units(full_command_line)
    if full_command_units is None:
        return {"ok": False, "error": "Full command line is not valid UTF-16"}
    if full_command_units > _MAX_WINDOWS_COMMAND_LINE_UNITS:
        return {
            "ok": False,
            "error": "Windows command line exceeds 32766 UTF-16 code units",
        }
    return {
        "ok": True,
        "contractVersion": _LAUNCH_CONTRACT_VERSION,
        "exePath": target_path,
        "arguments": list(argv or []),
        "commandLine": rendered_command_line,
        "rawCommandLine": raw_command_line,
        "rawCommandLineTail": raw_command_line,
        "fullCommandLine": full_command_line,
        "fullCommandLineUtf16Units": full_command_units,
        "workingDirectory": cwd,
        "environment": dict(env or {}),
        "inheritEnvironment": bool(inherit_environment),
        "streams": streams,
        "streamsExplicit": streams_explicit,
        "stdin": dict(streams["stdin"]),
        "stdout": dict(streams["stdout"]),
        "stderr": dict(streams["stderr"]),
        "childPolicy": normalized_child_policy,
        "captureLimitBytes": capture_limit,
    }


def _launch_capabilities() -> Dict[str, Any]:
    capabilities = _get_cached_bridge_identity().get("capabilities")
    if not isinstance(capabilities, dict):
        return {}
    launch = capabilities.get("launch")
    return dict(launch) if isinstance(launch, dict) else {}


def _advertised_child_policy_modes(launch_caps: Dict[str, Any]) -> set[str]:
    value: Any = launch_caps.get("childPolicies")
    if isinstance(value, dict):
        value = value.get("modes")
    if not isinstance(value, (list, tuple, set)):
        return set()
    return {
        str(item).strip().casefold()
        for item in value
        if isinstance(item, str) and str(item).strip()
    }


def _validate_launch_v2_capabilities(
    spec: Dict[str, Any], launch_caps: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    if int(_parse_int(spec.get("contractVersion"), 0) or 0) < 2:
        return None
    version = int(_parse_int(launch_caps.get("version"), 0) or 0)
    if version < _LAUNCH_CONTRACT_VERSION:
        return {
            "ok": False,
            "success": False,
            "unsupported": True,
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "error": "Bridge/Hello must advertise launch contract version 2 or newer.",
            "capability": "launch.version",
            "required": _LAUNCH_CONTRACT_VERSION,
            "advertised": version,
        }
    environment_mode = str(launch_caps.get("environmentMode") or "").casefold()
    if environment_mode != "unicode_create_process_block":
        return {
            "ok": False,
            "success": False,
            "unsupported": True,
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "error": (
                "Bridge/Hello must advertise an isolated Unicode CreateProcess "
                "environment block."
            ),
            "capability": "launch.environmentMode",
            "required": "unicode_create_process_block",
            "advertised": environment_mode or None,
        }
    stream_capability = launch_caps.get("streams")
    if isinstance(stream_capability, dict):
        streams_supported = stream_capability.get("supported", True) is True and bool(
            stream_capability
        )
    else:
        streams_supported = stream_capability is True
    if not streams_supported:
        return {
            "ok": False,
            "success": False,
            "unsupported": True,
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "error": "Bridge/Hello does not advertise typed launch stream support.",
            "capability": "launch.streams",
        }
    child_policy = str(spec.get("childPolicy") or "none").casefold()
    child_modes = _advertised_child_policy_modes(launch_caps)
    # 'none' means no child-debug feature is requested.  Every other policy is
    # rejected unless the bridge explicitly names that exact semantic mode.
    if child_policy != "none" and child_policy not in child_modes:
        return {
            "ok": False,
            "success": False,
            "unsupported": True,
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "error": f"Bridge/Hello does not advertise child policy {child_policy!r}.",
            "capability": "launch.childPolicies",
            "requested": child_policy,
            "advertised": sorted(child_modes),
        }
    if child_modes and child_policy not in child_modes:
        return {
            "ok": False,
            "success": False,
            "unsupported": True,
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "error": f"Bridge/Hello rejects child policy {child_policy!r}.",
            "capability": "launch.childPolicies",
            "requested": child_policy,
            "advertised": sorted(child_modes),
        }
    return None


def _launch_via_bridge(spec: Dict[str, Any], timeout_sec: float) -> Dict[str, Any]:
    launch_caps = _launch_capabilities()
    is_v2 = int(_parse_int(spec.get("contractVersion"), 0) or 0) >= 2
    capability_error = _validate_launch_v2_capabilities(spec, launch_caps)
    if capability_error:
        return capability_error
    custom_environment = bool(spec.get("environment")) or not bool(
        spec.get("inheritEnvironment", True)
    )
    if not is_v2 and custom_environment and not bool(launch_caps.get("environment")):
        return {
            "ok": False,
            "success": False,
            "unsupported": True,
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "error": "This x64dbg bridge cannot supply a per-launch environment block.",
            "capability": "launch.environment",
        }
    needs_args = bool(spec.get("arguments") or spec.get("rawCommandLine"))
    needs_cwd = bool(spec.get("workingDirectory"))
    if not is_v2 and ((needs_args and not bool(launch_caps.get("args"))) or (
        needs_cwd and not bool(launch_caps.get("cwd"))
    )):
        return {
            "ok": False,
            "success": False,
            "unsupported": True,
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "error": "Bridge/Hello does not advertise the requested launch args/cwd support.",
            "capabilities": launch_caps,
        }
    if is_v2 or (launch_caps and (
        launch_caps.get("args")
        or launch_caps.get("cwd")
        or launch_caps.get("environment")
    )):
        arguments_json = json.dumps(
            list(spec.get("arguments") or []),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        launch_form: Dict[str, Any] = {
            "contractVersion": str(
                int(_parse_int(spec.get("contractVersion"), 1) or 1)
            ),
            "exe": str(spec.get("exePath") or ""),
            "arguments": arguments_json,
            "rawCommandLineTail": str(spec.get("rawCommandLineTail") or ""),
            "cwd": str(spec.get("workingDirectory") or ""),
            "environment": json.dumps(
                dict(spec.get("environment") or {}),
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            "inheritEnvironment": (
                "true" if spec.get("inheritEnvironment", True) else "false"
            ),
            "childPolicy": str(spec.get("childPolicy") or "none"),
            "captureLimitBytes": str(
                int(spec.get("captureLimitBytes") or _DEFAULT_CAPTURE_LIMIT_BYTES)
            ),
        }
        # Omitted stream configuration is intentionally distinct from explicit
        # inherit. x32dbg/x64dbg are GUI processes and commonly have invalid
        # standard handles; the native bridge creates a fresh console only when
        # all three fields are absent. Explicit inherit keeps strict handle
        # duplication/allow-list semantics and fails on invalid handles.
        if bool(spec.get("streamsExplicit")):
            launch_form.update(
                {
                    "stdin": json.dumps(
                        dict(spec.get("stdin") or {}),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                    "stdout": json.dumps(
                        dict(spec.get("stdout") or {}),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                    "stderr": json.dumps(
                        dict(spec.get("stderr") or {}),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                }
            )
        if not is_v2:
            # The legacy route accepted one already-rendered argument tail.
            launch_form["args"] = str(spec.get("commandLine") or "")
        envelope = _bridge_request(
            "POST",
            "Debug/Launch",
            form_data=launch_form,
            timeout_sec=max(0.25, float(timeout_sec)),
            guard="bridge",
            idempotent=False,
        )
        if envelope.ok:
            data = envelope.data
            payload = dict(data) if isinstance(data, dict) else {"result": data}
            payload.setdefault("ok", True)
            payload.setdefault("success", True)
            payload["launchApi"] = "Debug/Launch"
            return payload
        return {
            "ok": False,
            "success": False,
            "errorCode": envelope.error.code if envelope.error else "BRIDGE_ERROR",
            "error": envelope.error.message if envelope.error else "Launch failed.",
            "meta": envelope.meta,
            "launchApi": "Debug/Launch",
        }
    if is_v2 or needs_args or needs_cwd or custom_environment:
        return {
            "ok": False,
            "success": False,
            "unsupported": True,
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "error": "The connected legacy bridge cannot launch with args/cwd/environment.",
        }
    return ExecCommand(f'init "{spec.get("exePath")}"')


def _capture_launch_context(
    exe_path: str, launch_spec: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    processes = _list_processes()
    windows = _enumerate_top_windows_global(visible_only=True)
    foreground = _foreground_window_info()
    target_path = _repair_text_mojibake(str(exe_path or "").strip())
    target_base = os.path.basename(target_path).lower() if target_path else ""
    context = {
        "timestamp": time.time(),
        "targetPath": target_path,
        "targetBaseName": target_base,
        "processIds": sorted(int(item.get("pid") or 0) for item in processes),
        "windowIds": sorted(str(item.get("hwnd") or "") for item in windows),
        "windowMap": {
            str(item.get("hwnd") or ""): {
                "title": str(item.get("title") or ""),
                "className": str(item.get("className") or ""),
                "pid": int(item.get("pid") or 0),
            }
            for item in windows
            if str(item.get("hwnd") or "")
        },
        "foreground": foreground,
        "sourcePid": 0,
    }
    if isinstance(launch_spec, dict):
        context["launchSpec"] = {
            key: value
            for key, value in launch_spec.items()
            if key != "environment"
        }
        context["environmentKeys"] = sorted(
            str(key) for key in (launch_spec.get("environment") or {})
        )
    return context


def _update_launch_context_source_pid(pid: int) -> None:
    if not pid:
        return
    context = _get_runtime_value("lastLaunchContext")
    if not isinstance(context, dict):
        return
    updated = dict(context)
    updated["sourcePid"] = int(pid)
    _remember_runtime(lastLaunchContext=updated)


def _mark_launch_context_passthrough(pid: int = 0) -> None:
    context = _get_runtime_value("lastLaunchContext")
    if not isinstance(context, dict):
        return
    updated = dict(context)
    updated["passthroughAttempted"] = True
    updated["passthroughPid"] = int(pid or 0)
    updated["passthroughAt"] = time.time()
    _remember_runtime(lastLaunchContext=updated)


def _launch_target_passthrough(exe_path: str) -> Dict[str, Any]:
    target_path = _repair_text_mojibake(str(exe_path or "").strip())
    if not target_path or not os.path.exists(target_path):
        return {"ok": False, "error": "Target path is missing or does not exist"}
    try:
        if os.name == "nt" and hasattr(os, "startfile"):
            os.startfile(target_path)
            _mark_launch_context_passthrough(0)
            _log_event(
                "launch_target_passthrough",
                exePath=target_path,
                pid=0,
                method="startfile",
            )
            return {"ok": True, "pid": 0, "exePath": target_path, "method": "startfile"}
        creation_flags = 0x08000000 if os.name == "nt" else 0
        process = subprocess.Popen(
            [target_path],
            cwd=os.path.dirname(target_path) or None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags,
        )
        _mark_launch_context_passthrough(process.pid)
        _log_event(
            "launch_target_passthrough",
            exePath=target_path,
            pid=process.pid,
            method="create_process",
        )
        return {
            "ok": True,
            "pid": int(process.pid),
            "exePath": target_path,
            "method": "create_process",
        }
    except Exception as e:
        _log_event("launch_target_passthrough_error", exePath=target_path, error=str(e))
        return {"ok": False, "error": str(e), "exePath": target_path}


def _score_launch_retarget_candidate(
    candidate: Dict[str, Any],
    context: Dict[str, Any],
    new_pid_set: set,
    new_window_set: set,
    changed_window_set: set,
) -> int:
    pid_value = int(candidate.get("pid") or 0)
    hwnd_value = str(candidate.get("hwnd") or "")
    exe_name = str(candidate.get("exe") or "").lower()
    title = str(candidate.get("title") or "")
    class_name = str(candidate.get("className") or "")
    target_base = str(context.get("targetBaseName") or "").lower()
    target_tokens = _normalize_name_tokens(target_base)
    title_lower = title.casefold()
    class_lower = class_name.casefold()
    token_match = any(
        token and (token in exe_name or token in title_lower or token in class_lower)
        for token in target_tokens
    )
    direct_child = bool(
        int(context.get("sourcePid") or 0)
        and int(candidate.get("ppid") or 0) == int(context.get("sourcePid") or 0)
    )
    score = 0
    if pid_value in new_pid_set:
        score += 80
    if hwnd_value in new_window_set:
        score += 70
    if hwnd_value in changed_window_set:
        score += 65
    if title:
        score += 10
    if exe_name in GENERIC_UI_HOST_EXES:
        score -= 70
        if token_match:
            score += 45
        if direct_child:
            score += 20
    if class_lower in GENERIC_UI_HOST_CLASSES_CASEFOLD:
        score -= 40
        if token_match:
            score += 20
    source_pid = int(context.get("sourcePid") or 0)
    if source_pid and int(candidate.get("ppid") or 0) == source_pid:
        score += 90
    if target_base and exe_name == target_base:
        score += 120
    for token in target_tokens:
        if token and token in exe_name:
            score += 25
        if token and token in title_lower:
            score += 20
        if token and token in class_lower:
            score += 10
    area = (candidate.get("rect", {}) or {}).get("width", 0) * (
        candidate.get("rect", {}) or {}
    ).get("height", 0)
    if area >= 120000:
        score += 8
    if bool(candidate.get("enabled")):
        score += 4
    if _is_noise_window_node(candidate):
        score -= 220
    return score


def _candidate_matches_launch_target(
    candidate: Dict[str, Any], context: Dict[str, Any]
) -> bool:
    exe_name = str(candidate.get("exe") or "").lower()
    title = str(candidate.get("title") or "").casefold()
    class_name = str(candidate.get("className") or "").casefold()
    target_tokens = _normalize_name_tokens(str(context.get("targetBaseName") or ""))
    return any(
        token and (token in exe_name or token in title or token in class_name)
        for token in target_tokens
    )


def _is_generic_ui_host_candidate(candidate: Dict[str, Any]) -> bool:
    exe_name = str(candidate.get("exe") or "").lower()
    class_name = str(candidate.get("className") or "").casefold()
    return exe_name in GENERIC_UI_HOST_EXES or class_name in GENERIC_UI_HOST_CLASSES_CASEFOLD


def _discover_launch_retarget_candidate(
    title_contains: str = "",
    class_name: str = "",
    visible_only: bool = True,
) -> Optional[Dict[str, Any]]:
    context = _get_runtime_value("lastLaunchContext")
    if not isinstance(context, dict):
        return None
    started_at = float(context.get("timestamp") or 0.0)
    if not started_at or (time.time() - started_at) > 90.0:
        return None
    source_pid = int(context.get("sourcePid") or 0)
    if (
        source_pid
        and _process_exists(source_pid)
        and _find_top_window_for_pid(source_pid)
    ):
        return None
    before_pids = {int(item) for item in (context.get("processIds") or [])}
    before_windows = {str(item) for item in (context.get("windowIds") or [])}
    before_window_map = dict(context.get("windowMap") or {})
    current_windows = _enumerate_top_windows_global(visible_only=visible_only)
    current_foreground = _foreground_window_info()
    before_foreground = dict(context.get("foreground") or {})
    current_foreground_hwnd = _normalize_hex(current_foreground.get("hwnd"))
    before_foreground_hwnd = _normalize_hex(before_foreground.get("hwnd"))
    foreground_changed = (
        bool(current_foreground.get("ok"))
        and bool(current_foreground_hwnd)
        and current_foreground_hwnd != before_foreground_hwnd
    )
    current_pids = {int(item.get("pid") or 0) for item in _list_processes()}
    new_pid_set = {pid for pid in current_pids if pid and pid not in before_pids}
    new_window_set = {
        str(item.get("hwnd") or "")
        for item in current_windows
        if str(item.get("hwnd") or "") not in before_windows
    }
    changed_window_set = set()
    for item in current_windows:
        hwnd_value = str(item.get("hwnd") or "")
        previous = before_window_map.get(hwnd_value)
        if not previous:
            continue
        if _normalize_gui_text(str(previous.get("title") or "")) != _normalize_gui_text(
            str(item.get("title") or "")
        ) or _normalize_gui_text(
            str(previous.get("className") or "")
        ) != _normalize_gui_text(str(item.get("className") or "")):
            changed_window_set.add(hwnd_value)
    stored = _get_runtime_value("lastUiRetarget")
    stored_pid = int((stored or {}).get("pid") or 0) if isinstance(stored, dict) else 0
    stored_hwnd = (
        str((stored or {}).get("hwnd") or "") if isinstance(stored, dict) else ""
    )
    passthrough_attempted = bool(context.get("passthroughAttempted"))
    debugger_pids = {
        int(item.get("pid") or 0)
        for item in _list_processes()
        if str(item.get("exe") or "").lower() in ("x64dbg.exe", "x32dbg.exe")
    }

    def collect_candidates(window_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        found: List[Dict[str, Any]] = []
        for window in window_items:
            pid_value = int(window.get("pid") or 0)
            exe_name = str(window.get("exe") or "").lower()
            hwnd_value = str(window.get("hwnd") or "")
            class_name_value = str(window.get("className") or "")
            title_value = str(window.get("title") or "")
            if (
                not pid_value
                or pid_value in debugger_pids
                or exe_name in IGNORED_RETARGET_EXES
            ):
                continue
            if not (title_contains or class_name) and _is_noise_window_node(window):
                continue
            if title_contains and not _text_matches(title_value, title_contains):
                continue
            if class_name and not _text_matches(class_name_value, class_name):
                continue
            token_match = _candidate_matches_launch_target(window, context)
            direct_child = bool(source_pid and int(window.get("ppid") or 0) == source_pid)
            generic_host = _is_generic_ui_host_candidate(window)
            if (
                generic_host
                and not token_match
                and not direct_child
                and not (title_contains or class_name)
            ):
                continue
            is_foreground = bool(
                foreground_changed
                and current_foreground_hwnd
                and _normalize_hex(hwnd_value) == current_foreground_hwnd
            )
            foreground_signal = bool(
                is_foreground
                and (
                    token_match
                    or direct_child
                    or not generic_host
                )
            )
            if hwnd_value == stored_hwnd and pid_value == stored_pid:
                score = 220
            else:
                is_candidate = (
                    hwnd_value in new_window_set
                    or pid_value in new_pid_set
                    or hwnd_value in changed_window_set
                    or foreground_signal
                )
                if not is_candidate:
                    continue
                score = _score_launch_retarget_candidate(
                    window, context, new_pid_set, new_window_set, changed_window_set
                )
                if is_foreground:
                    score += 95
                    if generic_host and not token_match and not direct_child:
                        score -= 140
                    elif generic_host:
                        score -= 30
            if score < 80:
                continue
            enriched = dict(window)
            enriched["score"] = score
            enriched["foregroundCandidate"] = bool(is_foreground)
            found.append(enriched)
        return found

    candidates = collect_candidates(current_windows)
    if (
        not candidates
        and not passthrough_attempted
        and (time.time() - started_at) <= 30.0
    ):
        passthrough = _launch_target_passthrough(str(context.get("targetPath") or ""))
        if passthrough.get("ok"):
            passthrough_attempted = True
            time.sleep(1.5)
            current_windows = _enumerate_top_windows_global(visible_only=visible_only)
            new_window_set = {
                str(item.get("hwnd") or "")
                for item in current_windows
                if str(item.get("hwnd") or "") not in before_windows
            }
            changed_window_set = set()
            for item in current_windows:
                hwnd_value = str(item.get("hwnd") or "")
                previous = before_window_map.get(hwnd_value)
                if not previous:
                    continue
                if _normalize_gui_text(
                    str(previous.get("title") or "")
                ) != _normalize_gui_text(
                    str(item.get("title") or "")
                ) or _normalize_gui_text(
                    str(previous.get("className") or "")
                ) != _normalize_gui_text(str(item.get("className") or "")):
                    changed_window_set.add(hwnd_value)
            candidates = collect_candidates(current_windows)
    if not candidates:
        return None
    candidates.sort(
        key=lambda item: (
            int(item.get("score") or 0),
            int(
                (item.get("rect", {}) or {}).get("width", 0)
                * (item.get("rect", {}) or {}).get("height", 0)
            ),
            1 if item.get("title") else 0,
        ),
        reverse=True,
    )
    chosen = candidates[0]
    payload = {
        "pid": int(chosen.get("pid") or 0),
        "hwnd": str(chosen.get("hwnd") or ""),
        "ppid": int(chosen.get("ppid") or 0),
        "exe": str(chosen.get("exe") or ""),
        "imagePath": str(chosen.get("imagePath") or ""),
        "title": str(chosen.get("title") or ""),
        "className": str(chosen.get("className") or ""),
        "score": int(chosen.get("score") or 0),
        "sourcePid": source_pid,
        "sourceTarget": str(context.get("targetPath") or ""),
        "retargeted": True,
        "attached": False,
        "mode": "launcher_window",
        "foregroundCandidate": bool(chosen.get("foregroundCandidate")),
        "passthroughLaunch": passthrough_attempted,
        "timestamp": _now_iso(),
    }
    _remember_runtime(lastUiRetarget=payload)
    return payload


def _collect_retarget_gui_snapshot(
    title_contains: str = "",
    class_name: str = "",
    visible_only: bool = True,
    include_children: bool = True,
    max_depth: int = 4,
) -> Optional[Dict[str, Any]]:
    candidate = _discover_launch_retarget_candidate(
        title_contains=title_contains,
        class_name=class_name,
        visible_only=visible_only,
    )
    if not candidate:
        return None
    snapshot = _collect_gui_snapshot(
        pid=int(candidate.get("pid") or 0),
        include_children=include_children,
        visible_only=visible_only,
        max_depth=max_depth,
    )
    snapshot["retarget"] = candidate
    return snapshot


def _discover_launch_retarget_process_candidate(
    visible_only: bool = True, exe_filter: str = ""
) -> Optional[Dict[str, Any]]:
    context = _get_runtime_value("lastLaunchContext")
    if not isinstance(context, dict):
        return None
    started_at = float(context.get("timestamp") or 0.0)
    if not started_at or (time.time() - started_at) > 90.0:
        return None
    baseline_pids = {
        int(item) for item in list(context.get("processIds") or []) if int(item or 0)
    }
    source_pid = int(context.get("sourcePid") or 0)
    source_alive = _process_exists(source_pid)
    target_tokens = _normalize_name_tokens(
        exe_filter or str(context.get("targetBaseName") or "")
    )
    if not target_tokens:
        return None
    debugger_pids = {
        int(item.get("pid") or 0)
        for item in _list_processes()
        if str(item.get("exe") or "").lower() in ("x64dbg.exe", "x32dbg.exe")
    }
    candidates: List[Dict[str, Any]] = []
    for item in _list_processes():
        pid_value = int(item.get("pid") or 0)
        exe_name = _process_basename(item.get("exe") or "")
        if (
            not pid_value
            or pid_value == source_pid
            or pid_value in debugger_pids
            or exe_name in IGNORED_RETARGET_EXES
        ):
            continue
        described = _describe_process_candidate(
            {**item, "depth": 1}, baseline_pids=baseline_pids, visible_only=visible_only
        )
        token_haystack = " ".join(
            [
                exe_name,
                str(described.get("imagePath") or "").casefold(),
                str(described.get("topWindowTitle") or "").casefold(),
                str(described.get("topWindowClass") or "").casefold(),
            ]
        )
        token_match = any(token and token in token_haystack for token in target_tokens)
        if not token_match:
            continue
        score = int(described.get("score") or 0)
        score += 130
        if described.get("isNew"):
            score += 60
        if source_pid and int(item.get("ppid") or 0) == source_pid:
            score += 160
        if not source_alive:
            score += 30
        described["relationship"] = "retarget_process"
        described["score"] = score
        candidates.append(described)
    if not candidates:
        return None
    candidates.sort(
        key=lambda item: (
            int(item.get("score") or 0),
            1 if item.get("hasWindow") else 0,
            1 if item.get("isNew") else 0,
            int(item.get("pid") or 0),
        ),
        reverse=True,
    )
    return candidates[0]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = float(len(data))
    entropy = 0.0
    for count in counts:
        if not count:
            continue
        probability = count / total
        entropy -= probability * math.log(probability, 2)
    return round(entropy, 4)


def _read_c_string(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("ascii", errors="ignore")


def _parse_pe_layout(exe_path: str) -> Dict[str, Any]:
    with open(exe_path, "rb") as handle:
        data = handle.read()
    if len(data) < 0x100:
        raise RuntimeError("File is too small to be a valid PE image")
    if data[:2] != b"MZ":
        raise RuntimeError("Not a PE executable (missing MZ header)")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if (
        pe_offset + 0x18 >= len(data)
        or data[pe_offset : pe_offset + 4] != b"PE\x00\x00"
    ):
        raise RuntimeError("Invalid PE header")
    machine, section_count, time_date_stamp, _, _, size_of_optional_header, characteristics = (
        struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    )
    optional_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    is_64 = magic == 0x20B
    if magic not in (0x10B, 0x20B):
        raise RuntimeError(f"Unsupported PE optional header magic: 0x{magic:X}")
    address_of_entry_point = struct.unpack_from("<I", data, optional_offset + 16)[0]
    image_base = struct.unpack_from(
        "<Q" if is_64 else "<I",
        data,
        optional_offset + (24 if is_64 else 28),
    )[0]
    size_of_image = struct.unpack_from("<I", data, optional_offset + 56)[0]
    size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
    checksum = struct.unpack_from("<I", data, optional_offset + 64)[0]
    subsystem = struct.unpack_from("<H", data, optional_offset + 68)[0]
    dll_characteristics = struct.unpack_from("<H", data, optional_offset + 70)[0]
    section_alignment = struct.unpack_from("<I", data, optional_offset + 32)[0]
    file_alignment = struct.unpack_from("<I", data, optional_offset + 36)[0]
    number_of_rva_and_sizes = struct.unpack_from(
        "<I", data, optional_offset + (108 if is_64 else 92)
    )[0]
    data_directory_offset = optional_offset + (112 if is_64 else 96)
    directories: List[Dict[str, Any]] = []
    for index in range(min(number_of_rva_and_sizes, 16)):
        rva, size = struct.unpack_from("<II", data, data_directory_offset + (index * 8))
        directories.append({"index": index, "rva": rva, "size": size})
    section_offset = optional_offset + size_of_optional_header
    sections: List[Dict[str, Any]] = []
    for index in range(section_count):
        base = section_offset + (40 * index)
        if base + 40 > len(data):
            break
        raw_name = data[base : base + 8].split(b"\x00", 1)[0]
        name = raw_name.decode("ascii", errors="ignore")
        (
            virtual_size,
            virtual_address,
            raw_size,
            raw_pointer,
            _,
            _,
            _,
            _,
            characteristics_sec,
        ) = struct.unpack_from("<IIIIIIHHI", data, base + 8)
        raw_bytes = (
            data[raw_pointer : raw_pointer + raw_size]
            if raw_pointer and raw_pointer < len(data)
            else b""
        )
        sections.append(
            {
                "name": name,
                "virtualAddress": virtual_address,
                "virtualSize": virtual_size,
                "rawSize": raw_size,
                "rawPointer": raw_pointer,
                "characteristics": f"0x{characteristics_sec:08X}",
                "entropy": _shannon_entropy(raw_bytes[: min(len(raw_bytes), 0x20000)]),
                "executable": bool(characteristics_sec & 0x20000000),
                "writable": bool(characteristics_sec & 0x80000000),
                "readable": bool(characteristics_sec & 0x40000000),
            }
        )

    def rva_to_offset(rva: int) -> int:
        for section in sections:
            start = int(section["virtualAddress"])
            size = max(int(section["virtualSize"]), int(section["rawSize"]))
            if start <= rva < start + size:
                return int(section["rawPointer"]) + (rva - start)
        if rva < size_of_headers:
            return rva
        return 0

    imports: List[Dict[str, Any]] = []
    if len(directories) > 1 and directories[1]["rva"] and directories[1]["size"]:
        import_offset = rva_to_offset(int(directories[1]["rva"]))
        cursor = import_offset
        descriptor_count = 0
        while cursor and cursor + 20 <= len(data) and descriptor_count < 4096:
            original_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from(
                "<IIIII", data, cursor
            )
            if not any((original_first_thunk, name_rva, first_thunk)):
                break
            name_offset = rva_to_offset(name_rva)
            dll_name = _read_c_string(data, name_offset) if name_offset else ""
            thunk_rva = original_first_thunk or first_thunk
            thunk_offset = rva_to_offset(thunk_rva)
            funcs: List[str] = []
            if thunk_offset:
                step = 8 if is_64 else 4
                ordinal_mask = 0x8000000000000000 if is_64 else 0x80000000
                thunk_count = 0
                while thunk_offset + step <= len(data) and thunk_count < 1_000_000:
                    thunk_value = struct.unpack_from(
                        "<Q" if is_64 else "<I", data, thunk_offset
                    )[0]
                    if thunk_value == 0:
                        break
                    if thunk_value & ordinal_mask:
                        funcs.append(f"ordinal:{thunk_value & 0xFFFF}")
                    else:
                        hint_name_offset = rva_to_offset(int(thunk_value))
                        func_name = (
                            _read_c_string(data, hint_name_offset + 2)
                            if hint_name_offset
                            else ""
                        )
                        funcs.append(func_name or f"rva:0x{int(thunk_value):X}")
                    thunk_offset += step
                    thunk_count += 1
            imports.append({"dll": dll_name, "functions": funcs})
            cursor += 20
            descriptor_count += 1

    exports: List[Dict[str, Any]] = []
    if directories and directories[0]["rva"] and directories[0]["size"]:
        export_rva = int(directories[0]["rva"])
        export_size = int(directories[0]["size"])
        export_offset = rva_to_offset(export_rva)
        if export_offset and export_offset + 40 <= len(data):
            (
                _,
                _,
                _,
                _,
                _export_name_rva,
                ordinal_base,
                function_count,
                name_count,
                functions_rva,
                names_rva,
                ordinals_rva,
            ) = struct.unpack_from("<IIHHIIIIIII", data, export_offset)
            functions_offset = rva_to_offset(functions_rva)
            names_offset = rva_to_offset(names_rva)
            ordinals_offset = rva_to_offset(ordinals_rva)
            for index in range(min(int(name_count), 1_000_000)):
                if (
                    not functions_offset
                    or not names_offset
                    or not ordinals_offset
                    or names_offset + (index * 4) + 4 > len(data)
                    or ordinals_offset + (index * 2) + 2 > len(data)
                ):
                    break
                symbol_name_rva = struct.unpack_from(
                    "<I", data, names_offset + (index * 4)
                )[0]
                ordinal_index = struct.unpack_from(
                    "<H", data, ordinals_offset + (index * 2)
                )[0]
                if (
                    ordinal_index >= int(function_count)
                    or functions_offset + (ordinal_index * 4) + 4 > len(data)
                ):
                    continue
                function_rva = struct.unpack_from(
                    "<I", data, functions_offset + (ordinal_index * 4)
                )[0]
                symbol_name_offset = rva_to_offset(symbol_name_rva)
                symbol_name = (
                    _read_c_string(data, symbol_name_offset)
                    if symbol_name_offset
                    else ""
                )
                if not symbol_name:
                    continue
                forwarded = (
                    export_rva <= function_rva < export_rva + export_size
                )
                forwarder_offset = rva_to_offset(function_rva) if forwarded else 0
                exports.append(
                    {
                        "name": symbol_name,
                        "rva": f"0x{int(function_rva):X}",
                        "ordinal": int(ordinal_base) + int(ordinal_index),
                        "forwarder": (
                            _read_c_string(data, forwarder_offset)
                            if forwarder_offset
                            else None
                        ),
                    }
                )
            exports.sort(
                key=lambda item: (
                    int(str(item.get("rva") or "0"), 0),
                    str(item.get("name") or "").casefold(),
                )
            )

    entry_section = next(
        (
            section
            for section in sections
            if int(section["virtualAddress"])
            <= address_of_entry_point
            < int(section["virtualAddress"])
            + max(int(section["virtualSize"]), int(section["rawSize"]))
        ),
        None,
    )
    directory_names = [
        "export", "import", "resource", "exception", "certificate", "relocation",
        "debug", "architecture", "global_ptr", "tls", "load_config", "bound_import",
        "iat", "delay_import", "clr", "reserved",
    ]
    public_directories = [
        {
            "index": int(item["index"]),
            "name": directory_names[int(item["index"])]
            if int(item["index"]) < len(directory_names)
            else f"directory_{int(item['index'])}",
            "rva": f"0x{int(item['rva']):X}",
            "size": int(item["size"]),
            "va": f"0x{int(image_base) + int(item['rva']):X}"
            if int(item["rva"])
            else None,
        }
        for item in directories
    ]
    iat_directory = next(
        (dict(item) for item in public_directories if item.get("name") == "iat"),
        {"index": 12, "name": "iat", "rva": "0x0", "size": 0, "va": None},
    )
    tls_directory = next(
        (dict(item) for item in public_directories if item.get("name") == "tls"),
        {"index": 9, "name": "tls", "rva": "0x0", "size": 0, "va": None},
    )
    tls_callbacks: List[Dict[str, Any]] = []
    tls_diagnostics: List[str] = []
    tls_rva = int(str(tls_directory.get("rva") or "0x0"), 16)
    tls_offset = rva_to_offset(tls_rva) if tls_rva else 0
    tls_struct_size = 40 if is_64 else 24
    callbacks_va = 0
    if tls_offset and tls_offset + tls_struct_size <= len(data):
        if is_64:
            _, _, _, callbacks_va, _, _ = struct.unpack_from(
                "<QQQQII", data, tls_offset
            )
        else:
            _, _, _, callbacks_va, _, _ = struct.unpack_from(
                "<IIIIII", data, tls_offset
            )
        if callbacks_va:
            if image_base <= callbacks_va < image_base + max(size_of_image, 1):
                callbacks_rva = int(callbacks_va - image_base)
            elif callbacks_va < max(size_of_image, 1):
                # A few non-conforming packers store an RVA here. Keep the
                # evidence, but make the normalization explicit.
                callbacks_rva = int(callbacks_va)
                tls_diagnostics.append("callbacks_address_was_rva_not_va")
            else:
                callbacks_rva = 0
                tls_diagnostics.append("callbacks_address_outside_image")
            callback_offset = rva_to_offset(callbacks_rva) if callbacks_rva else 0
            step = 8 if is_64 else 4
            for callback_index in range(128):
                if not callback_offset or callback_offset + step > len(data):
                    if callback_index == 0:
                        tls_diagnostics.append("callbacks_array_unmapped")
                    break
                callback_va = struct.unpack_from(
                    "<Q" if is_64 else "<I", data, callback_offset
                )[0]
                if callback_va == 0:
                    break
                if image_base <= callback_va < image_base + max(size_of_image, 1):
                    callback_rva = int(callback_va - image_base)
                    encoding = "va"
                elif callback_va < max(size_of_image, 1):
                    callback_rva = int(callback_va)
                    encoding = "rva"
                    tls_diagnostics.append(
                        f"callback_{callback_index}_was_rva_not_va"
                    )
                else:
                    tls_diagnostics.append(
                        f"callback_{callback_index}_outside_image"
                    )
                    break
                callback_section = next(
                    (
                        section
                        for section in sections
                        if int(section["virtualAddress"])
                        <= callback_rva
                        < int(section["virtualAddress"])
                        + max(
                            int(section["virtualSize"]),
                            int(section["rawSize"]),
                        )
                    ),
                    None,
                )
                tls_callbacks.append(
                    {
                        "index": callback_index,
                        "rva": f"0x{callback_rva:X}",
                        "va": f"0x{int(image_base) + callback_rva:X}",
                        "encoding": encoding,
                        "section": (callback_section or {}).get("name"),
                        "executable": bool(
                            callback_section and callback_section.get("executable")
                        ),
                    }
                )
                callback_offset += step
        else:
            tls_diagnostics.append("callbacks_address_is_null")
    elif tls_rva:
        tls_diagnostics.append("tls_directory_unmapped_or_truncated")

    exception_directory = next(
        (
            dict(item)
            for item in public_directories
            if item.get("name") == "exception"
        ),
        {"index": 3, "name": "exception", "rva": "0x0", "size": 0, "va": None},
    )
    exception_rva = int(str(exception_directory.get("rva") or "0x0"), 16)
    exception_size = int(exception_directory.get("size") or 0)
    exception_offset = rva_to_offset(exception_rva) if exception_rva else 0
    runtime_functions: List[Dict[str, Any]] = []
    runtime_function_count = 0
    invalid_runtime_function_count = 0
    exception_diagnostics: List[str] = []

    def add_exception_diagnostic(message: str) -> None:
        if len(exception_diagnostics) < 32:
            exception_diagnostics.append(message)

    if is_64 and exception_rva and exception_size:
        if exception_offset:
            entry_count = min(exception_size // 12, 16384)
            for index in range(entry_count):
                item_offset = exception_offset + (index * 12)
                if item_offset + 12 > len(data):
                    add_exception_diagnostic("runtime_function_table_truncated")
                    break
                begin_rva, end_rva, unwind_rva = struct.unpack_from(
                    "<III", data, item_offset
                )
                if not any((begin_rva, end_rva, unwind_rva)):
                    continue
                if begin_rva >= end_rva or end_rva > max(size_of_image, 1):
                    invalid_runtime_function_count += 1
                    add_exception_diagnostic(
                        f"runtime_function_{index}_invalid_range"
                    )
                    continue
                runtime_function_count += 1
                if len(runtime_functions) < 256:
                    runtime_functions.append(
                        {
                            "index": index,
                            "beginRva": f"0x{begin_rva:X}",
                            "endRva": f"0x{end_rva:X}",
                            "unwindInfoRva": f"0x{unwind_rva:X}",
                        }
                    )
        else:
            add_exception_diagnostic("exception_directory_unmapped")
    return {
        "path": exe_path,
        "arch": "x64" if is_64 else "x86",
        "machine": f"0x{machine:04X}",
        "timeDateStamp": f"0x{int(time_date_stamp):08X}",
        "fileSize": len(data),
        "characteristics": f"0x{characteristics:04X}",
        "imageBase": f"0x{int(image_base):X}",
        "entryPointRva": f"0x{int(address_of_entry_point):X}",
        "entryPointVa": f"0x{int(image_base) + int(address_of_entry_point):X}",
        "sizeOfImage": size_of_image,
        "sizeOfHeaders": size_of_headers,
        "checksum": f"0x{int(checksum):X}",
        "subsystem": int(subsystem),
        "dllCharacteristics": f"0x{int(dll_characteristics):04X}",
        "dynamicBase": bool(dll_characteristics & 0x0040),
        "highEntropyVa": bool(dll_characteristics & 0x0020),
        "sectionAlignment": int(section_alignment),
        "fileAlignment": int(file_alignment),
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "dataDirectories": public_directories,
        "iatDirectory": iat_directory,
        "tlsDirectory": {
            **tls_directory,
            "callbacksAddressVa": f"0x{callbacks_va:X}" if callbacks_va else None,
            "callbacks": tls_callbacks,
            "callbackCount": len(tls_callbacks),
            "diagnostics": tls_diagnostics,
        },
        "exceptionDirectory": {
            **exception_directory,
            "runtimeFunctionCount": (
                runtime_function_count
                if is_64
                else None
            ),
            "runtimeFunctions": runtime_functions,
            "runtimeFunctionsTruncated": bool(
                is_64 and runtime_function_count > len(runtime_functions)
            ),
            "invalidRuntimeFunctionCount": invalid_runtime_function_count,
            "diagnosticsTruncated": bool(
                invalid_runtime_function_count > len(exception_diagnostics)
            ),
            "diagnostics": exception_diagnostics,
        },
        "entrySection": entry_section,
        "fileEntropy": _shannon_entropy(data[: min(len(data), 0x80000)]),
    }


def _runtime_dll_search_paths(exe_path: str, arch: str = "auto") -> List[str]:
    exe_dir = os.path.dirname(os.path.abspath(exe_path))
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    arch_lower = str(arch or "").strip().lower()
    candidates = [
        exe_dir,
        os.getcwd(),
        os.path.join(system_root, "SysWOW64" if arch_lower == "x86" else "System32"),
        os.path.join(system_root, "System32"),
        os.path.join(system_root, "SysWOW64"),
        system_root,
    ]
    for raw in str(os.environ.get("PATH") or "").split(os.pathsep):
        path = str(raw or "").strip()
        if path:
            candidates.append(path)
    ordered: List[str] = []
    seen = set()
    for raw in candidates:
        try:
            path = os.path.abspath(raw)
        except Exception:
            path = str(raw or "").strip()
        if not path:
            continue
        key = os.path.normcase(path)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(path)
    return ordered


def _find_missing_runtime_dependencies(exe_path: str) -> Dict[str, Any]:
    path = _repair_text_mojibake(str(exe_path or "").strip())
    if not path or not os.path.exists(path):
        return {"ok": False, "error": "Executable path is not available"}
    try:
        layout = _parse_pe_layout(path)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    imports = [
        str(item.get("dll") or "").strip()
        for item in list(layout.get("imports", []))
        if isinstance(item, dict) and str(item.get("dll") or "").strip()
    ]
    search_paths = _runtime_dll_search_paths(path, str(layout.get("arch") or "auto"))
    skip_prefixes = ("api-ms-win-", "ext-ms-win-")
    missing: List[str] = []
    resolved: List[Dict[str, Any]] = []
    for dll_name in imports:
        lowered = dll_name.lower()
        if lowered.startswith(skip_prefixes):
            continue
        found_path = ""
        for base in search_paths:
            candidate = os.path.join(base, dll_name)
            if os.path.isfile(candidate):
                found_path = candidate
                break
        resolved.append({"dll": dll_name, "path": found_path or None})
        if not found_path:
            missing.append(dll_name)
    hint = None
    if missing:
        hint = (
            "The target may fail before user code because required runtime DLLs are missing: "
            + ", ".join(missing[:3])
            + "."
        )
    return {
        "ok": True,
        "arch": str(layout.get("arch") or ""),
        "imports": imports,
        "missing": missing,
        "resolved": resolved,
        "searchPaths": search_paths,
        "hint": hint,
    }


def _candidate_x64dbg_root_dirs() -> List[str]:
    roots: List[str] = []
    for raw in (
        os.getenv("X64DBG_ROOT"),
        r"C:\x64dbg",
    ):
        value = str(raw or "").strip()
        if not value:
            continue
        normalized = os.path.abspath(value)
        if normalized not in roots:
            roots.append(normalized)
    return roots


def _resolve_debugger_install_dir(arch: str = "auto") -> Optional[str]:
    desired = str(arch or "auto").strip().lower()
    suffixes = (
        ["x64", "x32"] if desired == "auto" else ["x64" if desired == "x64" else "x32"]
    )
    for root in _candidate_x64dbg_root_dirs():
        for suffix in suffixes:
            candidate = os.path.join(root, suffix)
            exe_name = "x64dbg.exe" if suffix == "x64" else "x32dbg.exe"
            if os.path.exists(os.path.join(candidate, exe_name)):
                return candidate
    return None


def _normalize_debugger_arch(arch: str = "auto", exe_path: str = "") -> str:
    desired = str(arch or "auto").strip().lower()
    if desired in ("x64", "64", "amd64"):
        return "x64"
    if desired in ("x86", "x32", "32", "win32", "i386"):
        return "x86"
    target_arch = _detect_pe_arch(str(exe_path or "").strip()) if exe_path else None
    if target_arch in ("x86", "x64"):
        return target_arch
    active_arch = str((_get_active_debugger_info() or {}).get("arch") or "").lower()
    if active_arch in ("x86", "x64"):
        return active_arch
    return "x64" if _resolve_debugger_install_dir("x64") else "x86"


def _resolve_debugger_exe_path(arch: str = "auto") -> Dict[str, Any]:
    desired_arch = _normalize_debugger_arch(arch)
    install_dir = _resolve_debugger_install_dir(desired_arch)
    if not install_dir:
        return {
            "ok": False,
            "arch": desired_arch,
            "error": f"Could not find an installed debugger for arch {desired_arch}.",
        }
    exe_name = "x64dbg.exe" if desired_arch == "x64" else "x32dbg.exe"
    exe_path = os.path.join(install_dir, exe_name)
    if not os.path.exists(exe_path):
        return {
            "ok": False,
            "arch": desired_arch,
            "installDir": install_dir,
            "exePath": exe_path,
            "error": f"Debugger executable was not found: {exe_path}",
        }
    return {
        "ok": True,
        "arch": desired_arch,
        "installDir": install_dir,
        "exePath": exe_path,
        "exeName": exe_name,
    }


def _list_debugger_processes(arch: str = "auto") -> List[Dict[str, Any]]:
    desired_arch = str(arch or "auto").strip().lower()
    processes = _list_processes()
    matches = [
        item
        for item in processes
        if str(item.get("exe") or "").lower() in ("x64dbg.exe", "x32dbg.exe")
    ]
    if desired_arch in ("x64", "x86"):
        exe_name = "x64dbg.exe" if desired_arch == "x64" else "x32dbg.exe"
        matches = [
            item for item in matches if str(item.get("exe") or "").lower() == exe_name
        ]
    matches.sort(key=lambda item: int(item.get("pid") or 0), reverse=True)
    return matches


def _spawn_detached_process(exe_path: str, cwd: str = "") -> Dict[str, Any]:
    """Launch a long-lived GUI process so it is NOT a member of this process's tree.

    Some hosts run each command inside a job/process tree that they tear down on
    completion by killing the whole tree (by parent-PID walk). A debugger spawned
    as an ordinary child would be killed together with the launcher — and on
    Windows that teardown can cascade and take the host process down too. To make
    the debugger survive independently, re-parent the launch through the shell
    (``explorer.exe``): explorer becomes the parent, so the new process is outside
    this process's tree and a host tree-kill cannot reach it.

    Returns ``{"ok", "pid", "method"}``. ``explorer.exe`` returns before the child
    appears and does not report its PID, so the new debugger PID is discovered from
    a process snapshot diff. Falls back to a direct spawn if re-parenting fails.
    """
    if os.name != "nt":
        proc = subprocess.Popen(
            [exe_path],
            cwd=cwd or None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return {"ok": True, "pid": int(proc.pid), "method": "posix_setsid"}

    exe_base = os.path.basename(exe_path).lower()

    def _debugger_pids() -> set:
        try:
            return {
                int(it["pid"])
                for it in _list_processes()
                if str(it.get("exe") or "").lower() == exe_base
            }
        except Exception:
            return set()

    before = _debugger_pids()
    reparented = False
    try:
        subprocess.Popen(
            ["explorer.exe", exe_path],
            cwd=cwd or None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        reparented = True
    except Exception as exc:  # pragma: no cover - explorer should always exist
        _log_event("spawn_detached_explorer_failed", exePath=exe_path, error=str(exc))

    if reparented:
        deadline = time.time() + 10.0
        while time.time() < deadline:
            new_pids = _debugger_pids() - before
            if new_pids:
                return {"ok": True, "pid": max(new_pids), "method": "explorer"}
            time.sleep(0.15)

    # Fallback: direct spawn (fine on hosts that do not tree-kill; better than
    # not launching at all).
    proc = subprocess.Popen(
        [exe_path],
        cwd=cwd or None,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=0x08000000,
    )
    return {"ok": True, "pid": int(proc.pid), "method": "popen_fallback"}


def _start_debugger_process(arch: str = "auto") -> Dict[str, Any]:
    resolved = _resolve_debugger_exe_path(arch)
    if not resolved.get("ok"):
        return resolved
    exe_path = str(resolved.get("exePath") or "")
    install_dir = str(resolved.get("installDir") or "")
    try:
        spawn = _spawn_detached_process(exe_path, install_dir)
        payload = dict(resolved)
        payload.update(
            {
                "ok": True,
                "pid": int(spawn.get("pid") or 0),
                "launched": True,
                "launchMethod": spawn.get("method"),
                "timestamp": _now_iso(),
            }
        )
        _log_event(
            "start_debugger_process",
            arch=payload.get("arch"),
            pid=payload.get("pid"),
            method=payload.get("launchMethod"),
            exePath=payload.get("exePath"),
        )
        return payload
    except Exception as e:
        _log_event(
            "start_debugger_process_error",
            arch=resolved.get("arch"),
            exePath=exe_path,
            error=str(e),
        )
        payload = dict(resolved)
        payload.update({"ok": False, "error": str(e)})
        return payload


def _probe_bridge_ready(timeout_sec: float = 1.0) -> Dict[str, Any]:
    started = time.time()
    hello = _bridge_request(
        "GET",
        "Bridge/Hello",
        log=False,
        timeout_sec=max(0.2, float(timeout_sec)),
        guard="none",
        idempotent=True,
    )
    if hello.ok and isinstance(hello.data, dict):
        identity = _cache_bridge_identity(hello.data)
        if not identity.get("bridgeInstanceId"):
            return {
                "ok": False,
                "status": hello.meta.get("httpStatus"),
                "error": "Bridge/Hello omitted bridgeInstanceId.",
                "payload": hello.data,
                "elapsedMs": round((time.time() - started) * 1000, 2),
            }
        return {
            "ok": True,
            "status": hello.meta.get("httpStatus", 200),
            "payload": hello.data,
            "identity": identity,
            "protocolVersion": identity.get("protocolVersion"),
            "legacy": False,
            "elapsedMs": round((time.time() - started) * 1000, 2),
        }
    # Read-only compatibility probe for an old plugin.  It proves that an HTTP
    # bridge exists, but deliberately does not synthesize an identity: guarded
    # mutations remain fail-closed until the v2 plugin is installed.
    legacy = _bridge_request(
        "GET",
        "IsDebugActive",
        log=False,
        timeout_sec=max(0.2, float(timeout_sec)),
        guard="none",
        idempotent=True,
    )
    if legacy.ok and isinstance(legacy.data, dict):
        return {
            "ok": True,
            "status": legacy.meta.get("httpStatus", 200),
            "payload": legacy.data,
            "legacy": True,
            "strictSessionGuards": False,
            "warning": "Legacy bridge is reachable but Bridge/Hello identity is unavailable; mutations are disabled.",
            "elapsedMs": round((time.time() - started) * 1000, 2),
        }
    error = hello.error or legacy.error
    return {
        "ok": False,
        "status": (hello.meta or {}).get("httpStatus"),
        "error": error.message if error else "Bridge did not respond.",
        "errorCode": error.code if error else "BRIDGE_UNAVAILABLE",
        "elapsedMs": round((time.time() - started) * 1000, 2),
    }


def _wait_for_debugger_bridge_ready(
    arch: str = "auto",
    expected_pid: int = 0,
    timeout_ms: int = 15000,
    poll_ms: int = 200,
) -> Dict[str, Any]:
    desired_arch = _normalize_debugger_arch(arch)
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    last_probe: Dict[str, Any] = {"ok": False, "error": "Bridge not checked yet."}
    last_active: Dict[str, Any] = {}
    while time.time() < deadline:
        last_active = _get_active_debugger_info()
        active_pid = int(last_active.get("pid") or 0)
        active_arch = str(last_active.get("arch") or "").lower()
        if active_pid and active_arch == desired_arch:
            allow_active_pid = not expected_pid or active_pid == int(expected_pid)
            if not allow_active_pid and expected_pid:
                expected_alive = _process_exists(int(expected_pid))
                same_arch_debuggers = _list_debugger_processes(desired_arch)
                if not expected_alive and len(same_arch_debuggers) == 1:
                    allow_active_pid = (
                        int(same_arch_debuggers[0].get("pid") or 0) == active_pid
                    )
            if allow_active_pid:
                last_probe = _probe_bridge_ready(
                    timeout_sec=max(0.25, min(1.0, poll_ms / 1000.0))
                )
                if last_probe.get("ok"):
                    return {
                        "ok": True,
                        "arch": desired_arch,
                        "activeDebugger": last_active,
                        "bridge": last_probe,
                    }
        time.sleep(max(0.05, poll_ms / 1000.0))
    return {
        "ok": False,
        "arch": desired_arch,
        "activeDebugger": last_active,
        "bridge": last_probe,
        "error": "Timed out waiting for debugger bridge to become ready.",
    }


def _stop_debugger_processes(
    arch: str = "auto", timeout_ms: int = 10000
) -> Dict[str, Any]:
    victims = _list_debugger_processes(arch)
    results: List[Dict[str, Any]] = []
    attempted_keys: set[tuple[str, int, str]] = set()

    def _record_taskkill(args: List[str], pid: int = 0, exe: str = "") -> None:
        key = (str(exe or "").lower(), int(pid or 0), " ".join(args).lower())
        if key in attempted_keys:
            return
        attempted_keys.add(key)
        started = time.time()
        try:
            completed = subprocess.run(
                args,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=max(1, int(timeout_ms)) / 1000.0,
                check=False,
                creationflags=0x08000000 if os.name == "nt" else 0,
            )
            results.append(
                {
                    "pid": int(pid or 0),
                    "exe": str(exe or ""),
                    "command": " ".join(args),
                    "returncode": int(completed.returncode),
                    "stdout": str(completed.stdout or "").strip(),
                    "stderr": str(completed.stderr or "").strip(),
                    "elapsedMs": round((time.time() - started) * 1000, 2),
                }
            )
        except Exception as e:
            results.append(
                {
                    "pid": int(pid or 0),
                    "exe": str(exe or ""),
                    "command": " ".join(args),
                    "returncode": -1,
                    "stdout": "",
                    "stderr": str(e),
                    "elapsedMs": round((time.time() - started) * 1000, 2),
                }
            )

    image_names: List[str]
    desired_arch = str(arch or "auto").strip().lower()
    if desired_arch == "x64":
        image_names = ["x64dbg.exe"]
    elif desired_arch == "x86":
        image_names = ["x32dbg.exe"]
    else:
        image_names = ["x64dbg.exe", "x32dbg.exe"]

    for image_name in image_names:
        _record_taskkill(["taskkill", "/IM", image_name, "/T", "/F"], exe=image_name)

    remaining_after_image_kill = _list_debugger_processes(arch)
    for item in remaining_after_image_kill:
        pid_value = int(item.get("pid") or 0)
        if not pid_value:
            continue
        _record_taskkill(
            ["taskkill", "/PID", str(pid_value), "/T", "/F"],
            pid=pid_value,
            exe=str(item.get("exe") or ""),
        )

    # A debugger restart rotates the protected bridge token while the new
    # instance commonly reuses the same loopback port.  Keeping the old
    # descriptor in the fast-path cache can therefore authenticate the first
    # readiness probe with the dead instance's token and incorrectly classify
    # the new bridge as legacy.  Invalidate both the descriptor and normalized
    # Hello identity before any replacement debugger is launched.
    _invalidate_bridge_auth_cache()
    _clear_bound_session()
    _remember_runtime(
        bridgeIdentity={},
        lastBridgeHelloAt=None,
        selectedBridgeInstanceId=None,
        selectedBridgeDebuggerPid=0,
        selectedBridgeAt=None,
        lastDebuggeePid=0,
        lastDebuggeeImage=None,
        lastDebuggeePath=None,
    )
    wait_deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    remaining = _list_debugger_processes(arch)
    while remaining and time.time() < wait_deadline:
        time.sleep(0.15)
        remaining = _list_debugger_processes(arch)
    payload = {
        "ok": not remaining,
        "requestedArch": str(arch or "auto"),
        "killed": results,
        "remaining": remaining,
        "count": len(results),
    }
    _log_event(
        "stop_debugger_processes",
        requestedArch=payload.get("requestedArch"),
        count=payload.get("count"),
        ok=payload.get("ok"),
        remaining=[int(item.get("pid") or 0) for item in remaining],
    )
    return payload


def _scyllahide_paths_for_arch(arch: str = "auto") -> Dict[str, Any]:
    install_dir = _resolve_debugger_install_dir(arch)
    normalized_arch = "x64" if str(arch or "").lower() == "x64" else "x86"
    if not install_dir:
        return {"arch": normalized_arch, "installDir": None}
    root_dir = os.path.dirname(install_dir)
    is_64 = os.path.basename(install_dir).lower() == "x64"
    return {
        "arch": "x64" if is_64 else "x86",
        "installDir": install_dir,
        "pluginPath": os.path.join(
            install_dir,
            "plugins",
            "ScyllaHideX64DBGPlugin.dp64" if is_64 else "ScyllaHideX64DBGPlugin.dp32",
        ),
        "hookPath": os.path.join(
            install_dir,
            "plugins",
            "HookLibraryx64.dll" if is_64 else "HookLibraryx86.dll",
        ),
        "configPath": os.path.join(install_dir, "plugins", "scylla_hide.ini"),
        "injectorPath": os.path.join(
            root_dir,
            "ScyllaHide",
            "InjectorCLIx64.exe" if is_64 else "InjectorCLIx86.exe",
        ),
        "testExePath": os.path.join(
            root_dir,
            "ScyllaHide",
            "ScyllaTest_x64.exe" if is_64 else "ScyllaTest_x86.exe",
        ),
        "logPath": os.path.join(root_dir, "ScyllaHide", "scylla_hide.log"),
    }


def _read_ini_sections(path: str) -> List[str]:
    parser = configparser.RawConfigParser(strict=False)
    parser.optionxform = str
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        parser.read_file(handle)
    return list(parser.sections())


def _read_ini_section_items(path: str, section: str) -> Dict[str, str]:
    parser = configparser.RawConfigParser(strict=False)
    parser.optionxform = str
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        parser.read_file(handle)
    if not parser.has_section(section):
        return {}
    return {str(key): str(value) for key, value in parser.items(section)}


def _read_scyllahide_profile(path: str) -> Dict[str, Any]:
    parser = configparser.RawConfigParser(strict=False)
    parser.optionxform = str
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        parser.read_file(handle)
    current = ""
    if parser.has_section("SETTINGS"):
        current = str(parser.get("SETTINGS", "CurrentProfile", fallback="") or "")
    profiles = [section for section in parser.sections() if section != "SETTINGS"]
    return {
        "currentProfile": current,
        "profiles": profiles,
        "activeProfiles": [p for p in profiles if not _is_disabled_scylla_profile(p)],
        "disabledProfiles": [p for p in profiles if _is_disabled_scylla_profile(p)],
        "currentProfileDisabled": _is_disabled_scylla_profile(current),
    }


def _write_scyllahide_profile(
    path: str, profile: str, *, allow_disabled: bool = False
) -> Dict[str, Any]:
    profile_name = str(profile or "").strip()
    if not profile_name:
        raise RuntimeError("ScyllaHide profile name is required")
    if _is_disabled_scylla_profile(profile_name) and not allow_disabled:
        raise RuntimeError(
            "The requested virtualization research profile is disabled in this build; "
            "use a supported generic ScyllaHide profile or restore the archived research "
            "snapshot after a fresh review."
        )
    parser = configparser.RawConfigParser(strict=False)
    parser.optionxform = str
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        parser.read_file(handle)
    if not parser.has_section("SETTINGS"):
        parser.add_section("SETTINGS")
    available_profiles = [
        section for section in parser.sections() if section != "SETTINGS"
    ]
    available = set(available_profiles)
    if profile_name not in available:
        raise RuntimeError(f"Unknown ScyllaHide profile: {profile_name}")
    parser.set("SETTINGS", "CurrentProfile", profile_name)
    target = Path(path)
    size_before = int(target.stat().st_size) if target.exists() else 0
    temp_fd = -1
    temp_path = ""
    try:
        temp_fd, temp_path = tempfile.mkstemp(
            prefix=f"{target.stem}-",
            suffix=target.suffix or ".ini",
            dir=str(target.parent),
        )
        with os.fdopen(temp_fd, "w", encoding="utf-8", newline="\r\n") as handle:
            parser.write(handle, space_around_delimiters=False)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        temp_fd = -1
        os.replace(temp_path, path)
    finally:
        if temp_fd != -1:
            try:
                os.close(temp_fd)
            except OSError:
                pass
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
    size_after = int(target.stat().st_size) if target.exists() else None
    return {
        "ok": True,
        "configPath": path,
        "currentProfile": profile_name,
        "availableProfiles": [
            p for p in available_profiles if not _is_disabled_scylla_profile(p)
        ],
        "disabledProfiles": [
            p for p in available_profiles if _is_disabled_scylla_profile(p)
        ],
        "sizeBefore": size_before,
        "sizeAfter": size_after,
        "compacted": bool(
            size_before and size_after is not None and int(size_after) < int(size_before)
        ),
    }


def _read_scyllahide_log_status(
    paths: Dict[str, Any], since_mtime: float = 0.0, since_size: int = 0
) -> Dict[str, Any]:
    log_path = str((paths or {}).get("logPath") or "")
    if not log_path:
        return {
            "path": "",
            "exists": False,
            "size": 0,
            "mtime": 0.0,
            "fresh": False,
            "hasHookingLines": False,
            "tail": "",
        }
    if not os.path.exists(log_path):
        return {
            "path": log_path,
            "exists": False,
            "size": 0,
            "mtime": 0.0,
            "fresh": False,
            "hasHookingLines": False,
            "tail": "",
        }
    try:
        stat = os.stat(log_path)
        raw_bytes = Path(log_path).read_bytes()
        recent = (time.time() - float(stat.st_mtime)) <= 10.0
        fresh = bool(
            (since_mtime and stat.st_mtime > (float(since_mtime) + 0.01))
            or (since_size and stat.st_size > int(since_size or 0))
        )
        delta_bytes = raw_bytes
        if since_size and len(raw_bytes) >= int(since_size):
            delta_bytes = raw_bytes[int(since_size) :]
            # ScyllaHide commonly rewrites the whole log file. When the file is refreshed
            # with the same size, slicing from the old byte count produces an empty delta.
            # In that case, fall back to the rewritten content.
            if (
                not delta_bytes
                and since_mtime
                and stat.st_mtime > (float(since_mtime) + 0.01)
            ):
                delta_bytes = raw_bytes
        tail_text = raw_bytes.decode("utf-8", errors="replace")
        delta_text = delta_bytes.decode("utf-8", errors="replace")
        lowered = delta_text.lower()
        has_hooking = any(
            marker in lowered
            for marker in (
                "applyntdllhook",
                "hooking nt",
                "loaded va for nt",
            )
        )
        # Only include log text when it's actually fresh/recent — stale hook logs
        # from previous sessions bloat every response by 10+ KB without adding info.
        result: Dict[str, Any] = {
            "path": log_path,
            "exists": True,
            "size": int(stat.st_size),
            "mtime": float(stat.st_mtime),
            "recent": recent,
            "fresh": fresh,
            "hasHookingLines": bool(has_hooking),
            "tail": "",
        }
        if fresh or recent:
            result["tail"] = "\n".join(tail_text.splitlines()[-8:])
            result["deltaTail"] = "\n".join(delta_text.splitlines()[-8:])
        return result
    except Exception as e:
        return {
            "path": log_path,
            "exists": True,
            "size": 0,
            "mtime": 0.0,
            "recent": False,
            "fresh": False,
            "hasHookingLines": False,
            "tail": "",
            "error": str(e),
        }


def _is_windows_system_path(path: str) -> bool:
    try:
        candidate = os.path.abspath(str(path or "")).lower()
    except Exception:
        candidate = str(path or "").lower()
    if not candidate:
        return False
    roots: List[str] = []
    for env_name in ("SystemRoot", "WinDir"):
        value = os.environ.get(env_name)
        if value:
            roots.append(os.path.abspath(value).lower())
    if not roots:
        roots.append(os.path.abspath(r"C:\Windows").lower())
    for root in roots:
        if candidate == root or candidate.startswith(root + os.sep):
            return True
    return False


def _detect_toolchain_hint(exe_path: str, section_names: set) -> Optional[str]:
    """Return 'rust'/'go'/'dotnet' if file looks like a known toolchain output.

    Packer heuristics (high entropy, few imports) false-positive on Rust/Go
    binaries because their runtimes statically link and embed many strings.
    """
    try:
        name_lower = os.path.basename(exe_path).lower()
        if any(s in section_names for s in (".go.buildid", "text.go")):
            return "go"
        if any(s in section_names for s in (".textbss", ".00cfg")) and "clr" in name_lower:
            return "dotnet"
        # Scan for Rust/Go fingerprint strings in first 2 MB.
        with open(exe_path, "rb") as fh:
            buf = fh.read(2 * 1024 * 1024)
        if b"rustc/" in buf or b"RUST_BACKTRACE" in buf or b"\\.cargo\\registry" in buf:
            return "rust"
        if b"Go build ID:" in buf or b"runtime.goexit" in buf or b"go.buildid" in buf:
            return "go"
        if b"mscoree.dll" in buf or b".NET Framework" in buf or b"_CorExeMain" in buf:
            return "dotnet"
    except Exception:
        return None
    return None


def _analyze_antidebug_surface(exe_path: str) -> Dict[str, Any]:
    layout = _parse_pe_layout(exe_path)
    imports = list(layout.get("imports", []))
    import_dll_count = len(imports)
    import_func_count = sum(len(item.get("functions", [])) for item in imports)
    section_names = {
        str(item.get("name", "")).lower() for item in layout.get("sections", [])
    }
    standard_sections = {
        ".text",
        ".rdata",
        ".data",
        ".pdata",
        ".idata",
        ".rsrc",
        ".reloc",
        ".tls",
        ".bss",
        ".edata",
        ".xdata",
        ".crt",
    }
    custom_sections = [
        item
        for item in list(layout.get("sections", []))
        if str(item.get("name", "")).lower() not in standard_sections
    ]
    custom_exec_sections = [
        item for item in custom_sections if bool(item.get("executable"))
    ]
    custom_writable_sections = [
        item for item in custom_sections if bool(item.get("writable"))
    ]
    import_names = {
        func.lower() for item in imports for func in item.get("functions", []) if func
    }
    matched_imports = sorted(
        name for name in import_names if name in ANTI_DEBUG_IMPORT_HINTS
    )
    strong_imports = [
        name for name in matched_imports if name in STRONG_ANTI_DEBUG_IMPORT_HINTS
    ]
    weak_imports = [
        name for name in matched_imports if name in WEAK_ANTI_DEBUG_IMPORT_HINTS
    ]
    neutral_imports = [
        name
        for name in matched_imports
        if name not in STRONG_ANTI_DEBUG_IMPORT_HINTS
        and name not in WEAK_ANTI_DEBUG_IMPORT_HINTS
    ]
    protector_matches: List[str] = []
    for key, profile in SCYLLA_PROTECTOR_PROFILES.items():
        if (
            any(key in section for section in section_names)
            or key in os.path.basename(exe_path).lower()
        ):
            if profile not in protector_matches:
                protector_matches.append(profile)
    # Rust/Go binaries have high entropy and lots of internal strings but
    # are NOT packed. Detect and exempt from packer heuristics.
    runtime_hint = _detect_toolchain_hint(exe_path, section_names)

    packer_signals: List[str] = []
    if any(name.startswith("upx") for name in section_names):
        packer_signals.append("upx_section_names")
    entry_section = layout.get("entrySection") or {}
    # Skip entropy-based signals when we know this is Rust/Go/.NET output.
    if entry_section and float(entry_section.get("entropy", 0.0) or 0.0) >= 6.9 and not runtime_hint:
        packer_signals.append("high_entropy_entry_section")
    if layout.get("fileEntropy", 0.0) >= 6.8 and not runtime_hint:
        packer_signals.append("high_file_entropy")
    if import_dll_count <= 3 and not runtime_hint:
        packer_signals.append("few_imported_dlls")
    if import_func_count <= 20 and not runtime_hint:
        packer_signals.append("small_import_table")
    if import_dll_count == 0:
        packer_signals.append("no_import_table")
    if len(custom_sections) >= 4:
        packer_signals.append("many_nonstandard_sections")
    if len(custom_exec_sections) >= 2:
        packer_signals.append("multiple_custom_executable_sections")
    if len(custom_writable_sections) >= 2:
        packer_signals.append("multiple_custom_writable_sections")
    if import_dll_count == 0 and custom_exec_sections:
        packer_signals.append("manual_loader_like_layout")
    system_path = _is_windows_system_path(exe_path)
    risk_score = (
        (len(strong_imports) * 3)
        + len(weak_imports)
        + len(neutral_imports)
        + len(packer_signals)
        + (4 if protector_matches else 0)
        + (0 if system_path else 1 if matched_imports else 0)
    )
    suggested_profile = "Disabled"
    decision_reason = "no_antidebug_signal"
    arch = str(layout.get("arch") or "").lower()
    if protector_matches:
        suggested_profile = protector_matches[0]
        if suggested_profile == "Armadillo x86" and arch != "x86":
            suggested_profile = "Basic"
        decision_reason = "protector_signal"
    elif system_path and not protector_matches and not packer_signals:
        if len(strong_imports) >= 3 and len(matched_imports) >= 5:
            suggested_profile = "Basic"
            decision_reason = "system_binary_strong_antidebug_surface"
        else:
            suggested_profile = "Disabled"
            decision_reason = "system_binary_conservative_skip"
    elif packer_signals and (strong_imports or len(matched_imports) >= 3):
        suggested_profile = "Basic"
        decision_reason = "packer_plus_antidebug"
    elif len(strong_imports) >= 2:
        suggested_profile = "Basic"
        decision_reason = "multiple_strong_antidebug_imports"
    elif len(strong_imports) >= 1 and len(matched_imports) >= 4:
        suggested_profile = "Basic"
        decision_reason = "mixed_antidebug_surface"
    elif len(matched_imports) >= 6 and not system_path:
        suggested_profile = "Basic"
        decision_reason = "broad_antidebug_surface"
    elif import_dll_count == 0 and len(custom_exec_sections) >= 2 and not system_path:
        decision_reason = "packed_custom_loader_no_explicit_antidebug"
    return {
        "ok": True,
        "path": exe_path,
        "arch": layout.get("arch"),
        "antiDebugImports": matched_imports,
        "strongAntiDebugImports": strong_imports,
        "weakAntiDebugImports": weak_imports,
        "packerSignals": packer_signals,
        "protectorSignals": protector_matches,
        "isWindowsSystemPath": system_path,
        "riskScore": risk_score,
        "suggestedScyllaHideProfile": suggested_profile,
        "autoDecisionReason": decision_reason,
        "scyllaHideRecommended": suggested_profile != "Disabled",
        "customSectionCount": len(custom_sections),
        "customExecutableSectionCount": len(custom_exec_sections),
        "customWritableSectionCount": len(custom_writable_sections),
        "runtimeHint": runtime_hint,
    }


def _collect_module_names() -> List[str]:
    payload = GetModuleList()
    modules = payload.get("modules", []) if isinstance(payload, dict) else []
    return [
        str((item or {}).get("name") or "").lower()
        for item in modules
        if isinstance(item, dict)
    ]


def _inject_scyllahide_for_pid(
    target_pid: int, arch: str, profile: str
) -> Dict[str, Any]:
    from mcp_runtime.scylla import run_injector

    paths = _scyllahide_paths_for_arch(arch)
    hook_path = str(paths.get("hookPath") or "")
    injector_path = str(paths.get("injectorPath") or "")
    config_path = str(paths.get("configPath") or "")
    desired_profile = str(profile or "Basic")
    missing = [path for path in (hook_path, injector_path, config_path)
               if not path or not os.path.isfile(path)]
    if missing:
        return {"ok": False, "error": f"Missing ScyllaHide files: {missing}", "paths": paths}
    process_info = _get_process_info(int(target_pid))
    process_name = str(process_info.get("exe") or "").strip()
    if int(target_pid) <= 0 or not process_name:
        return {"ok": False, "error": "The requested target PID is not available.", "paths": paths}
    runtime_record = _get_runtime_value("lastScyllaHide")
    if (isinstance(runtime_record, dict)
        and int(runtime_record.get("pid") or 0) == int(target_pid)
        and _process_exists(int(target_pid))
        and str(runtime_record.get("hookPath") or "").lower() == hook_path.lower()
        and runtime_record.get("ok")):
        if runtime_record.get("profile") != desired_profile:
            return {"ok": False, "error": "Restart the target before changing an applied ScyllaHide profile."}
        previous = runtime_record.get("injectResult")
        if isinstance(previous, dict):
            return {**previous, "alreadyInjected": True, "skippedInjector": True}

    try:
        result = run_injector(
            injector=injector_path, hook=hook_path, config=config_path,
            profile=desired_profile, pid=int(target_pid), work_dir=LOG_DIR,
        )
    except (OSError, ValueError, configparser.Error) as exc:
        return {"ok": False, "pid": int(target_pid), "profile": desired_profile, "error": str(exc)}
    module_names = _collect_module_names()
    module_list_present = os.path.basename(hook_path).lower() in module_names
    native_log = str(result.pop("nativeLog", ""))
    log_status = {
        "source": "isolated_injector", "pid": int(target_pid),
        "fresh": bool(native_log), "recent": bool(native_log),
        "hasHookingLines": "hooking " in native_log.lower(),
        "tail": native_log[-16000:],
    }
    result.update({
        "arch": arch, "configPath": config_path, "hookPath": hook_path,
        "injectorPath": injector_path, "modulePresent": bool(result.get("hookInjected")),
        "moduleListPresent": module_list_present, "moduleNames": module_names[:64],
        "processName": process_name, "scyllaLog": log_status,
    })
    if result.get("ok"):
        _remember_runtime(lastScyllaHide={
            "pid": int(target_pid), "arch": arch, "profile": desired_profile,
            "hookPath": hook_path, "ok": True, "hookInjected": result.get("hookInjected"),
            "protectionApplied": True, "processName": process_name,
            "scyllaLog": log_status, "injectResult": dict(result), "timestamp": _now_iso(),
        })
    return result



def _resolve_target_exe_path(exe_path: str = "") -> str:
    target_path = _repair_text_mojibake(str(exe_path or "").strip())
    if target_path:
        if os.path.exists(target_path):
            return target_path
        for candidate in _build_init_launch_paths(target_path):
            if candidate and os.path.exists(candidate):
                return candidate
        return target_path
    state = _build_debug_state(
        include_console=False, include_callstack=False, max_console_chars=0
    )
    return _repair_text_mojibake(str(state.get("debuggeePath") or ""))


def ListDebugSessions(
    root_launch_id: str = "",
    broker_id: str = "",
    include_state: bool = True,
) -> dict:
    """List authenticated x32/x64dbg bridge instances and broker sessions.

    The result never exposes bearer tokens. ``root_launch_id`` or ``broker_id``
    can restrict the list to one typed-launch process tree.
    """

    return _enumerate_bridge_instances(
        root_launch_id=str(root_launch_id or "").strip(),
        broker_id=str(broker_id or "").strip(),
        include_state=bool(include_state),
    )


def GetChildBrokerState() -> dict:
    """Return the child-process broker state for the currently selected bridge."""

    envelope = _bridge_request(
        "GET",
        "Debug/ChildBroker/State",
        timeout_sec=3.0,
        guard="none",
        idempotent=True,
    )
    return envelope.data if envelope.ok and isinstance(envelope.data, dict) else envelope.as_dict()


def SelectDebugSession(
    session_ref: str = "",
    debugger_pid: int = 0,
    bridge_instance_id: str = "",
    debuggee_pid: int = 0,
) -> dict:
    """Select one exact authenticated bridge instance for subsequent tools.

    At least one selector is required and the match must be unique. The
    descriptor PID, creation time, architecture, port and bridge UUID are
    revalidated against Bridge/Hello before the global MCP target changes.
    """

    requested_ref = str(session_ref or "").strip()
    requested_bridge = str(bridge_instance_id or "").strip()
    requested_debugger_pid = int(debugger_pid or 0)
    requested_debuggee_pid = int(debuggee_pid or 0)
    if not any(
        (requested_ref, requested_bridge, requested_debugger_pid, requested_debuggee_pid)
    ):
        return {
            "ok": False,
            "error": {
                "code": "session_selector_required",
                "message": "session_ref, debugger_pid, bridge_instance_id, or debuggee_pid is required",
                "retryable": False,
            },
        }
    inventory = _enumerate_bridge_instances(include_state=True)
    if not inventory.get("ok"):
        return inventory
    matches: List[Dict[str, Any]] = []
    for item in inventory.get("sessions") or []:
        debugger = item.get("debugger") if isinstance(item.get("debugger"), dict) else {}
        session = item.get("session") if isinstance(item.get("session"), dict) else {}
        if requested_ref and str(item.get("sessionRef") or "") != requested_ref:
            continue
        if requested_bridge and str(item.get("bridgeInstanceId") or "") != requested_bridge:
            continue
        if requested_debugger_pid and int(debugger.get("pid") or 0) != requested_debugger_pid:
            continue
        if requested_debuggee_pid and int(session.get("processId") or 0) != requested_debuggee_pid:
            continue
        matches.append(item)
    if len(matches) != 1:
        return {
            "ok": False,
            "error": {
                "code": "session_selector_not_unique" if matches else "session_not_found",
                "message": (
                    f"selector matched {len(matches)} bridge instances; exactly one is required"
                ),
                "retryable": False,
            },
            "matchCount": len(matches),
        }
    selected = matches[0]
    selected_debugger = dict(selected.get("debugger") or {})
    selected_pid = int(selected_debugger.get("pid") or 0)
    local_app_data = str(os.getenv("LOCALAPPDATA") or "").strip()
    descriptor = _parse_bridge_auth_file(
        Path(local_app_data) / "x64dbgMCP" / f"bridge-{selected_pid}.token"
    )
    hello_result = _request_bridge_descriptor(
        descriptor, "Bridge/Hello", timeout_sec=1.5
    )
    hello = hello_result.get("data") if hello_result.get("ok") else None
    valid, mismatched = _validate_descriptor_hello(descriptor, hello)
    if not valid:
        return {
            "ok": False,
            "error": {
                "code": "session_identity_changed",
                "message": "the selected descriptor no longer matches its live bridge",
                "retryable": False,
                "details": {"fields": mismatched},
            },
        }

    global x64dbg_server_url
    selected_url = f"http://127.0.0.1:{int(descriptor['port'])}/"
    cache_key = f"{descriptor.get('path')}:{descriptor.get('mtimeNs')}"
    with _BRIDGE_AUTH_LOCK:
        x64dbg_server_url = selected_url
        _BRIDGE_AUTH_CACHE.clear()
        _BRIDGE_AUTH_CACHE.update(
            {
                "key": cache_key,
                "source": "descriptor",
                "token": descriptor["token"],
                "pid": descriptor["pid"],
                "processStartTime100ns": descriptor["processStartTime100ns"],
                "bridgeInstanceId": descriptor["bridgeInstanceId"],
                "port": descriptor["port"],
                "arch": descriptor["arch"],
                "path": descriptor["path"],
                "mtimeNs": descriptor["mtimeNs"],
                "size": descriptor["size"],
            }
        )
    identity = _cache_bridge_identity(hello)
    _clear_bound_session()
    session = dict(hello.get("session") or {})
    binding: Dict[str, Any] = {}
    if int(session.get("processId") or 0):
        binding = _bind_debuggee_session(
            pid=int(session.get("processId") or 0),
            image_path=str(session.get("imagePath") or ""),
            strict=True,
            source="SelectDebugSession",
        )
    _remember_runtime(
        selectedBridgeInstanceId=str(identity.get("bridgeInstanceId") or ""),
        selectedBridgeDebuggerPid=int(identity.get("debuggerPid") or 0),
        selectedBridgeAt=_now_iso(),
    )
    return {
        "ok": True,
        "sessionRef": str(selected.get("sessionRef") or ""),
        "serverUrl": selected_url,
        "identity": identity,
        "binding": binding or None,
        "childBroker": dict(hello.get("childBroker") or {}),
    }


def GetSelectedDebugSession() -> dict:
    """Return the currently selected bridge/session identity without secrets."""

    identity = _get_cached_bridge_identity()
    return {
        "ok": bool(identity.get("bridgeInstanceId")),
        "serverUrl": str(x64dbg_server_url),
        "identity": identity,
        "binding": _get_bound_session() or None,
        "selectedAt": _get_runtime_value("selectedBridgeAt"),
    }


def _get_active_debugger_info() -> Dict[str, Any]:
    try:
        processes = _list_processes()
    except Exception:
        return {}
    matches = [
        item
        for item in processes
        if str(item.get("exe", "")).lower() in ("x32dbg.exe", "x64dbg.exe")
    ]
    if not matches:
        return {}
    matches.sort(key=lambda item: int(item.get("pid") or 0), reverse=True)
    preferred = None
    if len(matches) == 1:
        preferred = matches[0]
    else:
        with_children = [
            item
            for item in matches
            if any(
                int(p.get("ppid") or 0) == int(item.get("pid") or 0) for p in processes
            )
        ]
        preferred = with_children[0] if with_children else matches[0]
    exe_name = str(preferred.get("exe") or "").lower()
    arch = (
        "x64"
        if exe_name == "x64dbg.exe"
        else "x86"
        if exe_name == "x32dbg.exe"
        else None
    )
    return {
        "pid": int(preferred.get("pid") or 0),
        "exe": exe_name,
        "arch": arch,
        "count": len(matches),
    }


def _remember_runtime(**fields: Any) -> None:
    with _RUNTIME_LOCK:
        _RUNTIME_STATE.update(fields)


def _get_runtime_value(key: str, default: Any = None) -> Any:
    with _RUNTIME_LOCK:
        return _RUNTIME_STATE.get(key, default)


def _normalize_path_identity(path: str) -> str:
    repaired = _repair_text_mojibake(str(path or "").strip())
    if not repaired:
        return ""
    try:
        # QueryFullProcessImageNameW commonly returns the Win32 extended
        # prefix (\\\\?\\C:\\...), while CreateProcess/PE identity records
        # use the ordinary DOS spelling. They are the same file identity and
        # must not create a false session mismatch.
        if repaired.startswith("\\\\?\\UNC\\"):
            repaired = "\\\\" + repaired[8:]
        elif repaired.startswith("\\\\?\\"):
            repaired = repaired[4:]
        elif repaired.startswith("\\??\\"):
            repaired = repaired[4:]
        return os.path.normcase(os.path.normpath(repaired))
    except Exception:
        return repaired.casefold()


def _normalize_bound_session_record(record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    payload = dict(record) if isinstance(record, dict) else {}
    pid = int(payload.get("pid") or 0)
    image_path = _repair_text_mojibake(str(payload.get("imagePath") or "").strip())
    image_name = (
        _process_basename(image_path)
        or _process_basename(payload.get("imageName") or payload.get("exe") or "")
    )
    module_base = _normalize_hex(payload.get("moduleBase") or payload.get("base"))
    return {
        "pid": pid,
        "imagePath": image_path,
        "imageName": image_name,
        "imageSha256": str(payload.get("imageSha256") or "").upper(),
        "moduleBase": module_base,
        "bridgeInstanceId": str(payload.get("bridgeInstanceId") or ""),
        "sessionId": str(payload.get("sessionId") or ""),
        "sessionGeneration": int(
            _parse_int(payload.get("sessionGeneration", payload.get("generation")), 0)
            or 0
        ),
        "eventSeq": int(_parse_int(payload.get("eventSeq"), 0) or 0),
        "debuggerPid": int(_parse_int(payload.get("debuggerPid"), 0) or 0),
        "debuggerArch": str(payload.get("debuggerArch") or "").lower(),
        "strict": bool(payload.get("strict", True)),
        "source": str(payload.get("source") or ""),
        "createdAt": str(payload.get("createdAt") or ""),
    }


def _get_bound_session() -> Dict[str, Any]:
    binding = _get_runtime_value("boundSession")
    return _normalize_bound_session_record(binding if isinstance(binding, dict) else {})


def _current_main_module_identity() -> Dict[str, Any]:
    try:
        payload = safe_get("GetModuleList", log=False)
    except Exception:
        payload = {}
    modules = payload.get("modules", []) if isinstance(payload, dict) else payload
    if not isinstance(modules, list):
        return {}
    image_name = str(_get_current_debuggee_image_name() or "").lower()
    chosen: Optional[Dict[str, Any]] = None
    for item in modules:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").lower()
        if image_name and name == image_name:
            chosen = item
            break
        if chosen is None:
            chosen = item
    if not isinstance(chosen, dict):
        return {}
    return {
        "name": _process_basename(chosen.get("name") or ""),
        "path": _repair_text_mojibake(str(chosen.get("path") or "").strip()),
        "base": _normalize_hex(chosen.get("base")),
        "entry": _normalize_hex(chosen.get("entry")),
    }


def _describe_bound_session_match(
    binding: Optional[Dict[str, Any]] = None, state: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    normalized = _normalize_bound_session_record(binding or _get_bound_session())
    if not normalized or not any(
        normalized.get(key)
        for key in (
            "bridgeInstanceId",
            "sessionId",
            "sessionGeneration",
            "pid",
            "imagePath",
            "imageName",
            "moduleBase",
        )
    ):
        return {"active": False, "matches": False, "reason": "No bound session"}
    current_state = state if isinstance(state, dict) else {}
    current_pid = int(current_state.get("debuggeePid") or 0)
    current_image_path = _repair_text_mojibake(
        str(
            current_state.get("debuggeePath")
            or (
                (current_state.get("session") or {}).get("imagePath")
                if isinstance(current_state.get("session"), dict)
                else ""
            )
            or ""
        ).strip()
    )
    if not current_image_path and current_pid:
        current_image_path = _get_process_image_path(current_pid)
    current_image = _process_basename(
        current_image_path or current_state.get("debuggeeImage") or ""
    )
    current_module = _current_main_module_identity()
    current_module_base = _normalize_hex(current_module.get("base"))
    current_identity = _get_cached_bridge_identity()
    session_record = (
        current_state.get("session", {})
        if isinstance(current_state.get("session"), dict)
        else {}
    )
    current_bridge_id = str(current_identity.get("bridgeInstanceId") or "")
    current_session_id = str(
        session_record.get("sessionId") or current_identity.get("sessionId") or ""
    )
    current_generation = int(
        _parse_int(
            session_record.get(
                "generation",
                session_record.get(
                    "sessionGeneration", current_identity.get("sessionGeneration")
                ),
            ),
            0,
        )
        or 0
    )

    expected_pid = int(normalized.get("pid") or 0)
    expected_path = str(normalized.get("imagePath") or "")
    expected_image = _process_basename(expected_path or normalized.get("imageName") or "")
    expected_base = _normalize_hex(normalized.get("moduleBase"))
    expected_bridge_id = str(normalized.get("bridgeInstanceId") or "")
    expected_session_id = str(normalized.get("sessionId") or "")
    expected_generation = int(normalized.get("sessionGeneration") or 0)
    expected_sha256 = str(normalized.get("imageSha256") or "").strip().upper()
    strict = bool(normalized.get("strict"))

    matches_bridge = not expected_bridge_id or (
        bool(current_bridge_id) and current_bridge_id == expected_bridge_id
    )
    matches_session_id = not expected_session_id or (
        bool(current_session_id) and current_session_id == expected_session_id
    )
    matches_generation = not expected_generation or (
        bool(current_generation) and current_generation == expected_generation
    )
    matches_pid = expected_pid == 0 or (
        bool(current_pid) and current_pid == expected_pid
    )
    matches_image = not expected_image or (
        bool(current_image) and current_image == expected_image
    )
    matches_path = (
        not expected_path
        or (
            bool(current_image_path)
            and _normalize_path_identity(current_image_path)
            == _normalize_path_identity(expected_path)
        )
    )
    matches_base = (
        not expected_base
        or (bool(current_module_base) and current_module_base == expected_base)
    )
    reported_sha256 = str(
        current_state.get("imageSha256")
        or session_record.get("imageSha256")
        or current_identity.get("imageSha256")
        or ""
    ).strip().upper()
    current_sha256 = _image_sha256_cached(current_image_path) if current_image_path else ""
    if not current_sha256 and TARGET_SHA256_RE.fullmatch(reported_sha256):
        current_sha256 = reported_sha256
    # Legacy bindings created before the v4 contract may not contain a hash;
    # new bindings always do.  When a hash is present, absence or mismatch is
    # never treated as a wildcard.
    matches_sha256 = (
        not expected_sha256
        or (bool(current_sha256) and current_sha256.upper() == expected_sha256)
    )
    alive = expected_pid == 0 or _process_exists(expected_pid)
    matches = bool(
        alive
        and matches_bridge
        and matches_session_id
        and matches_generation
        and matches_pid
        and matches_image
        and matches_path
        and matches_base
        and matches_sha256
    )
    reasons: List[str] = []
    if not alive:
        reasons.append("bound_pid_exited")
    if expected_bridge_id and current_bridge_id != expected_bridge_id:
        reasons.append("bridge_id_missing" if not current_bridge_id else "bridge_id_mismatch")
    if expected_session_id and current_session_id != expected_session_id:
        reasons.append("session_id_missing" if not current_session_id else "session_id_mismatch")
    if expected_generation and current_generation != expected_generation:
        reasons.append(
            "session_generation_missing"
            if not current_generation
            else "session_generation_mismatch"
        )
    if expected_pid and current_pid != expected_pid:
        reasons.append("pid_mismatch")
    if expected_image and current_image != expected_image:
        reasons.append("image_mismatch")
    if expected_path and not matches_path:
        reasons.append("path_mismatch")
    if expected_base and not matches_base:
        reasons.append("module_base_mismatch")
    if expected_sha256 and current_sha256.upper() != expected_sha256:
        reasons.append(
            "image_sha256_missing" if not current_sha256 else "image_sha256_mismatch"
        )
    return {
        "active": True,
        "matches": matches,
        "strict": strict,
        "alive": alive,
        "reason": ", ".join(reasons) if reasons else ("match" if matches else "pending"),
        "binding": normalized,
        "currentPid": current_pid,
        "currentImagePath": current_image_path,
        "currentImage": current_image,
        "currentModuleBase": current_module_base,
        "currentImageSha256": current_sha256,
        "expectedImageSha256": expected_sha256,
        "currentBridgeInstanceId": current_bridge_id,
        "currentSessionId": current_session_id,
        "currentSessionGeneration": current_generation,
    }


_IMAGE_HASH_CACHE: Dict[tuple[str, int, int], str] = {}
_IMAGE_HASH_LOCK = Lock()


def _image_sha256_cached(path: str) -> str:
    normalized = _repair_text_mojibake(str(path or "").strip())
    if not normalized or not os.path.isfile(normalized):
        return ""
    try:
        stat = os.stat(normalized)
        key = (
            _normalize_path_identity(normalized),
            int(stat.st_size),
            int(stat.st_mtime_ns),
        )
        with _IMAGE_HASH_LOCK:
            cached = _IMAGE_HASH_CACHE.get(key)
        if cached:
            return cached
        digest = hashlib.sha256()
        with open(normalized, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        value = digest.hexdigest().upper()
        with _IMAGE_HASH_LOCK:
            if len(_IMAGE_HASH_CACHE) >= 64:
                _IMAGE_HASH_CACHE.clear()
            _IMAGE_HASH_CACHE[key] = value
        return value
    except Exception:
        return ""


def _bind_debuggee_session(
    pid: int = 0,
    image_path: str = "",
    module_base: str = "",
    strict: bool = True,
    source: str = "",
) -> Dict[str, Any]:
    bound_pid = int(pid or 0)
    if not bound_pid:
        try:
            bound_pid = _infer_debuggee_pid(0)
        except Exception:
            bound_pid = int(_get_runtime_value("lastDebuggeePid", 0) or 0)
    resolved_image_path = _repair_text_mojibake(str(image_path or "").strip())
    if not resolved_image_path and bound_pid:
        resolved_image_path = _get_process_image_path(bound_pid)
    current_module = _current_main_module_identity()
    resolved_module_base = _normalize_hex(module_base)
    if not resolved_module_base:
        resolved_module_base = _normalize_hex(
            current_module.get("base") or _get_current_debuggee_module_base()
        )
    identity = _get_cached_bridge_identity()
    if int(identity.get("debuggeePid") or 0) != bound_pid or not identity.get(
        "sessionId"
    ):
        hello = _bridge_request(
            "GET",
            "Bridge/Hello",
            log=False,
            timeout_sec=0.75,
            guard="none",
            idempotent=True,
        )
        if hello.ok:
            identity = _cache_bridge_identity(hello.data)
    record = _normalize_bound_session_record(
        {
            "pid": bound_pid,
            "imagePath": resolved_image_path,
            "imageSha256": _image_sha256_cached(resolved_image_path),
            "moduleBase": resolved_module_base,
            "bridgeInstanceId": identity.get("bridgeInstanceId"),
            "sessionId": identity.get("sessionId"),
            "sessionGeneration": identity.get("sessionGeneration"),
            "eventSeq": identity.get("eventSeq"),
            "debuggerPid": identity.get("debuggerPid"),
            "debuggerArch": identity.get("debuggerArch"),
            "strict": strict,
            "source": source,
            "createdAt": _now_iso(),
        }
    )
    _remember_runtime(boundSession=record)
    return record


def _clear_bound_session() -> None:
    _remember_runtime(boundSession=None)


def _get_current_debuggee_image_name() -> Optional[str]:
    try:
        modules = safe_get("GetModuleList", log=False)
    except Exception:
        return None
    if isinstance(modules, dict):
        modules = [modules]
    if not isinstance(modules, list) or not modules:
        return None
    first = modules[0]
    if not isinstance(first, dict):
        return None
    path = first.get("path") or first.get("name")
    if not path:
        return None
    return os.path.basename(path).lower()


def _infer_debuggee_pid(pid: int = 0) -> int:
    if pid:
        return pid
    processes = _list_processes()
    dbg_pids = {
        p["pid"] for p in processes if p["exe"].lower() in ("x64dbg.exe", "x32dbg.exe")
    }
    image_name = _get_current_debuggee_image_name()
    candidates = [
        p
        for p in processes
        if p["ppid"] in dbg_pids and p["exe"].lower() not in ("conhost.exe",)
    ]
    attached_pid = _infer_attached_pid_from_debugger_windows(
        sorted(dbg_pids), image_name
    )
    binding = _get_bound_session()
    bound_pid = int(binding.get("pid") or 0)
    if bound_pid and _process_exists(bound_pid):
        if attached_pid and attached_pid != bound_pid:
            bound_match = _describe_bound_session_match(
                binding,
                {
                    "debuggeePid": attached_pid,
                    "debuggeeImage": image_name
                    or _process_basename(_get_process_image_path(attached_pid)),
                    "debuggeePath": _get_process_image_path(attached_pid),
                },
            )
            if not bound_match.get("matches") and bound_match.get("strict"):
                bound_pid = 0
        elif not image_name:
            _remember_runtime(
                lastDebuggeePid=bound_pid,
                lastDebuggeeImage=_process_basename(
                    binding.get("imagePath") or binding.get("imageName") or ""
                ),
                lastDebuggeePath=binding.get("imagePath") or None,
            )
            return bound_pid
        else:
            current_path = _get_process_image_path(attached_pid or bound_pid)
            bound_match = _describe_bound_session_match(
                binding,
                {
                    "debuggeePid": attached_pid or bound_pid,
                    "debuggeeImage": image_name,
                    "debuggeePath": current_path or "",
                },
            )
            if bound_match.get("matches") or not bound_match.get("strict"):
                _remember_runtime(
                    lastDebuggeePid=bound_pid,
                    lastDebuggeeImage=_process_basename(
                        binding.get("imagePath") or binding.get("imageName") or image_name
                    ),
                    lastDebuggeePath=binding.get("imagePath") or None,
                )
                return bound_pid
    if attached_pid and _process_exists(attached_pid):
        _remember_runtime(lastDebuggeePid=attached_pid, lastDebuggeeImage=image_name)
        return attached_pid
    if image_name:
        preferred = [p for p in candidates if p["exe"].lower() == image_name]
        if preferred:
            candidates = preferred
        elif not candidates:
            same_name = [
                p
                for p in processes
                if p["exe"].lower() == image_name
                and p["exe"].lower() not in ("x64dbg.exe", "x32dbg.exe", "conhost.exe")
            ]
            if len(same_name) == 1:
                chosen = int(same_name[0]["pid"])
                _remember_runtime(lastDebuggeePid=chosen, lastDebuggeeImage=image_name)
                return chosen
    last_pid = int(_get_runtime_value("lastDebuggeePid", 0) or 0)
    if last_pid and _process_exists(last_pid):
        candidates = sorted(
            candidates, key=lambda p: (int(p["pid"]) != last_pid, -int(p["pid"]))
        )
    if not candidates:
        if last_pid and _process_exists(last_pid):
            return last_pid
        raise RuntimeError(
            f"Could not infer the debuggee PID (debuggers={sorted(dbg_pids)}, image={image_name}, lastPid={last_pid})"
        )
    candidates.sort(key=lambda p: p["pid"], reverse=True)
    chosen = int(candidates[0]["pid"])
    _remember_runtime(lastDebuggeePid=chosen, lastDebuggeeImage=image_name)
    return chosen


def _infer_conhost_pid(debuggee_pid: int) -> Optional[int]:
    processes = _list_processes()
    candidates = [
        p
        for p in processes
        if p["ppid"] == debuggee_pid and p["exe"].lower() == "conhost.exe"
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p["pid"], reverse=True)
    return int(candidates[0]["pid"])


def _wait_for_conhost_pid(debuggee_pid: int, timeout_ms: int = 2500) -> Optional[int]:
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    while time.time() <= deadline:
        conhost_pid = _infer_conhost_pid(debuggee_pid)
        if conhost_pid:
            return conhost_pid
        time.sleep(0.05)
    return _infer_conhost_pid(debuggee_pid)


def _get_window_text(hwnd: int) -> str:
    length = user32.GetWindowTextLengthW(hwnd)
    if length <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buf, len(buf))
    return _repair_text_mojibake(buf.value)


def _get_window_text_ansi(hwnd: int, max_chars: int = 1024) -> str:
    buf = ctypes.create_string_buffer(max(2, max_chars))
    copied = user32.GetWindowTextA(hwnd, buf, len(buf))
    if copied <= 0:
        return ""
    return _decode_best_effort_bytes(buf.raw[:copied])


def _infer_attached_pid_from_debugger_windows(
    debugger_pids: List[int], image_name: Optional[str]
) -> Optional[int]:
    if not debugger_pids:
        return None
    title_pattern = re.compile(r"\bPID:\s*(\d+)\b", flags=re.IGNORECASE)
    for dbg_pid in debugger_pids:
        result: List[int] = []

        @WNDENUMPROC
        def enum_proc(hwnd: int, _lparam: int) -> bool:
            window_pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
            if int(window_pid.value) == int(dbg_pid):
                result.append(int(hwnd))
            return True

        user32.EnumWindows(enum_proc, 0)
        for hwnd in result:
            title = _get_window_text(hwnd)
            if not title:
                continue
            if image_name and image_name.casefold() not in title.casefold():
                continue
            match = title_pattern.search(title)
            if match:
                return int(match.group(1))
    return None


def _find_top_window_for_pid(pid: int) -> Optional[int]:
    result: List[int] = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def enum_proc(hwnd: int, _lparam: int) -> bool:
        window_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
        if int(window_pid.value) == int(pid) and user32.IsWindowVisible(hwnd):
            result.append(int(hwnd))
            return False
        return True

    user32.EnumWindows(enum_proc, 0)
    return result[0] if result else None


def _wait_for_top_window(pid: int, timeout_ms: int = 2500) -> Optional[int]:
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    while time.time() <= deadline:
        hwnd = _find_top_window_for_pid(pid)
        if hwnd:
            return hwnd
        time.sleep(0.05)
    return _find_top_window_for_pid(pid)


def _focus_window(hwnd: int) -> bool:
    if not hwnd:
        return False
    root = int(user32.GetAncestor(hwnd, GA_ROOT)) or int(hwnd)
    window_pid = wintypes.DWORD()
    target_thread = int(
        user32.GetWindowThreadProcessId(root, ctypes.byref(window_pid)) or 0
    )
    current_thread = int(kernel32.GetCurrentThreadId() or 0)
    attached = False
    if target_thread and current_thread and target_thread != current_thread:
        attached = bool(user32.AttachThreadInput(current_thread, target_thread, True))
    try:
        user32.ShowWindow(root, SW_RESTORE)
        user32.BringWindowToTop(root)
        user32.SetActiveWindow(root)
        user32.SetFocus(root)
        result = bool(user32.SetForegroundWindow(root))
        time.sleep(0.05)
        current = int(user32.GetForegroundWindow())
        if current in (root, int(hwnd)):
            return True
        _send_key_combo("ALT", delay_ms=0)
        result = bool(user32.SetForegroundWindow(root)) or result
        time.sleep(0.08)
        current = int(user32.GetForegroundWindow())
        return result or current in (root, int(hwnd))
    finally:
        if attached:
            user32.AttachThreadInput(current_thread, target_thread, False)


def _open_process_for_sync(pid: int) -> int:
    handle = kernel32.OpenProcess(
        SYNCHRONIZE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        int(pid),
    )
    if not handle:
        raise OSError(f"OpenProcess failed for pid {pid}: {ctypes.get_last_error()}")
    return int(handle)


def _wait_for_process_input_idle(pid: int, timeout_ms: int = 1500) -> Dict[str, Any]:
    _require_windows()
    target_pid = int(pid or 0)
    if not target_pid:
        return {
            "ok": False,
            "ready": False,
            "timedOut": False,
            "supported": False,
            "pid": target_pid,
            "reason": "no_pid",
        }
    handle = _open_process_for_sync(target_pid)
    try:
        result = int(user32.WaitForInputIdle(handle, max(0, int(timeout_ms))))
        if result == WAIT_OBJECT_0:
            return {
                "ok": True,
                "ready": True,
                "timedOut": False,
                "supported": True,
                "pid": target_pid,
                "waitCode": result,
            }
        if result == WAIT_TIMEOUT:
            return {
                "ok": False,
                "ready": False,
                "timedOut": True,
                "supported": True,
                "pid": target_pid,
                "waitCode": result,
                "reason": "timeout",
            }
        error = ctypes.get_last_error()
        return {
            "ok": True,
            "ready": False,
            "timedOut": False,
            "supported": False,
            "pid": target_pid,
            "waitCode": result,
            "lastError": error,
            "reason": "not_gui_or_unavailable",
        }
    finally:
        kernel32.CloseHandle(handle)


def _window_ready_signature(hwnd: int, client_only: bool = False) -> Dict[str, Any]:
    rect = _window_bounds(hwnd, client_only=client_only)
    return {
        "title": _repair_text_mojibake(_get_window_text(hwnd)),
        "className": _repair_text_mojibake(_get_class_name(hwnd)),
        "visible": bool(user32.IsWindowVisible(hwnd)),
        "enabled": bool(user32.IsWindowEnabled(hwnd)),
        "rect": rect,
    }


def _wait_for_window_stable(
    hwnd: int,
    timeout_ms: int = 1500,
    poll_ms: int = 80,
    stable_polls: int = 2,
    client_only: bool = False,
    min_width: int = 24,
    min_height: int = 24,
) -> Dict[str, Any]:
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    previous: Optional[Dict[str, Any]] = None
    stable_hits = 0
    last_signature: Dict[str, Any] = {}
    while time.time() <= deadline:
        last_signature = _window_ready_signature(hwnd, client_only=client_only)
        rect = last_signature.get("rect", {})
        if not last_signature.get("visible"):
            stable_hits = 0
        elif int(rect.get("width") or 0) < int(min_width) or int(
            rect.get("height") or 0
        ) < int(min_height):
            stable_hits = 0
        else:
            current = {
                "title": str(last_signature.get("title") or ""),
                "className": str(last_signature.get("className") or ""),
                "rect": (
                    int(rect.get("left") or 0),
                    int(rect.get("top") or 0),
                    int(rect.get("right") or 0),
                    int(rect.get("bottom") or 0),
                ),
            }
            if current == previous:
                stable_hits += 1
            else:
                previous = current
                stable_hits = 0
            if stable_hits >= max(1, int(stable_polls)):
                return {
                    "ok": True,
                    "ready": True,
                    "timedOut": False,
                    "hwnd": f"0x{int(hwnd):X}",
                    "window": last_signature,
                    "stablePolls": stable_hits,
                }
        time.sleep(max(20, int(poll_ms)) / 1000.0)
    return {
        "ok": False,
        "ready": False,
        "timedOut": True,
        "hwnd": f"0x{int(hwnd):X}",
        "window": last_signature,
        "stablePolls": stable_hits,
        "reason": "Timed out waiting for window stability.",
    }


def _rect_to_dict(rect: RECT) -> Dict[str, int]:
    return {
        "left": int(rect.left),
        "top": int(rect.top),
        "right": int(rect.right),
        "bottom": int(rect.bottom),
        "width": int(rect.right) - int(rect.left),
        "height": int(rect.bottom) - int(rect.top),
    }


def _get_class_name(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    if user32.GetClassNameW(hwnd, buf, len(buf)) <= 0:
        return ""
    return buf.value


def _send_message_timeout(
    hwnd: int, message: int, wparam: int = 0, lparam: int = 0, timeout_ms: int = 200
) -> Optional[int]:
    result = ULONG_PTR()
    ok = user32.SendMessageTimeoutW(
        hwnd,
        message,
        wparam,
        lparam,
        SMTO_ABORTIFHUNG | SMTO_BLOCK,
        max(50, timeout_ms),
        ctypes.byref(result),
    )
    if not ok:
        return None
    return int(result.value)


def _send_message_timeout_ansi(
    hwnd: int, message: int, wparam: int = 0, lparam: int = 0, timeout_ms: int = 200
) -> Optional[int]:
    result = ULONG_PTR()
    ok = user32.SendMessageTimeoutA(
        hwnd,
        message,
        wparam,
        lparam,
        SMTO_ABORTIFHUNG | SMTO_BLOCK,
        max(50, timeout_ms),
        ctypes.byref(result),
    )
    if not ok:
        return None
    return int(result.value)


def _decode_best_effort_bytes(data: bytes) -> str:
    if not data:
        return ""
    candidates: List[str] = []
    for encoding in ("utf-8", "mbcs", "cp1251", "cp866", "cp1252", "latin-1"):
        try:
            decoded = data.decode(encoding)
        except Exception:
            continue
        if decoded:
            candidates.append(decoded)
    if not candidates:
        return ""
    return _repair_text_mojibake(_pick_best_text(candidates))


def _repair_text_variants(text: str) -> List[str]:
    if not text:
        return []
    variants = [text]
    for source in ("latin-1", "cp1252"):
        for target in ("utf-8", "cp1251", "cp866"):
            try:
                repaired = text.encode(source).decode(target)
            except Exception:
                continue
            if repaired:
                variants.append(repaired)
    return _dedupe_texts(variants)


def _score_text_candidate(text: str) -> int:
    if not text:
        return -1000
    score = 0
    for ch in text:
        code = ord(ch)
        if ch.isdigit():
            score += 3
        elif "\u0400" <= ch <= "\u04ff":
            score += 4
        elif ch.isalpha():
            score += 2
        elif ch.isspace():
            score += 1
        elif ch in ".,:;!?-_+/\\()[]{}<>@#%&*=+\"'":
            score += 1
        elif 0x00C0 <= code <= 0x017F:
            score -= 2
        elif code < 32 and ch not in "\r\n\t":
            score -= 6
    if "\ufffd" in text:
        score -= 10
    if re.search(r"(?:\u00D0|\u00D1|\u00C3|\u00C2|\u00CE|\u00CA|\u00CF){2,}", text):
        score -= 4
    return score


def _dedupe_texts(values: List[str]) -> List[str]:
    result: List[str] = []
    seen = set()
    for value in values:
        if value is None:
            continue
        normalized = value.strip("\x00")
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def _pick_best_text(values: List[str]) -> str:
    candidates = _dedupe_texts(
        [item for value in values for item in _repair_text_variants(value)]
    )
    if not candidates:
        return ""
    ranked = sorted(
        candidates,
        key=lambda item: (_score_text_candidate(item), len(item)),
        reverse=True,
    )
    return ranked[0]


def _normalize_gui_text(text: str) -> str:
    value = text or ""
    value = value.replace("\x00", "").replace("\r", " ").replace("\n", " ")
    value = value.replace("&&", "\u0000").replace("&", "").replace("\u0000", "&")
    return " ".join(value.split()).casefold()


def _get_window_text_message(hwnd: int, max_chars: int = 1024) -> str:
    length = _send_message_timeout(hwnd, WM_GETTEXTLENGTH, 0, 0, timeout_ms=150)
    if length is None:
        length = 0
    buf_len = min(max(int(length) + 2, 2), max_chars)
    buf = ctypes.create_unicode_buffer(buf_len)
    copied = _send_message_timeout(
        hwnd, WM_GETTEXT, buf_len, ctypes.addressof(buf), timeout_ms=200
    )
    if copied is None:
        return ""
    return _repair_text_mojibake(buf.value)


def _get_window_text_message_ansi(hwnd: int, max_chars: int = 1024) -> str:
    buf_len = max(2, max_chars)
    buf = ctypes.create_string_buffer(buf_len)
    copied = _send_message_timeout_ansi(
        hwnd, WM_GETTEXT, buf_len, ctypes.addressof(buf), timeout_ms=200
    )
    if copied is None:
        return ""
    return _decode_best_effort_bytes(buf.raw[: min(int(copied), buf_len - 1)])


def _get_control_text(hwnd: int, max_chars: int = 1024) -> str:
    candidates = [
        _get_window_text(hwnd),
        _get_window_text_message(hwnd, max_chars=max_chars),
        _get_window_text_ansi(hwnd, max_chars=max_chars),
        _get_window_text_message_ansi(hwnd, max_chars=max_chars),
    ]
    return _repair_text_mojibake(_pick_best_text(candidates))


def _get_window_style(hwnd: int) -> int:
    try:
        return int(_get_window_long(hwnd, GWL_STYLE)) & 0xFFFFFFFF
    except Exception:
        return 0


def _get_window_ex_style(hwnd: int) -> int:
    try:
        return int(_get_window_long(hwnd, GWL_EXSTYLE)) & 0xFFFFFFFF
    except Exception:
        return 0


def _button_kind_from_style(style: int) -> str:
    kind = style & 0xF
    mapping = {
        BS_PUSHBUTTON: "push",
        BS_DEFPUSHBUTTON: "default_push",
        BS_CHECKBOX: "checkbox",
        BS_AUTOCHECKBOX: "auto_checkbox",
        BS_RADIOBUTTON: "radio",
        BS_3STATE: "3state",
        BS_AUTO3STATE: "auto_3state",
        BS_GROUPBOX: "groupbox",
        BS_AUTORADIOBUTTON: "auto_radio",
    }
    return mapping.get(kind, "button")


def _button_priority(control: Dict[str, Any]) -> int:
    text = str(control.get("title", ""))
    button_kind = str(control.get("buttonKind", ""))
    score = 0
    if button_kind == "default_push":
        score += 5
    elif button_kind == "push":
        score += 2
    common_tokens = (
        "ok",
        "check",
        "register",
        "submit",
        "continue",
        "next",
        "login",
        "run",
        "start",
        "yes",
    )
    if any(_text_matches(text, token) for token in common_tokens):
        score += 4
    if text:
        score += 1
    return score


def _classify_window_role(
    class_name: str, style: int, parent_hwnd: int
) -> Dict[str, Any]:
    name = class_name.lower()
    role = "window" if not parent_hwnd else "control"
    meta: Dict[str, Any] = {}
    if (
        name in ("edit", "richedit20w", "richedit20a")
        or "edit" in name
        or "textbox" in name
        or name.startswith("tedit")
    ):
        role = "edit"
        meta["isPassword"] = bool(style & ES_PASSWORD)
    elif name == "button" or "button" in name or name.startswith("tbutton"):
        role = "button"
        meta["buttonKind"] = _button_kind_from_style(style)
    elif name == "static" or "label" in name:
        role = "static"
    elif name == "combobox" or "combo" in name:
        role = "combo"
    elif name == "listbox" or "listbox" in name:
        role = "listbox"
    elif name in ("syslistview32",):
        role = "listview"
    elif name in ("sysheader32",):
        role = "header"
    elif name in ("#32770",):
        role = "dialog"
    elif name.startswith("afx:"):
        role = "mfc_window" if not parent_hwnd else "mfc_control"
    return {"role": role, **meta}


def _enumerate_child_windows(parent_hwnd: int) -> List[int]:
    items: List[int] = []

    @WNDENUMPROC
    def enum_proc(hwnd: int, _lparam: int) -> bool:
        items.append(int(hwnd))
        return True

    user32.EnumChildWindows(parent_hwnd, enum_proc, 0)
    return items


def _collect_window_node(
    hwnd: int,
    pid: int,
    parent_hwnd: int = 0,
    include_children: bool = True,
    visible_only: bool = False,
    max_depth: int = 4,
    depth: int = 0,
) -> Dict[str, Any]:
    class_name = _get_class_name(hwnd)
    title = _get_control_text(hwnd)
    style = _get_window_style(hwnd)
    ex_style = _get_window_ex_style(hwnd)
    visible = bool(user32.IsWindowVisible(hwnd))
    enabled = bool(user32.IsWindowEnabled(hwnd))
    rect = RECT()
    rect_data = None
    if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        rect_data = _rect_to_dict(rect)
    role_meta = _classify_window_role(class_name, style, parent_hwnd)
    node: Dict[str, Any] = {
        "hwnd": f"0x{int(hwnd):X}",
        "parentHwnd": f"0x{int(parent_hwnd):X}" if parent_hwnd else None,
        "pid": int(pid),
        "depth": int(depth),
        "title": title,
        "className": class_name,
        "visible": visible,
        "enabled": enabled,
        "controlId": int(user32.GetDlgCtrlID(hwnd)),
        "style": f"0x{style:08X}",
        "exStyle": f"0x{ex_style:08X}",
        "rect": rect_data,
        "children": [],
    }
    node.update(role_meta)
    if include_children and depth < max_depth:
        for child_hwnd in _enumerate_child_windows(hwnd):
            child_visible = bool(user32.IsWindowVisible(child_hwnd))
            if visible_only and not child_visible:
                continue
            child_node = _collect_window_node(
                child_hwnd,
                pid=pid,
                parent_hwnd=hwnd,
                include_children=True,
                visible_only=visible_only,
                max_depth=max_depth,
                depth=depth + 1,
            )
            node["children"].append(child_node)
    return node


def _enumerate_top_windows_for_pid(pid: int, visible_only: bool = False) -> List[int]:
    items: List[int] = []

    @WNDENUMPROC
    def enum_proc(hwnd: int, _lparam: int) -> bool:
        window_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
        if int(window_pid.value) != int(pid):
            return True
        if int(user32.GetAncestor(hwnd, GA_ROOT)) != int(hwnd):
            return True
        if visible_only and not user32.IsWindowVisible(hwnd):
            return True
        items.append(int(hwnd))
        return True

    user32.EnumWindows(enum_proc, 0)
    return items


def _score_top_window_candidate(hwnd: int) -> int:
    class_name = _repair_text_mojibake(_get_class_name(hwnd))
    title = _repair_text_mojibake(_get_window_text(hwnd))
    rect = _window_bounds(hwnd, client_only=False)
    area = int((rect or {}).get("width", 0) * (rect or {}).get("height", 0))
    score = area
    if bool(user32.IsWindowVisible(hwnd)):
        score += 50000
    if title:
        score += min(len(title) * 20, 1200)
    class_lower = class_name.casefold()
    title_lower = title.casefold()
    if class_lower in ("ime", "msctfime ui", "gdi+ hook window class"):
        score -= 250000
    if "hook window" in class_lower or "default ime" in title_lower:
        score -= 200000
    if _is_noise_window_node({"className": class_name, "title": title, "rect": rect}):
        score -= 250000
    if area <= 4:
        score -= 200000
    elif area <= 64:
        score -= 120000
    return score


def _select_preferred_top_window(pid: int, visible_only: bool = False) -> int:
    windows = _enumerate_top_windows_for_pid(pid, visible_only=visible_only)
    if not windows:
        return 0
    windows.sort(key=_score_top_window_candidate, reverse=True)
    return int(windows[0])


def _flatten_window_tree(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    flat: List[Dict[str, Any]] = []

    def visit(node: Dict[str, Any]) -> None:
        shallow = {k: v for k, v in node.items() if k != "children"}
        flat.append(shallow)
        for child in node.get("children", []):
            visit(child)

    for node in nodes:
        visit(node)
    return flat


def _find_windows_by_title_substring(
    title_contains: str, visible_only: bool = True, max_depth: int = 3
) -> List[Dict[str, Any]]:
    needle = _repair_text_mojibake(str(title_contains or "")).strip().casefold()
    if not needle:
        return []
    matches: List[Dict[str, Any]] = []

    @WNDENUMPROC
    def enum_proc(hwnd: int, _lparam: int) -> bool:
        if visible_only and not user32.IsWindowVisible(hwnd):
            return True
        title = _repair_text_mojibake(_get_window_text(hwnd)).strip()
        if needle not in title.casefold():
            return True
        window_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
        matches.append(
            _collect_window_node(
                hwnd,
                pid=int(window_pid.value),
                include_children=True,
                visible_only=False,
                max_depth=max_depth,
                depth=0,
            )
        )
        return True

    user32.EnumWindows(enum_proc, 0)
    return matches


def _inspect_scyllahide_dialog() -> Dict[str, Any]:
    windows = _find_windows_by_title_substring(
        "ScyllaHide", visible_only=True, max_depth=3
    )
    for window in windows:
        # A browser tab or document can legitimately mention "ScyllaHide" in
        # its title. Never close an unrelated application: only a window owned
        # by the debugger can be the injector/plugin dialog handled here.
        window_pid = int(window.get("pid") or 0)
        owner_exe = _process_basename(_get_process_image_path(window_pid))
        if owner_exe not in {"x64dbg.exe", "x32dbg.exe"}:
            continue
        controls = _flatten_window_tree([window])[1:]
        texts = [str(window.get("title") or "")]
        texts.extend(
            str(control.get("title") or "")
            for control in controls
            if str(control.get("title") or "").strip()
        )
        message = " ".join(texts).strip()
        button = next(
            (
                control
                for control in controls
                if str(control.get("role") or "").lower() == "button"
                and str(control.get("title") or "").strip().casefold() in {"ok", "&ok"}
            ),
            None,
        )
        return {
            "found": True,
            "window": window,
            "message": message,
            "buttonHwnd": str((button or {}).get("hwnd") or ""),
        }
    return {"found": False}


def _dismiss_scyllahide_dialog(
    expected_substrings: Optional[List[str]] = None,
    timeout_ms: int = 1500,
    poll_ms: int = 100,
) -> Dict[str, Any]:
    normalized_expected = [
        str(item or "").strip().casefold()
        for item in (expected_substrings or [])
        if str(item or "").strip()
    ]
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    last_info: Dict[str, Any] = {"found": False}
    actions: List[Dict[str, Any]] = []
    while True:
        dialog_info = _inspect_scyllahide_dialog()
        last_info = dialog_info if isinstance(dialog_info, dict) else {"found": False}
        if not last_info.get("found"):
            return {
                "found": False,
                "dismissed": bool(actions),
                "actions": actions,
            }
        dialog_message = str(last_info.get("message") or "")
        lowered = dialog_message.casefold()
        if normalized_expected and not any(
            token in lowered for token in normalized_expected
        ):
            return {
                "found": True,
                "matched": False,
                "dismissed": False,
                "message": dialog_message,
                "actions": actions,
                "dialog": last_info,
            }
        button_hwnd = _parse_hwnd_value(last_info.get("buttonHwnd"))
        window_hwnd = _parse_hwnd_value(
            (
                (last_info.get("window") or {})
                if isinstance(last_info.get("window"), dict)
                else {}
            ).get("hwnd")
        )
        if button_hwnd:
            click_result = _click_control(button_hwnd)
            actions.append(
                {
                    "mode": "button_click",
                    "hwnd": f"0x{int(button_hwnd):X}",
                    "ok": bool(click_result.get("ok")),
                }
            )
        if window_hwnd:
            close_sent = bool(user32.PostMessageW(window_hwnd, 0x0010, 0, 0))
            actions.append(
                {
                    "mode": "wm_close",
                    "hwnd": f"0x{int(window_hwnd):X}",
                    "ok": close_sent,
                }
            )
        time.sleep(max(0.05, poll_ms / 1000.0))
        refreshed = _inspect_scyllahide_dialog()
        if not refreshed.get("found"):
            return {
                "found": True,
                "matched": True,
                "dismissed": True,
                "message": dialog_message,
                "actions": actions,
                "dialog": last_info,
            }
        if time.time() >= deadline:
            return {
                "found": True,
                "matched": True,
                "dismissed": False,
                "message": dialog_message,
                "actions": actions,
                "dialog": refreshed,
            }


def _control_rect(control: Dict[str, Any]) -> Dict[str, int]:
    rect = control.get("rect", {}) if isinstance(control, dict) else {}
    return rect if isinstance(rect, dict) else {}


def _sorted_controls_by_layout(controls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        controls,
        key=lambda item: (
            int((_control_rect(item).get("top", 0) // 8) if _control_rect(item) else 0),
            _control_rect(item).get("left", 0),
            item.get("depth", 0),
            item.get("controlId", 0),
        ),
    )


def _infer_field_hints(controls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    edits = [
        item
        for item in controls
        if isinstance(item, dict)
        and str(item.get("role", "")).lower() == "edit"
        and bool(item.get("visible"))
        and bool(item.get("enabled"))
    ]
    labels = [
        item
        for item in controls
        if isinstance(item, dict)
        and str(item.get("role", "")).lower() == "static"
        and bool(item.get("visible"))
        and str(item.get("title", "")).strip()
    ]
    hints: List[Dict[str, Any]] = []
    for edit in _sorted_controls_by_layout(edits):
        edit_rect = _control_rect(edit)
        best_label = None
        best_score: Optional[int] = None
        for label in labels:
            label_rect = _control_rect(label)
            if not edit_rect or not label_rect:
                continue
            score: Optional[int] = None
            if label_rect.get("right", 0) <= edit_rect.get("left", 0) + 36:
                vertical_delta = abs(
                    ((label_rect.get("top", 0) + label_rect.get("bottom", 0)) // 2)
                    - ((edit_rect.get("top", 0) + edit_rect.get("bottom", 0)) // 2)
                )
                horizontal_gap = max(
                    0, edit_rect.get("left", 0) - label_rect.get("right", 0)
                )
                if vertical_delta <= max(28, edit_rect.get("height", 0) + 6):
                    score = horizontal_gap + (vertical_delta * 2)
            if (
                score is None
                and label_rect.get("bottom", 0) <= edit_rect.get("top", 0) + 24
            ):
                above_gap = max(
                    0, edit_rect.get("top", 0) - label_rect.get("bottom", 0)
                )
                horizontal_delta = abs(
                    label_rect.get("left", 0) - edit_rect.get("left", 0)
                )
                if above_gap <= 48:
                    score = (above_gap * 3) + horizontal_delta
            if score is None:
                continue
            if best_score is None or score < best_score:
                best_score = score
                best_label = label
        hints.append(
            {
                "hwnd": edit.get("hwnd"),
                "controlId": edit.get("controlId"),
                "isPassword": bool(edit.get("isPassword")),
                "labelText": best_label.get("title") if best_label else "",
                "labelHwnd": best_label.get("hwnd") if best_label else None,
                "title": edit.get("title"),
                "rect": edit_rect,
            }
        )
    return hints


def _collect_gui_snapshot(
    pid: int,
    include_children: bool = True,
    visible_only: bool = False,
    max_depth: int = 4,
) -> Dict[str, Any]:
    target_pid = _infer_debuggee_pid(pid)
    top_windows = [
        _collect_window_node(
            hwnd,
            pid=target_pid,
            parent_hwnd=0,
            include_children=include_children,
            visible_only=visible_only,
            max_depth=max_depth,
            depth=0,
        )
        for hwnd in _enumerate_top_windows_for_pid(
            target_pid, visible_only=visible_only
        )
    ]
    flat = _flatten_window_tree(top_windows)
    edits = [item for item in flat if item.get("role") == "edit"]
    buttons = [item for item in flat if item.get("role") == "button"]
    statics = [
        item for item in flat if item.get("role") == "static" and item.get("title")
    ]
    dialogs = [
        item for item in flat if item.get("role") in ("dialog", "window", "mfc_window")
    ]
    field_hints = _infer_field_hints(flat)
    visible_top = [item for item in top_windows if item.get("visible")]
    meaningful_top = [item for item in visible_top if _is_meaningful_window_node(item)]
    primary = None
    if meaningful_top:
        primary = sorted(
            meaningful_top,
            key=lambda item: (
                0 if item.get("enabled") else 1,
                0 if item.get("title") else 1,
                -len(item.get("children", [])),
                -_rect_area(item.get("rect") or {}),
            ),
        )[0]
    elif visible_top:
        primary = sorted(
            visible_top,
            key=lambda item: (
                0 if item.get("enabled") else 1,
                0 if item.get("title") else 1,
                -len(item.get("children", [])),
                -_rect_area(item.get("rect") or {}),
            ),
        )[0]
    summary = {
        "topWindowCount": len(top_windows),
        "meaningfulTopWindowCount": len(meaningful_top),
        "noiseWindowCount": max(0, len(visible_top) - len(meaningful_top)),
        "controlCount": len(flat),
        "editCount": len(edits),
        "buttonCount": len(buttons),
        "dialogCount": len(dialogs),
        "hasEdit": bool(edits),
        "hasButton": bool(buttons),
        "titles": [item.get("title") for item in top_windows if item.get("title")][:10],
        "buttonTexts": [item.get("title") for item in buttons if item.get("title")][
            :20
        ],
        "staticTexts": [item.get("title") for item in statics[:20]],
        "editHandles": [item.get("hwnd") for item in edits[:20]],
        "buttonHandles": [item.get("hwnd") for item in buttons[:20]],
        "fieldHints": field_hints[:20],
        "primaryWindowHwnd": primary.get("hwnd") if primary else None,
        "primaryWindowTitle": primary.get("title") if primary else None,
    }
    return {
        "pid": target_pid,
        "visibleOnly": visible_only,
        "windows": top_windows,
        "controls": flat,
        "summary": summary,
    }


def _parse_hwnd_value(hwnd: Any) -> int:
    if hwnd in (None, "", 0, "0"):
        return 0
    return int(str(hwnd), 0)


def _text_matches(haystack: str, needle: str) -> bool:
    if not needle:
        return True
    needle_variants = {
        _normalize_gui_text(value) for value in _repair_text_variants(needle) if value
    }
    haystack_variants = {
        _normalize_gui_text(value)
        for value in _repair_text_variants(haystack or "")
        if value
    }
    if not needle_variants:
        return True
    return any(
        needle_value and needle_value in haystack_value
        for haystack_value in haystack_variants
        for needle_value in needle_variants
    )


def _select_gui_control(
    controls: List[Dict[str, Any]],
    role: str = "",
    hwnd: str = "",
    text_contains: str = "",
    class_name: str = "",
    index: int = 0,
    visible_only: bool = True,
    enabled_only: bool = True,
) -> Optional[Dict[str, Any]]:
    parsed_hwnd = _normalize_hex(hwnd) if hwnd else None
    candidates: List[Dict[str, Any]] = []
    for control in controls:
        if not isinstance(control, dict):
            continue
        if parsed_hwnd and _normalize_hex(control.get("hwnd")) != parsed_hwnd:
            continue
        if role and str(control.get("role", "")).lower() != role.lower():
            continue
        if class_name and not _text_matches(
            str(control.get("className", "")), class_name
        ):
            continue
        if text_contains and not _text_matches(
            str(control.get("title", "")), text_contains
        ):
            continue
        if visible_only and not bool(control.get("visible")):
            continue
        if enabled_only and not bool(control.get("enabled")):
            continue
        candidates.append(control)
    if not candidates:
        return None
    candidates.sort(
        key=lambda item: (
            item.get("depth", 0),
            -_button_priority(item)
            if str(item.get("role", "")).lower() == "button"
            else 0,
            _control_rect(item).get("top", 0),
            _control_rect(item).get("left", 0),
            item.get("controlId", 0),
        )
    )
    picked_index = max(0, int(index))
    if picked_index >= len(candidates):
        picked_index = len(candidates) - 1
    return candidates[picked_index]


def _encode_best_effort_text(text: str) -> bytes:
    for encoding in ("mbcs", "cp1251", "cp866", "utf-8", "latin-1"):
        try:
            return text.encode(encoding)
        except Exception:
            continue
    return text.encode("utf-8", errors="ignore")


def _verify_control_text(hwnd: int, expected: str) -> Dict[str, Any]:
    actual = _get_control_text(hwnd)
    normalized_actual = _normalize_gui_text(actual)
    normalized_expected = _normalize_gui_text(expected)
    is_password = bool(_get_window_style(hwnd) & ES_PASSWORD)
    verified = (
        bool(normalized_actual == normalized_expected)
        or (not expected and not actual)
        or is_password
    )
    return {
        "verified": verified,
        "isPassword": is_password,
        "actual": actual,
        "normalizedActual": normalized_actual,
        "normalizedExpected": normalized_expected,
    }


def _set_control_text(hwnd: int, text: str, timeout_ms: int = 300) -> Dict[str, Any]:
    root = int(user32.GetAncestor(hwnd, GA_ROOT))
    if root:
        _focus_window(root)
        time.sleep(0.05)
    attempts: List[str] = []

    buf = ctypes.create_unicode_buffer(text)
    result = _send_message_timeout(
        hwnd, WM_SETTEXT, 0, ctypes.addressof(buf), timeout_ms=timeout_ms
    )
    if result is not None:
        attempts.append("wm_settext_unicode")
        verification = _verify_control_text(hwnd, text)
        if verification["verified"]:
            return {
                "ok": True,
                "hwnd": f"0x{int(hwnd):X}",
                "text": text,
                "refreshedText": verification["actual"],
                "verified": True,
                "mode": attempts[-1],
                "attempts": attempts,
            }

    encoded = _encode_best_effort_text(text)
    ansi_buf = ctypes.create_string_buffer(encoded + b"\x00")
    result = _send_message_timeout_ansi(
        hwnd, WM_SETTEXT, 0, ctypes.addressof(ansi_buf), timeout_ms=timeout_ms
    )
    if result is not None:
        attempts.append("wm_settext_ansi")
        verification = _verify_control_text(hwnd, text)
        if verification["verified"]:
            return {
                "ok": True,
                "hwnd": f"0x{int(hwnd):X}",
                "text": text,
                "refreshedText": verification["actual"],
                "verified": True,
                "mode": attempts[-1],
                "attempts": attempts,
            }

    _send_message_timeout(hwnd, EM_SETSEL, 0, -1, timeout_ms=timeout_ms)
    replace_buf = ctypes.create_unicode_buffer(text)
    result = _send_message_timeout(
        hwnd, EM_REPLACESEL, 1, ctypes.addressof(replace_buf), timeout_ms=timeout_ms
    )
    if result is not None:
        attempts.append("em_replacesel_unicode")
        verification = _verify_control_text(hwnd, text)
        if verification["verified"]:
            return {
                "ok": True,
                "hwnd": f"0x{int(hwnd):X}",
                "text": text,
                "refreshedText": verification["actual"],
                "verified": True,
                "mode": attempts[-1],
                "attempts": attempts,
            }

    _send_message_timeout_ansi(hwnd, EM_SETSEL, 0, -1, timeout_ms=timeout_ms)
    ansi_replace_buf = ctypes.create_string_buffer(encoded + b"\x00")
    result = _send_message_timeout_ansi(
        hwnd,
        EM_REPLACESEL,
        1,
        ctypes.addressof(ansi_replace_buf),
        timeout_ms=timeout_ms,
    )
    if result is not None:
        attempts.append("em_replacesel_ansi")

    verification = _verify_control_text(hwnd, text)
    if verification["verified"]:
        return {
            "ok": True,
            "hwnd": f"0x{int(hwnd):X}",
            "text": text,
            "refreshedText": verification["actual"],
            "verified": True,
            "mode": attempts[-1] if attempts else "unknown",
            "attempts": attempts,
        }
    raise RuntimeError(
        f"Failed to set control text. attempts={attempts}, actual={verification['actual']!r}"
    )


def _build_lparam_xy(x: int, y: int) -> int:
    return (int(y) << 16) | (int(x) & 0xFFFF)


def _click_control(hwnd: int, timeout_ms: int = 300) -> Dict[str, Any]:
    root = int(user32.GetAncestor(hwnd, GA_ROOT))
    if root:
        _focus_window(root)
        time.sleep(0.05)
    attempts: List[str] = []
    result = _send_message_timeout(hwnd, BM_CLICK, 0, 0, timeout_ms=timeout_ms)
    if result is not None:
        attempts.append("bm_click_sendmessage")
        return {
            "ok": True,
            "hwnd": f"0x{int(hwnd):X}",
            "clicked": True,
            "mode": attempts[-1],
            "attempts": attempts,
        }
    if user32.PostMessageW(hwnd, BM_CLICK, 0, 0):
        attempts.append("bm_click_postmessage")
        return {
            "ok": True,
            "hwnd": f"0x{int(hwnd):X}",
            "clicked": True,
            "mode": attempts[-1],
            "attempts": attempts,
        }

    parent_hwnd = int(user32.GetParent(hwnd))
    control_id = int(user32.GetDlgCtrlID(hwnd))
    if parent_hwnd and control_id:
        command_wparam = (BN_CLICKED << 16) | (control_id & 0xFFFF)
        result = _send_message_timeout(
            parent_hwnd, WM_COMMAND, command_wparam, hwnd, timeout_ms=timeout_ms
        )
        if result is not None:
            attempts.append("wm_command_parent")
            return {
                "ok": True,
                "hwnd": f"0x{int(hwnd):X}",
                "clicked": True,
                "mode": attempts[-1],
                "attempts": attempts,
                "parentHwnd": f"0x{parent_hwnd:X}",
            }

    click_lparam = _build_lparam_xy(5, 5)
    if user32.PostMessageW(
        hwnd, WM_LBUTTONDOWN, MK_LBUTTON, click_lparam
    ) and user32.PostMessageW(hwnd, WM_LBUTTONUP, 0, click_lparam):
        attempts.append("mouse_click_postmessage")
        return {
            "ok": True,
            "hwnd": f"0x{int(hwnd):X}",
            "clicked": True,
            "mode": attempts[-1],
            "attempts": attempts,
        }
    raise RuntimeError(
        "Control click failed via BM_CLICK, WM_COMMAND, and mouse message fallbacks"
    )


def _analyze_gui_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    summary = snapshot.get("summary", {}) if isinstance(snapshot, dict) else {}
    controls = snapshot.get("controls", []) if isinstance(snapshot, dict) else []
    primary_window = (
        _select_top_window(snapshot, hwnd=str(summary.get("primaryWindowHwnd") or ""))
        if summary.get("primaryWindowHwnd")
        else None
    )
    focus_controls = (
        _controls_for_window(primary_window) if primary_window else controls
    )
    if not focus_controls:
        focus_controls = controls
    first_edit = _select_gui_control(
        focus_controls, role="edit", visible_only=True, enabled_only=True
    )
    button_candidates = [
        item
        for item in focus_controls
        if isinstance(item, dict)
        and str(item.get("role", "")).lower() == "button"
        and bool(item.get("visible"))
        and bool(item.get("enabled"))
    ]
    button_candidates = sorted(
        button_candidates,
        key=lambda item: (
            -_button_priority(item),
            _control_rect(item).get("top", 0),
            _control_rect(item).get("left", 0),
        ),
    )
    first_button = button_candidates[0] if button_candidates else None
    suggested_submit = (
        _select_gui_control(
            focus_controls,
            role="button",
            text_contains="ok",
            visible_only=True,
            enabled_only=True,
        )
        or _select_gui_control(
            focus_controls,
            role="button",
            text_contains="check",
            visible_only=True,
            enabled_only=True,
        )
        or _select_gui_control(
            focus_controls,
            role="button",
            text_contains="register",
            visible_only=True,
            enabled_only=True,
        )
        or first_button
    )
    safe_auto_button = (
        suggested_submit
        if suggested_submit
        and any(
            _text_matches(str(suggested_submit.get("title", "")), token)
            for token in (
                "ok",
                "check",
                "register",
                "submit",
                "continue",
                "next",
                "yes",
            )
        )
        else None
    )
    if (
        not safe_auto_button
        and first_button
        and not first_edit
        and str(first_button.get("buttonKind", "")) == "default_push"
    ):
        safe_auto_button = first_button
    if (
        not safe_auto_button
        and first_button
        and not first_edit
        and len(button_candidates) == 1
    ):
        safe_auto_button = first_button
    return {
        "pid": snapshot.get("pid"),
        "hasVisibleWindow": bool(summary.get("meaningfulTopWindowCount")),
        "hasAnyWindow": bool(summary.get("topWindowCount")),
        "hasEdit": bool(summary.get("hasEdit")),
        "hasButton": bool(summary.get("hasButton")),
        "primaryWindowHwnd": summary.get("primaryWindowHwnd"),
        "primaryWindowTitle": summary.get("primaryWindowTitle"),
        "suggestedEditHwnd": first_edit.get("hwnd") if first_edit else None,
        "suggestedEditTitle": first_edit.get("title") if first_edit else None,
        "suggestedButtonHwnd": suggested_submit.get("hwnd")
        if suggested_submit
        else None,
        "suggestedButtonTitle": suggested_submit.get("title")
        if suggested_submit
        else None,
        "safeAutoButtonHwnd": safe_auto_button.get("hwnd")
        if safe_auto_button
        else None,
        "safeAutoButtonTitle": safe_auto_button.get("title")
        if safe_auto_button
        else None,
        "fieldHints": summary.get("fieldHints", []),
        "buttonTexts": summary.get("buttonTexts", []),
        "staticTexts": summary.get("staticTexts", []),
        "titles": summary.get("titles", []),
        "noiseWindowCount": int(summary.get("noiseWindowCount") or 0),
    }


def _flatten_uia_tree(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    stack = list(reversed(nodes or []))
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        items.append(node)
        children = node.get("children", [])
        if isinstance(children, list):
            stack.extend(reversed(children))
    return items


def _uia_top_window_handles(target_pid: int, visible_only: bool = True) -> List[int]:
    hwnds = _enumerate_top_windows_for_pid(target_pid, visible_only=visible_only)
    if hwnds or not visible_only:
        return hwnds
    return _enumerate_top_windows_for_pid(target_pid, visible_only=False)


def _run_with_uia_pump(
    target_pid: int,
    action: Callable[[], Dict[str, Any]],
    pump_ms: int = 220,
    pause_timeout_ms: int = 2500,
) -> Dict[str, Any]:
    state = _build_debug_state(
        include_console=False, include_callstack=False, max_console_chars=0
    )
    context: Dict[str, Any] = {
        "targetPid": int(target_pid),
        "initialState": state.get("state"),
        "usedPump": False,
        "resumeResult": None,
        "pauseResult": None,
        "waitState": None,
        "directAttempt": True,
        "firstError": None,
    }
    should_pump = (
        int(state.get("debuggeePid") or 0) == int(target_pid)
        and bool(state.get("debugging"))
        and bool(state.get("paused"))
        and bool(_uia_top_window_handles(target_pid, visible_only=False))
    )
    try:
        result = action()
    except Exception as first_error:
        context["firstError"] = str(first_error)
        if not should_pump:
            raise
        context["resumeResult"] = DebugRun()
        context["usedPump"] = True
        context["directAttempt"] = False
        time.sleep(max(50, min(int(pump_ms), 600)) / 1000.0)
        try:
            result = action()
        finally:
            if context["usedPump"]:
                current = _build_debug_state(
                    include_console=False, include_callstack=False, max_console_chars=0
                )
                if current.get("running"):
                    context["pauseResult"] = DebugPause()
                    context["waitState"] = WaitForPause(
                        timeout_ms=max(800, int(pause_timeout_ms)), poll_ms=50
                    )
                else:
                    context["waitState"] = current
        if isinstance(result, dict) and "uiaPump" not in result:
            result["uiaPump"] = context
        return result
    try:
        pass
    finally:
        if context["usedPump"]:
            current = _build_debug_state(
                include_console=False, include_callstack=False, max_console_chars=0
            )
            if current.get("running"):
                context["pauseResult"] = DebugPause()
                context["waitState"] = WaitForPause(
                    timeout_ms=max(800, int(pause_timeout_ms)), poll_ms=50
                )
            else:
                context["waitState"] = current
    if isinstance(result, dict) and "uiaPump" not in result:
        result["uiaPump"] = context
    return result


def _collect_uia_snapshot(
    pid: int, visible_only: bool = True, max_depth: int = 4, timeout_ms: int = 12000
) -> Dict[str, Any]:
    target_pid = _infer_debuggee_pid(pid)
    hwnds = _uia_top_window_handles(target_pid, visible_only=visible_only)
    if not hwnds and visible_only:
        hwnds = _uia_top_window_handles(target_pid, visible_only=False)
    visible_literal = "$true" if visible_only else "$false"
    handles_literal = ",".join(str(int(hwnd)) for hwnd in hwnds)
    script = f"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$targetPid = {int(target_pid)}
$visibleOnly = {visible_literal}
$maxDepth = {int(max_depth)}
$targetHandles = @({handles_literal})
function Get-Patterns($element) {{
  $patterns = @()
  foreach ($item in @(
    @{{ Name = 'Invoke'; Pattern = [System.Windows.Automation.InvokePattern]::Pattern }},
    @{{ Name = 'Value'; Pattern = [System.Windows.Automation.ValuePattern]::Pattern }},
    @{{ Name = 'SelectionItem'; Pattern = [System.Windows.Automation.SelectionItemPattern]::Pattern }},
    @{{ Name = 'ExpandCollapse'; Pattern = [System.Windows.Automation.ExpandCollapsePattern]::Pattern }},
    @{{ Name = 'Toggle'; Pattern = [System.Windows.Automation.TogglePattern]::Pattern }}
  )) {{
    $patternObj = $null
    if ($element.TryGetCurrentPattern($item.Pattern, [ref]$patternObj)) {{
      $patterns += $item.Name
    }}
  }}
  return $patterns
}}
function Safe-RectInt($value) {{
  try {{
    $doubleValue = [double]$value
    if ([double]::IsNaN($doubleValue) -or [double]::IsInfinity($doubleValue)) {{ return 0 }}
    if ($doubleValue -gt [int]::MaxValue) {{ return [int]::MaxValue }}
    if ($doubleValue -lt [int]::MinValue) {{ return [int]::MinValue }}
    return [int][math]::Round($doubleValue)
  }} catch {{
    return 0
  }}
}}
function Convert-Rect($rect) {{
  if ($null -eq $rect) {{ return $null }}
  $left = Safe-RectInt $rect.Left
  $top = Safe-RectInt $rect.Top
  $right = Safe-RectInt $rect.Right
  $bottom = Safe-RectInt $rect.Bottom
  return @{{
    left = $left
    top = $top
    right = $right
    bottom = $bottom
    width = [math]::Max(0, $right - $left)
    height = [math]::Max(0, $bottom - $top)
  }}
}}
function Get-Node($element, $depth) {{
  if ($null -eq $element -or $depth -gt $maxDepth) {{ return $null }}
  try {{ $processId = [int]$element.Current.ProcessId }} catch {{ $processId = 0 }}
  if ($processId -ne $targetPid) {{ return $null }}
  try {{ $offscreen = [bool]$element.Current.IsOffscreen }} catch {{ $offscreen = $false }}
  if ($visibleOnly -and $offscreen) {{ return $null }}
  try {{ $nativeHandle = [int]$element.Current.NativeWindowHandle }} catch {{ $nativeHandle = 0 }}
  try {{ $name = [string]$element.Current.Name }} catch {{ $name = '' }}
  try {{ $className = [string]$element.Current.ClassName }} catch {{ $className = '' }}
  try {{ $automationId = [string]$element.Current.AutomationId }} catch {{ $automationId = '' }}
  try {{ $frameworkId = [string]$element.Current.FrameworkId }} catch {{ $frameworkId = '' }}
  try {{ $localizedControlType = [string]$element.Current.LocalizedControlType }} catch {{ $localizedControlType = '' }}
  try {{ $programmaticName = [string]$element.Current.ControlType.ProgrammaticName }} catch {{ $programmaticName = '' }}
  try {{ $enabled = [bool]$element.Current.IsEnabled }} catch {{ $enabled = $false }}
  try {{ $focused = [bool]$element.Current.HasKeyboardFocus }} catch {{ $focused = $false }}
  $patterns = Get-Patterns $element
  $node = @{{
    pid = $processId
    name = $name
    className = $className
    automationId = $automationId
    frameworkId = $frameworkId
    controlType = $localizedControlType
    controlTypeProgrammatic = $programmaticName
    hwnd = if ($nativeHandle) {{ ('0x{0:X}' -f $nativeHandle) }} else {{ $null }}
    nativeHandle = $nativeHandle
    enabled = $enabled
    visible = (-not $offscreen)
    focused = $focused
    patterns = $patterns
    rect = Convert-Rect $element.Current.BoundingRectangle
    depth = $depth
    children = @()
  }}
  if ($depth -lt $maxDepth) {{
    $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
    $child = $walker.GetFirstChild($element)
    while ($null -ne $child) {{
      $childNode = Get-Node $child ($depth + 1)
      if ($null -ne $childNode) {{
        $node.children += $childNode
      }}
      $child = $walker.GetNextSibling($child)
    }}
  }}
  return $node
}}
$windows = @()
foreach ($handleValue in $targetHandles) {{
  if (-not $handleValue) {{ continue }}
  try {{
    $element = [System.Windows.Automation.AutomationElement]::FromHandle([intptr]::new([int64]$handleValue))
  }} catch {{
    $element = $null
  }}
  if ($null -eq $element) {{ continue }}
  $node = Get-Node $element 0
  if ($null -ne $node) {{
    $windows += $node
  }}
}}
$all = New-Object System.Collections.ArrayList
function Add-Flat($node) {{
  if ($null -eq $node) {{ return }}
  [void]$all.Add($node)
  foreach ($child in @($node.children)) {{ Add-Flat $child }}
}}
foreach ($window in $windows) {{ Add-Flat $window }}
$summary = @{{
  topWindowCount = @($windows).Count
  elementCount = @($all).Count
  valueCount = @($all | Where-Object {{ $_.patterns -contains 'Value' }}).Count
  invokeCount = @($all | Where-Object {{ $_.patterns -contains 'Invoke' }}).Count
  selectionCount = @($all | Where-Object {{ $_.patterns -contains 'SelectionItem' }}).Count
  titles = @($windows | ForEach-Object {{ $_.name }} | Where-Object {{ $_ }})
}}
@{{
  ok = $true
  pid = $targetPid
  windows = $windows
  elements = @($all)
  summary = $summary
}} | ConvertTo-Json -Depth 10 -Compress
"""
    payload = _run_powershell_json(script, timeout_ms=timeout_ms)
    if isinstance(payload, dict):
        payload["pid"] = payload.get("pid", target_pid)
        payload["windows"] = _normalize_uia_nodes(
            list(payload.get("windows", []) or [])
        )
        payload["elements"] = _flatten_uia_tree(payload["windows"])
        return payload
    return {
        "ok": False,
        "pid": target_pid,
        "windows": [],
        "elements": [],
        "summary": {},
    }


def _text_matches_uia(element: Dict[str, Any], needle: str) -> bool:
    if not needle:
        return True
    return _text_matches(str(element.get("name", "")), needle) or _text_matches(
        str(element.get("automationId", "")), needle
    )


def _normalize_uia_patterns(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str):
        return [value] if value else []
    return []


def _normalize_uia_nodes(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for node in nodes or []:
        if not isinstance(node, dict):
            continue
        item = dict(node)
        native_handle = _parse_int(item.get("nativeHandle"), default=0) or 0
        if native_handle and _normalize_hex(item.get("hwnd")) in (None, "0x0"):
            item["hwnd"] = f"0x{int(native_handle):X}"
        item["patterns"] = _normalize_uia_patterns(item.get("patterns"))
        item["children"] = _normalize_uia_nodes(list(item.get("children", []) or []))
        normalized.append(item)
    return normalized


def _uia_element_is_value_candidate(element: Dict[str, Any]) -> bool:
    patterns = set(_normalize_uia_patterns(element.get("patterns")))
    class_name = str(element.get("className", "")).lower()
    control_programmatic = str(element.get("controlTypeProgrammatic", "")).lower()
    control_type = str(element.get("controlType", "")).lower()
    return (
        "Value" in patterns
        or "edit" in class_name
        or "textbox" in class_name
        or "richedit" in class_name
        or "controltype.edit" in control_programmatic
        or "document" in control_programmatic
        or "edit" in control_type
    )


def _uia_element_is_invoke_candidate(element: Dict[str, Any]) -> bool:
    patterns = set(_normalize_uia_patterns(element.get("patterns")))
    class_name = str(element.get("className", "")).lower()
    control_programmatic = str(element.get("controlTypeProgrammatic", "")).lower()
    control_type = str(element.get("controlType", "")).lower()
    return (
        "Invoke" in patterns
        or "button" in class_name
        or "controltype.button" in control_programmatic
        or "controltype.hyperlink" in control_programmatic
        or "button" in control_type
        or "link" in control_type
    )


def _select_uia_element(
    elements: List[Dict[str, Any]],
    hwnd: str = "",
    automation_id: str = "",
    name: str = "",
    pattern: str = "",
    control_type: str = "",
    enabled_only: bool = True,
) -> Optional[Dict[str, Any]]:
    target_hwnd = _normalize_hex(hwnd) if hwnd else None
    chosen: List[Dict[str, Any]] = []
    for element in elements:
        if not isinstance(element, dict):
            continue
        if target_hwnd and _normalize_hex(element.get("hwnd")) != target_hwnd:
            continue
        if automation_id and not _text_matches(
            str(element.get("automationId", "")), automation_id
        ):
            continue
        if name and not _text_matches_uia(element, name):
            continue
        if (
            control_type
            and not _text_matches(str(element.get("controlType", "")), control_type)
            and not _text_matches(
                str(element.get("controlTypeProgrammatic", "")), control_type
            )
        ):
            continue
        if pattern and pattern not in list(element.get("patterns", []) or []):
            continue
        if enabled_only and not bool(element.get("enabled", True)):
            continue
        chosen.append(element)
    if not chosen:
        return None
    chosen.sort(
        key=lambda item: (
            0 if item.get("focused") else 1,
            item.get("depth", 0),
            0 if item.get("name") else 1,
            (item.get("rect", {}) or {}).get("top", 0),
            (item.get("rect", {}) or {}).get("left", 0),
        )
    )
    return chosen[0]


def _analyze_uia_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    elements = list(
        snapshot.get("elements", []) or _flatten_uia_tree(snapshot.get("windows", []))
    )
    value_candidates = [
        item
        for item in elements
        if isinstance(item, dict)
        and bool(item.get("enabled", True))
        and _uia_element_is_value_candidate(item)
    ]
    value_candidates.sort(
        key=lambda item: (
            0 if "Value" in set(_normalize_uia_patterns(item.get("patterns"))) else 1,
            item.get("depth", 0),
            0 if item.get("name") else 1,
            (item.get("rect", {}) or {}).get("top", 0),
            (item.get("rect", {}) or {}).get("left", 0),
        )
    )
    value_candidate = value_candidates[0] if value_candidates else None
    invoke_candidates = [
        item
        for item in elements
        if isinstance(item, dict)
        and bool(item.get("enabled", True))
        and _uia_element_is_invoke_candidate(item)
    ]
    preferred_invoke = [
        item
        for item in invoke_candidates
        if any(
            _text_matches(str(item.get("name", "")), token)
            for token in ("ok", "check", "register", "submit", "continue", "next")
        )
    ]
    invoke_pool = preferred_invoke or invoke_candidates
    invoke_pool.sort(
        key=lambda item: (
            0 if "Invoke" in set(_normalize_uia_patterns(item.get("patterns"))) else 1,
            item.get("depth", 0),
            0 if item.get("name") else 1,
            (item.get("rect", {}) or {}).get("top", 0),
            (item.get("rect", {}) or {}).get("left", 0),
        )
    )
    invoke_candidate = invoke_pool[0] if invoke_pool else None
    return {
        "pid": snapshot.get("pid"),
        "hasElements": bool(elements),
        "hasValueElement": bool(value_candidate),
        "hasInvokeElement": bool(invoke_candidate),
        "suggestedValueHwnd": value_candidate.get("hwnd") if value_candidate else None,
        "suggestedValueName": value_candidate.get("name") if value_candidate else None,
        "suggestedValueAutomationId": value_candidate.get("automationId")
        if value_candidate
        else None,
        "suggestedInvokeHwnd": invoke_candidate.get("hwnd")
        if invoke_candidate
        else None,
        "suggestedInvokeName": invoke_candidate.get("name")
        if invoke_candidate
        else None,
        "suggestedInvokeAutomationId": invoke_candidate.get("automationId")
        if invoke_candidate
        else None,
        "frameworkIds": sorted(
            {
                str(item.get("frameworkId", ""))
                for item in elements
                if str(item.get("frameworkId", ""))
            }
        ),
        "titles": list(snapshot.get("summary", {}).get("titles", [])),
    }


def _synthesize_uia_patterns_from_gui_node(node: Dict[str, Any]) -> List[str]:
    role = str(node.get("role") or "").strip().lower()
    class_name = str(node.get("className") or "").strip().lower()
    patterns: List[str] = []
    if role in ("edit", "combo") or class_name in ("edit", "combobox"):
        patterns.append("Value")
    if role == "button" or "button" in class_name:
        patterns.append("Invoke")
    return patterns


def _synthesize_uia_programmatic_type(node: Dict[str, Any]) -> str:
    role = str(node.get("role") or "").strip().lower()
    class_name = str(node.get("className") or "").strip().lower()
    if role == "dialog":
        return "ControlType.Window"
    if role == "button" or "button" in class_name:
        return "ControlType.Button"
    if role in ("edit", "combo") or class_name in ("edit", "combobox"):
        return "ControlType.Edit"
    if role == "static":
        return "ControlType.Text"
    return "ControlType.Pane"


def _synthesize_uia_node_from_gui(
    node: Dict[str, Any], depth: int = 0
) -> Dict[str, Any]:
    hwnd_text = str(node.get("hwnd") or "")
    native_handle = _parse_hwnd_value(hwnd_text) if hwnd_text else 0
    children = [
        _synthesize_uia_node_from_gui(child, depth=depth + 1)
        for child in list(node.get("children", []) or [])
        if isinstance(child, dict)
    ]
    return {
        "hwnd": hwnd_text or None,
        "nativeHandle": int(native_handle or 0),
        "pid": int(node.get("pid") or 0),
        "name": str(node.get("title") or ""),
        "automationId": str(node.get("controlId") or "")
        if node.get("controlId") is not None
        else "",
        "className": str(node.get("className") or ""),
        "frameworkId": "Win32",
        "controlType": str(node.get("role") or node.get("className") or ""),
        "controlTypeProgrammatic": _synthesize_uia_programmatic_type(node),
        "patterns": _synthesize_uia_patterns_from_gui_node(node),
        "visible": bool(node.get("visible", True)),
        "enabled": bool(node.get("enabled", True)),
        "focused": False,
        "depth": int(depth),
        "rect": dict(node.get("rect") or {}),
        "children": children,
    }


def _synthesize_uia_snapshot_from_gui(gui_snapshot: Dict[str, Any]) -> Dict[str, Any]:
    windows = [
        _synthesize_uia_node_from_gui(window, depth=0)
        for window in list(gui_snapshot.get("windows", []) or [])
        if isinstance(window, dict)
    ]
    elements = _flatten_uia_tree(windows)
    value_count = sum(
        1
        for item in elements
        if "Value" in set(_normalize_uia_patterns(item.get("patterns")))
    )
    invoke_count = sum(
        1
        for item in elements
        if "Invoke" in set(_normalize_uia_patterns(item.get("patterns")))
    )
    selection_count = sum(
        1
        for item in elements
        if "SelectionItem" in set(_normalize_uia_patterns(item.get("patterns")))
    )
    summary = {
        "topWindowCount": len(windows),
        "elementCount": len(elements),
        "valueCount": value_count,
        "invokeCount": invoke_count,
        "selectionCount": selection_count,
        "titles": [
            str(item.get("name") or "")
            for item in windows
            if str(item.get("name") or "")
        ],
    }
    snapshot = {
        "ok": True,
        "pid": gui_snapshot.get("pid"),
        "windows": windows,
        "elements": elements,
        "summary": summary,
        "fallback": "win32_gui_snapshot",
        "logPath": LOG_PATH,
    }
    snapshot["analysis"] = _analyze_uia_snapshot(snapshot)
    return snapshot


def _resolve_uia_target(
    snapshot: Dict[str, Any],
    hwnd: str = "",
    automation_id: str = "",
    name: str = "",
    pattern: str = "",
) -> Optional[Dict[str, Any]]:
    elements = list(
        snapshot.get("elements", []) or _flatten_uia_tree(snapshot.get("windows", []))
    )
    target = _select_uia_element(
        elements, hwnd=hwnd, automation_id=automation_id, name=name, pattern=pattern
    )
    if target:
        return target
    if pattern == "Value":
        candidates = [
            item
            for item in elements
            if isinstance(item, dict) and _uia_element_is_value_candidate(item)
        ]
    elif pattern == "Invoke":
        candidates = [
            item
            for item in elements
            if isinstance(item, dict) and _uia_element_is_invoke_candidate(item)
        ]
    else:
        candidates = [item for item in elements if isinstance(item, dict)]
    if hwnd:
        normalized = _normalize_hex(hwnd)
        candidates = [
            item
            for item in candidates
            if _normalize_hex(item.get("hwnd")) == normalized
        ]
    if automation_id:
        candidates = [
            item
            for item in candidates
            if _text_matches(str(item.get("automationId", "")), automation_id)
        ]
    if name:
        candidates = [item for item in candidates if _text_matches_uia(item, name)]
    if not candidates:
        return None
    candidates.sort(
        key=lambda item: (
            0 if item.get("focused") else 1,
            item.get("depth", 0),
            0 if item.get("name") else 1,
            (item.get("rect", {}) or {}).get("top", 0),
            (item.get("rect", {}) or {}).get("left", 0),
        )
    )
    return candidates[0]


def _uia_selector_script(
    target_pid: int,
    hwnd: str = "",
    automation_id: str = "",
    name: str = "",
    pattern: str = "",
) -> str:
    hwnd_value = _parse_hwnd_value(hwnd) if hwnd else 0
    top_hwnds = _uia_top_window_handles(target_pid, visible_only=False)
    handles_literal = ",".join(str(int(item)) for item in top_hwnds)
    return f"""
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$targetPid = {int(target_pid)}
$targetHwnd = {int(hwnd_value)}
$targetHandles = @({handles_literal})
$targetAutomationId = {json.dumps(str(automation_id or ""))}
$targetName = {json.dumps(str(name or ""))}
$targetPattern = {json.dumps(str(pattern or ""))}
function Match-Element($element) {{
  try {{ $pid = [int]$element.Current.ProcessId }} catch {{ $pid = 0 }}
  if ($pid -ne $targetPid) {{ return $false }}
  try {{ $nativeHandle = [int]$element.Current.NativeWindowHandle }} catch {{ $nativeHandle = 0 }}
  try {{ $automationId = [string]$element.Current.AutomationId }} catch {{ $automationId = '' }}
  try {{ $name = [string]$element.Current.Name }} catch {{ $name = '' }}
  if ($targetHwnd -and $nativeHandle -ne $targetHwnd) {{ return $false }}
  if ($targetAutomationId -and $automationId -notlike ('*' + $targetAutomationId + '*')) {{ return $false }}
  if ($targetName -and $name -notlike ('*' + $targetName + '*')) {{ return $false }}
  if (-not $targetPattern) {{ return $true }}
  $patternObj = $null
  switch ($targetPattern) {{
    'Invoke' {{ return $element.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$patternObj) }}
    'Value' {{ return $element.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$patternObj) }}
    default {{ return $true }}
  }}
}}
function Find-MatchingElement($rootElement) {{
  if ($null -eq $rootElement) {{ return $null }}
  if (Match-Element $rootElement) {{ return $rootElement }}
  $walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
  $child = $walker.GetFirstChild($rootElement)
  while ($null -ne $child) {{
    $matched = Find-MatchingElement $child
    if ($null -ne $matched) {{ return $matched }}
    $child = $walker.GetNextSibling($child)
  }}
  return $null
}}
$picked = $null
if ($targetHwnd) {{
  try {{
    $picked = [System.Windows.Automation.AutomationElement]::FromHandle([intptr]::new([int64]$targetHwnd))
  }} catch {{
    $picked = $null
  }}
  if ($null -ne $picked -and -not (Match-Element $picked)) {{
    $picked = Find-MatchingElement $picked
  }}
}} else {{
  foreach ($handleValue in $targetHandles) {{
    if (-not $handleValue) {{ continue }}
    $rootElement = $null
    try {{
      $rootElement = [System.Windows.Automation.AutomationElement]::FromHandle([intptr]::new([int64]$handleValue))
    }} catch {{
      $rootElement = $null
    }}
    if ($null -eq $rootElement) {{ continue }}
    $picked = Find-MatchingElement $rootElement
    if ($null -ne $picked) {{ break }}
  }}
}}
if ($null -eq $picked) {{
  throw 'UI Automation element not found'
}}
"""


def _select_top_window(
    snapshot: Dict[str, Any],
    title_contains: str = "",
    class_name: str = "",
    hwnd: str = "",
) -> Optional[Dict[str, Any]]:
    windows = snapshot.get("windows", []) if isinstance(snapshot, dict) else []
    parsed_hwnd = _normalize_hex(hwnd) if hwnd else None
    candidates: List[Dict[str, Any]] = []
    for window in windows:
        if parsed_hwnd and _normalize_hex(window.get("hwnd")) != parsed_hwnd:
            continue
        if title_contains and not _text_matches(
            str(window.get("title", "")), title_contains
        ):
            continue
        if class_name and not _text_matches(
            str(window.get("className", "")), class_name
        ):
            continue
        candidates.append(window)
    if not candidates:
        return None
    if not (parsed_hwnd or title_contains or class_name):
        meaningful = [item for item in candidates if _is_meaningful_window_node(item)]
        if meaningful:
            candidates = meaningful
        else:
            return None
    candidates.sort(
        key=lambda item: (
            0 if _is_meaningful_window_node(item) else 1,
            0 if item.get("visible") else 1,
            0 if item.get("enabled") else 1,
            0 if item.get("title") else 1,
            -len(item.get("children", [])),
        )
    )
    return candidates[0]


def _controls_for_window(window_node: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not window_node:
        return []
    return _flatten_window_tree([window_node])[1:]


def _parse_json_string_list(raw: str) -> List[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [raw]
    if isinstance(data, list):
        return [str(item) for item in data]
    return [str(data)]


def _parse_text_payload(raw: str) -> Dict[str, Any]:
    if not raw:
        return {"mode": "empty", "list": [], "map": {}}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"mode": "list", "list": [raw], "map": {}}
    if isinstance(data, dict):
        return {
            "mode": "map",
            "list": [],
            "map": {str(key): str(value) for key, value in data.items()},
        }
    if isinstance(data, list):
        return {"mode": "list", "list": [str(item) for item in data], "map": {}}
    return {"mode": "list", "list": [str(data)], "map": {}}


def _parse_json_array(raw: str) -> List[Any]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [raw]
    if isinstance(data, list):
        return data
    return [data]


def _parse_capture_specs(raw: str) -> List[Dict[str, Any]]:
    specs: List[Dict[str, Any]] = []
    for entry in _parse_json_array(raw):
        if isinstance(entry, dict):
            expr = str(entry.get("expr", entry.get("address", ""))).strip()
            if not expr:
                continue
            specs.append(
                {
                    "label": str(entry.get("label", "")).strip(),
                    "expr": expr,
                    "size": int(entry.get("size", entry.get("length", 0)) or 0),
                    "format": str(entry.get("format", entry.get("ty", "hex"))).strip()
                    or "hex",
                }
            )
            continue
        if isinstance(entry, str):
            text = entry.strip()
            if not text:
                continue
            parts = text.split("|")
            expr = parts[1].strip() if len(parts) >= 2 else parts[0].strip()
            if not expr:
                continue
            specs.append(
                {
                    "label": parts[0].strip() if len(parts) >= 2 else "",
                    "expr": expr,
                    "size": int(parts[2], 0)
                    if len(parts) >= 3 and str(parts[2]).strip()
                    else 0,
                    "format": parts[3].strip()
                    if len(parts) >= 4 and str(parts[3]).strip()
                    else "hex",
                }
            )
    return specs


def _normalize_name_items(raw: str) -> List[str]:
    items: List[str] = []
    for entry in _parse_json_array(raw):
        if isinstance(entry, str):
            for part in entry.replace("\r", "\n").split("\n"):
                for token in part.split(","):
                    token = str(token).strip()
                    if token:
                        items.append(token)
        elif entry is not None:
            token = str(entry).strip()
            if token:
                items.append(token)
    return items


def _encode_expression_payload(raw: str) -> str:
    items = _normalize_name_items(raw)
    return "\n".join(items)


def _encode_capture_specs(raw: str) -> str:
    encoded: List[str] = []
    for entry in _parse_json_array(raw):
        if isinstance(entry, str):
            spec = entry.strip()
            if spec:
                encoded.append(spec)
            continue
        if not isinstance(entry, dict):
            continue
        label = str(entry.get("label", "")).strip()
        expr = str(entry.get("expr", entry.get("address", ""))).strip()
        size = entry.get("size", entry.get("length", 0))
        fmt = str(entry.get("format", entry.get("ty", "hex"))).strip() or "hex"
        if not expr:
            continue
        encoded.append(f"{label}|{expr}|{size}|{fmt}")
    return "\n".join(encoded)


def _append_trace_history(entry: Dict[str, Any]) -> None:
    with _RUNTIME_LOCK:
        history = list(_RUNTIME_STATE.get("traceHistory", []))
        history.append(entry)
        if len(history) > 32:
            history = history[-32:]
        _RUNTIME_STATE["traceHistory"] = history


def _append_breakpoint_capture_history(entry: Dict[str, Any]) -> None:
    with _RUNTIME_LOCK:
        history = list(_RUNTIME_STATE.get("breakpointCaptureHistory", []))
        history.append(entry)
        if len(history) > 32:
            history = history[-32:]
        _RUNTIME_STATE["breakpointCaptureHistory"] = history


def _append_input_history(entry: Dict[str, Any]) -> None:
    with _RUNTIME_LOCK:
        history = list(_RUNTIME_STATE.get("inputHistory", []))
        history.append(_json_safe(entry))
        if len(history) > 128:
            history = history[-128:]
        _RUNTIME_STATE["inputHistory"] = history


def _capture_snapshot_owner(require_thread: bool = False) -> Dict[str, Any]:
    identity = _get_cached_bridge_identity()
    binding = _get_bound_session()
    session = identity.get("session") if isinstance(identity.get("session"), dict) else {}
    if require_thread:
        try:
            refreshed = _get_debug_session_state(include_history=False, history_limit=0)
            if isinstance(refreshed, dict):
                session = refreshed
                identity = _get_cached_bridge_identity()
        except Exception:
            pass
    image_sha256 = str(
        binding.get("imageSha256")
        or session.get("imageSha256")
        or identity.get("imageSha256")
        or ""
    ).strip().upper()
    owner = {
        "clientInstanceId": _CLIENT_INSTANCE_ID,
        "bridgeInstanceId": str(
            binding.get("bridgeInstanceId") or identity.get("bridgeInstanceId") or ""
        ),
        "sessionId": str(binding.get("sessionId") or identity.get("sessionId") or ""),
        "sessionGeneration": int(
            binding.get("sessionGeneration")
            or identity.get("sessionGeneration")
            or 0
        ),
        "processId": int(binding.get("pid") or identity.get("debuggeePid") or 0),
        "eventSeq": int(session.get("eventSeq") or identity.get("eventSeq") or 0),
        "threadId": int(session.get("threadId") or 0),
        "imagePath": str(
            binding.get("imagePath") or identity.get("debuggeeImagePath") or ""
        ),
        "imageSha256": image_sha256,
        "moduleBase": _normalize_hex(binding.get("moduleBase")),
        "capturedAt": _now_iso(),
    }
    owner["strong"] = bool(
        owner["bridgeInstanceId"]
        and owner["sessionId"]
        and owner["sessionGeneration"]
        and owner["processId"]
        and (
            not _target_identity_hash_required(identity)
            or bool(TARGET_SHA256_RE.fullmatch(owner["imageSha256"]))
        )
        and (not require_thread or owner["threadId"])
    )
    return owner


def _snapshot_owner_match(
    snapshot_owner: Any,
    *,
    require_thread: bool = False,
) -> Dict[str, Any]:
    expected = dict(snapshot_owner) if isinstance(snapshot_owner, dict) else {}
    current = _capture_snapshot_owner(require_thread=require_thread)
    required = [
        "bridgeInstanceId",
        "sessionId",
        "sessionGeneration",
        "processId",
    ]
    if expected.get("imageSha256"):
        required.append("imageSha256")
    if require_thread:
        required.append("threadId")
    missing = [key for key in required if not expected.get(key)]
    mismatches = [
        key
        for key in required
        if expected.get(key) and expected.get(key) != current.get(key)
    ]
    return {
        "matches": not missing and not mismatches,
        "missing": missing,
        "mismatches": mismatches,
        "expected": expected,
        "current": current,
    }


def _next_memory_snapshot_id() -> str:
    with _RUNTIME_LOCK:
        seq = int(_RUNTIME_STATE.get("memorySnapshotSeq", 0) or 0) + 1
        _RUNTIME_STATE["memorySnapshotSeq"] = seq
    generation = int(_get_cached_bridge_identity().get("sessionGeneration") or 0)
    return f"memsnap-{generation}-{seq}-{uuid.uuid4().hex[:8]}"


def _store_memory_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    snapshot_id = _next_memory_snapshot_id()
    record = dict(snapshot)
    record["snapshotId"] = snapshot_id
    record.setdefault("owner", _capture_snapshot_owner(require_thread=False))
    with _RUNTIME_LOCK:
        snapshots = dict(_RUNTIME_STATE.get("memorySnapshots", {}))
        order = list(_RUNTIME_STATE.get("memorySnapshotOrder", []))
        snapshots[snapshot_id] = record
        order.append(snapshot_id)
        if len(order) > 64:
            stale = order[:-64]
            order = order[-64:]
            for item in stale:
                snapshots.pop(item, None)
        _RUNTIME_STATE["memorySnapshots"] = snapshots
        _RUNTIME_STATE["memorySnapshotOrder"] = order
    return record


def _get_memory_snapshot(snapshot_id: str) -> Optional[Dict[str, Any]]:
    with _RUNTIME_LOCK:
        snapshots = dict(_RUNTIME_STATE.get("memorySnapshots", {}))
    return snapshots.get(str(snapshot_id or "").strip())


def _next_state_snapshot_id() -> str:
    with _RUNTIME_LOCK:
        seq = int(_RUNTIME_STATE.get("stateSnapshotSeq", 0)) + 1
        _RUNTIME_STATE["stateSnapshotSeq"] = seq
    generation = int(_get_cached_bridge_identity().get("sessionGeneration") or 0)
    return f"state-{generation}-{seq}-{uuid.uuid4().hex[:8]}"


def _store_state_snapshot(record: Dict[str, Any]) -> Dict[str, Any]:
    snapshot_id = _next_state_snapshot_id()
    record = dict(record)
    record["snapshotId"] = snapshot_id
    record.setdefault("owner", _capture_snapshot_owner(require_thread=True))
    with _RUNTIME_LOCK:
        snapshots = dict(_RUNTIME_STATE.get("stateSnapshots", {}))
        order = list(_RUNTIME_STATE.get("stateSnapshotOrder", []))
        snapshots[snapshot_id] = record
        order.append(snapshot_id)
        if len(order) > MAX_STATE_SNAPSHOTS:
            stale = order[:-MAX_STATE_SNAPSHOTS]
            order = order[-MAX_STATE_SNAPSHOTS:]
            for item in stale:
                snapshots.pop(item, None)
        _RUNTIME_STATE["stateSnapshots"] = snapshots
        _RUNTIME_STATE["stateSnapshotOrder"] = order
    return record


def _get_state_snapshot(snapshot_id: str) -> Optional[Dict[str, Any]]:
    with _RUNTIME_LOCK:
        snapshots = dict(_RUNTIME_STATE.get("stateSnapshots", {}))
    return snapshots.get(str(snapshot_id or "").strip())


def _delete_state_snapshot(snapshot_id: str) -> bool:
    sid = str(snapshot_id or "").strip()
    with _RUNTIME_LOCK:
        snapshots = dict(_RUNTIME_STATE.get("stateSnapshots", {}))
        order = list(_RUNTIME_STATE.get("stateSnapshotOrder", []))
        if sid not in snapshots:
            return False
        snapshots.pop(sid, None)
        order = [item for item in order if item != sid]
        _RUNTIME_STATE["stateSnapshots"] = snapshots
        _RUNTIME_STATE["stateSnapshotOrder"] = order
    return True


# Registers to include in state snapshots (covers x86 and x64 GP + flags).
_SNAPSHOT_REGISTERS_X86 = [
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags",
]
_SNAPSHOT_REGISTERS_X64 = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags",
]


def _detect_debuggee_bitness() -> int:
    """Return 32 or 64 depending on active debugger arch."""
    try:
        info = _get_active_debugger_info()
        arch = str(info.get("arch") or "").lower()
        return 32 if arch in ("x86", "x32") else 64
    except Exception:
        return 64


def _read_snapshot_registers() -> Dict[str, str]:
    bitness = _detect_debuggee_bitness()
    registers = (
        _SNAPSHOT_REGISTERS_X86 if bitness == 32 else _SNAPSHOT_REGISTERS_X64
    )
    regs: Dict[str, str] = {}
    for name in registers:
        try:
            value = RegisterGet(name)
        except Exception:
            continue
        # Normalize: x64dbg bridge may return raw str "0x..." or {"result": "0x..."}.
        if isinstance(value, dict):
            raw = value.get("result") or value.get("value") or ""
        else:
            raw = value
        raw_str = str(raw or "")
        if raw_str.startswith("0x"):
            regs[name] = raw_str
    return regs


def _sha256_file(path: str) -> Optional[str]:
    file_path = str(path or "").strip()
    if not file_path or not os.path.exists(file_path) or not os.path.isfile(file_path):
        return None
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _file_signature(path: str, include_hash: bool = True) -> Dict[str, Any]:
    file_path = str(path or "").strip()
    target = Path(file_path) if file_path else None
    exists = bool(target and target.exists())
    is_file = bool(target and target.is_file()) if exists else False
    stat = target.stat() if is_file else None
    return {
        "path": str(target) if target else file_path,
        "exists": exists,
        "isFile": is_file,
        "size": int(stat.st_size) if stat else None,
        "mtimeUtc": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
        if stat
        else None,
        "sha256": _sha256_file(str(target)) if include_hash and is_file else None,
    }


def _discover_source_root(explicit_root: str = "") -> Optional[Path]:
    def _bridge_path_for_root(root: Path) -> Optional[Path]:
        for relative in (("server", "x64dbg.py"), ("src", "x64dbg.py")):
            candidate = root.joinpath(*relative)
            if candidate.exists():
                return candidate
        return None

    candidates: List[Path] = []
    for raw in (
        explicit_root,
        os.getenv("X64DBG_MCP_SOURCE_ROOT", ""),
    ):
        if raw:
            candidates.append(Path(raw))
    current = Path(__file__).resolve()
    if current.parent.name in {"server", "src"}:
        candidates.append(current.parent.parent)
    candidates.extend([current.parent] + list(current.parents))
    seen: set[str] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        key = str(resolved).lower()
        if key in seen:
            continue
        seen.add(key)
        if _bridge_path_for_root(resolved):
            return resolved
    return None


def _resolve_bridge_artifact_paths(source_root: str = "") -> Dict[str, Any]:
    current = Path(__file__).resolve()
    home = Path.home()
    current_root = current.parent.parent if current.parent.name in {"server", "src"} else current.parent

    def _bridge_path_for_root(root: Path) -> Optional[Path]:
        for relative in (("server", "x64dbg.py"), ("src", "x64dbg.py")):
            candidate = root.joinpath(*relative)
            if candidate.exists():
                return candidate
        return None

    live_root = current_root
    for candidate_root in (
        current_root,
        home / "mcp-servers" / "x64dbg",
        home / "plugins" / "x64dbg-mcp",
        home / "plugins-disabled" / "x64dbg-mcp",
    ):
        if _bridge_path_for_root(candidate_root):
            live_root = candidate_root
            break
    live_bridge = _bridge_path_for_root(live_root) or current
    cache_bridge = (
        home
        / ".codex"
        / "plugins"
        / "cache"
        / "local-plugins"
        / "x64dbg-mcp"
        / "local"
        / "server"
        / "x64dbg.py"
    )
    source_dir = _discover_source_root(source_root)
    source_bridge = _bridge_path_for_root(source_dir) if source_dir else None
    vendor_dir = live_root / "vendor" / "MCP_Plugins"
    if not vendor_dir.exists() and source_dir:
        candidate_vendor = source_dir / "vendor" / "MCP_Plugins"
        if candidate_vendor.exists():
            vendor_dir = candidate_vendor
    runtime_x64 = None
    runtime_x86 = None
    install_x64 = _resolve_debugger_install_dir("x64")
    install_x86 = _resolve_debugger_install_dir("x86")
    if install_x64:
        runtime_x64 = Path(install_x64) / "plugins" / "MCPx64dbg.dp64"
    if install_x86:
        runtime_x86 = Path(install_x86) / "plugins" / "MCPx64dbg.dp32"
    return {
        "currentBridge": current,
        "sourceRoot": source_dir,
        "sourceBridge": source_bridge,
        "liveBridge": live_bridge,
        "cacheBridge": cache_bridge,
        "vendorDp64": vendor_dir / "MCPx64dbg.dp64",
        "vendorDp32": vendor_dir / "MCPx64dbg.dp32",
        "runtimeDp64": runtime_x64,
        "runtimeDp32": runtime_x86,
    }


def _compare_signatures(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "samePath": bool(
            str(left.get("path") or "").lower() == str(right.get("path") or "").lower()
        ),
        "sameSize": bool(
            left.get("size") is not None and left.get("size") == right.get("size")
        ),
        "sameSha256": bool(
            left.get("sha256") and left.get("sha256") == right.get("sha256")
        ),
        "leftExists": bool(left.get("exists")),
        "rightExists": bool(right.get("exists")),
    }


def _resolve_expression_value(expression: str) -> Optional[int]:
    raw = str(expression or "").strip()
    if not raw:
        return None
    value = MiscParseExpression(raw)
    parsed = _parse_int(value)
    if parsed is not None:
        return parsed
    batch = EvalBatch(json.dumps([raw]))
    if isinstance(batch, dict):
        items = batch.get("items") or []
        if items and isinstance(items[0], dict) and items[0].get("success"):
            return _parse_int(items[0].get("value"))
    return None


def _read_memory_bytes(expr: str, size: int) -> Dict[str, Any]:
    payload = ReadMemory(expr, int(size), ty="hex", max_chars=max(1024, int(size) * 2))
    if not isinstance(payload, dict) or not payload.get("ok"):
        return {
            "ok": False,
            "error": (payload or {}).get("error")
            if isinstance(payload, dict)
            else str(payload),
            "payload": payload,
        }
    raw_hex = str(payload.get("hex") or "")
    try:
        data = bytes.fromhex(raw_hex)
    except ValueError as exc:
        return {"ok": False, "error": f"Invalid hex payload: {exc}", "payload": payload}
    return {"ok": True, "bytes": data, "payload": payload}


def _decode_text_bytes(data: bytes, ty: str = "utf8", max_chars: int = 4096) -> str:
    limited = bytes(data[: max(0, int(max_chars))])
    flavor = str(ty or "utf8").strip().lower()
    if flavor == "utf16":
        return limited.decode("utf-16le", errors="replace").rstrip("\x00")
    if flavor == "ascii":
        return limited.decode("ascii", errors="replace").rstrip("\x00")
    if flavor == "bytes":
        return limited.hex()
    if flavor == "utf8":
        return limited.decode("utf-8", errors="replace").rstrip("\x00")
    return _decode_best_effort_bytes(limited).rstrip("\x00")


def _decode_pointer(data: bytes, offset: int, arch: str) -> Optional[int]:
    pointer_size = _pointer_size_for_arch(arch)
    end = offset + pointer_size
    if offset < 0 or end > len(data):
        return None
    fmt = "<Q" if pointer_size == 8 else "<I"
    return int(struct.unpack_from(fmt, data, offset)[0])


def _decode_u16(data: bytes, offset: int) -> Optional[int]:
    end = offset + 2
    if offset < 0 or end > len(data):
        return None
    return int(struct.unpack_from("<H", data, offset)[0])


def _decode_u32(data: bytes, offset: int) -> Optional[int]:
    end = offset + 4
    if offset < 0 or end > len(data):
        return None
    return int(struct.unpack_from("<I", data, offset)[0])


def _decode_u64(data: bytes, offset: int) -> Optional[int]:
    end = offset + 8
    if offset < 0 or end > len(data):
        return None
    return int(struct.unpack_from("<Q", data, offset)[0])


def _decode_i32(data: bytes, offset: int) -> Optional[int]:
    end = offset + 4
    if offset < 0 or end > len(data):
        return None
    return int(struct.unpack_from("<i", data, offset)[0])


def _decode_pointed_buffer(
    pointer_value: Optional[int], length: int, ty: str = "utf8", max_bytes: int = 4096
) -> Dict[str, Any]:
    if not pointer_value:
        return {
            "ok": False,
            "error": "Buffer pointer resolved to null",
            "ptr": pointer_value,
            "length": int(length),
        }
    safe_length = max(0, min(int(length), int(max_bytes)))
    payload = _read_memory_bytes(
        _normalize_hex(pointer_value) or hex(pointer_value), safe_length
    )
    if not payload.get("ok"):
        return {
            "ok": False,
            "ptr": pointer_value,
            "length": safe_length,
            "read": payload,
        }
    data = bytes(payload.get("bytes") or b"")
    return {
        "ok": True,
        "ptr": _normalize_hex(pointer_value) or hex(pointer_value),
        "length": safe_length,
        "hex": data.hex(),
        "text": _decode_text_bytes(data, ty=ty, max_chars=max_bytes),
        "read": payload.get("payload"),
    }


def _resolve_common_layout_name(layout: str) -> str:
    normalized = str(layout or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "unicode": "unicode_string",
        "wstring": "unicode_string",
        "unicode_string": "unicode_string",
        "ansi": "ansi_string",
        "cstring": "ansi_string",
        "ansi_string": "ansi_string",
        "filetime": "filetime",
        "sockaddr": "sockaddr",
        "rect": "rect",
        "ptr_len": "ptr_len",
        "ptr_len_cap": "ptr_len_cap",
        "rust_string": "rust_string",
        "rust_vec": "rust_vec",
        "cpp_string": "cpp_string_simple",
        "cpp_string_simple": "cpp_string_simple",
        "cpp_vector": "cpp_vector_simple",
        "cpp_vector_simple": "cpp_vector_simple",
    }
    return aliases.get(normalized, normalized)


def _decode_common_layout(
    layout: str,
    base_expr: str,
    layout_payload: Dict[str, Any],
    arch: str,
    ty: str,
    max_bytes: int,
) -> Dict[str, Any]:
    resolved_layout = _resolve_common_layout_name(layout)
    base_value = _resolve_expression_value(base_expr)
    if base_value is None:
        return {
            "ok": False,
            "layout": resolved_layout,
            "error": f"Could not resolve base expression: {base_expr}",
        }
    base_hex = _normalize_hex(base_value) or hex(base_value)
    pointer_size = _pointer_size_for_arch(arch)

    if resolved_layout in ("unicode_string", "ansi_string"):
        buffer_offset_default = 8 if arch == "x64" else 4
        buffer_offset = int(layout_payload.get("bufferOffset", buffer_offset_default))
        length_offset = int(layout_payload.get("lengthOffset", 0))
        max_length_offset = int(layout_payload.get("maximumLengthOffset", 2))
        header_size = max(buffer_offset + pointer_size, max_length_offset + 2)
        raw = _read_memory_bytes(base_hex, header_size)
        if not raw.get("ok"):
            return {
                "ok": False,
                "layout": resolved_layout,
                "baseAddr": base_hex,
                "error": raw.get("error"),
                "read": raw,
            }
        header = bytes(raw.get("bytes") or b"")
        length_value = _decode_u16(header, length_offset) or 0
        maximum_length = _decode_u16(header, max_length_offset) or 0
        buffer_value = _decode_pointer(header, buffer_offset, arch)
        text_ty = "utf16" if resolved_layout == "unicode_string" else ty
        buffer = _decode_pointed_buffer(
            buffer_value, length_value, ty=text_ty, max_bytes=max_bytes
        )
        return {
            "ok": bool(buffer.get("ok")),
            "layout": resolved_layout,
            "arch": arch,
            "baseAddr": base_hex,
            "length": int(length_value),
            "maximumLength": int(maximum_length),
            "buffer": buffer,
        }

    if resolved_layout == "filetime":
        raw = _read_memory_bytes(base_hex, 8)
        scalar_value = (
            _decode_u64(bytes(raw.get("bytes") or b""), 0) if raw.get("ok") else None
        )
        if scalar_value is None:
            scalar_value = base_value
        if scalar_value is None:
            return {
                "ok": False,
                "layout": resolved_layout,
                "error": "Could not decode FILETIME value",
                "baseAddr": base_hex,
            }
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        try:
            decoded_dt = epoch + timedelta(microseconds=(int(scalar_value) / 10.0))
            iso_value = decoded_dt.isoformat()
        except Exception:
            iso_value = None
        return {
            "ok": True,
            "layout": resolved_layout,
            "baseAddr": base_hex,
            "value": _normalize_hex(scalar_value) or hex(int(scalar_value)),
            "valueDecimal": int(scalar_value),
            "isoUtc": iso_value,
        }

    if resolved_layout == "sockaddr":
        safe_size = max(16, min(int(layout_payload.get("size", 28) or 28), 128))
        raw = _read_memory_bytes(base_hex, safe_size)
        if not raw.get("ok"):
            return {
                "ok": False,
                "layout": resolved_layout,
                "baseAddr": base_hex,
                "error": raw.get("error"),
                "read": raw,
            }
        data = bytes(raw.get("bytes") or b"")
        family = _decode_u16(data, 0) or 0
        port = int(struct.unpack_from(">H", data, 2)[0]) if len(data) >= 4 else 0
        result = {
            "ok": True,
            "layout": resolved_layout,
            "baseAddr": base_hex,
            "family": family,
            "port": port,
            "hex": data.hex(),
        }
        if family == 2 and len(data) >= 8:
            address = ipaddress.IPv4Address(data[4:8])
            result["familyName"] = "AF_INET"
            result["address"] = str(address)
        elif family == 23 and len(data) >= 28:
            address = ipaddress.IPv6Address(data[8:24])
            scope_id = _decode_u32(data, 24) or 0
            result["familyName"] = "AF_INET6"
            result["address"] = str(address)
            result["scopeId"] = scope_id
        else:
            result["familyName"] = f"AF_{family}"
        return result

    if resolved_layout == "rect":
        raw = _read_memory_bytes(base_hex, 16)
        if not raw.get("ok"):
            return {
                "ok": False,
                "layout": resolved_layout,
                "baseAddr": base_hex,
                "error": raw.get("error"),
                "read": raw,
            }
        data = bytes(raw.get("bytes") or b"")
        left = _decode_i32(data, 0) or 0
        top = _decode_i32(data, 4) or 0
        right = _decode_i32(data, 8) or 0
        bottom = _decode_i32(data, 12) or 0
        return {
            "ok": True,
            "layout": resolved_layout,
            "baseAddr": base_hex,
            "left": left,
            "top": top,
            "right": right,
            "bottom": bottom,
            "width": right - left,
            "height": bottom - top,
        }

    if resolved_layout in (
        "ptr_len",
        "ptr_len_cap",
        "rust_string",
        "rust_vec",
        "cpp_string_simple",
        "cpp_vector_simple",
    ):
        pointer_offset = int(layout_payload.get("ptrOffset", 0))
        length_offset = int(layout_payload.get("lengthOffset", pointer_size))
        capacity_offset = int(layout_payload.get("capacityOffset", pointer_size * 2))
        header_size = max(
            pointer_offset + pointer_size,
            length_offset + pointer_size,
            capacity_offset + pointer_size,
        )
        raw = _read_memory_bytes(base_hex, header_size)
        if not raw.get("ok"):
            return {
                "ok": False,
                "layout": resolved_layout,
                "baseAddr": base_hex,
                "error": raw.get("error"),
                "read": raw,
            }
        header = bytes(raw.get("bytes") or b"")
        pointer_value = _decode_pointer(header, pointer_offset, arch)
        length_value = _decode_pointer(header, length_offset, arch) or 0
        capacity_value = _decode_pointer(header, capacity_offset, arch)
        buffer = _decode_pointed_buffer(
            pointer_value, int(length_value), ty=ty, max_bytes=max_bytes
        )
        result = {
            "ok": bool(buffer.get("ok")),
            "layout": resolved_layout,
            "arch": arch,
            "baseAddr": base_hex,
            "ptr": _normalize_hex(pointer_value) if pointer_value is not None else None,
            "length": int(length_value),
            "capacity": int(capacity_value) if capacity_value is not None else None,
            "buffer": buffer,
        }
        return result

    return {
        "ok": False,
        "layout": resolved_layout,
        "baseAddr": base_hex,
        "error": f"Unsupported layout: {resolved_layout}",
    }


def _current_instruction(addr: Any) -> Optional[Dict[str, Any]]:
    normalized = _normalize_hex(addr)
    if not normalized:
        return None
    instructions = DisasmGetInstructionRange(normalized, 1)
    if isinstance(instructions, dict):
        items = instructions.get("instructions")
        if isinstance(items, list) and items:
            first = items[0]
            if isinstance(first, dict):
                return first
        if any(key in instructions for key in ("address", "instruction", "size")):
            return instructions
    elif isinstance(instructions, list) and instructions:
        first = instructions[0]
        if isinstance(first, dict):
            return first
    return None


def _extract_scalar_value(item: Any) -> Any:
    if isinstance(item, dict):
        if "value" in item:
            return item.get("value")
        if "text" in item:
            return item.get("text")
    return item


def _summarize_trace_entries(
    entries: List[Dict[str, Any]],
    include_breakpoint_history: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    register_changes: Dict[str, int] = {}
    touched_ranges: Dict[str, int] = {}
    unique_rips: List[str] = []
    api_calls: List[str] = []
    branch_samples: List[Dict[str, Any]] = []
    call_count = 0
    jump_count = 0
    ret_count = 0

    def record_rip(value: Any) -> None:
        normalized = _normalize_hex(value)
        if normalized and normalized not in unique_rips:
            unique_rips.append(normalized)

    for entry in entries:
        before = entry.get("before", {}) if isinstance(entry, dict) else {}
        after = entry.get("after", {}) if isinstance(entry, dict) else {}
        before_state = before.get("state", {}) if isinstance(before, dict) else {}
        after_state = after.get("state", {}) if isinstance(after, dict) else {}
        before_ip = before_state.get("ip") or before_state.get("address")
        after_ip = after_state.get("ip") or after_state.get("address")
        record_rip(before_ip)
        record_rip(after_ip)

        before_regs = before.get("registers", {}) if isinstance(before, dict) else {}
        after_regs = after.get("registers", {}) if isinstance(after, dict) else {}
        for reg_name in sorted(set(before_regs.keys()) | set(after_regs.keys())):
            before_value = _extract_scalar_value(before_regs.get(reg_name))
            after_value = _extract_scalar_value(after_regs.get(reg_name))
            if before_value != after_value:
                register_changes[reg_name] = int(register_changes.get(reg_name, 0)) + 1

        before_ranges = before.get("ranges", []) if isinstance(before, dict) else []
        after_ranges = after.get("ranges", []) if isinstance(after, dict) else []
        for idx, after_range in enumerate(after_ranges):
            before_range = before_ranges[idx] if idx < len(before_ranges) else {}
            label = str(
                after_range.get("label") or before_range.get("label") or f"range{idx}"
            )
            before_hex = str(before_range.get("hex") or "")
            after_hex = str(after_range.get("hex") or "")
            if before_hex != after_hex:
                touched_ranges[label] = int(touched_ranges.get(label, 0)) + 1

        before_instruction = (
            entry.get("beforeInstruction") if isinstance(entry, dict) else None
        )
        instruction_text = ""
        if isinstance(before_instruction, dict):
            instruction_text = str(
                before_instruction.get("instruction")
                or before_instruction.get("text")
                or ""
            )
        lower_instruction = instruction_text.lower()
        if lower_instruction.startswith("call"):
            call_count += 1
            if before_instruction.get("comment"):
                api_calls.append(str(before_instruction.get("comment")))
        elif lower_instruction.startswith(
            ("jmp", "jz", "jnz", "je", "jne", "ja", "jb", "jg", "jl", "jo", "js")
        ):
            jump_count += 1
            branch_samples.append(
                {
                    "from": _normalize_hex(before_ip),
                    "to": _normalize_hex(after_ip),
                    "instruction": instruction_text,
                }
            )
        elif lower_instruction.startswith("ret"):
            ret_count += 1

    breakpoint_hits = include_breakpoint_history or []
    if breakpoint_hits:
        for entry in breakpoint_hits:
            instruction = entry.get("instruction") if isinstance(entry, dict) else None
            if isinstance(instruction, dict) and instruction.get("comment"):
                api_calls.append(str(instruction.get("comment")))

    unique_api_calls: List[str] = []
    for item in api_calls:
        cleaned = str(item or "").strip()
        if cleaned and cleaned not in unique_api_calls:
            unique_api_calls.append(cleaned)

    return {
        "entryCount": len(entries),
        "uniqueRipCount": len(unique_rips),
        "uniqueRips": unique_rips[:32],
        "registerChanges": [
            {"name": key, "count": value}
            for key, value in sorted(
                register_changes.items(), key=lambda item: (-item[1], item[0])
            )[:24]
        ],
        "touchedBuffers": [
            {"label": key, "count": value}
            for key, value in sorted(
                touched_ranges.items(), key=lambda item: (-item[1], item[0])
            )[:24]
        ],
        "callCount": call_count,
        "jumpCount": jump_count,
        "retCount": ret_count,
        "apiCalls": unique_api_calls[:24],
        "branches": branch_samples[:12],
        "breakpointCaptureCount": len(breakpoint_hits),
    }


def _normalize_memory_breakpoint_type(
    access_type: str, singleshot: bool = False
) -> str:
    normalized = str(access_type or "write").strip().lower()
    mapping = {
        "write": "w",
        "w": "w",
        "read": "r",
        "r": "r",
        "execute": "x",
        "x": "x",
        "access": "a",
        "a": "a",
    }
    base = mapping.get(normalized, "w")
    return f"{base}ss" if singleshot else base


def _memory_breakpoint_name(addr: str, size: int) -> str:
    normalized = re.sub(r"[^0-9a-fA-F]", "", str(addr or ""))[-12:] or "0"
    return f"mw_{normalized}_{int(size)}_{int(time.time() * 1000) % 1000000}"


def _next_window_capture_id() -> str:
    with _RUNTIME_LOCK:
        seq = int(_RUNTIME_STATE.get("windowCaptureSeq", 0) or 0) + 1
        _RUNTIME_STATE["windowCaptureSeq"] = seq
    return f"winsnap-{seq}"


def _store_window_capture(
    capture: Dict[str, Any], pixel_bytes: bytes
) -> Dict[str, Any]:
    capture_id = _next_window_capture_id()
    record = dict(capture)
    record["captureId"] = capture_id
    record["_pixelBytes"] = bytes(pixel_bytes)
    with _RUNTIME_LOCK:
        captures = dict(_RUNTIME_STATE.get("windowCaptures", {}))
        order = list(_RUNTIME_STATE.get("windowCaptureOrder", []))
        captures[capture_id] = record
        order.append(capture_id)
        if len(order) > 24:
            stale = order[:-24]
            order = order[-24:]
            for item in stale:
                captures.pop(item, None)
        _RUNTIME_STATE["windowCaptures"] = captures
        _RUNTIME_STATE["windowCaptureOrder"] = order
    return record


def _get_window_capture(capture_id: str) -> Optional[Dict[str, Any]]:
    with _RUNTIME_LOCK:
        captures = dict(_RUNTIME_STATE.get("windowCaptures", {}))
    return captures.get(str(capture_id or "").strip())


def _window_capture_public(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in dict(record or {}).items()
        if not str(key).startswith("_")
    }


def _iter_changed_byte_offsets(before_hex: str, after_hex: str) -> List[int]:
    before = bytes.fromhex(str(before_hex or ""))
    after = bytes.fromhex(str(after_hex or ""))
    limit = min(len(before), len(after))
    changed = [index for index in range(limit) if before[index] != after[index]]
    if len(before) != len(after):
        changed.extend(range(limit, max(len(before), len(after))))
    return changed


def _summarize_hex_changes(
    before_hex: str, after_hex: str, max_changes: int = 32
) -> Dict[str, Any]:
    before = bytes.fromhex(str(before_hex or ""))
    after = bytes.fromhex(str(after_hex or ""))
    offsets = _iter_changed_byte_offsets(before_hex, after_hex)
    changes: List[Dict[str, Any]] = []
    for offset in offsets[: max(1, int(max_changes))]:
        before_byte = before[offset] if offset < len(before) else None
        after_byte = after[offset] if offset < len(after) else None
        changes.append(
            {
                "offset": offset,
                "before": None if before_byte is None else f"0x{before_byte:02x}",
                "after": None if after_byte is None else f"0x{after_byte:02x}",
            }
        )
    return {
        "changed": bool(offsets),
        "changedCount": len(offsets),
        "changes": changes,
    }


def _send_input_records(inputs: List[INPUT]) -> int:
    if not inputs:
        return 0
    array = (INPUT * len(inputs))(*inputs)
    sent = user32.SendInput(len(array), array, ctypes.sizeof(INPUT))
    if sent == 0:
        raise OSError(f"SendInput failed: {ctypes.get_last_error()}")
    return int(sent)


def _unicode_key_inputs(ch: str) -> List[INPUT]:
    down = INPUT(
        type=INPUT_KEYBOARD, ki=KEYBDINPUT(0, ord(ch), KEYEVENTF_UNICODE, 0, 0)
    )
    up = INPUT(
        type=INPUT_KEYBOARD,
        ki=KEYBDINPUT(0, ord(ch), KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, 0, 0),
    )
    return [down, up]


def _extended_vk(vk: int) -> bool:
    return int(vk) in {
        VK_LEFT,
        VK_RIGHT,
        VK_UP,
        VK_DOWN,
        VK_HOME,
        VK_END,
        VK_PRIOR,
        VK_NEXT,
        VK_INSERT,
        VK_DELETE,
    }


def _vk_key_inputs(vk: int, event: str = "tap") -> List[INPUT]:
    normalized_event = str(event or "tap").strip().lower()
    scan = user32.MapVirtualKeyW(vk, 0)
    flags = KEYEVENTF_EXTENDEDKEY if _extended_vk(vk) else 0
    down = INPUT(type=INPUT_KEYBOARD, ki=KEYBDINPUT(vk, scan, flags, 0, 0))
    up = INPUT(
        type=INPUT_KEYBOARD, ki=KEYBDINPUT(vk, scan, flags | KEYEVENTF_KEYUP, 0, 0)
    )
    if normalized_event == "down":
        return [down]
    if normalized_event == "up":
        return [up]
    return [down, up]


def _scan_key_inputs(vk: int, event: str = "tap") -> List[INPUT]:
    normalized_event = str(event or "tap").strip().lower()
    scan = user32.MapVirtualKeyW(vk, 0)
    flags = KEYEVENTF_SCANCODE | (KEYEVENTF_EXTENDEDKEY if _extended_vk(vk) else 0)
    down = INPUT(type=INPUT_KEYBOARD, ki=KEYBDINPUT(0, scan, flags, 0, 0))
    up = INPUT(
        type=INPUT_KEYBOARD, ki=KEYBDINPUT(0, scan, flags | KEYEVENTF_KEYUP, 0, 0)
    )
    if normalized_event == "down":
        return [down]
    if normalized_event == "up":
        return [up]
    return [down, up]


def _mouse_inputs(flags: int, data: int = 0) -> List[INPUT]:
    return [INPUT(type=INPUT_MOUSE, mi=MOUSEINPUT(0, 0, int(data), flags, 0, 0))]


def _mouse_wheel_inputs(delta: int) -> List[INPUT]:
    if int(delta) == 0:
        return []
    return _mouse_inputs(MOUSEEVENTF_WHEEL, data=int(delta))


def _mouse_button_flags(button: str = "left") -> tuple[int, int, str]:
    button_name = str(button or "left").strip().lower()
    if button_name == "right":
        return MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, "right"
    return MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, "left"


def _click_window_relative(
    hwnd: int,
    x: int,
    y: int,
    button: str = "left",
    double_click: bool = False,
    client_only: bool = True,
) -> Dict[str, Any]:
    bounds = _window_bounds(hwnd, client_only=client_only)
    target_x = int(bounds["left"]) + int(x)
    target_y = int(bounds["top"]) + int(y)
    if not user32.SetCursorPos(target_x, target_y):
        raise OSError(f"SetCursorPos failed: {ctypes.get_last_error()}")
    down_flag, up_flag, button_name = _mouse_button_flags(button)
    click_count = 2 if double_click else 1
    total_sent = 0
    for _ in range(click_count):
        total_sent += _send_input_records(_mouse_inputs(down_flag))
        total_sent += _send_input_records(_mouse_inputs(up_flag))
    return {
        "ok": True,
        "hwnd": f"0x{int(hwnd):X}",
        "x": target_x,
        "y": target_y,
        "relativeX": int(x),
        "relativeY": int(y),
        "button": button_name,
        "doubleClick": bool(double_click),
        "eventsSent": total_sent,
        "clientOnly": bool(client_only),
    }


def _drag_window_relative(
    hwnd: int,
    start_x: int,
    start_y: int,
    end_x: int,
    end_y: int,
    button: str = "left",
    client_only: bool = True,
    steps: int = 18,
    step_delay_ms: int = 8,
) -> Dict[str, Any]:
    bounds = _window_bounds(hwnd, client_only=client_only)
    abs_start_x = int(bounds["left"]) + int(start_x)
    abs_start_y = int(bounds["top"]) + int(start_y)
    abs_end_x = int(bounds["left"]) + int(end_x)
    abs_end_y = int(bounds["top"]) + int(end_y)
    down_flag, up_flag, button_name = _mouse_button_flags(button)
    safe_steps = max(1, min(int(steps), 128))
    if not user32.SetCursorPos(abs_start_x, abs_start_y):
        raise OSError(f"SetCursorPos(start) failed: {ctypes.get_last_error()}")
    total_sent = _send_input_records(_mouse_inputs(down_flag))
    for step in range(1, safe_steps + 1):
        t = step / float(safe_steps)
        target_x = round(abs_start_x + ((abs_end_x - abs_start_x) * t))
        target_y = round(abs_start_y + ((abs_end_y - abs_start_y) * t))
        if not user32.SetCursorPos(int(target_x), int(target_y)):
            raise OSError(f"SetCursorPos(move) failed: {ctypes.get_last_error()}")
        if step_delay_ms > 0:
            time.sleep(max(0, int(step_delay_ms)) / 1000.0)
    total_sent += _send_input_records(_mouse_inputs(up_flag))
    return {
        "ok": True,
        "hwnd": f"0x{int(hwnd):X}",
        "start": {"x": abs_start_x, "y": abs_start_y},
        "end": {"x": abs_end_x, "y": abs_end_y},
        "relativeStart": {"x": int(start_x), "y": int(start_y)},
        "relativeEnd": {"x": int(end_x), "y": int(end_y)},
        "steps": safe_steps,
        "button": button_name,
        "eventsSent": total_sent,
        "clientOnly": bool(client_only),
    }


def _client_rect_to_screen(hwnd: int) -> Dict[str, int]:
    rect = RECT()
    if not user32.GetClientRect(hwnd, ctypes.byref(rect)):
        raise OSError(f"GetClientRect failed: {ctypes.get_last_error()}")
    top_left = POINT(int(rect.left), int(rect.top))
    bottom_right = POINT(int(rect.right), int(rect.bottom))
    if not user32.ClientToScreen(hwnd, ctypes.byref(top_left)):
        raise OSError(f"ClientToScreen(top-left) failed: {ctypes.get_last_error()}")
    if not user32.ClientToScreen(hwnd, ctypes.byref(bottom_right)):
        raise OSError(f"ClientToScreen(bottom-right) failed: {ctypes.get_last_error()}")
    return {
        "left": int(top_left.x),
        "top": int(top_left.y),
        "right": int(bottom_right.x),
        "bottom": int(bottom_right.y),
        "width": max(0, int(bottom_right.x) - int(top_left.x)),
        "height": max(0, int(bottom_right.y) - int(top_left.y)),
    }


def _window_bounds(hwnd: int, client_only: bool = True) -> Dict[str, int]:
    if client_only:
        return _client_rect_to_screen(hwnd)
    rect = RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        raise OSError(f"GetWindowRect failed: {ctypes.get_last_error()}")
    return _rect_to_dict(rect)


def _resolve_target_window(
    pid: int = 0,
    hwnd: str = "",
    title_contains: str = "",
    class_name: str = "",
    visible_only: bool = True,
    timeout_ms: int = 0,
) -> Dict[str, Any]:
    parsed_hwnd = _parse_hwnd_value(hwnd) if hwnd else 0
    if parsed_hwnd:
        target_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(parsed_hwnd, ctypes.byref(target_pid))
        return {
            "pid": int(target_pid.value),
            "hwnd": int(parsed_hwnd),
            "window": {
                "hwnd": f"0x{int(parsed_hwnd):X}",
                "title": _get_window_text(parsed_hwnd),
                "className": _get_class_name(parsed_hwnd),
                "visible": bool(user32.IsWindowVisible(parsed_hwnd)),
                "enabled": bool(user32.IsWindowEnabled(parsed_hwnd)),
                "rect": _window_bounds(parsed_hwnd, client_only=False),
            },
        }
    target_pid = 0
    try:
        target_pid = _infer_debuggee_pid(pid)
    except Exception:
        if not pid:
            retarget_snapshot = _collect_retarget_gui_snapshot(
                title_contains=title_contains,
                class_name=class_name,
                visible_only=visible_only,
                include_children=False,
                max_depth=1,
            )
            if retarget_snapshot:
                window = _select_top_window(
                    retarget_snapshot,
                    title_contains=title_contains,
                    class_name=class_name,
                )
                if window:
                    return {
                        "pid": int(retarget_snapshot.get("pid") or 0),
                        "hwnd": _parse_hwnd_value(window.get("hwnd")),
                        "window": window,
                        "snapshot": retarget_snapshot,
                        "retarget": retarget_snapshot.get("retarget"),
                    }
        raise
    wait_ms = max(0, int(timeout_ms))
    if wait_ms:
        hwnd_value = _wait_for_top_window(target_pid, timeout_ms=wait_ms)
        if hwnd_value:
            window = _collect_window_node(
                hwnd_value,
                pid=target_pid,
                parent_hwnd=0,
                include_children=False,
                visible_only=visible_only,
                max_depth=0,
                depth=0,
            )
            if not (title_contains or class_name) and _is_noise_window_node(window):
                window = None
            if (
                window
                and (
                    not title_contains
                    or _text_matches(str(window.get("title", "")), title_contains)
                )
                and (
                    not class_name
                    or _text_matches(str(window.get("className", "")), class_name)
                )
            ):
                return {"pid": target_pid, "hwnd": int(hwnd_value), "window": window}
    snapshot = _collect_gui_snapshot(
        pid=target_pid,
        include_children=False,
        visible_only=visible_only,
        max_depth=1,
    )
    noise_only_available = bool(
        ((snapshot.get("summary") or {}) if isinstance(snapshot, dict) else {}).get(
            "topWindowCount"
        )
    ) and not bool(
        ((snapshot.get("summary") or {}) if isinstance(snapshot, dict) else {}).get(
            "meaningfulTopWindowCount"
        )
    )
    window = _select_top_window(
        snapshot, title_contains=title_contains, class_name=class_name
    )
    if window:
        return {
            "pid": target_pid,
            "hwnd": _parse_hwnd_value(window.get("hwnd")),
            "window": window,
            "snapshot": snapshot,
        }
    if not (title_contains or class_name):
        state = _build_debug_state(
            include_console=False, include_callstack=False, max_console_chars=0
        )
        console_pid = int(state.get("conhostPid") or 0)
        if console_pid and console_pid != target_pid:
            console_snapshot = _collect_gui_snapshot(
                pid=console_pid,
                include_children=False,
                visible_only=visible_only,
                max_depth=1,
            )
            console_window = _select_top_window(console_snapshot)
            if console_window:
                return {
                    "pid": console_pid,
                    "hwnd": _parse_hwnd_value(console_window.get("hwnd")),
                    "window": console_window,
                    "snapshot": console_snapshot,
                    "fallbackConsoleHost": True,
                }
    hwnd_value = (
        _wait_for_top_window(target_pid, timeout_ms=max(0, wait_ms))
        if wait_ms
        else _find_top_window_for_pid(target_pid)
    )
    if hwnd_value:
        window = _collect_window_node(
            hwnd_value,
            pid=target_pid,
            parent_hwnd=0,
            include_children=False,
            visible_only=visible_only,
            max_depth=0,
            depth=0,
        )
        if not (title_contains or class_name) and _is_noise_window_node(window):
            window = None
        if window:
            return {"pid": target_pid, "hwnd": int(hwnd_value), "window": window}
    if noise_only_available and not (title_contains or class_name):
        raise RuntimeError(
            "Only noise or placeholder windows are available for the requested debuggee"
        )
    raise RuntimeError("No target window was found for the requested debuggee")


def _wait_for_resolved_window_ready(
    pid: int = 0,
    hwnd: str = "",
    title_contains: str = "",
    class_name: str = "",
    visible_only: bool = True,
    timeout_ms: int = 5000,
    poll_ms: int = 100,
    stable_polls: int = 2,
    require_input_idle: bool = True,
    client_only: bool = False,
) -> Dict[str, Any]:
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    last_target: Dict[str, Any] = {}
    last_idle: Dict[str, Any] = {}
    last_stable: Dict[str, Any] = {}
    saw_noise_only = False
    while time.time() <= deadline:
        remaining_ms = max(100, int((deadline - time.time()) * 1000))
        try:
            last_target = _resolve_target_window(
                pid=pid,
                hwnd=hwnd,
                title_contains=title_contains,
                class_name=class_name,
                visible_only=visible_only,
                timeout_ms=min(remaining_ms, max(300, int(poll_ms) * 2)),
            )
        except Exception as e:
            if "noise or placeholder windows" in str(e).lower():
                saw_noise_only = True
            time.sleep(max(20, int(poll_ms)) / 1000.0)
            continue
        target_pid = int(last_target.get("pid") or 0)
        if require_input_idle and target_pid:
            last_idle = _wait_for_process_input_idle(
                target_pid, timeout_ms=min(remaining_ms, 1200)
            )
            if last_idle.get("supported") and not last_idle.get("ready"):
                time.sleep(max(20, int(poll_ms)) / 1000.0)
                continue
        target_hwnd = _parse_hwnd_value(last_target.get("hwnd"))
        if not target_hwnd:
            time.sleep(max(20, int(poll_ms)) / 1000.0)
            continue
        last_stable = _wait_for_window_stable(
            target_hwnd,
            timeout_ms=min(remaining_ms, max(600, int(poll_ms) * 6)),
            poll_ms=max(20, int(poll_ms)),
            stable_polls=stable_polls,
            client_only=client_only,
        )
        if last_stable.get("ok"):
            return {
                "ok": True,
                "timedOut": False,
                "pid": target_pid,
                "hwnd": f"0x{target_hwnd:X}",
                "window": {
                    **dict(last_target.get("window") or {}),
                    **dict(last_stable.get("window") or {}),
                    "hwnd": f"0x{target_hwnd:X}",
                },
                "inputIdle": last_idle,
                "stability": last_stable,
            }
        time.sleep(max(20, int(poll_ms)) / 1000.0)
    return {
        "ok": False,
        "timedOut": True,
        "pid": int((last_target or {}).get("pid") or 0),
        "hwnd": f"0x{int((last_target or {}).get('hwnd') or 0):X}"
        if int((last_target or {}).get("hwnd") or 0)
        else None,
        "window": (last_target or {}).get("window"),
        "inputIdle": last_idle,
        "stability": last_stable,
        "reason": "Only noise or placeholder windows became available."
        if saw_noise_only
        else "Timed out waiting for a ready/stable debuggee window.",
    }


def _capture_screen_region(left: int, top: int, width: int, height: int) -> bytes:
    if width <= 0 or height <= 0:
        raise RuntimeError(
            "Window capture bounds must have a positive width and height"
        )
    screen_dc = user32.GetDC(0)
    if not screen_dc:
        raise OSError(f"GetDC failed: {ctypes.get_last_error()}")
    mem_dc = 0
    bitmap = 0
    previous = 0
    try:
        mem_dc = gdi32.CreateCompatibleDC(screen_dc)
        if not mem_dc:
            raise OSError(f"CreateCompatibleDC failed: {ctypes.get_last_error()}")
        bitmap = gdi32.CreateCompatibleBitmap(screen_dc, int(width), int(height))
        if not bitmap:
            raise OSError(f"CreateCompatibleBitmap failed: {ctypes.get_last_error()}")
        previous = gdi32.SelectObject(mem_dc, bitmap)
        if not previous:
            raise OSError(f"SelectObject failed: {ctypes.get_last_error()}")
        if not gdi32.BitBlt(
            mem_dc,
            0,
            0,
            int(width),
            int(height),
            screen_dc,
            int(left),
            int(top),
            SRCCOPY,
        ):
            raise OSError(f"BitBlt failed: {ctypes.get_last_error()}")
        bmi = BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = int(width)
        bmi.bmiHeader.biHeight = -int(height)
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = BI_RGB
        bmi.bmiHeader.biSizeImage = int(width) * int(height) * 4
        pixel_buffer = ctypes.create_string_buffer(bmi.bmiHeader.biSizeImage)
        copied = gdi32.GetDIBits(
            mem_dc,
            bitmap,
            0,
            int(height),
            pixel_buffer,
            ctypes.byref(bmi),
            DIB_RGB_COLORS,
        )
        if copied == 0:
            raise OSError(f"GetDIBits failed: {ctypes.get_last_error()}")
        return pixel_buffer.raw[: int(width) * int(height) * 4]
    finally:
        if previous and mem_dc and bitmap:
            gdi32.SelectObject(mem_dc, previous)
        if bitmap:
            gdi32.DeleteObject(bitmap)
        if mem_dc:
            gdi32.DeleteDC(mem_dc)
        if screen_dc:
            user32.ReleaseDC(0, screen_dc)


def _write_bmp_file(path: str, width: int, height: int, pixel_bytes: bytes) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    info_header = struct.pack(
        "<IiiHHIIiiII",
        40,
        int(width),
        -int(height),
        1,
        32,
        BI_RGB,
        len(pixel_bytes),
        0,
        0,
        0,
        0,
    )
    file_size = 14 + len(info_header) + len(pixel_bytes)
    file_header = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, 14 + len(info_header))
    with open(path, "wb") as handle:
        handle.write(file_header)
        handle.write(info_header)
        handle.write(pixel_bytes)


def _capture_window_snapshot(
    pid: int = 0,
    hwnd: str = "",
    title_contains: str = "",
    class_name: str = "",
    client_only: bool = True,
    visible_only: bool = True,
    focus_window: bool = True,
    timeout_ms: int = 0,
    save_path: str = "",
) -> Dict[str, Any]:
    if timeout_ms:
        ready_target = _wait_for_resolved_window_ready(
            pid=pid,
            hwnd=hwnd,
            title_contains=title_contains,
            class_name=class_name,
            visible_only=visible_only,
            timeout_ms=timeout_ms,
            poll_ms=80,
            stable_polls=2,
            require_input_idle=True,
            client_only=client_only,
        )
        if ready_target.get("ok"):
            target = {
                "pid": int(ready_target.get("pid") or 0),
                "hwnd": _parse_hwnd_value(ready_target.get("hwnd")),
                "window": dict(ready_target.get("window") or {}),
            }
        else:
            target = _resolve_target_window(
                pid=pid,
                hwnd=hwnd,
                title_contains=title_contains,
                class_name=class_name,
                visible_only=visible_only,
                timeout_ms=timeout_ms,
            )
    else:
        target = _resolve_target_window(
            pid=pid,
            hwnd=hwnd,
            title_contains=title_contains,
            class_name=class_name,
            visible_only=visible_only,
            timeout_ms=timeout_ms,
        )
    target_hwnd = _parse_hwnd_value(target.get("hwnd"))
    if not target_hwnd:
        raise RuntimeError("No target hwnd was resolved for capture")
    if focus_window:
        _focus_window(target_hwnd)
        time.sleep(0.08)
    rect = _window_bounds(target_hwnd, client_only=client_only)
    if int(rect.get("width") or 0) <= 0 or int(rect.get("height") or 0) <= 0:
        fallback_rect = _window_bounds(target_hwnd, client_only=False)
        if (
            int(fallback_rect.get("width") or 0) > 0
            and int(fallback_rect.get("height") or 0) > 0
        ):
            rect = fallback_rect
    pixel_bytes = _capture_screen_region(
        rect["left"], rect["top"], rect["width"], rect["height"]
    )
    digest = hashlib.sha256(pixel_bytes).hexdigest()
    record = _store_window_capture(
        {
            "capturedAt": _now_iso(),
            "pid": int(target.get("pid") or 0),
            "hwnd": f"0x{target_hwnd:X}",
            "clientOnly": bool(client_only),
            "focused": bool(focus_window),
            "rect": rect,
            "width": int(rect["width"]),
            "height": int(rect["height"]),
            "byteCount": len(pixel_bytes),
            "pixelCount": int(rect["width"]) * int(rect["height"]),
            "sha256": digest,
            "windowTitle": str(
                (target.get("window") or {}).get("title")
                or _get_window_text(target_hwnd)
            ),
            "className": str(
                (target.get("window") or {}).get("className")
                or _get_class_name(target_hwnd)
            ),
            "savedPath": None,
        },
        pixel_bytes=pixel_bytes,
    )
    if save_path:
        target_path = os.path.abspath(save_path)
        _write_bmp_file(target_path, record["width"], record["height"], pixel_bytes)
        record["savedPath"] = target_path
        with _RUNTIME_LOCK:
            captures = dict(_RUNTIME_STATE.get("windowCaptures", {}))
            captures[record["captureId"]] = record
            _RUNTIME_STATE["windowCaptures"] = captures
    return _window_capture_public(record)


def _compare_window_capture_records(
    before: Dict[str, Any], after: Dict[str, Any], max_changes: int = 16
) -> Dict[str, Any]:
    before_bytes = bytes(before.get("_pixelBytes") or b"")
    after_bytes = bytes(after.get("_pixelBytes") or b"")
    width_before = int(before.get("width") or 0)
    height_before = int(before.get("height") or 0)
    width_after = int(after.get("width") or 0)
    height_after = int(after.get("height") or 0)
    comparable_pixels = min(len(before_bytes), len(after_bytes)) // 4
    changed_pixels = 0
    samples: List[Dict[str, Any]] = []
    for index in range(comparable_pixels):
        offset = index * 4
        before_pixel = before_bytes[offset : offset + 4]
        after_pixel = after_bytes[offset : offset + 4]
        if before_pixel == after_pixel:
            continue
        changed_pixels += 1
        if len(samples) < max(1, int(max_changes)):
            x = index % max(1, width_after or width_before or 1)
            y = index // max(1, width_after or width_before or 1)
            samples.append(
                {
                    "pixelIndex": index,
                    "x": x,
                    "y": y,
                    "before": before_pixel.hex(),
                    "after": after_pixel.hex(),
                }
            )
    pixel_delta = abs((width_before * height_before) - (width_after * height_after))
    changed_pixels += pixel_delta
    pixel_count = max(width_before * height_before, width_after * height_after, 0)
    return {
        "ok": True,
        "beforeCaptureId": before.get("captureId"),
        "afterCaptureId": after.get("captureId"),
        "hashChanged": str(before.get("sha256") or "")
        != str(after.get("sha256") or ""),
        "changedPixels": changed_pixels,
        "pixelCount": pixel_count,
        "changeRatio": round((changed_pixels / pixel_count), 6) if pixel_count else 0.0,
        "beforeRect": before.get("rect"),
        "afterRect": after.get("rect"),
        "samples": samples,
    }


def _modifier_vk(name: str) -> Optional[int]:
    mapping = {
        "CTRL": VK_CONTROL,
        "CONTROL": VK_CONTROL,
        "ALT": VK_MENU,
        "SHIFT": VK_SHIFT,
    }
    return mapping.get(str(name or "").strip().upper())


def _named_vk(name: str) -> Optional[int]:
    token = str(name or "").strip().upper()
    mapping = {
        "ENTER": VK_RETURN,
        "RETURN": VK_RETURN,
        "TAB": VK_TAB,
        "ESC": VK_ESCAPE,
        "ESCAPE": VK_ESCAPE,
        "SPACE": VK_SPACE,
        "LEFT": VK_LEFT,
        "RIGHT": VK_RIGHT,
        "UP": VK_UP,
        "DOWN": VK_DOWN,
        "HOME": VK_HOME,
        "END": VK_END,
        "PAGEUP": VK_PRIOR,
        "PGUP": VK_PRIOR,
        "PAGEDOWN": VK_NEXT,
        "PGDN": VK_NEXT,
        "INSERT": VK_INSERT,
        "INS": VK_INSERT,
        "DELETE": VK_DELETE,
        "DEL": VK_DELETE,
        "BACKSPACE": VK_BACK,
    }
    if token in mapping:
        return mapping[token]
    if len(token) == 2 and token.startswith("F") and token[1].isdigit():
        return 0x70 + int(token[1]) - 1
    if len(token) == 3 and token.startswith("F") and token[1:].isdigit():
        value = int(token[1:])
        if 1 <= value <= 12:
            return 0x70 + value - 1
    if len(token) == 1:
        return ord(token)
    return None


def _send_key_combo(
    combo: str, delay_ms: int = 0, mode: str = "auto", event: str = "tap"
) -> int:
    parts = [part.strip() for part in str(combo or "").split("+") if part.strip()]
    if not parts:
        return 0
    normalized_mode = str(mode or "auto").strip().lower()
    normalized_event = str(event or "tap").strip().lower()
    modifiers = [_modifier_vk(part) for part in parts[:-1]]
    modifiers = [value for value in modifiers if value]
    terminal = parts[-1]
    standalone_modifier = _modifier_vk(terminal)
    named_vk = _named_vk(terminal)
    if (
        not modifiers
        and len(terminal) == 1
        and terminal not in ("\r", "\n", "\t")
        and normalized_mode in ("auto", "unicode")
        and normalized_event == "tap"
    ):
        sent = _send_input_records(_unicode_key_inputs(terminal))
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
        return sent
    key_vk = named_vk or standalone_modifier
    if key_vk is None and len(terminal) == 1 and normalized_mode in ("vk", "scan"):
        key_vk = _named_vk(terminal)
        if key_vk is None:
            vkscan = int(user32.VkKeyScanW(terminal))
            if vkscan != -1:
                key_vk = vkscan & 0xFF
                shift_state = (vkscan >> 8) & 0xFF
                if shift_state & 0x01 and VK_SHIFT not in modifiers:
                    modifiers.insert(0, VK_SHIFT)
                if shift_state & 0x02 and VK_CONTROL not in modifiers:
                    modifiers.insert(0, VK_CONTROL)
                if shift_state & 0x04 and VK_MENU not in modifiers:
                    modifiers.insert(0, VK_MENU)
    if key_vk is None:
        raise RuntimeError(f"Unsupported key combo: {combo}")
    modifier_down = lambda vk: INPUT(
        type=INPUT_KEYBOARD, ki=KEYBDINPUT(vk, user32.MapVirtualKeyW(vk, 0), 0, 0, 0)
    )
    modifier_up = lambda vk: INPUT(
        type=INPUT_KEYBOARD,
        ki=KEYBDINPUT(vk, user32.MapVirtualKeyW(vk, 0), KEYEVENTF_KEYUP, 0, 0),
    )
    if normalized_mode == "scan":
        terminal_inputs = _scan_key_inputs(key_vk, event=normalized_event)
    else:
        terminal_inputs = _vk_key_inputs(key_vk, event=normalized_event)
    sent = 0
    if normalized_event != "up":
        for modifier in modifiers:
            sent += _send_input_records([modifier_down(modifier)])
    sent += _send_input_records(terminal_inputs)
    if normalized_event != "down":
        for modifier in reversed(modifiers):
            sent += _send_input_records([modifier_up(modifier)])
    if delay_ms > 0:
        time.sleep(delay_ms / 1000.0)
    return sent


def _build_console_key_event(ch: str, key_down: bool) -> INPUT_RECORD:
    record = INPUT_RECORD()
    record.EventType = KEY_EVENT
    record.KeyEvent.bKeyDown = bool(key_down)
    record.KeyEvent.wRepeatCount = 1
    record.KeyEvent.uChar.UnicodeChar = ch
    if ch == "\r":
        vk = VK_RETURN
        modifiers = 0
    else:
        vkscan = user32.VkKeyScanW(ch)
        vk = 0 if vkscan == -1 else vkscan & 0xFF
        shift_state = 0 if vkscan == -1 else (vkscan >> 8) & 0xFF
        modifiers = 0
        if shift_state & 0x01:
            modifiers |= SHIFT_PRESSED
        if shift_state & 0x02:
            modifiers |= LEFT_CTRL_PRESSED
        if shift_state & 0x04:
            modifiers |= LEFT_ALT_PRESSED
    record.KeyEvent.wVirtualKeyCode = vk
    record.KeyEvent.wVirtualScanCode = user32.MapVirtualKeyW(vk, 0) if vk else 0
    record.KeyEvent.dwControlKeyState = modifiers
    return record


def _clean_console_text(text: str) -> str:
    cleaned = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    lines = [line.rstrip() for line in cleaned.split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def _last_nonempty_console_lines(text: str, limit: int = 5) -> List[str]:
    cleaned = _clean_console_text(text)
    return [line for line in cleaned.splitlines() if line.strip()][-limit:]


def _attach_console(target_pid: int, conhost_pid: Optional[int] = None) -> int:
    candidates: List[int] = []
    for value in (target_pid, conhost_pid):
        if value and int(value) not in candidates:
            candidates.append(int(value))
    errors: List[str] = []
    for candidate in candidates:
        kernel32.FreeConsole()
        ctypes.set_last_error(0)
        if kernel32.AttachConsole(candidate):
            return candidate
        err = ctypes.get_last_error()
        errors.append(f"{candidate}:{err}")
    raise OSError(f"AttachConsole failed ({', '.join(errors)})")


def _read_console_text_once(
    target_pid: int, max_chars: int, conhost_pid: Optional[int] = None
) -> Dict[str, Any]:
    attached_pid = _attach_console(target_pid, conhost_pid=conhost_pid)

    handle = kernel32.CreateFileW(
        "CONOUT$",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if handle in (0, INVALID_HANDLE_VALUE):
        err = ctypes.get_last_error()
        kernel32.FreeConsole()
        raise OSError(f"CreateFileW(CONOUT$) failed: {err}")

    try:
        info = CONSOLE_SCREEN_BUFFER_INFO()
        if not kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(info)):
            err = ctypes.get_last_error()
            raise OSError(f"GetConsoleScreenBufferInfo failed: {err}")

        width = max(0, int(info.srWindow.Right) - int(info.srWindow.Left) + 1)
        height = max(0, int(info.srWindow.Bottom) - int(info.srWindow.Top) + 1)
        remaining = max(0, int(max_chars))
        lines: List[str] = []
        for y in range(int(info.srWindow.Top), int(info.srWindow.Bottom) + 1):
            if remaining <= 0:
                break
            read_len = min(width, remaining)
            if read_len <= 0:
                break
            buf = ctypes.create_unicode_buffer(read_len + 1)
            chars_read = wintypes.DWORD()
            origin = COORD(int(info.srWindow.Left), y)
            ok = kernel32.ReadConsoleOutputCharacterW(
                handle, buf, read_len, origin, ctypes.byref(chars_read)
            )
            err = ctypes.get_last_error()
            if not ok:
                raise OSError(f"ReadConsoleOutputCharacterW failed: {err}")
            lines.append("".join(buf[: int(chars_read.value)]).rstrip())
            remaining -= read_len

        text = _clean_console_text("\n".join(lines))
        return {
            "text": text,
            "lines": _last_nonempty_console_lines(text, limit=20),
            "attachPid": attached_pid,
            "cursor": {
                "x": int(info.dwCursorPosition.X),
                "y": int(info.dwCursorPosition.Y),
            },
            "window": {
                "left": int(info.srWindow.Left),
                "top": int(info.srWindow.Top),
                "right": int(info.srWindow.Right),
                "bottom": int(info.srWindow.Bottom),
                "width": width,
                "height": height,
            },
            "buffer": {"width": int(info.dwSize.X), "height": int(info.dwSize.Y)},
        }
    finally:
        kernel32.CloseHandle(handle)
        kernel32.FreeConsole()


def _read_console_text(pid: int, max_chars: int = 4000) -> Dict[str, Any]:
    target_pid = _infer_debuggee_pid(pid)
    conhost_pid = _wait_for_conhost_pid(target_pid, timeout_ms=800)
    if not conhost_pid:
        return {
            "ok": False,
            "pid": target_pid,
            "conhostPid": None,
            "text": "",
            "lines": [],
            "reason": "No console host found for the debuggee",
        }

    last_error: Optional[Exception] = None
    for attempt in range(4):
        try:
            if attempt:
                time.sleep(min(0.1 * attempt, 0.25))
            data = _read_console_text_once(
                target_pid, max_chars=max_chars, conhost_pid=conhost_pid
            )
            data.update(
                {
                    "ok": True,
                    "pid": target_pid,
                    "conhostPid": conhost_pid,
                    "attempts": attempt + 1,
                }
            )
            _remember_runtime(lastConsoleText=data.get("text", ""))
            return data
        except Exception as exc:
            last_error = exc

    return {
        "ok": False,
        "pid": target_pid,
        "conhostPid": conhost_pid,
        "text": "",
        "lines": [],
        "error": str(last_error) if last_error else "Unknown console read error",
    }


def _write_console_text_once(
    target_pid: int, payload: str, conhost_pid: Optional[int] = None
) -> Dict[str, Any]:
    attached_pid = _attach_console(target_pid, conhost_pid=conhost_pid)

    handle = kernel32.CreateFileW(
        "CONIN$",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if handle in (0, INVALID_HANDLE_VALUE):
        err = ctypes.get_last_error()
        kernel32.FreeConsole()
        raise OSError(f"CreateFileW(CONIN$) failed: {err}")

    try:
        records: List[INPUT_RECORD] = []
        for ch in payload:
            records.append(_build_console_key_event(ch, True))
            records.append(_build_console_key_event(ch, False))
        array = (INPUT_RECORD * len(records))(*records)
        written = wintypes.DWORD()
        ok = kernel32.WriteConsoleInputW(
            handle, array, len(records), ctypes.byref(written)
        )
        err = ctypes.get_last_error()
        if not ok:
            raise OSError(f"WriteConsoleInputW failed: {err}")
        return {"written": int(written.value), "attachPid": attached_pid}
    finally:
        kernel32.CloseHandle(handle)
        kernel32.FreeConsole()


def _write_console_text(pid: int, text: str, submit: bool) -> Dict[str, Any]:
    target_pid = _infer_debuggee_pid(pid)
    payload = text + ("\r" if submit else "")
    if not payload:
        return {"ok": True, "pid": target_pid, "written": 0, "mode": "console"}

    conhost_pid = _wait_for_conhost_pid(target_pid, timeout_ms=2500)
    last_error: Optional[Exception] = None
    for attempt in range(6):
        try:
            if attempt:
                time.sleep(min(0.1 * attempt, 0.35))
            write_info = _write_console_text_once(
                target_pid, payload, conhost_pid=conhost_pid
            )
            return {
                "ok": True,
                "pid": target_pid,
                "conhostPid": conhost_pid,
                "written": int(write_info.get("written") or 0),
                "attachPid": write_info.get("attachPid"),
                "text": text,
                "submitted": submit,
                "mode": "console",
                "attempts": attempt + 1,
            }
        except Exception as exc:
            last_error = exc

    fallback = _type_text_to_debuggee_window(text, submit, 10, target_pid)
    fallback["pid"] = target_pid
    fallback["conhostPid"] = conhost_pid
    fallback["mode"] = "window-fallback"
    fallback["attempts"] = 6
    if last_error:
        fallback["consoleError"] = str(last_error)
    return fallback


def _type_text_to_foreground(text: str, submit: bool, delay_ms: int) -> Dict[str, Any]:
    hwnd = int(user32.GetForegroundWindow())
    if not hwnd:
        raise RuntimeError("No foreground window is available")

    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    title = _get_window_text(hwnd)

    total_sent = 0
    for ch in text:
        total_sent += _send_input_records(_unicode_key_inputs(ch))
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
    if submit:
        total_sent += _send_input_records(_vk_key_inputs(VK_RETURN))

    return {
        "ok": True,
        "hwnd": f"0x{hwnd:X}",
        "pid": int(pid.value),
        "title": title,
        "eventsSent": total_sent,
        "text": text,
        "submitted": submit,
    }


def _type_text_to_debuggee_window(
    text: str, submit: bool, delay_ms: int, pid: int
) -> Dict[str, Any]:
    target_pid = _infer_debuggee_pid(pid)
    ready = _wait_for_resolved_window_ready(
        pid=target_pid,
        timeout_ms=2500,
        poll_ms=80,
        stable_polls=2,
        require_input_idle=True,
        client_only=False,
    )
    hwnd = _parse_hwnd_value(ready.get("hwnd")) if ready.get("ok") else 0
    if not hwnd:
        conhost_pid = _wait_for_conhost_pid(target_pid, timeout_ms=2500)
        if conhost_pid:
            hwnd = _wait_for_top_window(conhost_pid, timeout_ms=2500)
    if not hwnd:
        raise RuntimeError("Could not find a visible window for the debuggee")
    _focus_window(hwnd)
    if delay_ms > 0:
        time.sleep(delay_ms / 1000.0)
    return _type_text_to_foreground(text, submit, delay_ms)


def _foreground_window_info() -> Dict[str, Any]:
    # ctypes returns ``None`` for a NULL HWND on some Python/Windows builds.
    # Foreground ownership is diagnostic only and must never abort a launch.
    hwnd = int(user32.GetForegroundWindow() or 0)
    pid = wintypes.DWORD()
    if hwnd:
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return {
        "ok": bool(hwnd),
        "hwnd": f"0x{hwnd:X}" if hwnd else None,
        "pid": int(pid.value) if hwnd else None,
        "title": _get_window_text(hwnd) if hwnd else "",
        "className": _get_class_name(hwnd) if hwnd else "",
    }


def _collect_breakpoint_snapshot(
    bp_type: str = "all", log: bool = False
) -> Dict[str, Any]:
    result = safe_get("Breakpoint/List", {"type": bp_type or "all"}, log=log)
    payload = _coerce_json_payload(result)
    if isinstance(payload, dict):
        breakpoints = payload.get("breakpoints", [])
        if isinstance(breakpoints, list):
            return {
                "count": int(payload.get("count", len(breakpoints))),
                "breakpoints": breakpoints,
            }
    return {"count": 0, "breakpoints": []}


def _is_safe_startup_breakpoint_name(name: str) -> bool:
    lowered = _repair_text_mojibake(str(name or "")).strip().lower()
    if not lowered:
        return False
    markers = (
        "tls callback",
        "entry point",
        "point of entry",
        "entry breakpoint",
        "точке входа",
        "точка входа",
        "entry",
    )
    return any(marker in lowered for marker in markers)


def _breakpoint_delete_succeeded(result: Any) -> bool:
    lowered = str(result or "").strip().lower()
    return bool(
        lowered
        and (
            "deleted" in lowered
            or "already absent" in lowered
            or "not present" in lowered
        )
    )


def _breakpoint_exists(addr: str, bp_type: str = "all") -> Optional[bool]:
    normalized = _normalize_hex(addr)
    if not normalized:
        return None
    try:
        snapshot = _collect_breakpoint_snapshot(bp_type=bp_type, log=False)
    except Exception:
        return None
    items = snapshot.get("breakpoints", []) if isinstance(snapshot, dict) else []
    return any(
        _normalize_hex(item.get("addr")) == normalized
        for item in items
        if isinstance(item, dict)
    )


def _is_current_debuggee_entrypoint_breakpoint(
    bp: Dict[str, Any], debuggee_image: Optional[str], current_addr: str = ""
) -> bool:
    bp_addr = _normalize_hex(bp.get("addr"))
    paused_addr = _normalize_hex(current_addr)
    if not bp_addr or not paused_addr or bp_addr != paused_addr:
        return False
    module = str(bp.get("module", "")).strip().lower()
    debuggee_module = str(debuggee_image or "").strip().lower()
    if debuggee_module and module and module != debuggee_module:
        return False
    if not bool(bp.get("enabled", True)) or not bool(bp.get("active", True)):
        return False
    if int(bp.get("hitCount", 0) or 0) > 1:
        return False
    raw_name = _repair_text_mojibake(str(bp.get("name", "")))
    lowered_name = raw_name.lower()
    if "tls callback" in lowered_name:
        return False
    if bool(bp.get("singleshoot")):
        return True
    return _is_safe_startup_breakpoint_name(raw_name)


def _remove_safe_startup_breakpoints(
    debuggee_image: Optional[str],
    allow_debuggee_entrypoint: bool = False,
    current_addr: str = "",
) -> List[str]:
    snapshot = _collect_breakpoint_snapshot(log=False)
    removed: List[str] = []
    debuggee_module = str(debuggee_image or "").lower()
    for bp in snapshot.get("breakpoints", []):
        if not isinstance(bp, dict):
            continue
        addr = _normalize_hex(bp.get("addr"))
        if not addr:
            continue
        raw_name = _repair_text_mojibake(str(bp.get("name", "")))
        name = raw_name.lower()
        lowered_name = name
        module = str(bp.get("module", "")).lower()
        singleshoot = bool(bp.get("singleshoot"))
        hit_count = int(bp.get("hitCount", 0) or 0)
        enabled = bool(bp.get("enabled", True))
        active = bool(bp.get("active", True))
        is_current_debuggee_entrypoint = allow_debuggee_entrypoint and (
            _is_current_debuggee_entrypoint_breakpoint(
                bp, debuggee_image=debuggee_image, current_addr=current_addr
            )
        )
        if not (
            singleshoot
            or _is_safe_startup_breakpoint_name(raw_name)
            or is_current_debuggee_entrypoint
        ):
            continue
        if not enabled or not active:
            continue
        if hit_count > 1:
            continue
        if (
            module
            and debuggee_module
            and module not in ("", debuggee_module)
            and not singleshoot
            and "tls callback" not in lowered_name
        ):
            continue
        # Default behavior preserves entry-point pauses for manual debugging.
        # Automation paths can opt in to deleting the currently paused
        # debuggee entry-point breakpoint so headless auto-run does not re-hit it.
        is_debuggee_module = (
            not module or not debuggee_module or module == debuggee_module
        )
        looks_like_startup = (
            ("tls callback" in name)
            or (singleshoot and not is_debuggee_module)
            or is_current_debuggee_entrypoint
        )
        if not looks_like_startup:
            continue
        if (
            module
            and debuggee_image
            and module not in ("", str(debuggee_image).lower())
            and not singleshoot
            and "tls callback" not in name
        ):
            continue
        delete_result = DebugDeleteBreakpoint(addr)
        if _breakpoint_delete_succeeded(delete_result):
            removed.append(addr)
    if removed:
        _log_event(
            "removed_safe_startup_breakpoints",
            debuggeeImage=debuggee_image,
            allowDebuggeeEntrypoint=allow_debuggee_entrypoint,
            currentAddr=_normalize_hex(current_addr),
            removed=removed,
        )
    return removed


def _delete_breakpoints(addresses: List[str]) -> List[str]:
    removed: List[str] = []
    for addr in addresses:
        normalized = _normalize_hex(addr)
        if not normalized or normalized in removed:
            continue
        result = DebugDeleteBreakpoint(normalized)
        if _breakpoint_delete_succeeded(result):
            removed.append(normalized)
    return removed


_BREAKPOINT_LEASE_MIN_MS = 1000
_BREAKPOINT_LEASE_MAX_MS = 120000
_BREAKPOINT_LEASE_MAX_ENTRIES = 256


def _breakpoint_lease_identity() -> Dict[str, Any]:
    """Return the immutable identity used to bind workflow breakpoint leases."""

    identity = _get_cached_bridge_identity()
    session = identity.get("session") if isinstance(identity.get("session"), dict) else {}
    session_id = str(
        identity.get("sessionId") or session.get("sessionId") or ""
    ).strip()
    generation = int(
        _parse_int(
            identity.get("sessionGeneration", session.get("generation")),
            0,
        )
        or 0
    )
    debuggee_pid = int(
        _parse_int(
            identity.get("debuggeePid", session.get("processId")),
            0,
        )
        or 0
    )
    return {
        "bridgeInstanceId": str(identity.get("bridgeInstanceId") or "").strip(),
        "sessionId": session_id,
        "sessionGeneration": generation,
        "debuggeePid": debuggee_pid,
        "imageSha256": str(
            identity.get("imageSha256") or session.get("imageSha256") or ""
        ).strip().upper(),
    }


def _breakpoint_lease_identity_key(identity: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        str(identity.get("bridgeInstanceId") or ""),
        str(identity.get("sessionId") or ""),
        int(identity.get("sessionGeneration") or 0),
        int(identity.get("debuggeePid") or 0),
        str(identity.get("imageSha256") or "").upper(),
    )


def _normalize_managed_breakpoint_type(value: Any) -> str:
    normalized = str(value or "normal").strip().lower().replace("_", "-")
    aliases = {
        "software": "normal",
        "code": "normal",
        "bp": "normal",
        "hw": "hardware",
        "watch": "memory",
        "watchpoint": "memory",
        "conditional-breakpoint": "conditional",
    }
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in {"normal", "hardware", "memory", "conditional"} else ""


def _managed_breakpoint_snapshot_record(
    addr: str, bp_type: str = "normal"
) -> Optional[Dict[str, Any]]:
    normalized = _normalize_hex(addr)
    managed_type = _normalize_managed_breakpoint_type(bp_type)
    if not normalized or not managed_type:
        return None
    try:
        snapshot = _collect_breakpoint_snapshot(bp_type="all", log=False)
    except Exception:
        return None
    items = snapshot.get("breakpoints", []) if isinstance(snapshot, dict) else []
    for item in items:
        if not isinstance(item, dict):
            continue
        if _normalize_hex(item.get("addr")) != normalized:
            continue
        raw_type = str(item.get("type") or item.get("breakpointType") or "").lower()
        if managed_type == "hardware" and "hardware" not in raw_type and raw_type not in {"hw"}:
            continue
        if managed_type == "memory" and "memory" not in raw_type and "watch" not in raw_type:
            continue
        # Conditional breakpoints are represented as normal/software BPs by
        # x64dbg; their condition/log fields are retained in the fingerprint.
        return dict(item)
    return None


def _managed_breakpoint_fingerprint(item: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    fields = (
        "addr",
        "type",
        "breakpointType",
        "module",
        "name",
        "enabled",
        "active",
        "singleshoot",
        "fastResume",
        "silent",
        "breakCondition",
        "condition",
        "logText",
        "commandText",
        "command",
        "size",
    )
    result: Dict[str, Any] = {}
    for field_name in fields:
        value = item.get(field_name)
        if isinstance(value, str):
            result[field_name] = _repair_text_mojibake(value).strip()
        elif value is not None:
            result[field_name] = value
    result["addr"] = _normalize_hex(item.get("addr")) or str(item.get("addr") or "")
    return result


def _managed_breakpoint_fingerprint_matches(
    expected: Dict[str, Any], current: Optional[Dict[str, Any]]
) -> bool:
    if not expected:
        return False
    actual = _managed_breakpoint_fingerprint(current)
    if not actual:
        return False
    # x64dbg versions differ in optional fields. Compare every field observed
    # when the workflow created/acquired the breakpoint.
    return all(actual.get(key) == value for key, value in expected.items())


def _compare_delete_managed_breakpoint(record: Dict[str, Any]) -> Dict[str, Any]:
    """Delete only when the breakpoint still matches the workflow before-image."""

    addr = _normalize_hex(record.get("addr"))
    if not addr:
        return {"status": "invalid_address", "deleted": False}
    managed_type = _normalize_managed_breakpoint_type(record.get("breakpointType"))
    current = _managed_breakpoint_snapshot_record(addr, managed_type)
    if current is None:
        return {"status": "already_absent", "deleted": False, "addr": addr}
    expected = record.get("fingerprint")
    if not _managed_breakpoint_fingerprint_matches(
        expected if isinstance(expected, dict) else {}, current
    ):
        return {
            "status": "preserved_compare_mismatch",
            "deleted": False,
            "addr": addr,
            "current": _managed_breakpoint_fingerprint(current),
            "expected": expected or {},
        }
    if managed_type == "memory":
        delete_result = DeleteMemoryBreakpoint(addr)
        deleted = bool(
            isinstance(delete_result, dict)
            and (delete_result.get("ok") or delete_result.get("success"))
        )
    elif managed_type == "hardware":
        delete_result = DeleteHardwareBreakpoint(addr)
        deleted = bool(
            isinstance(delete_result, dict)
            and (delete_result.get("ok") or delete_result.get("success"))
        )
    else:
        delete_result = DebugDeleteBreakpoint(addr)
        deleted = _breakpoint_delete_succeeded(delete_result)
    after = _managed_breakpoint_snapshot_record(addr, managed_type)
    if after is not None:
        return {
            "status": "delete_unverified",
            "deleted": False,
            "addr": addr,
            "deleteResult": delete_result,
        }
    return {
        "status": "deleted" if deleted else "delete_failed",
        "deleted": bool(deleted),
        "addr": addr,
        "deleteResult": delete_result,
    }


def _prune_breakpoint_leases() -> List[Dict[str, Any]]:
    """Expire leases and drop stale-session metadata without touching a new session."""

    now_ms = int(time.monotonic() * 1000)
    current_key = _breakpoint_lease_identity_key(_breakpoint_lease_identity())
    cleanup: List[Dict[str, Any]] = []
    with _RUNTIME_LOCK:
        leases = {
            str(key): dict(value)
            for key, value in (_RUNTIME_STATE.get("breakpointLeases") or {}).items()
            if isinstance(value, dict)
        }
    changed = False
    for key, record in list(leases.items()):
        record_identity = _breakpoint_lease_identity_key(
            record.get("identity") if isinstance(record.get("identity"), dict) else {}
        )
        if record_identity != current_key:
            # Never issue a delete against the replacement session: an address
            # may now be owned by a human or by another workflow.
            leases.pop(key, None)
            changed = True
            continue
        tokens = dict(record.get("tokens") or {})
        expired = [
            token
            for token, token_record in tokens.items()
            if not isinstance(token_record, dict)
            or int(token_record.get("expiresAtMs") or 0) <= now_ms
        ]
        if not expired:
            continue
        for token in expired:
            tokens.pop(token, None)
        record["tokens"] = tokens
        record["refCount"] = len(tokens)
        changed = True
        if not tokens:
            if bool(record.get("createdByWorkflow")):
                cleanup.append(record)
            leases.pop(key, None)
    if changed:
        _remember_runtime(breakpointLeases=leases)
    for record in cleanup:
        cleanup_result = _compare_delete_managed_breakpoint(record)
        _log_event(
            "breakpoint_lease_expired_cleanup",
            addr=record.get("addr"),
            breakpointType=record.get("breakpointType"),
            result=cleanup_result,
        )
    return cleanup


def _managed_breakpoint_set(
    addr: str,
    breakpoint_type: str,
    size: int = 1,
    access_type: str = "write",
    condition: str = "",
    name: str = "",
) -> Dict[str, Any]:
    normalized = _normalize_hex(addr) or str(addr)
    if breakpoint_type == "hardware":
        result = SetHardwareBreakpoint(normalized, type="execute")
        if isinstance(result, dict):
            return {
                **result,
                "ok": bool(result.get("ok") or result.get("success")),
            }
        return {"ok": False, "result": result}
    if breakpoint_type == "memory":
        return SetMemoryRangeBreakpoint(
            normalized, size=max(1, int(size)), access_type=access_type, name=name
        )
    if breakpoint_type == "conditional":
        return SetConditionalBreakpoint(normalized, condition=condition, name=name)
    result = DebugSetBreakpoint(normalized)
    return {
        "ok": "success" in str(result or "").lower()
        and "error" not in str(result or "").lower(),
        "result": result,
        "addr": normalized,
    }


def _resolve_remote_symbol_address(module_name: str, api_name: str) -> Optional[str]:
    normalized_module = str(module_name or "").strip()
    normalized_api = str(api_name or "").strip()
    if not normalized_module or not normalized_api:
        return None
    try:
        direct = _normalize_hex(
            MiscRemoteGetProcAddress(normalized_module, normalized_api)
        )
    except Exception:
        direct = None
    if direct:
        return direct
    try:
        modules = GetModuleList()
        module_items = modules.get("modules", []) if isinstance(modules, dict) else []
    except Exception:
        module_items = []
    module_record = next(
        (
            item
            for item in module_items
            if isinstance(item, dict)
            and _process_basename(item.get("name") or item.get("path") or "")
            == _process_basename(normalized_module)
        ),
        None,
    )
    module_base = _parse_int((module_record or {}).get("base"))
    if module_base is None:
        return None
    try:
        symbol_payload = QuerySymbols(normalized_module, offset=0, limit=20000)
    except Exception:
        return None
    symbol_items = (
        symbol_payload.get("symbols", []) if isinstance(symbol_payload, dict) else []
    )
    target_name = normalized_api.casefold()
    for symbol in symbol_items:
        if not isinstance(symbol, dict):
            continue
        symbol_name = str(symbol.get("name") or "").strip()
        if not symbol_name:
            continue
        lowered = symbol_name.casefold().lstrip("_")
        if lowered != target_name:
            continue
        rva_value = _parse_int(symbol.get("rva"))
        if rva_value is None:
            continue
        return _normalize_hex(module_base + rva_value)
    return None


def _ensure_common_antidebug_breakpoints() -> List[str]:
    snapshot = _collect_breakpoint_snapshot(log=False)
    existing = {
        _normalize_hex(bp.get("addr"))
        for bp in snapshot.get("breakpoints", [])
        if isinstance(bp, dict) and _normalize_hex(bp.get("addr"))
    }
    added: List[str] = []
    for module_name, api_name in COMMON_ANTI_DEBUG_BREAKPOINT_TARGETS:
        resolved = _resolve_remote_symbol_address(module_name, api_name)
        if not resolved or resolved in existing:
            continue
        result = DebugSetBreakpoint(resolved)
        lowered = str(result or "").lower()
        if "error" in lowered or "failed" in lowered:
            continue
        existing.add(resolved)
        added.append(resolved)
    if added:
        _log_event("added_common_antidebug_breakpoints", added=added)
    return added


def _looks_like_startup_breakpoint(name: str) -> bool:
    lowered = str(name or "").strip().lower()
    if not lowered:
        return False
    return (
        any(marker in lowered for marker in STARTUP_BREAKPOINT_MARKERS)
        or "рІс" in lowered
    )


def _looks_like_loader_stack(callstack: Dict[str, Any]) -> bool:
    entries = callstack.get("entries", []) if isinstance(callstack, dict) else []
    for entry in entries:
        comment = str(entry.get("comment", "")).lower()
        if any(marker in comment for marker in STARTUP_STACK_MARKERS):
            return True
    return False


def _looks_like_entrypoint_stack(
    callstack: Dict[str, Any], debuggee_image: str = ""
) -> bool:
    entries = callstack.get("entries", []) if isinstance(callstack, dict) else []
    image_name = str(debuggee_image or "").strip().lower()
    for entry in entries[:3]:
        comment = str(entry.get("comment", "")).strip().lower()
        if not comment:
            continue
        if "entrypoint" in comment:
            return True
        if image_name and comment.startswith(f"{image_name}."):
            return True
    return False


def _is_debuggee_entrypoint_pause(state: Dict[str, Any], module_name: str = "") -> bool:
    if not isinstance(state, dict) or not state.get("paused"):
        return False
    if str(state.get("stopReason") or "").lower() != "breakpoint":
        return False
    module_record = _resolve_module_record_for_address(state.get("rip"))
    if not module_record:
        return False
    current_name = _process_basename(
        module_record.get("name") or module_record.get("path") or ""
    )
    if module_name:
        requested = _process_basename(module_name)
        if requested and current_name != requested:
            return False
    else:
        debuggee_name = _process_basename(
            state.get("debuggeeImage") or state.get("debuggeePath") or ""
        )
        if debuggee_name and current_name != debuggee_name:
            return False
    return _looks_like_entrypoint_stack(
        state.get("callStack", {}), state.get("debuggeeImage")
    )


def _is_startup_pause(
    state: Dict[str, Any], gui_snapshot: Optional[Dict[str, Any]] = None
) -> bool:
    if not isinstance(state, dict) or not state.get("paused"):
        return False
    stop_reason = str(state.get("stopReason") or "").lower()
    session = state.get("session", {}) if isinstance(state.get("session"), dict) else {}
    breakpoint_name = str(session.get("breakpointName") or "")
    gui_analysis = (
        gui_snapshot.get("analysis", {}) if isinstance(gui_snapshot, dict) else {}
    )
    has_visible_window = bool(gui_analysis.get("hasVisibleWindow"))
    if stop_reason == "create_process":
        return True
    if stop_reason == "breakpoint" and _looks_like_startup_breakpoint(breakpoint_name):
        return True
    if (
        stop_reason == "breakpoint"
        and not has_visible_window
        and _looks_like_entrypoint_stack(
            state.get("callStack", {}), state.get("debuggeeImage")
        )
    ):
        return True
    if (
        stop_reason in ("pause", "stepped")
        and _looks_like_loader_stack(state.get("callStack", {}))
        and not has_visible_window
    ):
        return True
    return False


def _is_whitelisted_startup_exception(
    state: Dict[str, Any], gui_snapshot: Optional[Dict[str, Any]] = None
) -> bool:
    if not isinstance(state, dict):
        return False
    session = state.get("session", {}) if isinstance(state.get("session"), dict) else {}
    code = str(session.get("exceptionCode") or "").strip().lower()
    if code not in {"0x80000003", "0x4000001f", "0x4000001e"}:
        return False
    if not bool(session.get("exceptionFirstChance")):
        return False
    stop_reason = str(state.get("stopReason") or session.get("stopReason") or "").lower()
    last_event = str(session.get("lastEventType") or "").lower()
    if stop_reason not in ("", "exception", "create_process", "breakpoint", "pause"):
        return False
    if last_event not in ("", "exception", "create_process", "load_dll", "pause_debug"):
        return False
    gui_analysis = (
        gui_snapshot.get("analysis", {}) if isinstance(gui_snapshot, dict) else {}
    )
    if gui_analysis.get("hasVisibleWindow"):
        return False
    module_record = _resolve_module_record_for_address(state.get("rip"))
    current_name = _process_basename(
        (module_record or {}).get("name") or (module_record or {}).get("path") or ""
    )
    debuggee_name = _process_basename(
        state.get("debuggeeImage") or state.get("debuggeePath") or ""
    )
    if code in ("0x4000001f", "0x4000001e"):
        return True
    if stop_reason == "exception":
        return True
    if _looks_like_loader_stack(state.get("callStack", {})):
        return True
    if _looks_like_entrypoint_stack(state.get("callStack", {}), state.get("debuggeeImage")):
        return True
    return bool(current_name and debuggee_name and current_name != debuggee_name)


def _normalize_exception_code(code: Any) -> str:
    raw = str(code or "").strip().strip('"').strip("'")
    parsed = _parse_int(raw)
    if parsed is not None:
        return f"0x{parsed & 0xFFFFFFFF:x}"
    return raw.lower()


_EXCEPTION_POLICY_RULE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_EXCEPTION_POLICY_ACTION_ALIASES = {
    "pause": "pause",
    "stop": "pause",
    "handled": "handled",
    "handle": "handled",
    "swallow": "handled",
    "skip": "handled",
    "not_handled": "not_handled",
    "not-handled": "not_handled",
    "pass": "not_handled",
}
_EXCEPTION_POLICY_CHANCE_ALIASES = {
    "any": "any",
    "all": "any",
    "both": "any",
    "first": "first",
    "first_chance": "first",
    "first-chance": "first",
    "second": "second",
    "second_chance": "second",
    "second-chance": "second",
}


def _normalize_exception_policy_action(value: Any) -> Optional[str]:
    return _EXCEPTION_POLICY_ACTION_ALIASES.get(
        str(value or "").strip().lower()
    )


def _normalize_exception_policy_chance(value: Any) -> Optional[str]:
    return _EXCEPTION_POLICY_CHANCE_ALIASES.get(
        str(value or "any").strip().lower()
    )


def _normalize_exception_policy_selector(value: Any) -> Optional[str]:
    """Normalize one exact/masked/wildcard exception selector for native policy."""

    if isinstance(value, dict):
        raw_value = value.get("value", value.get("code"))
        raw_mask = value.get("mask")
        if raw_value is None or raw_mask is None:
            return None
        parsed_value = _parse_int(str(raw_value).strip())
        parsed_mask = _parse_int(str(raw_mask).strip())
        if parsed_value is None or parsed_mask is None:
            return None
        if not (0 <= parsed_value <= 0xFFFFFFFF and 0 < parsed_mask <= 0xFFFFFFFF):
            return None
        if parsed_mask == 0xFFFFFFFF:
            return f"0x{parsed_value:08x}"
        return f"0x{parsed_value & parsed_mask:08x}/0x{parsed_mask:08x}"

    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if 0 <= value <= 0xFFFFFFFF:
            return f"0x{value:08x}"
        return None
    raw = str(value or "").strip().strip('"').strip("'")
    if raw in ("*", "any", "default"):
        return "*"
    if "/" in raw:
        pieces = raw.split("/", 1)
        parsed_value = _parse_int(pieces[0].strip())
        parsed_mask = _parse_int(pieces[1].strip())
        if parsed_value is None or parsed_mask is None:
            return None
        if not (0 <= parsed_value <= 0xFFFFFFFF and 0 < parsed_mask <= 0xFFFFFFFF):
            return None
        if parsed_mask == 0xFFFFFFFF:
            return f"0x{parsed_value:08x}"
        return f"0x{parsed_value & parsed_mask:08x}/0x{parsed_mask:08x}"
    parsed = _parse_int(raw)
    if parsed is None or not (0 <= parsed <= 0xFFFFFFFF):
        return None
    return f"0x{parsed:08x}"


def _normalize_exception_policy_rules(rules_json: str) -> Dict[str, Any]:
    """Validate and canonicalize the public exception-policy JSON contract."""

    try:
        decoded: Any = json.loads(rules_json) if str(rules_json or "").strip() else []
    except (TypeError, ValueError) as exc:
        return {
            "ok": False,
            "errorCode": "INVALID_EXCEPTION_POLICY_JSON",
            "error": f"rules_json is not valid JSON: {exc}",
        }
    if isinstance(decoded, dict):
        if "rules" in decoded:
            decoded = decoded.get("rules")
        else:
            decoded = [decoded]
    if not isinstance(decoded, list):
        return {
            "ok": False,
            "errorCode": "INVALID_EXCEPTION_POLICY",
            "error": "rules_json must encode a rule object or an array of rules",
        }
    if len(decoded) > 64:
        return {
            "ok": False,
            "errorCode": "EXCEPTION_POLICY_TOO_LARGE",
            "error": "At most 64 exception policy rules are allowed",
        }

    normalized: List[Dict[str, Any]] = []
    seen_rule_ids: set[str] = set()
    for index, raw_rule in enumerate(decoded):
        if not isinstance(raw_rule, dict):
            return {
                "ok": False,
                "errorCode": "INVALID_EXCEPTION_POLICY_RULE",
                "error": f"Rule {index} must be an object",
            }
        rule_id = str(
            raw_rule.get("ruleId", raw_rule.get("id", f"rule-{index + 1}"))
        ).strip()
        if not _EXCEPTION_POLICY_RULE_ID_RE.fullmatch(rule_id):
            return {
                "ok": False,
                "errorCode": "INVALID_EXCEPTION_POLICY_RULE_ID",
                "error": (
                    f"Rule {index} has an invalid ruleId; use 1-64 ASCII letters, "
                    "digits, dot, underscore, colon or dash"
                ),
            }
        folded_rule_id = rule_id.casefold()
        if folded_rule_id in seen_rule_ids:
            return {
                "ok": False,
                "errorCode": "DUPLICATE_EXCEPTION_POLICY_RULE_ID",
                "error": f"Duplicate exception policy ruleId: {rule_id}",
            }
        seen_rule_ids.add(folded_rule_id)

        raw_codes: Any = raw_rule.get("codes", raw_rule.get("code"))
        if "codes" not in raw_rule and "mask" in raw_rule and (
            "code" in raw_rule or "value" in raw_rule
        ):
            raw_codes = [
                {
                    "value": raw_rule.get("value", raw_rule.get("code")),
                    "mask": raw_rule.get("mask"),
                }
            ]
        if not isinstance(raw_codes, list):
            raw_codes = [raw_codes]
        if not raw_codes or len(raw_codes) > 32:
            return {
                "ok": False,
                "errorCode": "INVALID_EXCEPTION_POLICY_SELECTORS",
                "error": f"Rule {rule_id} must contain between 1 and 32 selectors",
            }
        selectors: List[str] = []
        for raw_selector in raw_codes:
            selector = _normalize_exception_policy_selector(raw_selector)
            if selector is None:
                return {
                    "ok": False,
                    "errorCode": "INVALID_EXCEPTION_POLICY_SELECTOR",
                    "error": f"Rule {rule_id} contains an invalid selector: {raw_selector!r}",
                }
            if selector not in selectors:
                selectors.append(selector)

        chance = _normalize_exception_policy_chance(raw_rule.get("chance", "any"))
        if chance is None:
            return {
                "ok": False,
                "errorCode": "INVALID_EXCEPTION_POLICY_CHANCE",
                "error": f"Rule {rule_id} chance must be first, second, or any",
            }
        action = _normalize_exception_policy_action(raw_rule.get("action", "pause"))
        if action is None:
            return {
                "ok": False,
                "errorCode": "INVALID_EXCEPTION_POLICY_ACTION",
                "error": (
                    f"Rule {rule_id} action must be pause, handled, or not_handled"
                ),
            }
        raw_priority = raw_rule.get("priority", 0)
        if isinstance(raw_priority, bool):
            priority_valid = False
            priority = 0
        elif isinstance(raw_priority, int):
            priority_valid = True
            priority = raw_priority
        elif isinstance(raw_priority, str) and re.fullmatch(
            r"-?(?:0|[1-9][0-9]*)", raw_priority.strip()
        ):
            priority_valid = True
            priority = int(raw_priority.strip(), 10)
        else:
            priority_valid = False
            priority = 0
        if not priority_valid:
            return {
                "ok": False,
                "errorCode": "INVALID_EXCEPTION_POLICY_PRIORITY",
                "error": f"Rule {rule_id} priority must be an integer",
            }
        if priority < -100000 or priority > 100000:
            return {
                "ok": False,
                "errorCode": "INVALID_EXCEPTION_POLICY_PRIORITY",
                "error": f"Rule {rule_id} priority must be between -100000 and 100000",
            }
        enabled_value = raw_rule.get("enabled", True)
        if not isinstance(enabled_value, bool):
            return {
                "ok": False,
                "errorCode": "INVALID_EXCEPTION_POLICY_ENABLED",
                "error": f"Rule {rule_id} enabled must be a JSON boolean",
            }
        normalized.append(
            {
                "ruleId": rule_id,
                "codes": selectors,
                "chance": chance,
                "action": action,
                "priority": priority,
                "enabled": enabled_value,
            }
        )
    return {"ok": True, "rules": normalized, "count": len(normalized)}


def _get_exception_filters() -> List[Dict[str, Any]]:
    raw_filters = _get_runtime_value("exceptionFilters", [])
    if not isinstance(raw_filters, list):
        return []
    return [item for item in raw_filters if isinstance(item, dict)]


def _match_exception_filter(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    # Protocol-v3 native policies disposition exceptions directly from
    # CB_EXCEPTION.  Running the legacy WaitForPause adapter at the same time
    # would race that queued disposition and could handle the same event twice.
    bridge_identity = _get_runtime_value("bridgeIdentity", {})
    capabilities = (
        bridge_identity.get("capabilities", {})
        if isinstance(bridge_identity, dict)
        and isinstance(bridge_identity.get("capabilities"), dict)
        else {}
    )
    if bool(_get_runtime_value("nativeExceptionPolicyActive", False)) or isinstance(
        capabilities.get("exceptionPolicy"), dict
    ):
        return None
    if not isinstance(state, dict):
        return None
    session = state.get("session", {}) if isinstance(state.get("session"), dict) else {}
    code = _normalize_exception_code(session.get("exceptionCode"))
    if not code or code == "0x0":
        return None
    first_chance = bool(session.get("exceptionFirstChance"))
    for entry in _get_exception_filters():
        codes = entry.get("codes") if isinstance(entry.get("codes"), list) else []
        normalized_codes = {
            _normalize_exception_code(item) for item in codes if _normalize_exception_code(item)
        }
        if normalized_codes and code not in normalized_codes:
            continue
        if entry.get("firstChanceOnly") and not first_chance:
            continue
        matched = dict(entry)
        matched["matchedCode"] = code
        matched["exceptionFirstChance"] = first_chance
        return matched
    return None


def _should_auto_continue_filtered_exception(
    state: Dict[str, Any], matched_filter: Optional[Dict[str, Any]]
) -> bool:
    if not isinstance(state, dict) or not matched_filter or not state.get("paused"):
        return False
    action = str(matched_filter.get("action") or "skip").strip().lower()
    if action == "stop":
        return False
    if action == "pass":
        return bool(matched_filter.get("exceptionFirstChance"))
    return action == "skip"


def _advance_past_startup_pause(
    timeout_ms: int = 4000,
    max_runs: int = 4,
    poll_ms: int = 100,
    skip_startup_exceptions: bool = True,
) -> Dict[str, Any]:
    last_state = _build_debug_state(
        include_console=False, include_callstack=True, max_console_chars=0
    )
    removed_breakpoints: List[str] = []
    runs = 0
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    while runs < max_runs and time.time() < deadline:
        if (
            not isinstance(last_state, dict)
            or not last_state.get("debugging")
            or not last_state.get("paused")
        ):
            break
        whitelisted_exception = (
            skip_startup_exceptions and _is_whitelisted_startup_exception(last_state)
        )
        startup_noise = _detect_non_target_startup_breakpoint(last_state)
        if startup_noise.get("handled"):
            removed = _delete_breakpoints([str(startup_noise.get("addr") or "")])
            for addr in removed:
                if addr not in removed_breakpoints:
                    removed_breakpoints.append(addr)
        elif not _is_startup_pause(last_state) and not whitelisted_exception:
            break
        else:
            removed = _remove_safe_startup_breakpoints(
                last_state.get("debuggeeImage"),
                allow_debuggee_entrypoint=True,
                current_addr=str(last_state.get("rip") or ""),
            )
            for addr in removed:
                if addr not in removed_breakpoints:
                    removed_breakpoints.append(addr)
        DebugRun()
        runs += 1
        remaining_ms = max(0, int((deadline - time.time()) * 1000))
        if remaining_ms <= 0:
            break
        wait_budget = min(1200, max(250, poll_ms * 3), remaining_ms)
        wait_state = WaitForPause(
            timeout_ms=wait_budget, poll_ms=max(50, min(poll_ms, 150))
        )
        if not isinstance(wait_state, dict) or wait_state.get("state") != "paused":
            last_state = _build_debug_state(
                include_console=False, include_callstack=True, max_console_chars=0
            )
            break
        last_state = wait_state
        if not _is_startup_pause(last_state):
            break
    return {
        "advanced": runs > 0,
        "runs": runs,
        "removedBreakpoints": removed_breakpoints,
        "state": last_state,
    }


def _resolve_module_record_for_address(addr: Any) -> Optional[Dict[str, Any]]:
    normalized = _normalize_hex(addr)
    address_value = _parse_int(normalized)
    if not normalized or address_value is None:
        return None
    try:
        modules = safe_get("GetModuleList", log=False)
    except Exception:
        return None
    if isinstance(modules, dict):
        modules = [modules]
    if not isinstance(modules, list):
        return None
    for item in modules:
        if not isinstance(item, dict):
            continue
        base_value = _parse_int(item.get("base"))
        size_value = _parse_int(item.get("size"))
        if base_value is None or size_value is None or size_value <= 0:
            continue
        if base_value <= address_value < (base_value + size_value):
            return {
                "name": str(item.get("name") or ""),
                "path": str(item.get("path") or ""),
                "base": _normalize_hex(base_value),
                "size": f"0x{size_value:x}",
                "entry": _normalize_hex(item.get("entry")),
            }
    return None


def _is_user_code_pause(state: Dict[str, Any], module_name: str = "") -> bool:
    if not isinstance(state, dict) or not state.get("paused"):
        return False
    if _is_debuggee_entrypoint_pause(state, module_name=module_name):
        return True
    if _is_startup_pause(state):
        return False
    module_record = _resolve_module_record_for_address(state.get("rip"))
    if not module_record:
        return False
    current_name = _process_basename(
        module_record.get("name") or module_record.get("path") or ""
    )
    if module_name:
        requested = _process_basename(module_name)
        if requested and current_name != requested:
            return False
    else:
        debuggee_name = _process_basename(
            state.get("debuggeeImage") or state.get("debuggeePath") or ""
        )
        if debuggee_name and current_name != debuggee_name:
            return False
    return True


def _detect_useful_runtime_state(
    state: Dict[str, Any], module_name: str = ""
) -> Dict[str, Any]:
    if not isinstance(state, dict):
        return {"ready": False}
    if _is_user_code_pause(state, module_name=module_name):
        return {
            "ready": True,
            "reason": "paused_at_entrypoint"
            if _is_debuggee_entrypoint_pause(state, module_name=module_name)
            else "paused_in_user_module",
            "module": _resolve_module_record_for_address(state.get("rip")),
        }
    if state.get("waitingForInput") or state.get("shouldAutoSubmit"):
        return {
            "ready": True,
            "reason": "waiting_for_input",
            "module": _resolve_module_record_for_address(state.get("rip")),
        }
    target_pid = int(state.get("debuggeePid") or 0)
    if target_pid:
        gui_snapshot = GetDebuggeeWindows(
            pid=target_pid, include_children=False, visible_only=True, max_depth=2
        )
        if isinstance(gui_snapshot, dict) and gui_snapshot.get("ok") is not False:
            analysis = (
                gui_snapshot.get("analysis", {})
                if isinstance(gui_snapshot.get("analysis"), dict)
                else {}
            )
            if analysis.get("hasVisibleWindow"):
                return {
                    "ready": True,
                    "reason": "visible_window",
                    "module": _resolve_module_record_for_address(state.get("rip")),
                    "gui": gui_snapshot,
                }
    return {"ready": False}


def _stabilize_user_code_wait_state(
    deadline: float,
    poll_ms: int,
    module_name: str = "",
    skip_startup_exceptions: bool = True,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    state = _build_debug_state(
        include_console=True, include_callstack=True, max_console_chars=4000
    )
    readiness = _detect_useful_runtime_state(state, module_name=module_name)
    remaining_ms = max(0, int((deadline - time.time()) * 1000))
    if not state.get("running") or remaining_ms <= 0:
        return state, readiness
    try:
        DebugPause()
        paused = WaitForPause(
            timeout_ms=min(remaining_ms, max(600, poll_ms * 6)),
            poll_ms=max(50, min(poll_ms, 150)),
        )
        if isinstance(paused, dict):
            state = paused
            readiness = _detect_useful_runtime_state(state, module_name=module_name)
    except Exception:
        return state, readiness
    remaining_ms = max(0, int((deadline - time.time()) * 1000))
    if (
        remaining_ms > 0
        and state.get("paused")
        and (
            _is_startup_pause(state)
            or (
                skip_startup_exceptions
                and _is_whitelisted_startup_exception(state)
            )
        )
    ):
        try:
            DebugRun()
            follow_state = WaitForPause(
                timeout_ms=min(remaining_ms, max(500, poll_ms * 5)),
                poll_ms=max(50, min(poll_ms, 150)),
            )
            if isinstance(follow_state, dict):
                state = follow_state
                readiness = _detect_useful_runtime_state(
                    state, module_name=module_name
                )
        except Exception:
            pass
    return state, readiness


def _detect_non_target_startup_breakpoint(
    state: Dict[str, Any], gui_snapshot: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    if not isinstance(state, dict) or not state.get("paused"):
        return {"handled": False}
    if str(state.get("stopReason") or "").lower() != "breakpoint":
        return {"handled": False}
    gui_analysis = (
        gui_snapshot.get("analysis", {}) if isinstance(gui_snapshot, dict) else {}
    )
    if gui_analysis.get("hasVisibleWindow"):
        return {"handled": False}
    session = state.get("session", {}) if isinstance(state.get("session"), dict) else {}
    bp_module = str(session.get("breakpointModule") or "").strip().lower()
    debuggee_module = str(state.get("debuggeeImage") or "").strip().lower()
    current_rip = _normalize_hex(state.get("rip"))
    if not current_rip or not bp_module or bp_module in ("", debuggee_module):
        return {"handled": False}
    if not (
        _looks_like_loader_stack(state.get("callStack", {}))
        or _looks_like_entrypoint_stack(
            state.get("callStack", {}), state.get("debuggeeImage")
        )
    ):
        return {"handled": False}
    matched = (
        state.get("matchedBreakpoints", [])
        if isinstance(state.get("matchedBreakpoints"), list)
        else []
    )
    matched_entry = next(
        (bp for bp in matched if _normalize_hex(bp.get("addr")) == current_rip), None
    )
    if not isinstance(matched_entry, dict):
        return {"handled": False}
    if str(matched_entry.get("module") or "").strip().lower() != bp_module:
        return {"handled": False}
    raw_name = _repair_text_mojibake(str(matched_entry.get("name", ""))).strip()
    if raw_name and not _is_safe_startup_breakpoint_name(raw_name):
        return {"handled": False}
    return {
        "handled": True,
        "addr": current_rip,
        "module": bp_module,
        "name": raw_name,
        "hitCount": int(matched_entry.get("hitCount", 0) or 0),
        "singleshoot": bool(matched_entry.get("singleshoot")),
    }


def _get_runtime_arch() -> str:
    debugger_info = _get_active_debugger_info()
    arch = str(debugger_info.get("arch") or "").lower()
    return arch if arch in ("x86", "x64") else "x64"


def _pointer_size_for_arch(arch: str) -> int:
    return 8 if arch == "x64" else 4


def _register_name(arch: str, kind: str) -> str:
    kind = kind.lower()
    if arch == "x64":
        return {"ip": "rip", "sp": "rsp", "ax": "rax"}.get(kind, kind)
    return {"ip": "eip", "sp": "esp", "ax": "eax"}.get(kind, kind)


def _get_argument_value(arch: str, index: int) -> Optional[int]:
    if index < 0:
        return None
    if arch == "x64":
        if index == 0:
            return _parse_int(RegisterGet("rcx"))
        if index == 1:
            return _parse_int(RegisterGet("rdx"))
        if index == 2:
            return _parse_int(RegisterGet("r8"))
        if index == 3:
            return _parse_int(RegisterGet("r9"))
        stack_expr = f"[rsp+0x{0x28 + ((index - 4) * 8):X}]"
        return _parse_int(MiscParseExpression(stack_expr))
    stack_expr = f"[esp+0x{4 + (index * 4):X}]"
    return _parse_int(MiscParseExpression(stack_expr))


def _write_scalar_value(address: int, value: int, size: int) -> bool:
    if not address or size <= 0:
        return False
    addr_hex = _normalize_hex(address)
    if not addr_hex or not MemoryIsValidPtr(addr_hex):
        return False
    mask = (1 << (size * 8)) - 1
    payload = int(value) & mask
    hex_data = payload.to_bytes(size, "little", signed=False).hex()
    result = MemoryWrite(addr_hex, hex_data)
    return isinstance(result, str) and "written" in result.lower()


def _force_api_return(arch: str, arg_count: int, return_value: int) -> Dict[str, Any]:
    pointer_size = _pointer_size_for_arch(arch)
    ret_addr = _parse_int(StackPeek("0"))
    sp_name = _register_name(arch, "sp")
    ip_name = _register_name(arch, "ip")
    ax_name = _register_name(arch, "ax")
    current_sp = _parse_int(RegisterGet(sp_name))
    if ret_addr is None or current_sp is None:
        return {
            "ok": False,
            "reason": "Could not resolve return address or stack pointer for API bypass.",
        }
    cleanup = pointer_size if arch == "x64" else pointer_size + (max(arg_count, 0) * 4)
    RegisterSet(ax_name, _normalize_hex(return_value) or hex(return_value))
    RegisterSet(
        sp_name, _normalize_hex(current_sp + cleanup) or hex(current_sp + cleanup)
    )
    RegisterSet(ip_name, _normalize_hex(ret_addr) or hex(ret_addr))
    return {
        "ok": True,
        "returnAddress": _normalize_hex(ret_addr),
        "newSp": _normalize_hex(current_sp + cleanup),
        "returnValue": _normalize_hex(return_value),
        "arch": arch,
    }


def _detect_common_antidebug_pause(
    state: Dict[str, Any], gui_snapshot: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    if not isinstance(state, dict) or not state.get("paused"):
        return {"handled": False}
    gui_analysis = (
        gui_snapshot.get("analysis", {}) if isinstance(gui_snapshot, dict) else {}
    )
    if gui_analysis.get("hasVisibleWindow"):
        return {"handled": False}
    call_entries = (
        state.get("callStack", {}).get("entries", [])
        if isinstance(state.get("callStack"), dict)
        else []
    )
    top_comment = str(call_entries[0].get("comment", "")) if call_entries else ""
    lowered = top_comment.lower()
    if not any(marker in lowered for marker in COMMON_ANTI_DEBUG_APIS):
        return {"handled": False}
    if "isdebuggerpresent" in lowered:
        return {
            "handled": True,
            "api": "IsDebuggerPresent",
            "comment": top_comment,
            "argCount": 0,
        }
    if "checkremotedebuggerpresent" in lowered:
        return {
            "handled": True,
            "api": "CheckRemoteDebuggerPresent",
            "comment": top_comment,
            "argCount": 2,
        }
    if "ntqueryinformationprocess" in lowered:
        info_class = _get_argument_value(_get_runtime_arch(), 1)
        if info_class not in DEBUG_PROCESS_INFO_CLASSES:
            return {
                "handled": False,
                "observed": True,
                "api": "NtQueryInformationProcess",
                "comment": top_comment,
                "infoClass": _normalize_hex(info_class),
            }
        return {
            "handled": True,
            "observed": True,
            "api": "NtQueryInformationProcess",
            "comment": top_comment,
            "argCount": 5,
            "infoClass": info_class,
        }
    if "ntsetinformationthread" in lowered:
        info_class = _get_argument_value(_get_runtime_arch(), 1)
        if info_class not in DEBUG_THREAD_INFO_CLASSES:
            return {
                "handled": False,
                "observed": True,
                "api": "NtSetInformationThread",
                "comment": top_comment,
                "infoClass": _normalize_hex(info_class),
            }
        return {
            "handled": True,
            "observed": True,
            "api": "NtSetInformationThread",
            "comment": top_comment,
            "argCount": 4,
            "infoClass": info_class,
        }
    return {"handled": False}


def _apply_common_antidebug_bypass(
    state: Dict[str, Any], gui_snapshot: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    detection = _detect_common_antidebug_pause(state, gui_snapshot=gui_snapshot)
    if not detection.get("handled"):
        return detection

    arch = _get_runtime_arch()
    api = str(detection.get("api") or "")
    pointer_size = _pointer_size_for_arch(arch)
    writes: List[Dict[str, Any]] = []

    if api == "CheckRemoteDebuggerPresent":
        out_ptr = _get_argument_value(arch, 1)
        if out_ptr:
            writes.append(
                {
                    "target": _normalize_hex(out_ptr),
                    "size": 4,
                    "value": 0,
                    "ok": _write_scalar_value(out_ptr, 0, 4),
                }
            )
        force = _force_api_return(arch, arg_count=2, return_value=1)
    elif api == "NtQueryInformationProcess":
        info_class = int(detection.get("infoClass") or 0)
        mode_name, write_mode = DEBUG_PROCESS_INFO_CLASSES[info_class]
        out_ptr = _get_argument_value(arch, 2)
        out_len = int(_get_argument_value(arch, 3) or 0)
        ret_len_ptr = _get_argument_value(arch, 4)
        payload_size = pointer_size if write_mode == "ptr_zero" else 4
        if out_ptr and out_len >= payload_size:
            write_value = 1 if write_mode == "ulong_one" else 0
            writes.append(
                {
                    "target": _normalize_hex(out_ptr),
                    "size": payload_size,
                    "value": write_value,
                    "mode": mode_name,
                    "ok": _write_scalar_value(out_ptr, write_value, payload_size),
                }
            )
        if ret_len_ptr:
            writes.append(
                {
                    "target": _normalize_hex(ret_len_ptr),
                    "size": 4,
                    "value": payload_size,
                    "field": "ReturnLength",
                    "ok": _write_scalar_value(ret_len_ptr, payload_size, 4),
                }
            )
        force = _force_api_return(arch, arg_count=5, return_value=0)
    elif api == "NtSetInformationThread":
        info_class = int(detection.get("infoClass") or 0)
        mode_name, _ = DEBUG_THREAD_INFO_CLASSES[info_class]
        writes.append(
            {
                "target": "",
                "size": 0,
                "value": 0,
                "mode": mode_name,
                "ok": True,
            }
        )
        force = _force_api_return(arch, arg_count=4, return_value=0)
    else:
        force = _force_api_return(arch, arg_count=0, return_value=0)

    result = {
        "handled": bool(force.get("ok")),
        "api": api,
        "arch": arch,
        "writes": writes,
        "force": force,
        "comment": detection.get("comment"),
        "infoClass": _normalize_hex(detection.get("infoClass")),
    }
    current_rip = _normalize_hex(state.get("rip"))
    matched = (
        state.get("matchedBreakpoints", [])
        if isinstance(state.get("matchedBreakpoints"), list)
        else []
    )
    if current_rip:
        for bp in matched:
            if _normalize_hex(bp.get("addr")) != current_rip:
                continue
            module_name = str(bp.get("module") or "").lower()
            if module_name in ("kernel32.dll", "kernelbase.dll", "ntdll.dll"):
                delete_result = DebugDeleteBreakpoint(current_rip)
                if (
                    isinstance(delete_result, str)
                    and "deleted" in delete_result.lower()
                ):
                    result["removedBreakpoint"] = current_rip
                break
    if result["handled"]:
        _log_event(
            "common_antidebug_bypass",
            api=api,
            arch=arch,
            writes=writes,
            returnAddress=force.get("returnAddress"),
            infoClass=result.get("infoClass"),
            removedBreakpoint=result.get("removedBreakpoint"),
        )
    return result


def _advance_debuggee_toward_interaction(
    mode: str,
    timeout_ms: int,
    poll_ms: int,
    pid: int = 0,
    visible_only: bool = True,
    max_depth: int = 5,
) -> Dict[str, Any]:
    base_budget = max(timeout_ms, 0) / 1000.0
    deadline = time.time() + base_budget
    extra_budget = 0.0
    max_extra_budget = max(10.0, min(20.0, base_budget * 1.5))
    removed_breakpoints: List[str] = []
    managed_breakpoints: List[str] = []
    auto_runs = 0
    auto_bypasses: List[Dict[str, Any]] = []
    last_state: Dict[str, Any] = {}
    last_gui: Dict[str, Any] = {}
    last_input: Dict[str, Any] = {}
    resume_result: Optional[str] = None

    def finalize(payload: Dict[str, Any]) -> Dict[str, Any]:
        cleaned = _delete_breakpoints(managed_breakpoints)
        for addr in cleaned:
            if addr not in removed_breakpoints:
                removed_breakpoints.append(addr)
        payload["autoRuns"] = auto_runs
        payload["autoBypasses"] = auto_bypasses
        payload["removedBreakpoints"] = removed_breakpoints
        payload["resumeResult"] = resume_result
        return payload

    def extend_deadline(seconds: float) -> None:
        nonlocal deadline, extra_budget
        if seconds <= 0:
            return
        allowed = min(seconds, max_extra_budget - extra_budget)
        if allowed <= 0:
            return
        extra_budget += allowed
        deadline += allowed

    while time.time() <= deadline:
        last_state = _build_debug_state(
            include_console=True, include_callstack=True, max_console_chars=4000
        )
        if last_state.get("state") in ("exited", "not_debugging"):
            if mode == "gui" and not pid:
                retarget_gui = _collect_retarget_gui_snapshot(
                    visible_only=visible_only,
                    include_children=True,
                    max_depth=max_depth,
                )
                if retarget_gui and (retarget_gui.get("analysis") or {}).get(
                    "hasVisibleWindow"
                ):
                    return finalize(
                        {
                            "ok": True,
                            "ready": True,
                            "timedOut": False,
                            "mode": mode,
                            "state": last_state,
                            "gui": retarget_gui,
                        }
                    )
            break

        target_pid = pid or int(last_state.get("debuggeePid") or 0)
        if mode == "gui":
            last_gui = GetDebuggeeWindows(
                pid=target_pid,
                include_children=True,
                visible_only=visible_only,
                max_depth=max_depth,
            )
            if isinstance(last_gui, dict):
                analysis = last_gui.get("analysis", {})
                if analysis.get("hasEdit") and analysis.get("hasButton"):
                    return finalize(
                        {
                            "ok": True,
                            "ready": True,
                            "timedOut": False,
                            "mode": mode,
                            "state": last_state,
                            "gui": last_gui,
                        }
                    )
                if analysis.get("safeAutoButtonHwnd"):
                    return finalize(
                        {
                            "ok": True,
                            "ready": True,
                            "timedOut": False,
                            "mode": mode,
                            "state": last_state,
                            "gui": last_gui,
                        }
                    )
        else:
            last_input = {
                "debuggeePid": last_state.get("debuggeePid"),
                "state": last_state.get("state"),
                "waitingForInput": last_state.get("waitingForInput"),
                "confidence": last_state.get("inputConfidence"),
                "reason": last_state.get("inputReason"),
                "signals": last_state.get("inputSignals"),
                "promptText": last_state.get("promptText"),
                "shouldAutoSubmit": last_state.get("shouldAutoSubmit"),
                "consoleLines": last_state.get("console", {}).get("lines", [])[-8:],
                "rip": last_state.get("rip"),
                "stopReason": last_state.get("stopReason"),
                "logPath": last_state.get("logPath"),
            }
            if last_state.get("shouldAutoSubmit") or (
                last_state.get("waitingForInput")
                and last_state.get("inputConfidence") in ("high", "medium")
            ):
                return finalize(
                    {
                        "ok": True,
                        "ready": True,
                        "timedOut": False,
                        "mode": mode,
                        "state": last_state,
                        "analysis": last_input,
                    }
                )

        if last_state.get("running"):
            time.sleep(max(poll_ms, 20) / 1000.0)
            continue

        gui_analysis = (
            last_gui.get("analysis", {}) if isinstance(last_gui, dict) else {}
        )
        if not gui_analysis.get("hasVisibleWindow") and not managed_breakpoints:
            for addr in _ensure_common_antidebug_breakpoints():
                if addr not in managed_breakpoints:
                    managed_breakpoints.append(addr)
            if managed_breakpoints:
                extend_deadline(2.0)

        bypass = _apply_common_antidebug_bypass(last_state, gui_snapshot=last_gui)
        if bypass.get("handled"):
            removed_bp = _normalize_hex(bypass.get("removedBreakpoint"))
            if removed_bp and removed_bp not in removed_breakpoints:
                removed_breakpoints.append(removed_bp)
            if removed_bp and removed_bp in managed_breakpoints:
                managed_breakpoints = [
                    addr for addr in managed_breakpoints if addr != removed_bp
                ]
            auto_bypasses.append(
                {
                    "api": bypass.get("api"),
                    "arch": bypass.get("arch"),
                    "infoClass": bypass.get("infoClass"),
                    "returnAddress": bypass.get("force", {}).get("returnAddress"),
                }
            )
            resume_result = DebugRun()
            auto_runs += 1
            extend_deadline(3.0)
            remaining_ms = max(0, int((deadline - time.time()) * 1000))
            if remaining_ms <= 0:
                break
            wait_budget = min(1200, max(poll_ms * 3, 250), remaining_ms)
            wait_state = WaitForPause(
                timeout_ms=wait_budget, poll_ms=max(50, min(poll_ms, 150))
            )
            if isinstance(wait_state, dict) and wait_state.get("state") == "paused":
                last_state = wait_state
            time.sleep(max(20, min(poll_ms, 120)) / 1000.0)
            continue

        current_rip = _normalize_hex(last_state.get("rip"))
        call_entries = (
            last_state.get("callStack", {}).get("entries", [])
            if isinstance(last_state.get("callStack"), dict)
            else []
        )
        top_comment = str(call_entries[0].get("comment", "")) if call_entries else ""
        session_info = (
            last_state.get("session", {})
            if isinstance(last_state.get("session"), dict)
            else {}
        )
        bp_module = str(session_info.get("breakpointModule") or "").lower()
        if (
            current_rip
            and last_state.get("stopReason") == "breakpoint"
            and bp_module in ("kernel32.dll", "kernelbase.dll", "ntdll.dll")
            and any(marker in top_comment.lower() for marker in COMMON_ANTI_DEBUG_APIS)
        ):
            removed = _delete_breakpoints([current_rip])
            for addr in removed:
                if addr not in removed_breakpoints:
                    removed_breakpoints.append(addr)
            managed_breakpoints = [
                addr for addr in managed_breakpoints if addr != current_rip
            ]
            _log_event(
                "ignored_managed_antidebug_breakpoint",
                rip=current_rip,
                module=bp_module,
                comment=top_comment,
            )
            resume_result = DebugRun()
            auto_runs += 1
            extend_deadline(2.0)
            remaining_ms = max(0, int((deadline - time.time()) * 1000))
            if remaining_ms <= 0:
                break
            wait_budget = min(1200, max(poll_ms * 3, 250), remaining_ms)
            wait_state = WaitForPause(
                timeout_ms=wait_budget, poll_ms=max(50, min(poll_ms, 150))
            )
            if isinstance(wait_state, dict) and wait_state.get("state") == "paused":
                last_state = wait_state
            time.sleep(max(20, min(poll_ms, 120)) / 1000.0)
            continue

        startup_noise = _detect_non_target_startup_breakpoint(
            last_state, gui_snapshot=last_gui
        )
        if startup_noise.get("handled"):
            removed = _delete_breakpoints([str(startup_noise.get("addr") or "")])
            for addr in removed:
                if addr not in removed_breakpoints:
                    removed_breakpoints.append(addr)
            _log_event(
                "ignored_non_target_startup_breakpoint",
                rip=startup_noise.get("addr"),
                module=startup_noise.get("module"),
                name=startup_noise.get("name"),
                hitCount=startup_noise.get("hitCount"),
                singleshoot=startup_noise.get("singleshoot"),
            )
            resume_result = DebugRun()
            auto_runs += 1
            extend_deadline(2.0)
            remaining_ms = max(0, int((deadline - time.time()) * 1000))
            if remaining_ms <= 0:
                break
            wait_budget = min(1200, max(poll_ms * 3, 250), remaining_ms)
            wait_state = WaitForPause(
                timeout_ms=wait_budget, poll_ms=max(50, min(poll_ms, 150))
            )
            if isinstance(wait_state, dict) and wait_state.get("state") == "paused":
                last_state = wait_state
            time.sleep(max(20, min(poll_ms, 120)) / 1000.0)
            continue

        if not _is_startup_pause(last_state, gui_snapshot=last_gui):
            break

        removed = _remove_safe_startup_breakpoints(
            last_state.get("debuggeeImage"),
            allow_debuggee_entrypoint=True,
            current_addr=str(last_state.get("rip") or ""),
        )
        for addr in removed:
            if addr not in removed_breakpoints:
                removed_breakpoints.append(addr)
        if removed:
            extend_deadline(1.5)
        resume_result = DebugRun()
        auto_runs += 1
        remaining_ms = max(0, int((deadline - time.time()) * 1000))
        if remaining_ms <= 0:
            break
        wait_budget = min(1200, max(poll_ms * 3, 250), remaining_ms)
        wait_state = WaitForPause(
            timeout_ms=wait_budget, poll_ms=max(50, min(poll_ms, 150))
        )
        if isinstance(wait_state, dict) and wait_state.get("state") == "paused":
            last_state = wait_state
        time.sleep(max(20, min(poll_ms, 120)) / 1000.0)

    return finalize(
        {
            "ok": False,
            "ready": False,
            "timedOut": time.time() > deadline,
            "mode": mode,
            "state": last_state,
            "gui": last_gui,
            "analysis": last_input,
            "logPath": LOG_PATH,
        }
    )


def _advance_debuggee_toward_window(
    timeout_ms: int,
    poll_ms: int,
    pid: int = 0,
    visible_only: bool = True,
    include_children: bool = True,
    max_depth: int = 4,
) -> Dict[str, Any]:
    base_budget = max(timeout_ms, 0) / 1000.0
    deadline = time.time() + base_budget
    extra_budget = 0.0
    max_extra_budget = max(12.0, min(25.0, base_budget * 1.5))
    removed_breakpoints: List[str] = []
    managed_breakpoints: List[str] = []
    auto_runs = 0
    auto_bypasses: List[Dict[str, Any]] = []
    last_state: Dict[str, Any] = {}
    last_gui: Dict[str, Any] = {}
    resume_result: Optional[str] = None

    def finalize(payload: Dict[str, Any]) -> Dict[str, Any]:
        cleaned = _delete_breakpoints(managed_breakpoints)
        for addr in cleaned:
            if addr not in removed_breakpoints:
                removed_breakpoints.append(addr)
        payload["autoRuns"] = auto_runs
        payload["autoBypasses"] = auto_bypasses
        payload["removedBreakpoints"] = removed_breakpoints
        payload["resumeResult"] = resume_result
        return payload

    def extend_deadline(seconds: float) -> None:
        nonlocal deadline, extra_budget
        if seconds <= 0:
            return
        allowed = min(seconds, max_extra_budget - extra_budget)
        if allowed <= 0:
            return
        extra_budget += allowed
        deadline += allowed

    while time.time() <= deadline:
        last_state = _build_debug_state(
            include_console=False, include_callstack=True, max_console_chars=0
        )
        if last_state.get("state") in ("exited", "not_debugging"):
            if not pid:
                retarget_gui = _collect_retarget_gui_snapshot(
                    visible_only=visible_only,
                    include_children=include_children,
                    max_depth=max_depth,
                )
                if retarget_gui and (retarget_gui.get("analysis") or {}).get(
                    "hasVisibleWindow"
                ):
                    return finalize(
                        {
                            "ok": True,
                            "ready": True,
                            "timedOut": False,
                            "state": last_state,
                            "gui": retarget_gui,
                        }
                    )
            break
        target_pid = pid or int(last_state.get("debuggeePid") or 0)
        last_gui = GetDebuggeeWindows(
            pid=target_pid,
            include_children=include_children,
            visible_only=visible_only,
            max_depth=max_depth,
        )
        gui_analysis = (
            last_gui.get("analysis", {}) if isinstance(last_gui, dict) else {}
        )
        if gui_analysis.get("hasVisibleWindow"):
            return finalize(
                {
                    "ok": True,
                    "ready": True,
                    "timedOut": False,
                    "state": last_state,
                    "gui": last_gui,
                }
            )
        if last_state.get("running"):
            time.sleep(max(poll_ms, 20) / 1000.0)
            continue
        if not managed_breakpoints:
            for addr in _ensure_common_antidebug_breakpoints():
                if addr not in managed_breakpoints:
                    managed_breakpoints.append(addr)
            if managed_breakpoints:
                extend_deadline(2.0)
        bypass = _apply_common_antidebug_bypass(last_state, gui_snapshot=last_gui)
        if bypass.get("handled"):
            removed_bp = _normalize_hex(bypass.get("removedBreakpoint"))
            if removed_bp and removed_bp not in removed_breakpoints:
                removed_breakpoints.append(removed_bp)
            if removed_bp and removed_bp in managed_breakpoints:
                managed_breakpoints = [
                    addr for addr in managed_breakpoints if addr != removed_bp
                ]
            auto_bypasses.append(
                {
                    "api": bypass.get("api"),
                    "arch": bypass.get("arch"),
                    "infoClass": bypass.get("infoClass"),
                    "returnAddress": bypass.get("force", {}).get("returnAddress"),
                }
            )
            extend_deadline(3.0)
        else:
            current_rip = _normalize_hex(last_state.get("rip"))
            call_entries = (
                last_state.get("callStack", {}).get("entries", [])
                if isinstance(last_state.get("callStack"), dict)
                else []
            )
            top_comment = (
                str(call_entries[0].get("comment", "")) if call_entries else ""
            )
            session_info = (
                last_state.get("session", {})
                if isinstance(last_state.get("session"), dict)
                else {}
            )
            bp_module = str(session_info.get("breakpointModule") or "").lower()
            if (
                current_rip
                and last_state.get("stopReason") == "breakpoint"
                and bp_module in ("kernel32.dll", "kernelbase.dll", "ntdll.dll")
                and any(
                    marker in top_comment.lower() for marker in COMMON_ANTI_DEBUG_APIS
                )
            ):
                removed = _delete_breakpoints([current_rip])
                for addr in removed:
                    if addr not in removed_breakpoints:
                        removed_breakpoints.append(addr)
                managed_breakpoints = [
                    addr for addr in managed_breakpoints if addr != current_rip
                ]
                _log_event(
                    "ignored_managed_antidebug_breakpoint",
                    rip=current_rip,
                    module=bp_module,
                    comment=top_comment,
                )
                extend_deadline(2.5)
            else:
                startup_noise = _detect_non_target_startup_breakpoint(
                    last_state, gui_snapshot=last_gui
                )
                if startup_noise.get("handled"):
                    removed = _delete_breakpoints(
                        [str(startup_noise.get("addr") or "")]
                    )
                    for addr in removed:
                        if addr not in removed_breakpoints:
                            removed_breakpoints.append(addr)
                    _log_event(
                        "ignored_non_target_startup_breakpoint",
                        rip=startup_noise.get("addr"),
                        module=startup_noise.get("module"),
                        name=startup_noise.get("name"),
                        hitCount=startup_noise.get("hitCount"),
                        singleshoot=startup_noise.get("singleshoot"),
                    )
                    extend_deadline(2.0)
                elif not _is_startup_pause(last_state, gui_snapshot=last_gui):
                    break
                else:
                    removed = _remove_safe_startup_breakpoints(
                        last_state.get("debuggeeImage"),
                        allow_debuggee_entrypoint=True,
                        current_addr=str(last_state.get("rip") or ""),
                    )
                    for addr in removed:
                        if addr not in removed_breakpoints:
                            removed_breakpoints.append(addr)
                    if removed:
                        extend_deadline(1.5)
        resume_result = DebugRun()
        auto_runs += 1
        remaining_ms = max(0, int((deadline - time.time()) * 1000))
        if remaining_ms <= 0:
            break
        wait_budget = min(1200, max(poll_ms * 3, 250), remaining_ms)
        wait_state = WaitForPause(
            timeout_ms=wait_budget, poll_ms=max(50, min(poll_ms, 150))
        )
        if isinstance(wait_state, dict) and wait_state.get("state") == "paused":
            last_state = wait_state
        time.sleep(max(20, min(poll_ms, 120)) / 1000.0)

    return finalize(
        {
            "ok": False,
            "ready": False,
            "timedOut": time.time() > deadline,
            "state": last_state,
            "gui": last_gui,
            "logPath": LOG_PATH,
        }
    )


def _should_auto_advance_window_wait(
    state: Dict[str, Any], gui_snapshot: Optional[Dict[str, Any]] = None
) -> bool:
    if (
        not isinstance(state, dict)
        or not state.get("debugging")
        or state.get("running")
    ):
        return False
    gui_analysis = (
        gui_snapshot.get("analysis", {}) if isinstance(gui_snapshot, dict) else {}
    )
    if gui_analysis.get("hasVisibleWindow"):
        return False
    if _is_startup_pause(state, gui_snapshot=gui_snapshot):
        return True
    if _detect_non_target_startup_breakpoint(state, gui_snapshot=gui_snapshot).get(
        "handled"
    ):
        return True
    if str(state.get("stopReason") or "").lower() != "breakpoint":
        return False
    session_info = (
        state.get("session", {}) if isinstance(state.get("session"), dict) else {}
    )
    bp_module = str(session_info.get("breakpointModule") or "").lower()
    if bp_module not in ("kernel32.dll", "kernelbase.dll", "ntdll.dll"):
        return False
    call_entries = (
        state.get("callStack", {}).get("entries", [])
        if isinstance(state.get("callStack"), dict)
        else []
    )
    top_comment = str(call_entries[0].get("comment", "")) if call_entries else ""
    return any(marker in top_comment.lower() for marker in COMMON_ANTI_DEBUG_APIS)


def _collect_register_dump(log: bool = False) -> Dict[str, Any]:
    payload = _coerce_json_payload(safe_get("RegisterDump", log=log))
    return payload if isinstance(payload, dict) else {}


def _collect_call_stack(log: bool = False) -> Dict[str, Any]:
    payload = _coerce_json_payload(safe_get("GetCallStack", log=log))
    return payload if isinstance(payload, dict) else {}


def _detect_prompt_from_console(console_text: str) -> Dict[str, Any]:
    lines = _last_nonempty_console_lines(console_text, limit=5)
    prompt_line = lines[-1] if lines else ""
    lower_prompt = prompt_line.lower()
    signals: List[str] = []
    score = 0
    if prompt_line.rstrip().endswith((":", ">", "?", "]")):
        signals.append("console_line_ends_with_prompt_marker")
        score += 1
    if any(keyword in lower_prompt for keyword in INPUT_PROMPT_KEYWORDS):
        signals.append("console_line_contains_prompt_keyword")
        score += 2
    if "press any key" in lower_prompt:
        signals.append("console_line_requests_any_key")
        score += 3
    return {
        "promptText": prompt_line,
        "signals": signals,
        "score": score,
    }


def _detect_input_wait(
    callstack: Dict[str, Any], console: Dict[str, Any], paused: bool, running: bool
) -> Dict[str, Any]:
    prompt_info = _detect_prompt_from_console(console.get("text", ""))
    signals = list(prompt_info["signals"])
    score = int(prompt_info["score"])
    matched_frames: List[str] = []
    callstack_entries = (
        callstack.get("entries", []) if isinstance(callstack, dict) else []
    )
    for entry in callstack_entries:
        comment = str(entry.get("comment", "")).lower()
        if any(marker in comment for marker in INPUT_WAIT_STACK_MARKERS):
            matched_frames.append(str(entry.get("comment", "")))
    if matched_frames:
        signals.append("callstack_contains_input_read")
        score += 3 if paused else 2

    waiting = score >= 3 or (
        "callstack_contains_input_read" in signals and prompt_info["promptText"]
    )
    confidence = "high" if score >= 5 else ("medium" if score >= 3 else "low")
    reason = ""
    if waiting and "callstack_contains_input_read" in signals:
        reason = "The paused stack is inside console/stdin read functions."
    elif waiting and prompt_info["promptText"]:
        reason = "The console text looks like an input prompt."
    elif running and prompt_info["promptText"]:
        reason = "The target is running and the console shows a prompt-like line."

    return {
        "waitingForInput": waiting,
        "confidence": confidence,
        "reason": reason,
        "signals": signals,
        "promptText": prompt_info["promptText"],
        "matchedFrames": matched_frames[:10],
        "shouldAutoSubmit": waiting and confidence in ("high", "medium"),
    }


def _get_debug_session_state(
    include_history: bool = False, history_limit: int = 16
) -> Dict[str, Any]:
    try:
        payload = _coerce_json_payload(
            safe_get(
                "Debug/SessionState",
                {
                    "includeHistory": "true" if include_history else "false",
                    "historyLimit": max(0, int(history_limit)),
                },
                log=False,
            )
        )
    except Exception:
        return {}
    if isinstance(payload, dict):
        _update_bridge_identity_from_session(payload)
        return payload
    return {}


def _build_debug_state(
    include_console: bool = True,
    include_callstack: bool = True,
    max_console_chars: int = 4000,
    include_registers: bool = True,
    include_breakpoints: bool = True,
    include_session: bool = True,
) -> Dict[str, Any]:
    raw_session_payload = _get_debug_session_state(
        include_history=False, history_limit=0
    )
    session_payload = (
        dict(raw_session_payload) if isinstance(raw_session_payload, dict) else {}
    )
    if session_payload:
        for text_key in (
            "imagePath",
            "breakpointName",
            "breakpointModule",
            "note",
            "state",
            "lastEventType",
            "stopReason",
        ):
            value = session_payload.get(text_key)
            if isinstance(value, str):
                session_payload[text_key] = _repair_text_mojibake(value)
    debugging_payload = _coerce_json_payload(safe_get("Is_Debugging", log=False))
    active_payload = _coerce_json_payload(safe_get("IsDebugActive", log=False))
    runtime_debugging = (
        bool(debugging_payload.get("isDebugging"))
        if isinstance(debugging_payload, dict)
        else None
    )
    runtime_running = (
        bool(active_payload.get("isRunning"))
        if isinstance(active_payload, dict)
        else None
    )
    session_debugging = (
        bool(session_payload.get("debugging")) if session_payload else False
    )
    session_running = bool(session_payload.get("running")) if session_payload else False
    session_paused = bool(session_payload.get("paused")) if session_payload else False

    debugging = (
        runtime_debugging if runtime_debugging is not None else session_debugging
    )
    if debugging and session_paused:
        running = False
        paused = True
    else:
        running = runtime_running if runtime_running is not None else session_running
        if not debugging:
            running = False
        paused = debugging and not running

    debuggee_image = None
    session_image_path = (
        str(session_payload.get("imagePath") or "") if session_payload else ""
    )
    if session_image_path:
        debuggee_image = os.path.basename(session_image_path).lower()
    if not debuggee_image:
        debuggee_image = (
            _get_current_debuggee_image_name()
            if debugging
            else _get_runtime_value("lastDebuggeeImage")
        )
    debuggee_pid = 0
    try:
        debuggee_pid = (
            int(session_payload.get("processId") or 0) if session_payload else 0
        )
        if not debuggee_pid:
            debuggee_pid = (
                _infer_debuggee_pid(0)
                if debugging
                else int(_get_runtime_value("lastDebuggeePid", 0) or 0)
            )
    except Exception:
        debuggee_pid = int(_get_runtime_value("lastDebuggeePid", 0) or 0)

    process_exists = _process_exists(debuggee_pid)
    session_state_name = (
        str(session_payload.get("state") or "") if session_payload else ""
    )
    runtime_mismatch = bool(
        session_payload
        and (
            session_debugging != debugging
            or session_running != running
            or (session_paused != paused)
        )
    )
    if not debugging:
        if debuggee_pid and not process_exists:
            state_name = "exited"
        else:
            state_name = "not_debugging"
    elif session_state_name:
        if paused:
            state_name = "paused"
        elif session_state_name == "exited" and debugging:
            state_name = "paused" if paused else "running"
        else:
            state_name = session_state_name
    elif debugging:
        state_name = "running" if running else "paused"
    elif debuggee_pid and not process_exists:
        state_name = "exited"
    else:
        state_name = "not_debugging"

    if session_payload:
        session_payload["debugging"] = debugging
        session_payload["running"] = running
        session_payload["paused"] = paused
        session_payload["state"] = state_name
        session_payload["runtimeMismatch"] = runtime_mismatch

    if session_payload and session_payload.get("state"):
        state_name = str(session_payload.get("state"))

    breakpoint_snapshot = (
        _collect_breakpoint_snapshot(log=False)
        if debugging and include_breakpoints
        else {"count": 0, "breakpoints": []}
    )
    current_hits = {
        _normalize_hex(bp.get("addr")) or str(bp.get("addr")): int(
            bp.get("hitCount", 0) or 0
        )
        for bp in breakpoint_snapshot.get("breakpoints", [])
        if isinstance(bp, dict)
    }
    previous_hits = _get_runtime_value("lastBreakpointHits", {}) or {}
    newly_hit = []
    for bp in breakpoint_snapshot.get("breakpoints", []):
        if not isinstance(bp, dict):
            continue
        addr = _normalize_hex(bp.get("addr")) or str(bp.get("addr"))
        hit_count = int(bp.get("hitCount", 0) or 0)
        if hit_count > int(previous_hits.get(addr, 0) or 0):
            newly_hit.append(bp)

    register_dump = (
        _collect_register_dump(log=False) if paused and include_registers else {}
    )
    rip = (
        _normalize_hex(register_dump.get("cip"))
        if register_dump
        else _normalize_hex(session_payload.get("ip"))
        if session_payload
        else None
    )
    matching_breakpoints = [
        bp
        for bp in breakpoint_snapshot.get("breakpoints", [])
        if isinstance(bp, dict) and _normalize_hex(bp.get("addr")) == rip
    ]
    callstack = _collect_call_stack(log=False) if paused and include_callstack else {}
    console = (
        _read_console_text(debuggee_pid, max_chars=max_console_chars)
        if include_console and debuggee_pid and process_exists
        else {
            "ok": False,
            "pid": debuggee_pid,
            "conhostPid": None,
            "text": "",
            "lines": [],
            "reason": "Console not available",
        }
    )
    input_state = _detect_input_wait(callstack, console, paused=paused, running=running)

    stop_reason = (
        str(session_payload.get("stopReason") or "") if session_payload else ""
    )
    if not stop_reason and state_name == "paused":
        if matching_breakpoints or newly_hit:
            stop_reason = "breakpoint"
        elif input_state["waitingForInput"]:
            stop_reason = "waiting_for_input"
        elif register_dump.get("lastStatus", {}).get("code"):
            stop_reason = "status_pause"
    elif stop_reason == "pause" and input_state["waitingForInput"]:
        stop_reason = "waiting_for_input"

    bound_session = _describe_bound_session_match(
        state={
            "debuggeePid": debuggee_pid,
            "debuggeeImage": debuggee_image,
            "debuggeePath": session_image_path or _get_runtime_value("lastDebuggeePath"),
            "session": session_payload,
        }
    )
    if session_payload and include_session:
        session_payload["binding"] = bound_session

    state = {
        "timestamp": _now_iso(),
        "sessionStartedAt": _get_runtime_value("sessionStartedAt"),
        "state": state_name,
        "debugging": debugging,
        "running": running,
        "paused": paused,
        "exited": state_name == "exited",
        "processExists": process_exists,
        "debuggeePid": debuggee_pid or None,
        "debuggeeImage": debuggee_image,
        "debuggeePath": session_image_path or _get_runtime_value("lastDebuggeePath"),
        "conhostPid": console.get("conhostPid"),
        "rip": rip,
        "stopReason": stop_reason or None,
        "eventSeq": int(session_payload.get("eventSeq") or 0)
        if session_payload
        else int(_get_runtime_value("lastSessionEventSeq", 0) or 0),
        "lastEventType": session_payload.get("lastEventType")
        if session_payload
        else None,
        "matchedBreakpoints": matching_breakpoints,
        "newlyHitBreakpoints": newly_hit,
        "breakpointCount": breakpoint_snapshot.get("count", 0),
        "breakpointHitCounts": current_hits,
        "waitingForInput": input_state["waitingForInput"],
        "inputConfidence": input_state["confidence"],
        "inputReason": input_state["reason"],
        "inputSignals": input_state["signals"],
        "promptText": input_state["promptText"],
        "shouldAutoSubmit": input_state["shouldAutoSubmit"],
        "console": console,
        "registers": register_dump if paused and include_registers else {},
        "callStack": callstack if paused and include_callstack else {},
        "session": session_payload if include_session else {},
        "binding": bound_session,
        "runtimeMismatch": runtime_mismatch,
        "logPath": LOG_PATH,
    }

    _remember_runtime(
        lastDebuggeePid=debuggee_pid or 0,
        lastDebuggeeImage=debuggee_image,
        lastDebuggeePath=session_image_path or _get_runtime_value("lastDebuggeePath"),
        lastState=state_name,
        lastRip=rip,
        lastBreakpointHits=current_hits
        if include_breakpoints
        else _get_runtime_value("lastBreakpointHits", {}) or {},
        lastConsoleText=console.get("text", ""),
        lastSessionEventSeq=int(session_payload.get("eventSeq") or 0)
        if session_payload
        else int(_get_runtime_value("lastSessionEventSeq", 0) or 0),
    )
    _log_event(
        "debug_state",
        state=state_name,
        pid=debuggee_pid,
        rip=rip,
        stopReason=stop_reason,
        waitingForInput=input_state["waitingForInput"],
        promptText=input_state["promptText"],
        newBreakpointCount=len(newly_hit),
    )
    return state


def set_x64dbg_server_url(url: str) -> None:
    global x64dbg_server_url
    normalized = _normalize_loopback_server_url(url)
    if normalized and normalized != x64dbg_server_url:
        x64dbg_server_url = normalized
        _invalidate_bridge_auth_cache()


def _server_lock_payload() -> Dict[str, Any]:
    return {
        "pid": int(os.getpid()),
        "path": os.path.abspath(__file__),
        "createdAt": _now_iso(),
    }


def _read_server_lock() -> Dict[str, Any]:
    try:
        if not os.path.exists(SERVER_LOCK_PATH):
            return {}
        return json.loads(
            Path(SERVER_LOCK_PATH).read_text(encoding="utf-8", errors="replace")
        )
    except Exception:
        return {}


def _write_server_lock() -> None:
    payload = json.dumps(_server_lock_payload(), ensure_ascii=False, indent=2).encode(
        "utf-8"
    )
    fd = os.open(SERVER_LOCK_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)


def _clear_server_lock() -> None:
    try:
        payload = _read_server_lock()
        if int(payload.get("pid") or 0) == int(os.getpid()) and os.path.exists(
            SERVER_LOCK_PATH
        ):
            os.remove(SERVER_LOCK_PATH)
    except Exception:
        pass


def _terminate_process_quiet(pid: int) -> bool:
    try:
        if os.name == "nt":
            completed = subprocess.run(
                ["taskkill", "/PID", str(int(pid)), "/F", "/T"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
            return completed.returncode == 0
        os.kill(int(pid), 9)
        return True
    except Exception:
        return False


def _process_exists_quiet(pid: int) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except Exception:
        return False


def _become_primary_server_instance() -> None:
    # stdio MCP servers are spawned per client/session, so enforcing a singleton
    # here is unsafe: a stale PID lock can terminate unrelated processes.
    try:
        existing = _read_server_lock()
        existing_pid = int(existing.get("pid") or 0)
        if not existing_pid or not _process_exists_quiet(existing_pid):
            try:
                if os.path.exists(SERVER_LOCK_PATH):
                    os.remove(SERVER_LOCK_PATH)
            except Exception:
                pass
        try:
            _write_server_lock()
        except FileExistsError:
            # Another live instance already owns the advisory lock; do not
            # interfere with it because the host manages stdio lifetimes.
            return
        atexit.register(_clear_server_lock)
    except Exception:
        pass


def _start_server_lock_watchdog() -> None:
    # Disabled on purpose. The host process owns stdio MCP lifetimes; exiting the
    # server because a lock file changed causes spurious disconnects in Codex.
    return
