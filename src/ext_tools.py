"""
Extensions for x64dbg MCP server.

Loaded by x64dbg.py at the end of module init via:
    _load_ext_tools(mcp, globals())

- Patches existing helpers (_build_debug_state, _is_startup_pause) to fix
  mojibake paths.
- Registers new high-level tools used during reverse-engineering sessions.

Nothing here talks to the C++ bridge directly — everything routes through
the existing safe_get/safe_post/_coerce_json_payload primitives so that the
semantics match the rest of the server.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import struct
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import pefile  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    pefile = None


def _looks_mojibaked(text: str) -> bool:
    if not text or not isinstance(text, str):
        return False
    score = 0
    score += sum(text.count(ch) for ch in ("\u0420", "\u0421", "\u00d0", "\u00d1"))
    return score >= 2


def _strong_repair(value: str) -> str:
    """Fall-back CP1251<->UTF-8 repair for strings that passed through the
    heuristic cleaner in x64dbg.py unchanged."""
    if not isinstance(value, str) or len(value) < 4:
        return value
    if not _looks_mojibaked(value):
        return value
    candidates: List[str] = [value]
    for enc in ("cp1251", "latin-1"):
        try:
            repaired = value.encode(enc, errors="strict").decode("utf-8", errors="strict")
            candidates.append(repaired)
        except Exception:
            continue
    best = min(
        candidates,
        key=lambda s: (sum(1 for ch in s if ch in "\u0420\u0421\u00d0\u00d1"), -len(s)),
    )
    return best


def _looks_mojibaked_v2(text: str) -> bool:
    if not text or not isinstance(text, str):
        return False
    markers = ("Р", "С", "Ð", "Ñ", "Ã", "Â", "â")
    score = sum(text.count(ch) for ch in markers)
    score += len(re.findall(r"(?:Р.|С.|Ð.|Ñ.|Ã.|Â.|â.)", text))
    return score >= 2


def _strong_repair_v2(value: str) -> str:
    if not isinstance(value, str) or len(value) < 4:
        return value
    path_like = bool(re.match(r"^[A-Za-z]:[\\/]", value) or "\\" in value or "/" in value)
    if not _looks_mojibaked_v2(value) and not (path_like and any(ord(ch) >= 128 for ch in value)):
        return value

    candidates: List[str] = [value]
    for enc in ("cp1251", "cp866", "cp1252", "latin-1"):
        try:
            candidates.append(
                value.encode(enc, errors="strict").decode("utf-8", errors="strict")
            )
        except Exception:
            continue

    def _rank(text: str) -> tuple[int, int, int]:
        exists = 1 if path_like and os.path.exists(text) else 0
        parent = os.path.dirname(text) if path_like else ""
        parent_exists = 1 if parent and os.path.exists(parent) else 0
        suspicious = sum(text.count(ch) for ch in ("Р", "С", "Ð", "Ñ", "Ã", "Â", "â"))
        return (exists, parent_exists, -suspicious)

    return max(candidates, key=_rank)


def _looks_mojibaked_v3(text: str) -> bool:
    if not text or not isinstance(text, str):
        return False
    markers = ("\u0420", "\u0421", "\u00d0", "\u00d1", "\u0413", "\u0412", "\u0432")
    score = sum(text.count(ch) for ch in markers)
    score += len(
        re.findall(
            r"(?:\u0420.|\u0421.|\u00d0.|\u00d1.|\u0413.|\u0412.|\u0432.)",
            text,
        )
    )
    return score >= 2


def _strong_repair_v3(value: str) -> str:
    if not isinstance(value, str) or len(value) < 4:
        return value
    path_like = bool(re.match(r"^[A-Za-z]:[\\/]", value) or "\\" in value or "/" in value)
    if not _looks_mojibaked_v3(value) and not (path_like and any(ord(ch) >= 128 for ch in value)):
        return value

    candidates: List[str] = [value]
    for enc in ("cp1251", "cp866", "cp1252", "latin-1"):
        try:
            candidates.append(value.encode(enc, errors="strict").decode("utf-8", errors="strict"))
        except Exception:
            continue

    def _rank(text: str) -> tuple[int, int, int]:
        exists = 1 if path_like and os.path.exists(text) else 0
        parent = os.path.dirname(text) if path_like else ""
        parent_exists = 1 if parent and os.path.exists(parent) else 0
        suspicious = sum(text.count(ch) for ch in ("\u0420", "\u0421", "\u00d0", "\u00d1", "\u0413", "\u0412", "\u0432"))
        suspicious += len(
            re.findall(
                r"(?:\u0420.|\u0421.|\u00d0.|\u00d1.|\u0413.|\u0412.|\u0432.)",
                text,
            )
        )
        cyrillic = sum(1 for ch in text if "\u0400" <= ch <= "\u04ff")
        return (exists, parent_exists, -suspicious, cyrillic)

    return max(candidates, key=_rank)


_looks_mojibaked = _looks_mojibaked_v3
_strong_repair = _strong_repair_v3


def _classify_process_payload_evidence(
    *,
    runtime_headers_available: bool,
    layout_comparison: Dict[str, Any],
    code_compared_bytes: int,
    code_matches: bool,
    main_region_private: bool,
    header_matches: bool,
) -> Dict[str, Any]:
    """Classify PID-bound image evidence without relying on process names.

    Kept pure so normal, hollowed and ambiguous evidence can be regression
    tested without a live debugger.  A single mutable header or unreadable
    sample is never sufficient to claim hollowing.
    """

    signals: List[str] = []
    if not runtime_headers_available:
        signals.append("runtime-pe-headers-missing")
    else:
        for field, signal in (
            ("architectureMatches", "architecture-mismatch"),
            ("machineMatches", "machine-mismatch"),
            ("entryRvaMatches", "entry-rva-mismatch"),
            ("sizeOfImageMatches", "image-size-mismatch"),
            ("sectionsMatch", "section-layout-mismatch"),
        ):
            if not bool(layout_comparison.get(field)):
                signals.append(signal)
    if int(code_compared_bytes) >= 64 and not bool(code_matches):
        signals.append("immutable-code-mismatch")
    if main_region_private:
        signals.append("main-image-base-is-private")
    if not header_matches:
        signals.append("header-identity-mismatch")

    identity_replaced = any(
        signal in signals
        for signal in (
            "architecture-mismatch",
            "machine-mismatch",
            "entry-rva-mismatch",
            "image-size-mismatch",
            "section-layout-mismatch",
            "immutable-code-mismatch",
            "runtime-pe-headers-missing",
        )
    )
    independent_provenance = bool(
        main_region_private
        or "section-layout-mismatch" in signals
        or "runtime-pe-headers-missing" in signals
        or "immutable-code-mismatch" in signals
    )
    likely_hollowed = bool(
        identity_replaced and independent_provenance and len(signals) >= 2
    )
    confidence = (
        "high"
        if likely_hollowed and len(signals) >= 3
        else "medium"
        if likely_hollowed
        else "low"
    )
    return {
        "signals": signals,
        "likelyHollowed": likely_hollowed,
        "confidence": confidence,
    }


def register(mcp, g: Dict[str, Any]) -> None:
    safe_get: Callable = g["safe_get"]
    _coerce_json_payload: Callable = g["_coerce_json_payload"]
    _normalize_hex: Callable = g["_normalize_hex"]
    _parse_int: Callable = g["_parse_int"]
    _resolve_response_detail: Callable = g["_resolve_response_detail"]
    _repair_text_mojibake: Callable = g["_repair_text_mojibake"]
    _get_process_image_path: Callable = g["_get_process_image_path"]
    _log_event: Callable = g["_log_event"]
    _collect_register_dump: Callable = g["_collect_register_dump"]
    _collect_call_stack: Callable = g["_collect_call_stack"]
    _remember_runtime: Optional[Callable] = g.get("_remember_runtime")
    _get_runtime_value: Optional[Callable] = g.get("_get_runtime_value")
    _get_debug_session_state: Optional[Callable] = g.get("_get_debug_session_state")
    _get_mcp_tools_registry: Optional[Callable] = g.get("_get_mcp_tools_registry")
    _resolve_expression_value: Optional[Callable] = g.get("_resolve_expression_value")
    _resolve_remote_symbol_address: Optional[Callable] = g.get(
        "_resolve_remote_symbol_address"
    )
    _get_current_debuggee_module_base: Optional[Callable] = g.get(
        "_get_current_debuggee_module_base"
    )
    _bind_debuggee_session: Optional[Callable] = g.get("_bind_debuggee_session")
    _get_bound_session: Optional[Callable] = g.get("_get_bound_session")
    _clear_bound_session: Optional[Callable] = g.get("_clear_bound_session")
    _describe_bound_session_match: Optional[Callable] = g.get(
        "_describe_bound_session_match"
    )
    _enumerate_top_windows_global: Optional[Callable] = g.get(
        "_enumerate_top_windows_global"
    )
    _collect_window_node: Optional[Callable] = g.get("_collect_window_node")
    _flatten_window_tree: Optional[Callable] = g.get("_flatten_window_tree")
    _parse_hwnd_value: Optional[Callable] = g.get("_parse_hwnd_value")
    _scylla_dump_module: Optional[Callable] = g.get("_scylla_dump_module")
    _breakpoint_exists: Optional[Callable] = g.get("_breakpoint_exists")
    _parse_pe_layout: Optional[Callable] = g.get("_parse_pe_layout")
    _pe_import_evidence: Optional[Callable] = g.get("_pe_import_evidence")
    _is_system_noise_breakpoint: Optional[Callable] = g.get("_is_system_noise_breakpoint")

    ReadMemory = g["ReadMemory"]
    CaptureContext = g["CaptureContext"]
    DisasmGetInstructionRange = g["DisasmGetInstructionRange"]
    GetModuleList = g["GetModuleList"]
    GetCallStack = g["GetCallStack"]
    ExecCommand = g["ExecCommand"]
    DebugRun = g["DebugRun"]
    ContinueException = g.get("ContinueException")
    DebugPause = g["DebugPause"]
    DebugStepOver = g["DebugStepOver"]
    WaitForPause = g["WaitForPause"]
    WaitForBreakpointDetailed = g["WaitForBreakpointDetailed"]
    WaitForUserCode = g["WaitForUserCode"]
    ListChildProcesses = g.get("ListChildProcesses")
    WaitForChildProcess = g.get("WaitForChildProcess")
    AttachToProcess = g.get("AttachToProcess")
    IsDebugActive = g["IsDebugActive"]
    IsDebugging = g["IsDebugging"]
    MemoryBase = g["MemoryBase"]
    GetProcessDebugStatus = g.get("GetProcessDebugStatus")
    RemoveProcessDebug = g.get("RemoveProcessDebug")
    DebugSetBreakpoint = g.get("DebugSetBreakpoint")
    DebugDeleteBreakpoint = g.get("DebugDeleteBreakpoint")
    QuerySymbols = g.get("QuerySymbols")
    GetPatchList = g.get("GetPatchList")
    GetMemoryMap = g.get("GetMemoryMap")
    LabelList = g.get("LabelList")
    LabelGet = g.get("LabelGet")
    StringGetAt = g.get("StringGetAt")
    XrefGet = g.get("XrefGet")
    StartApiTrace = g.get("StartApiTrace")
    RunApiTrace = g.get("RunApiTrace")
    StopApiTrace = g.get("StopApiTrace")
    FindOEP = g.get("FindOEP")
    VerifyPEDump = g.get("VerifyPEDump")
    DumpLoadedModule = g.get("DumpLoadedModule")
    WriteMiniDump = g.get("WriteMiniDump")
    GetExceptionHistory = g.get("GetExceptionHistory")
    SetMemoryWatchpointWithCapture = g.get("SetMemoryWatchpointWithCapture")
    StepWithSnapshot = g.get("StepWithSnapshot")
    LaunchFileUnderDebugger = g.get("LaunchFileUnderDebugger")
    _detect_pe_arch = g.get("_detect_pe_arch")
    EnsureDebugger = g.get("EnsureDebugger")
    InitDebuggee = g.get("InitDebuggee")

    # ------------------------------------------------------------------
    # PATCH 1: clean debuggeePath/imagePath via QueryFullProcessImageNameW
    # ------------------------------------------------------------------
    _orig_build_debug_state = g["_build_debug_state"]

    def _build_debug_state_patched(
        include_console: bool = True,
        include_callstack: bool = True,
        max_console_chars: int = 4000,
        include_registers: bool = True,
        include_breakpoints: bool = True,
        include_session: bool = True,
    ) -> Dict[str, Any]:
        state = _orig_build_debug_state(
            include_console=include_console,
            include_callstack=include_callstack,
            max_console_chars=max_console_chars,
            include_registers=include_registers,
            include_breakpoints=include_breakpoints,
            include_session=include_session,
        )
        if not isinstance(state, dict):
            return state
        try:
            pid = int(state.get("debuggeePid") or 0)
            if pid:
                clean = _get_process_image_path(pid)
                if clean and ("\\" in clean or "/" in clean):
                    state["debuggeePath"] = clean
                    session = state.get("session")
                    if include_session and isinstance(session, dict):
                        session["imagePath"] = clean
        except Exception as e:
            _log_event("ext_patch_path_error", error=str(e))
        for key in ("debuggeePath",):
            value = state.get(key)
            if isinstance(value, str):
                state[key] = _strong_repair(value)
        return state

    g["_build_debug_state"] = _build_debug_state_patched

    # ------------------------------------------------------------------
    # Helpers shared by the new tools
    # ------------------------------------------------------------------

    def _state_main_module_fallback() -> Optional[Dict[str, Any]]:
        state = _build_debug_state_patched(
            include_console=False, include_callstack=False, max_console_chars=0
        )
        if not isinstance(state, dict):
            return None
        session = state.get("session", {}) if isinstance(state.get("session"), dict) else {}
        debuggee_path = _strong_repair(
            str(state.get("debuggeePath") or session.get("imagePath") or "")
        ).strip()
        debuggee_name = str(
            state.get("debuggeeImage") or os.path.basename(debuggee_path) or ""
        ).strip()
        if not debuggee_name and not debuggee_path:
            return None
        module_record: Dict[str, Any] = {"name": debuggee_name, "path": debuggee_path}
        if callable(_get_current_debuggee_module_base):
            try:
                base = _get_current_debuggee_module_base(want_entry=False)
                if base:
                    module_record["base"] = _normalize_hex(base)
            except Exception:
                pass
        return module_record

    def _resolve_main_module() -> Optional[Dict[str, Any]]:
        result = GetModuleList()
        modules = result.get("modules", []) if isinstance(result, dict) else []
        if not isinstance(modules, list):
            modules = []
        # Prefer the debuggee image name from state.
        state = _build_debug_state_patched(
            include_console=False, include_callstack=False, max_console_chars=0
        )
        target = str(state.get("debuggeeImage") or "").lower()
        for mod in modules:
            if isinstance(mod, dict) and str(mod.get("name", "")).lower() == target:
                return mod
        if modules and isinstance(modules[0], dict):
            return modules[0]
        return _state_main_module_fallback()

    def _module_for_addr(addr_hex: str) -> Optional[Dict[str, Any]]:
        try:
            addr = int(addr_hex, 0) if isinstance(addr_hex, str) else int(addr_hex or 0)
        except Exception:
            return None
        if not addr:
            return None
        result = GetModuleList()
        if not isinstance(result, dict):
            return None
        modules = result.get("modules", [])
        if not isinstance(modules, list):
            return None
        for mod in modules:
            if not isinstance(mod, dict):
                continue
            try:
                base = int(str(mod.get("base", "0")), 0)
                size = int(str(mod.get("size", "0")), 0)
            except Exception:
                continue
            if base and size and base <= addr < base + size:
                return mod
        return None

    def _addr_in_module(addr_hex: str, module: Optional[Dict[str, Any]]) -> bool:
        if not isinstance(module, dict):
            return False
        try:
            addr = int(str(addr_hex or "0"), 0)
            base = int(str(module.get("base") or "0"), 0)
            size = int(str(module.get("size") or "0"), 0)
        except Exception:
            return False
        return bool(addr and base and size and base <= addr < (base + size))

    def _infer_dump_entrypoint_from_state(
        module: Optional[Dict[str, Any]], state: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        if not isinstance(module, dict) or not isinstance(state, dict):
            return {
                "entrypoint": _normalize_hex((module or {}).get("entry") or (module or {}).get("base")),
                "source": "module_entry",
            }
        rip = _normalize_hex(state.get("rip"))
        if rip and _addr_in_module(rip, module):
            return {"entrypoint": rip, "source": "rip"}
        callstack = state.get("callStack", {}) if isinstance(state.get("callStack"), dict) else {}
        for entry in callstack.get("entries", []):
            if not isinstance(entry, dict):
                continue
            from_addr = _normalize_hex(entry.get("from"))
            if from_addr and _addr_in_module(from_addr, module):
                return {"entrypoint": from_addr, "source": "callstack_from"}
            to_addr = _normalize_hex(entry.get("to"))
            if to_addr and _addr_in_module(to_addr, module):
                return {"entrypoint": to_addr, "source": "callstack_to"}
        return {
            "entrypoint": _normalize_hex(module.get("entry") or module.get("base")),
            "source": "module_entry",
        }

    def _recover_fast_target_debug_session(
        timeout_ms: int = 8000, preferred_path: str = ""
    ) -> Dict[str, Any]:
        if not callable(InitDebuggee):
            return {
                "ok": False,
                "error": "InitDebuggee is not available for fast-target recovery",
            }
        candidates: List[str] = []
        for raw in (
            preferred_path,
            (GetDebugStateLean() or {}).get("debuggeePath"),
            _get_runtime_value("lastDebuggeePath") if callable(_get_runtime_value) else "",
        ):
            path = _repair_text_mojibake(str(raw or "").strip())
            if not path:
                continue
            try:
                normalized = os.path.abspath(path)
            except Exception:
                normalized = path
            if normalized not in candidates:
                candidates.append(normalized)
        target_path = next((path for path in candidates if os.path.exists(path)), "")
        if not target_path:
            return {
                "ok": False,
                "error": "No recent debuggee path is available for fast-target recovery",
                "candidates": candidates,
            }
        arch = (
            str(_detect_pe_arch(target_path) or "auto")
            if callable(_detect_pe_arch)
            else "auto"
        )
        ensure = (
            EnsureDebugger(
                arch=arch or "auto",
                timeout_ms=max(3000, min(int(timeout_ms), 12000)),
                restart=False,
            )
            if callable(EnsureDebugger)
            else {"ok": True, "requestedArch": arch or "auto"}
        )
        if isinstance(ensure, dict) and not ensure.get("ok"):
            return {
                "ok": False,
                "targetPath": target_path,
                "arch": arch or "auto",
                "ensure": ensure,
                "error": "Failed to prepare the debugger for fast-target recovery",
            }
        launch = InitDebuggee(
            target_path,
            timeout_ms=min(max(int(timeout_ms // 4), 800), 1800),
            retries=1,
            stop_first=True,
        )
        state = (
            (launch.get("state") if isinstance(launch, dict) else None)
            if isinstance(launch, dict)
            else None
        )
        if not isinstance(state, dict):
            state = GetDebugStateLean()
        wait_result = None
        pause_result = None
        if isinstance(state, dict) and state.get("debugging") and not state.get("paused"):
            try:
                wait_result = WaitForPause(timeout_ms=min(max(int(timeout_ms // 5), 300), 1200), poll_ms=50)
            except Exception:
                wait_result = None
            if isinstance(wait_result, dict) and wait_result.get("debugging"):
                state = wait_result
            if isinstance(state, dict) and state.get("debugging") and not state.get("paused"):
                try:
                    DebugPause()
                    pause_result = WaitForPause(timeout_ms=800, poll_ms=50)
                except Exception:
                    pause_result = None
                if isinstance(pause_result, dict) and pause_result.get("debugging"):
                    state = pause_result
        exit_code = 0
        if isinstance(state, dict):
            session = state.get("session", {}) if isinstance(state.get("session"), dict) else {}
            try:
                exit_code = int(session.get("exitCode") or 0)
            except Exception:
                exit_code = 0
        dialog = None
        deps = _find_missing_runtime_dependencies(target_path, arch or "auto")
        hint = None
        if not (isinstance(state, dict) and state.get("debugging")):
            dialog = _detect_launch_failure_dialog(target_path)
            hint = "The target exited before a stable post-launch pause could be captured."
            missing = list((deps or {}).get("missing", [])) if isinstance(deps, dict) else []
            if missing:
                dll_list = ", ".join(missing[:3])
                hint = f"The target failed before user code because required runtime DLLs are missing: {dll_list}."
            if isinstance(dialog, dict) and dialog.get("hint"):
                hint = str(dialog.get("hint"))
            if exit_code:
                hint += f" Exit code: 0x{exit_code & 0xFFFFFFFF:08X}."
                if (exit_code & 0xFFFFFFFF) == 0xC000001D:
                    hint += " The target raised an illegal-instruction exit under the debugger."
        return {
            "ok": bool(isinstance(state, dict) and state.get("debugging")),
            "targetPath": target_path,
            "arch": arch or "auto",
            "ensure": ensure,
            "launch": launch,
            "wait": wait_result,
            "pause": pause_result,
            "state": state,
            "dialog": dialog,
            "dependencies": deps,
            "hint": hint,
        }

    def _runtime_dll_search_paths(arch: str, exe_path: str) -> List[str]:
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
        seen = set()
        ordered: List[str] = []
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

    def _list_direct_import_dlls(exe_path: str) -> List[str]:
        imports: List[str] = []
        if pefile is not None:
            try:
                pe = pefile.PE(exe_path)
                for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                    try:
                        dll_name = entry.dll.decode(errors="ignore").strip()
                    except Exception:
                        dll_name = str(getattr(entry, "dll", "") or "").strip()
                    if dll_name:
                        imports.append(dll_name)
            except Exception:
                pass
        if not imports and callable(_parse_pe_layout):
            try:
                layout = _parse_pe_layout(exe_path)
                for item in list((layout or {}).get("imports", [])):
                    dll_name = str((item or {}).get("dll") or "").strip()
                    if dll_name:
                        imports.append(dll_name)
            except Exception:
                pass
        seen = set()
        ordered: List[str] = []
        for dll_name in imports:
            lowered = dll_name.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            ordered.append(dll_name)
        return ordered

    def _find_missing_runtime_dependencies(exe_path: str, arch: str) -> Dict[str, Any]:
        if not exe_path or not os.path.exists(exe_path):
            return {"ok": False, "error": "Executable path is not available"}
        imports = _list_direct_import_dlls(exe_path)
        if not imports:
            return {"ok": True, "imports": [], "missing": []}
        search_paths = _runtime_dll_search_paths(arch, exe_path)
        skip_prefixes = ("api-ms-win-", "ext-ms-win-")
        resolved: List[Dict[str, Any]] = []
        missing: List[str] = []
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
        return {
            "ok": True,
            "imports": imports,
            "missing": missing,
            "resolved": resolved,
            "searchPaths": search_paths,
        }

    def _detect_launch_failure_dialog(preferred_path: str = "") -> Dict[str, Any]:
        if not (
            callable(_enumerate_top_windows_global)
            and callable(_collect_window_node)
            and callable(_flatten_window_tree)
            and callable(_parse_hwnd_value)
        ):
            return {"found": False}
        candidates: List[str] = []
        for raw in (
            preferred_path,
            (GetDebugStateLean() or {}).get("debuggeePath"),
            _get_runtime_value("lastDebuggeePath") if callable(_get_runtime_value) else "",
        ):
            path = _repair_text_mojibake(str(raw or "").strip())
            if path and path not in candidates:
                candidates.append(path)
        base_names = {
            os.path.basename(path).lower() for path in candidates if str(path).strip()
        }
        top_windows = list(_enumerate_top_windows_global(visible_only=True) or [])
        best: Optional[Dict[str, Any]] = None
        best_score = -10**9
        for window in top_windows:
            if not isinstance(window, dict):
                continue
            title = _repair_text_mojibake(str(window.get("title") or ""))
            title_lower = title.casefold()
            class_name = _repair_text_mojibake(str(window.get("className") or ""))
            class_lower = class_name.casefold()
            title_match = any(name and name in title_lower for name in base_names)
            generic_error = any(
                token in title_lower
                for token in ("system error", "системная ошибка", "application error", "ошибка")
            )
            if not (title_match or generic_error or class_lower == "#32770"):
                continue
            hwnd = _parse_hwnd_value(window.get("hwnd"))
            if not hwnd:
                continue
            try:
                root = _collect_window_node(
                    hwnd,
                    pid=int(window.get("pid") or 0),
                    parent_hwnd=0,
                    include_children=True,
                    visible_only=False,
                    max_depth=3,
                    depth=0,
                )
            except Exception:
                root = None
            if not isinstance(root, dict):
                continue
            flat = list(_flatten_window_tree([root]) or [])
            static_texts = []
            for item in flat:
                if not isinstance(item, dict):
                    continue
                if str(item.get("role") or "") not in ("static", "dialog", "window"):
                    continue
                text = _repair_text_mojibake(str(item.get("title") or "")).strip()
                if text:
                    static_texts.append(text)
            button_texts = []
            for item in flat:
                if not isinstance(item, dict) or str(item.get("role") or "") != "button":
                    continue
                text = _repair_text_mojibake(str(item.get("title") or "")).strip()
                if text:
                    button_texts.append(text)
            joined = "\n".join(dict.fromkeys(static_texts))
            joined_lower = joined.casefold()
            score = 0
            if title_match:
                score += 180
            if generic_error:
                score += 80
            if class_lower == "#32770":
                score += 60
            if ".dll" in joined_lower:
                score += 220
            if any(token in joined_lower for token in ("not found", "не обнаруж", "не удается продолжить", "unable to continue")):
                score += 180
            if score > best_score:
                best_score = score
                best = {
                    "found": True,
                    "hwnd": f"0x{int(hwnd):X}",
                    "pid": int(window.get("pid") or 0),
                    "title": title,
                    "className": class_name,
                    "message": joined,
                    "buttons": button_texts,
                    "score": score,
                }
        if not isinstance(best, dict):
            return {"found": False}
        message = str(best.get("message") or "")
        dll_match = re.search(r"([A-Za-z0-9._-]+\.dll)", message, re.IGNORECASE)
        missing_dll = dll_match.group(1) if dll_match else ""
        hint = None
        if missing_dll:
            hint = (
                f"The target failed before user code because {missing_dll} is missing."
            )
        elif message:
            first_line = message.splitlines()[0].strip()
            if first_line:
                hint = f"The target failed before user code: {first_line}"
        best["missingDll"] = missing_dll or None
        best["hint"] = hint
        return best

    _ASM_TERMINATORS = {"ret", "retn", "ret ", "retn ", "retq"}

    def _disasm_batch(addr_hex: str, count: int) -> List[Dict[str, Any]]:
        payload = DisasmGetInstructionRange(addr=addr_hex, count=count)
        if isinstance(payload, dict) and isinstance(payload.get("instructions"), list):
            return [i for i in payload["instructions"] if isinstance(i, dict)]
        return []

    def _walk_function(start_addr: str, max_insns: int = 4096) -> Dict[str, Any]:
        """Follow fallthrough until ret/int3/jmp-out. Used for DisasmFunction
        and GetFunctionInfo when the analyzer has not been run."""
        try:
            start_int = int(start_addr, 0)
        except Exception:
            return {"ok": False, "error": f"bad address {start_addr!r}"}
        insns: List[Dict[str, Any]] = []
        chunk_size = 64
        cursor = start_int
        mnemonic_stops = ("ret", "retn", "retq", "int3", "ud2")
        branch_mnems = ("jmp", "jmpf", "jmpn")
        while len(insns) < max_insns:
            batch = _disasm_batch(hex(cursor), min(chunk_size, max_insns - len(insns)))
            if not batch:
                break
            stop = False
            for item in batch:
                insn = str(item.get("instruction") or "")
                size = int(item.get("size") or 0)
                addr = item.get("address") or hex(cursor)
                if not size:
                    stop = True
                    break
                insns.append({"addr": addr, "ins": insn, "size": size})
                cursor = int(addr, 0) + size
                mnem = insn.strip().split(" ", 1)[0].lower()
                if mnem in mnemonic_stops:
                    stop = True
                    break
                if mnem in branch_mnems and "0x" not in insn:
                    # indirect jmp — treat as end
                    stop = True
                    break
                if mnem in branch_mnems:
                    # unconditional jmp — end of fallthrough
                    stop = True
                    break
            if stop:
                break
        return {
            "ok": bool(insns),
            "start": hex(start_int),
            "end": insns[-1]["addr"] if insns else hex(start_int),
            "size": sum(i["size"] for i in insns),
            "count": len(insns),
            "instructions": insns,
        }

    def _iter_refview_rows(
        cmd: str, page_size: int = 400, max_rows: int = 5000
    ) -> Tuple[int, List[List[Any]]]:
        offset = 0
        total = 0
        rows: List[List[Any]] = []
        while offset < max_rows:
            requested = min(max(1, int(page_size)), max_rows - offset)
            batch = ExecCommand(
                cmd=cmd,
                offset=offset,
                limit=requested,
                # This is an internal consumer that filters and paginates the
                # final response itself.  ExecCommand's public character cap
                # must not silently turn a partial reference page into EOF.
                max_output_chars=0,
            )
            if not isinstance(batch, dict):
                break
            ref = batch.get("refView") or {}
            batch_rows = ref.get("rows") or []
            if isinstance(ref.get("rowCount"), int):
                total = int(ref.get("rowCount"))
            if not isinstance(batch_rows, list) or not batch_rows:
                break
            rows.extend([row for row in batch_rows if isinstance(row, list)])
            next_offset = batch.get("nextOffset")
            try:
                next_offset = int(next_offset)
            except (TypeError, ValueError):
                next_offset = offset + len(batch_rows)
            if next_offset <= offset:
                break
            offset = next_offset
            if total and offset >= total:
                break
            if len(batch_rows) < requested and not batch.get("truncated") and not total:
                break
        return total or len(rows), rows

    def _module_match_tokens(name: str) -> set[str]:
        raw = str(name or "").strip().lower()
        base = os.path.basename(raw)
        stem = os.path.splitext(base)[0]
        tokens = {raw, base, stem}
        if stem:
            tokens.add(f"{stem}.dll")
            tokens.add(f"{stem}.exe")
        return {token for token in tokens if token}

    def _resolve_module_by_name(name: str) -> Optional[Dict[str, Any]]:
        if not name:
            return None
        wanted = _module_match_tokens(name)
        payload = GetModuleList()
        modules = payload.get("modules", []) if isinstance(payload, dict) else []
        for mod in modules:
            if not isinstance(mod, dict):
                continue
            candidates = _module_match_tokens(mod.get("name") or mod.get("path") or "")
            if wanted & candidates:
                return mod
        fallback = _state_main_module_fallback()
        if isinstance(fallback, dict):
            candidates = _module_match_tokens(
                fallback.get("name") or fallback.get("path") or ""
            )
            if wanted & candidates:
                return fallback
        return None

    def _split_offset_suffix(expr: str) -> Tuple[str, int]:
        raw = str(expr or "").strip()
        if not raw:
            return "", 0
        match = re.match(r"^(.*?)([+-])\s*(0x[0-9a-fA-F]+|\d+)$", raw)
        if not match:
            return raw, 0
        base = str(match.group(1) or "").strip()
        sign = -1 if match.group(2) == "-" else 1
        try:
            delta = int(match.group(3), 0) * sign
        except Exception:
            return raw, 0
        return base, delta

    def _apply_offset(addr_hex: Optional[str], delta: int) -> Optional[str]:
        if not addr_hex:
            return None
        try:
            value = int(str(addr_hex), 0) + int(delta or 0)
        except Exception:
            return addr_hex
        return _normalize_hex(value)

    def _resolve_symbol_address(module_name: str, symbol_name: str) -> Optional[str]:
        symbol_name = str(symbol_name or "").strip()
        if not symbol_name:
            return None
        if module_name and callable(_resolve_remote_symbol_address):
            try:
                remote = _resolve_remote_symbol_address(module_name, symbol_name)
                if remote:
                    return _normalize_hex(remote)
            except Exception:
                pass
        if not callable(QuerySymbols):
            return None
        module_record = _resolve_module_by_name(module_name) if module_name else _resolve_main_module()
        if not module_record:
            return None
        module_base = _parse_int(module_record.get("base"))
        if module_base is None:
            return None
        query_name = str(module_record.get("name") or module_name or "")
        payload = QuerySymbols(module=query_name, offset=0, limit=50000)
        symbols = payload.get("symbols", []) if isinstance(payload, dict) else []
        wanted = symbol_name.casefold()
        for sym in symbols:
            if not isinstance(sym, dict):
                continue
            if str(sym.get("name") or "").casefold() != wanted:
                continue
            rva = _parse_int(sym.get("rva"))
            if rva is None:
                continue
            return _normalize_hex(module_base + rva)
        return None

    def _resolve_label_address(label_text: str, module_name: str = "") -> Optional[str]:
        if not callable(LabelList):
            return None
        payload = LabelList()
        labels = payload.get("labels", []) if isinstance(payload, dict) else []
        wanted_label = str(label_text or "").strip().casefold()
        wanted_module = _module_match_tokens(module_name) if module_name else set()
        for item in labels:
            if not isinstance(item, dict):
                continue
            if str(item.get("text") or "").strip().casefold() != wanted_label:
                continue
            module_tokens = _module_match_tokens(item.get("module") or "")
            if wanted_module and not (wanted_module & module_tokens):
                continue
            module_record = _resolve_module_by_name(item.get("module") or module_name)
            if not module_record:
                continue
            module_base = _parse_int(module_record.get("base"))
            rva = _parse_int(item.get("rva"))
            if module_base is None or rva is None:
                continue
            return _normalize_hex(module_base + rva)
        return None

    def _lookup_name_for_addr(addr_hex: str) -> Optional[str]:
        normalized = _normalize_hex(addr_hex)
        if not normalized:
            return None
        if callable(LabelGet):
            try:
                label = LabelGet(addr=normalized)
                if isinstance(label, dict) and label.get("found") and label.get("label"):
                    return str(label.get("label"))
            except Exception:
                pass
        module_record = _module_for_addr(normalized)
        if not module_record or not callable(QuerySymbols):
            return None
        module_base = _parse_int(module_record.get("base"))
        addr_value = _parse_int(normalized)
        if module_base is None or addr_value is None:
            return None
        payload = QuerySymbols(module=str(module_record.get("name") or ""), offset=0, limit=50000)
        symbols = payload.get("symbols", []) if isinstance(payload, dict) else []
        wanted_rva = addr_value - module_base
        for sym in symbols:
            if not isinstance(sym, dict):
                continue
            if _parse_int(sym.get("rva")) == wanted_rva and sym.get("name"):
                return str(sym.get("name"))
        return None

    def _parse_rva_literal(text: str) -> Optional[int]:
        raw = str(text or "").strip()
        if not raw:
            return None
        if raw.startswith("+"):
            raw = raw[1:].strip()
        if raw.lower().endswith("h") and re.fullmatch(r"[0-9a-fA-F]+h", raw):
            try:
                return int(raw[:-1], 16)
            except Exception:
                return None
        try:
            return int(raw, 0)
        except Exception:
            return None

    def _format_module_ref(addr: Any) -> Optional[str]:
        normalized = _normalize_hex(addr)
        if not normalized:
            return None
        module_record = _module_for_addr(normalized)
        if not module_record:
            return None
        module_base = _parse_int(module_record.get("base"))
        addr_value = _parse_int(normalized)
        module_name = str(module_record.get("name") or "")
        if module_base is None or addr_value is None or not module_name:
            return None
        return f"{module_name}!0x{max(0, addr_value - module_base):X}"

    def _get_binding_snapshot(state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if callable(_describe_bound_session_match):
            try:
                payload = _describe_bound_session_match(state=state or {})
                if isinstance(payload, dict):
                    return payload
            except Exception:
                pass
        if callable(_get_bound_session):
            try:
                record = _get_bound_session()
                if isinstance(record, dict):
                    return {
                        "active": bool(record),
                        "matches": False,
                        "binding": record,
                    }
            except Exception:
                pass
        return {"active": False, "matches": False, "binding": {}}

    def _capture_stop_context_structured(
        registers_json: str = "",
        expressions_json: str = "",
        ranges_json: str = "",
        stack_slots_json: str = "",
        disasm_before: int = 2,
        disasm_after: int = 4,
        callstack_limit: int = 12,
    ) -> Dict[str, Any]:
        state = _build_debug_state_patched(
            include_console=False, include_callstack=True, max_console_chars=0
        )
        capture = CaptureContext(
            registers_json=registers_json,
            expressions_json=expressions_json,
            ranges_json=ranges_json,
            stack_slots_json=stack_slots_json,
        )
        rip = _normalize_hex(state.get("rip"))
        disasm_rows: List[Dict[str, Any]] = []
        if rip:
            before = max(0, int(disasm_before))
            after = max(1, int(disasm_after))
            current_block = _disasm_batch(rip, after)
            if before > 0:
                walked = _walk_function(rip, max_insns=64)
                instructions = walked.get("instructions", []) if isinstance(walked, dict) else []
                index = next(
                    (
                        idx
                        for idx, row in enumerate(instructions)
                        if _normalize_hex((row or {}).get("addr")) == rip
                    ),
                    -1,
                )
                if index >= 0:
                    start = max(0, index - before)
                    disasm_rows.extend(instructions[start:index])
            disasm_rows.extend(current_block)
        callstack = GetCallStack() if callable(GetCallStack) else {}
        if isinstance(callstack, dict) and isinstance(callstack.get("entries"), list):
            callstack = dict(callstack)
            callstack["entries"] = list(callstack.get("entries") or [])[: max(1, int(callstack_limit))]
        return {
            "ok": bool(isinstance(capture, dict) and capture.get("ok")),
            "state": state,
            "binding": _get_binding_snapshot(state=state),
            "capture": capture,
            "callstack": callstack,
            "disasm": {
                "rip": rip,
                "ripRef": _format_module_ref(rip),
                "instructions": disasm_rows,
            },
        }

    def _resolve_addr(expr: str) -> Optional[str]:
        """Accept 0x..., register expressions, module!sym, labels, entry aliases."""
        if not expr:
            return None
        raw = str(expr).strip()
        if not raw:
            return None
        try:
            return _normalize_hex(int(raw, 0))
        except Exception:
            pass
        if callable(_resolve_expression_value):
            try:
                resolved = _resolve_expression_value(raw)
                if resolved is not None:
                    return _normalize_hex(resolved)
            except Exception:
                pass
        base_expr, delta = _split_offset_suffix(raw)
        alias = base_expr.casefold()
        if alias in ("entry", "module_entry", "main") and callable(
            _get_current_debuggee_module_base
        ):
            try:
                base = _get_current_debuggee_module_base(want_entry=True)
                if base:
                    return _apply_offset(base, delta)
            except Exception:
                pass
        if "!" in base_expr:
            module_name, symbol_name = base_expr.split("!", 1)
            module_record = _resolve_module_by_name(module_name)
            module_base = (
                _parse_int(module_record.get("base")) if isinstance(module_record, dict) else None
            )
            rva_value = _parse_rva_literal(symbol_name)
            if module_base is not None and rva_value is not None:
                return _apply_offset(_normalize_hex(module_base + rva_value), delta)
            resolved = _resolve_symbol_address(module_name, symbol_name)
            if resolved:
                return _apply_offset(resolved, delta)
        label_addr = _resolve_label_address(base_expr)
        if label_addr:
            return _apply_offset(label_addr, delta)
        symbol_addr = _resolve_symbol_address("", base_expr)
        if symbol_addr:
            return _apply_offset(symbol_addr, delta)
        module_record = _resolve_module_by_name(base_expr)
        if module_record and module_record.get("base"):
            return _apply_offset(_normalize_hex(module_record.get("base")), delta)
        payload = safe_get("Misc/ParseExpression", {"expression": raw}, log=False)
        if isinstance(payload, dict):
            for key in ("value", "result", "addr", "address"):
                val = payload.get(key)
                if val:
                    return _normalize_hex(val)
        if isinstance(payload, str):
            try:
                data = json.loads(payload)
                if isinstance(data, dict):
                    for key in ("value", "result", "addr", "address"):
                        val = data.get(key)
                        if val:
                            return _normalize_hex(val)
            except Exception:
                pass
        return None

    # ------------------------------------------------------------------
    # New MCP tools
    # ------------------------------------------------------------------

    @mcp.tool()
    def GetDebugStateLean() -> dict:
        """
        Minimal debugger state for cheap polling.

        Returns: pid, state, rip, stopReason, exceptionCode, module, paused.
        ~20x smaller than GetDebugState. Prefer this during loops, keep
        GetDebugState for one-off full inspections.
        """
        state = _build_debug_state_patched(
            include_console=False, include_callstack=False, max_console_chars=0
        )
        session = (
            state.get("session", {}) if isinstance(state.get("session"), dict) else {}
        )
        rip = _normalize_hex(state.get("rip")) or None
        module = _module_for_addr(rip) if rip else None
        binding = _get_binding_snapshot(state=state)
        return {
            "ok": True,
            "pid": int(state.get("debuggeePid") or 0),
            "state": state.get("state"),
            "paused": bool(state.get("paused")),
            "running": bool(state.get("running")),
            "rip": rip,
            "ripRef": _format_module_ref(rip),
            "stopReason": state.get("stopReason"),
            "exceptionCode": session.get("exceptionCode"),
            "exceptionFirstChance": session.get("exceptionFirstChance"),
            "module": (module or {}).get("name") if module else None,
            "moduleBase": _normalize_hex((module or {}).get("base")) if module else None,
            "modulePath": (module or {}).get("path") if module else None,
            "debuggeeImage": state.get("debuggeeImage"),
            "debuggeePath": state.get("debuggeePath"),
            "binding": binding,
        }

    @mcp.tool()
    def GetSessionBinding() -> dict:
        """
        Return the currently bound session identity and whether it matches the live state.
        """
        state = _build_debug_state_patched(
            include_console=False, include_callstack=False, max_console_chars=0
        )
        return {
            "ok": True,
            "binding": _get_binding_snapshot(state=state),
            "state": {
                "pid": int(state.get("debuggeePid") or 0),
                "image": state.get("debuggeeImage"),
                "path": state.get("debuggeePath"),
                "rip": _normalize_hex(state.get("rip")),
            },
        }

    @mcp.tool()
    def BindSessionTarget(
        pid: int = 0,
        image_path: str = "",
        module_base: str = "",
        strict: bool = True,
    ) -> dict:
        """
        Pin the current workflow to a specific PID + image path + module base identity.
        """
        if not callable(_bind_debuggee_session):
            return {"ok": False, "error": "_bind_debuggee_session is not available"}
        record = _bind_debuggee_session(
            pid=pid,
            image_path=image_path,
            module_base=module_base,
            strict=strict,
            source="BindSessionTarget",
        )
        state = _build_debug_state_patched(
            include_console=False, include_callstack=False, max_console_chars=0
        )
        return {
            "ok": True,
            "binding": _get_binding_snapshot(state=state),
            "record": record,
        }

    @mcp.tool()
    def ClearSessionBinding() -> dict:
        """
        Remove the current bound-session constraint.
        """
        if not callable(_clear_bound_session):
            return {"ok": False, "error": "_clear_bound_session is not available"}
        _clear_bound_session()
        return {"ok": True, "binding": _get_binding_snapshot(state={})}

    @mcp.tool()
    def EnsureReady() -> dict:
        """
        One-call health check.

        Returns {ok, reasons[], hints[]}. Tells whether x64dbg is running, a
        process is loaded, it is paused, and whether analysis has been run.
        """
        reasons: List[str] = []
        hints: List[str] = []
        try:
            debugging = bool(IsDebugging())
        except Exception:
            debugging = False
        if not debugging:
            reasons.append("no_debuggee")
            hints.append(
                "If the target EXE path is known, call InitDebuggee directly; "
                "it selects and starts x32dbg/x64dbg from X64DBG_ROOT and "
                "waits for the bridge. Do not preflight BridgeHello or search "
                "installation paths manually. Use AttachToProcess only for an "
                "already-running target."
            )
            return {
                "ok": False,
                "reasons": reasons,
                "hints": hints,
                "nextAction": {
                    "tool": "InitDebuggee",
                    "when": "target_executable_path_is_known",
                    "arguments": {"exe_path": "<absolute-target-exe-path>"},
                },
            }
        lean = GetDebugStateLean()
        if not lean.get("paused"):
            reasons.append("running")
            hints.append("Call DebugPause or wait for a breakpoint.")
        module = _resolve_main_module()
        if module is None:
            reasons.append("no_main_module")
            hints.append("GetModuleList returned nothing — verify process image.")
        ok = not reasons
        return {
            "ok": ok,
            "reasons": reasons,
            "hints": hints,
            "pid": lean.get("pid"),
            "module": (module or {}).get("name") if module else None,
            "rip": lean.get("rip"),
        }

    @mcp.tool()
    def SearchStrings(
        pattern: str,
        regex: bool = False,
        case_sensitive: bool = False,
        module: str = "",
        encoding: str = "auto",
        limit: int = 100,
        offset: int = 0,
        detail: str = "",
    ) -> dict:
        """
        Search ASCII/UTF-16 strings referenced by the current debuggee module.

        Uses x64dbg's strref view under the hood, then filters client-side.
        Returns deterministic pages of matches with module/RVA identity.
        ``detail=full`` adds scan diagnostics but does not bypass pagination.
        """
        detail_level, detail_error = _resolve_response_detail(detail)
        if detail_error:
            return detail_error
        try:
            safe_offset = max(0, int(offset))
            safe_limit = max(1, min(int(limit), 5000))
        except (TypeError, ValueError):
            return {
                "ok": False,
                "errorCode": "INVALID_ARGUMENT",
                "error": "offset and limit must be integers",
            }
        cmd = "strref"
        if module:
            module_record = _resolve_module_by_name(module)
            target = None
            if module_record:
                target = _normalize_hex(module_record.get("entry"))
                if not target or target == "0x0":
                    target = _normalize_hex(module_record.get("base"))
            if not target:
                target = _resolve_addr(module)
            if target:
                cmd = f"strref {target}"
        total_scanned, rows = _iter_refview_rows(cmd=cmd, page_size=500, max_rows=10000)
        all_matches: List[Dict[str, Any]] = []
        if regex:
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                compiled = re.compile(pattern, flags)
            except re.error as e:
                return {"ok": False, "error": f"bad regex: {e}"}
            predicate = lambda s: bool(compiled.search(s))
        else:
            needle = pattern if case_sensitive else pattern.lower()
            predicate = lambda s: (needle in (s if case_sensitive else s.lower()))
        for row in rows:
            if not isinstance(row, list) or len(row) < 2:
                continue
            ref_addr = row[0] if len(row) > 0 else ""
            instruction = row[1] if len(row) > 1 else ""
            str_addr = row[2] if len(row) > 2 else ""
            content = row[3] if len(row) > 3 else ""
            content_clean = _strong_repair(content) if content else ""
            if not content_clean:
                continue
            if predicate(content_clean):
                all_matches.append(
                    {
                        "refAddr": ref_addr,
                        "instruction": instruction,
                        "strAddr": str_addr,
                        "string": content_clean,
                        "source": "x64dbg_strref",
                        "confidence": "analyzed",
                    }
                )
        module_payload = GetModuleList()
        modules = (
            module_payload.get("modules", [])
            if isinstance(module_payload, dict)
            and isinstance(module_payload.get("modules"), list)
            else []
        )

        def _location(value: Any) -> Dict[str, Any]:
            address = _parse_int(value)
            if address is None:
                # Reference-view cells use x64dbg's bare hexadecimal format
                # (for example 00007FF6982012B4), not Python's 0x prefix.
                raw = str(value or "").strip()
                if re.fullmatch(r"[0-9A-Fa-f]+", raw):
                    address = int(raw, 16)
            if address is None:
                return {}
            for item in modules:
                if not isinstance(item, dict):
                    continue
                base = _parse_int(item.get("base"))
                size = _parse_int(item.get("size")) or 0
                if base is not None and size > 0 and base <= address < base + size:
                    return {
                        "module": item.get("name"),
                        "moduleBase": _normalize_hex(base),
                        "rva": f"0x{address - base:X}",
                    }
            return {}

        page = all_matches[safe_offset : safe_offset + safe_limit]
        for item in page:
            item["reference"] = _location(item.get("refAddr"))
            item["target"] = _location(item.get("strAddr"))
        total_matches = len(all_matches)
        has_more = safe_offset + len(page) < total_matches
        payload: Dict[str, Any] = {
            "ok": True,
            "pattern": pattern,
            "regex": regex,
            "encoding": encoding,
            "totalScanned": total_scanned,
            "totalMatches": total_matches,
            "offset": safe_offset,
            "count": len(page),
            "pageSize": len(page),
            "hasMore": has_more,
            "nextCursor": str(safe_offset + len(page)) if has_more else None,
            "completeScan": len(rows) >= int(total_scanned or 0),
            "matches": page,
        }
        if detail_level == "full":
            payload["scan"] = {
                "command": cmd,
                "rowsCollected": len(rows),
                "rowLimit": 10000,
                "truncated": len(rows) < int(total_scanned or 0),
            }
        else:
            payload["availableDetails"] = ["scan"]
        return payload

    @mcp.tool()
    def DisasmFunction(addr: str, max_instructions: int = 4096) -> dict:
        """
        Disassemble a whole function starting at `addr` until a ret/int3/jmp.

        Returns compact rows {addr, ins, size}. Always tries fallthrough —
        does not follow conditional branches into separate paths.
        """
        resolved = _resolve_addr(addr)
        if not resolved:
            return {"ok": False, "error": f"Cannot resolve address: {addr!r}"}
        walked = _walk_function(resolved, max_insns=max(16, int(max_instructions)))
        module = _module_for_addr(walked.get("start") or resolved)
        walked["module"] = (module or {}).get("name") if module else None
        return walked

    @mcp.tool()
    def DisasmRange(
        start: str,
        end: str,
        max_instructions: int = 4096,
        cursor: str = "",
        detail: str = "",
    ) -> dict:
        """
        Disassemble a raw address range without guessing function bounds.
        Pages resume from the opaque ``nextCursor`` address.
        """
        detail_level, detail_error = _resolve_response_detail(detail)
        if detail_error:
            return detail_error
        start_addr = _resolve_addr(start)
        end_addr = _resolve_addr(end)
        if not start_addr or not end_addr:
            return {"ok": False, "error": "could not resolve start/end"}
        try:
            requested_start = int(start_addr, 0)
            limit_addr = int(end_addr, 0)
        except Exception:
            return {"ok": False, "error": "invalid numeric address"}
        if limit_addr <= requested_start:
            return {"ok": False, "error": "end must be greater than start"}
        current = requested_start
        if str(cursor or "").strip():
            resolved_cursor = _resolve_addr(str(cursor))
            try:
                current = int(str(resolved_cursor or ""), 0)
            except Exception:
                return {
                    "ok": False,
                    "errorCode": "INVALID_ARGUMENT",
                    "error": "cursor is not a valid address",
                }
            if current < requested_start or current >= limit_addr:
                return {
                    "ok": False,
                    "errorCode": "INVALID_ARGUMENT",
                    "error": "cursor must be inside the requested range",
                }
        try:
            requested_count = max(1, min(int(max_instructions), 5000))
        except (TypeError, ValueError):
            return {
                "ok": False,
                "errorCode": "INVALID_ARGUMENT",
                "error": "max_instructions must be an integer",
            }
        page_start = current
        insns: List[Dict[str, Any]] = []
        decode_failed = False
        while current < limit_addr and len(insns) < requested_count:
            batch = _disasm_batch(
                hex(current), min(100, requested_count - len(insns))
            )
            if not batch:
                decode_failed = True
                break
            advanced = False
            for item in batch:
                addr = _parse_int(item.get("address"))
                size = int(item.get("size") or 0)
                if addr is None or size <= 0 or addr >= limit_addr:
                    break
                insns.append(
                    {
                        "addr": _normalize_hex(addr),
                        "ins": str(item.get("instruction") or ""),
                        "size": size,
                    }
                )
                current = addr + size
                advanced = True
                if current >= limit_addr or len(insns) >= requested_count:
                    break
            else:
                continue
            if not advanced:
                decode_failed = True
            break
        has_more = current < limit_addr and len(insns) >= requested_count
        payload: Dict[str, Any] = {
            "ok": bool(insns),
            "start": start_addr,
            "end": end_addr,
            "pageStart": _normalize_hex(page_start),
            "requestedCount": requested_count,
            "count": len(insns),
            "pageSize": len(insns),
            "hasMore": has_more,
            "nextCursor": _normalize_hex(current) if has_more else None,
            "complete": current >= limit_addr,
            "stoppedReason": (
                "end"
                if current >= limit_addr
                else "limit"
                if has_more
                else "decode_failed"
                if decode_failed
                else "stopped"
            ),
            "instructions": insns,
        }
        if detail_level == "full":
            payload["decodedBytes"] = max(0, current - page_start)
        else:
            payload["availableDetails"] = ["decodedBytes"]
        return payload

    @mcp.tool()
    def ReadMemoryBatch(regions_json: str) -> dict:
        """
        Read multiple memory ranges in one call.

        regions_json: JSON list of {addr, size, ty?, max_chars?}.
        Supported ty: hex (default), bytes, ascii, utf8, utf16, u8..u64.
        """
        try:
            specs = json.loads(regions_json) if regions_json else []
        except json.JSONDecodeError as e:
            return {"ok": False, "error": f"bad json: {e}"}
        if not isinstance(specs, list):
            return {"ok": False, "error": "regions_json must be an array"}
        results: List[Dict[str, Any]] = []
        for index, raw in enumerate(specs):
            if not isinstance(raw, dict):
                results.append({"index": index, "ok": False, "error": "not an object"})
                continue
            addr = raw.get("addr") or raw.get("address") or ""
            size = int(raw.get("size") or 0)
            ty = str(raw.get("ty") or raw.get("format") or "hex")
            max_chars = int(raw.get("max_chars") or raw.get("maxChars") or 512)
            try:
                res = ReadMemory(addr=str(addr), size=size, ty=ty, max_chars=max_chars)
            except Exception as e:
                res = {"ok": False, "error": str(e)}
            if isinstance(res, dict):
                res.setdefault("index", index)
            else:
                res = {"index": index, "ok": False, "error": str(res)}
            results.append(res)
        return {"ok": True, "count": len(results), "regions": results}

    def _load_imports_from_disk(module_name: str) -> Optional[Dict[str, Any]]:
        if pefile is None:
            return None
        module_record = _resolve_module_by_name(module_name) if module_name else _resolve_main_module()
        if not module_record:
            return None
        path = str(module_record.get("path") or "")
        if not path or not os.path.exists(path):
            return None
        try:
            pe = pefile.PE(path)
        except Exception:
            return None
        loaded_base = _parse_int(module_record.get("base")) or 0
        image_base = int(pe.OPTIONAL_HEADER.ImageBase or 0)
        pointer_size = 8 if int(pe.OPTIONAL_HEADER.Magic or 0) == 0x20B else 4
        imports: List[Dict[str, Any]] = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll_name = (
                entry.dll.decode("ascii", errors="replace")
                if isinstance(entry.dll, (bytes, bytearray))
                else str(entry.dll or "")
            )
            original_first_thunk = int(entry.struct.OriginalFirstThunk or 0)
            for index, imp in enumerate(entry.imports):
                iat_rva = int(imp.address or 0) - image_base if imp.address else 0
                thunk_rva = int(getattr(imp, "thunk_rva", 0) or 0)
                if not thunk_rva and original_first_thunk:
                    thunk_rva = original_first_thunk + (index * pointer_size)
                func_name = (
                    imp.name.decode("ascii", errors="replace")
                    if imp.name
                    else f"ordinal_{int(imp.ordinal or 0)}"
                )
                imports.append(
                    {
                        "module": dll_name,
                        "function": func_name,
                        "iatVa": _normalize_hex(loaded_base + iat_rva),
                        "thunkAddr": _normalize_hex(loaded_base + thunk_rva)
                        if thunk_rva
                        else None,
                        "thunkVa": _normalize_hex(loaded_base + thunk_rva)
                        if thunk_rva
                        else None,
                        "rva": _normalize_hex(iat_rva),
                    }
                )
        return {
            "ok": True,
            "module": str(module_record.get("name") or module_name or ""),
            "path": path,
            "count": len(imports),
            "imports": imports,
        }

    def _load_exports_from_disk(module_name: str) -> Optional[Dict[str, Any]]:
        if pefile is None:
            return None
        module_record = (
            _resolve_module_by_name(module_name) if module_name else _resolve_main_module()
        )
        if not module_record:
            return None
        path = str(module_record.get("path") or "")
        if not path or not os.path.exists(path):
            return None
        try:
            pe = pefile.PE(path)
        except Exception:
            return None
        loaded_base = _parse_int(module_record.get("base")) or 0
        exports: List[Dict[str, Any]] = []
        export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if export_dir is not None:
            for sym in getattr(export_dir, "symbols", []) or []:
                rva = int(getattr(sym, "address", 0) or 0)
                name = (
                    sym.name.decode("ascii", errors="replace")
                    if getattr(sym, "name", None)
                    else f"ordinal_{int(getattr(sym, 'ordinal', 0) or 0)}"
                )
                forwarder = getattr(sym, "forwarder", None)
                exports.append(
                    {
                        "module": str(module_record.get("name") or module_name or ""),
                        "function": name,
                        "address": _normalize_hex(loaded_base + rva) if loaded_base and rva else None,
                        "rva": _normalize_hex(rva),
                        "ordinal": int(getattr(sym, "ordinal", 0) or 0),
                        "forwarder": (
                            forwarder.decode("ascii", errors="replace")
                            if isinstance(forwarder, (bytes, bytearray))
                            else (str(forwarder) if forwarder else None)
                        ),
                    }
                )
        return {
            "ok": True,
            "module": str(module_record.get("name") or module_name or ""),
            "path": path,
            "count": len(exports),
            "exports": exports,
        }

    @mcp.tool()
    def GetImports(module: str = "", offset: int = 0, limit: int = 200) -> dict:
        """
        Return the import table for a loaded module.

        If `module` is empty, uses the current debuggee's main module.
        Each entry: {module, function, iatVa, thunkVa}.
        Falls back to QuerySymbols('Import*') if the plugin has no dedicated
        endpoint. Works on any PE loaded in the debugger.
        """
        target = module
        if not target:
            main = _resolve_main_module()
            if not main:
                return {"ok": False, "error": "no debuggee module"}
            target = str(main.get("name") or "")
        if not target:
            return {"ok": False, "error": "empty module name"}
        disk_payload = _load_imports_from_disk(target)
        if isinstance(disk_payload, dict) and disk_payload.get("ok"):
            imports = list(disk_payload.get("imports") or [])
            safe_offset = max(0, int(offset or 0))
            safe_limit = max(1, min(int(limit or 200), 5000))
            page = imports[safe_offset : safe_offset + safe_limit]
            next_offset = safe_offset + len(page)
            payload = dict(disk_payload)
            payload.update(
                {
                    "count": len(imports),
                    "offset": safe_offset,
                    "limit": safe_limit,
                    "returned": len(page),
                    "hasMore": next_offset < len(imports),
                    "nextOffset": next_offset if next_offset < len(imports) else None,
                    "imports": page,
                }
            )
            return payload
        target_record = _resolve_module_by_name(target)
        loaded_base = _parse_int((target_record or {}).get("base")) or 0
        symbols_payload = safe_get(
            "SymbolEnum",
            {"module": target, "offset": "0", "limit": "20000"},
            log=False,
        )
        if isinstance(symbols_payload, str):
            try:
                symbols_payload = json.loads(symbols_payload)
            except Exception:
                return {
                    "ok": False,
                    "error": "SymbolEnum returned non-JSON",
                    "raw": str(symbols_payload)[:200],
                }
        if not isinstance(symbols_payload, dict):
            return {"ok": False, "error": "SymbolEnum returned unexpected payload"}
        entries = symbols_payload.get("symbols") or []
        imports: List[Dict[str, Any]] = []
        for sym in entries:
            if not isinstance(sym, dict):
                continue
            sym_type = str(sym.get("type") or "").lower()
            if "import" not in sym_type:
                continue
            name = str(sym.get("name") or "")
            rva = str(sym.get("rva") or "0")
            rva_value = _parse_int(rva) or 0
            module_name = ""
            func_name = name
            if "!" in name:
                module_name, func_name = name.split("!", 1)
            imports.append(
                {
                    "module": module_name,
                    "function": func_name,
                    "iatVa": _normalize_hex(loaded_base + rva_value)
                    if loaded_base and rva_value
                    else _normalize_hex(rva_value),
                    "thunkAddr": None,
                    "thunkVa": None,
                    "rva": _normalize_hex(rva_value),
                    "raw": name,
                }
            )
        safe_offset = max(0, int(offset or 0))
        safe_limit = max(1, min(int(limit or 200), 5000))
        page = imports[safe_offset : safe_offset + safe_limit]
        next_offset = safe_offset + len(page)
        return {
            "ok": True,
            "module": target,
            "count": len(imports),
            "offset": safe_offset,
            "limit": safe_limit,
            "returned": len(page),
            "hasMore": next_offset < len(imports),
            "nextOffset": next_offset if next_offset < len(imports) else None,
            "imports": page,
        }

    def _runtime_module_records() -> List[Dict[str, Any]]:
        payload = GetModuleList()
        raw = payload.get("modules", []) if isinstance(payload, dict) else []
        records: List[Dict[str, Any]] = []
        for item in raw if isinstance(raw, list) else []:
            if not isinstance(item, dict):
                continue
            base = _parse_int(item.get("base")) or 0
            size = _parse_int(item.get("size")) or 0
            if base and size:
                records.append(
                    {
                        "name": str(item.get("name") or ""),
                        "path": str(item.get("path") or ""),
                        "base": base,
                        "size": size,
                    }
                )
        return records

    def _runtime_pointer(address: int, pointer_size: int) -> Optional[int]:
        read = ReadMemory(f"0x{address:X}", pointer_size, ty="hex", max_chars=0)
        data = _memory_bytes(read)
        if len(data) != pointer_size:
            return None
        return int.from_bytes(data, "little", signed=False)

    def _module_for_runtime_address(address: int, modules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        for module_record in modules:
            if int(module_record["base"]) <= address < int(module_record["base"]) + int(module_record["size"]):
                return module_record
        return None

    @mcp.tool()
    def InspectRuntimeIAT(
        module: str = "",
        limit: int = 5000,
        resolve_symbols: bool = False,
    ) -> dict:
        """Inspect live IAT slots and classify each pointer against loaded modules."""

        target_record = _resolve_module_by_name(module) if module else _resolve_main_module()
        if not target_record:
            return {"ok": False, "errorCode": "MODULE_NOT_FOUND", "error": "module is not loaded"}
        module_name = str(target_record.get("name") or module or "")
        path = str(target_record.get("path") or "")
        loaded_base = _parse_int(target_record.get("base")) or 0
        if not loaded_base or not path or pefile is None:
            return {"ok": False, "errorCode": "IMPORT_METADATA_UNAVAILABLE", "error": "loaded module path/base or pefile metadata is unavailable"}
        try:
            pe = pefile.PE(data=Path(path).read_bytes(), fast_load=False)
        except Exception as exc:
            return {"ok": False, "errorCode": "PE_PARSE_FAILED", "error": str(exc)}
        pointer_size = 8 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 4
        preferred_base = int(getattr(pe.OPTIONAL_HEADER, "ImageBase", 0) or 0)
        delta = loaded_base - preferred_base
        modules = _runtime_module_records()
        entries: List[Dict[str, Any]] = []
        try:
            imports = list(pe.DIRECTORY_ENTRY_IMPORT)
        except AttributeError:
            imports = []
        max_entries = max(1, min(int(limit or 5000), 20000))
        for descriptor in imports:
            imported_module = str(getattr(descriptor, "dll", b"") or b"")
            if isinstance(getattr(descriptor, "dll", None), (bytes, bytearray)):
                imported_module = descriptor.dll.decode("ascii", errors="replace")
            for entry in list(getattr(descriptor, "imports", []) or []):
                if len(entries) >= max_entries:
                    break
                iat_rva = int(getattr(entry, "address", 0) or 0) - preferred_base
                if iat_rva < 0:
                    continue
                iat_va = loaded_base + iat_rva
                value = _runtime_pointer(iat_va, pointer_size)
                function_name = getattr(entry, "name", None)
                if isinstance(function_name, (bytes, bytearray)):
                    function_name = function_name.decode("ascii", errors="replace")
                function = str(function_name or f"ordinal_{int(getattr(entry, 'ordinal', 0) or 0)}")
                target_module = _module_for_runtime_address(value or 0, modules) if value else None
                state = "null" if value in (None, 0) else "resolved" if target_module else "outside-modules"
                payload = {
                    "module": imported_module,
                    "function": function,
                    "ordinal": int(getattr(entry, "ordinal", 0) or 0),
                    "iatRva": f"0x{iat_rva:X}",
                    "iatVa": f"0x{iat_va:X}",
                    "value": f"0x{value:X}" if value is not None else None,
                    "state": state,
                    "resolved": {
                        "module": target_module.get("name") if target_module else None,
                        "rva": f"0x{value - int(target_module['base']):X}" if target_module and value else None,
                    },
                }
                if resolve_symbols and target_module and QuerySymbols:
                    try:
                        symbols = QuerySymbols(
                            str(target_module.get("name") or ""),
                            offset=max(0, int(value - int(target_module["base"]))),
                            limit=8,
                        )
                        payload["symbols"] = symbols.get("symbols", []) if isinstance(symbols, dict) else []
                    except Exception as exc:
                        payload["symbolError"] = str(exc)
                entries.append(payload)
            if len(entries) >= max_entries:
                break
        counts = {state: sum(1 for item in entries if item.get("state") == state) for state in ("resolved", "null", "outside-modules")}
        return {
            "ok": True,
            "schema": "runtime-iat-v1",
            "module": module_name,
            "path": path,
            "loadedBase": f"0x{loaded_base:X}",
            "preferredBase": f"0x{preferred_base:X}",
            "relocationDelta": delta,
            "pointerSize": pointer_size,
            "descriptorCount": len(imports),
            "count": len(entries),
            "counts": counts,
            "truncated": len(entries) >= max_entries,
            "entries": entries,
        }

    @mcp.tool()
    def FindIATCandidates(
        base: str,
        size: int,
        pointer_size: int = 0,
        min_entries: int = 3,
        max_candidates: int = 128,
    ) -> dict:
        """Find contiguous pointer runs that resolve into loaded modules."""

        base_int = _memory_int(base)
        size_int = int(size or 0)
        if not base_int or size_int <= 0:
            return {"ok": False, "errorCode": "INVALID_ARGUMENT", "error": "base and positive size are required"}
        modules = _runtime_module_records()
        if not modules:
            return {"ok": False, "errorCode": "NO_MODULES", "error": "no loaded module ranges are available"}
        if pointer_size not in (0, 4, 8):
            return {"ok": False, "errorCode": "INVALID_ARGUMENT", "error": "pointer_size must be 0, 4 or 8"}
        width = pointer_size or (8 if any(int(item["base"]) > 0xFFFFFFFF for item in modules) else 4)
        byte_budget = min(size_int, 16 * 1024 * 1024)
        try:
            data = _read_memory_exact(base_int, byte_budget, 1024 * 1024)
        except Exception as exc:
            return {"ok": False, "errorCode": "MEMORY_READ_FAILED", "error": str(exc)}
        minimum = max(2, int(min_entries or 3))
        cap = max(1, min(int(max_candidates or 128), 4096))
        candidates: List[Dict[str, Any]] = []
        run_start: Optional[int] = None
        run_values: List[int] = []

        def finish_run() -> None:
            nonlocal run_start, run_values
            if run_start is None or len(run_values) < minimum or len(candidates) >= cap:
                run_start, run_values = None, []
                return
            targets = []
            for value in run_values:
                target = _module_for_runtime_address(value, modules)
                if not target:
                    continue
                targets.append({
                    "value": f"0x{value:X}",
                    "module": target.get("name"),
                    "rva": f"0x{value - int(target['base']):X}",
                })
            candidates.append({"base": f"0x{base_int + run_start:X}", "count": len(run_values), "pointerSize": width, "targets": targets})
            run_start, run_values = None, []

        for offset in range(0, len(data) - width + 1, width):
            value = int.from_bytes(data[offset : offset + width], "little")
            if _module_for_runtime_address(value, modules):
                if run_start is None:
                    run_start = offset
                run_values.append(value)
            else:
                finish_run()
                if len(candidates) >= cap:
                    break
        finish_run()
        return {
            "ok": True,
            "schema": "iat-candidates-v1",
            "base": f"0x{base_int:X}",
            "sizeScanned": len(data),
            "pointerSize": width,
            "candidateCount": len(candidates),
            "truncated": len(data) < size_int or len(candidates) >= cap,
            "candidates": candidates,
        }

    @mcp.tool()
    def ValidateIAT(
        module: str = "",
        require_resolved: bool = True,
        min_imports: int = 1,
    ) -> dict:
        """Validate live IAT descriptors, slot reads and target-module membership."""

        inspected = InspectRuntimeIAT(module=module, limit=20000, resolve_symbols=False)
        if not inspected.get("ok"):
            return inspected
        counts = inspected.get("counts", {})
        failures: List[str] = []
        if int(inspected.get("descriptorCount") or 0) < 1:
            failures.append("no_import_descriptors")
        if int(inspected.get("count") or 0) < max(0, int(min_imports)):
            failures.append("too_few_import_slots")
        if require_resolved and int(counts.get("resolved") or 0) != int(inspected.get("count") or 0):
            failures.append("unresolved_or_null_slots")
        return {
            "ok": not failures,
            "schema": "runtime-iat-validation-v1",
            "module": inspected.get("module"),
            "checked": inspected.get("count"),
            "counts": counts,
            "failures": failures,
            "inspection": inspected,
        }

    @mcp.tool()
    def FixDumpImports(
        dump_path: str,
        output_path: str = "",
        overwrite: bool = False,
        zero_iat: bool = True,
    ) -> dict:
        """Repair a dump's load-time IAT slots conservatively and verify its PE structure."""

        source = Path(os.path.abspath(str(dump_path or "")))
        if not source.is_file():
            return {"ok": False, "errorCode": "INPUT_NOT_FOUND", "error": "dump_path does not exist"}
        target = Path(os.path.abspath(str(output_path or dump_path)))
        if target.exists() and target != source and not overwrite:
            return {"ok": False, "errorCode": "OUTPUT_EXISTS", "error": "output_path exists; set overwrite=true"}
        if target == source and not overwrite:
            return {"ok": False, "errorCode": "OUTPUT_EXISTS", "error": "in-place repair requires overwrite=true"}
        try:
            blob = bytearray(source.read_bytes())
            pe = pefile.PE(data=bytes(blob), fast_load=False) if pefile is not None else None
            if pe is None:
                raise RuntimeError("pefile is unavailable")
            imports = list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or [])
            repaired = 0
            skipped = 0
            for descriptor in imports:
                oft = int(getattr(descriptor.struct, "OriginalFirstThunk", 0) or 0)
                if not oft:
                    skipped += len(getattr(descriptor, "imports", []) or [])
                    continue
                width = 8 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 4
                for entry in list(getattr(descriptor, "imports", []) or []):
                    iat_rva = int(getattr(entry, "address", 0) or 0) - int(pe.OPTIONAL_HEADER.ImageBase)
                    file_offset = pe.get_offset_from_rva(iat_rva)
                    if zero_iat and file_offset + width <= len(blob):
                        blob[file_offset : file_offset + width] = b"\0" * width
                        repaired += 1
                    else:
                        skipped += 1
            if not imports:
                return {"ok": False, "errorCode": "NO_IMPORTS", "error": "dump has no import descriptors"}
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(target.name + f".tmp-{os.getpid()}-{time.time_ns()}")
            try:
                temporary.write_bytes(blob)
                os.replace(temporary, target)
            finally:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
            verified = pefile.PE(data=target.read_bytes(), fast_load=False)
            digest = hashlib.sha256(target.read_bytes()).hexdigest().upper()
            return {
                "ok": True,
                "schema": "dump-import-fix-v1",
                "path": str(target),
                "sizeOnDisk": target.stat().st_size,
                "sha256": digest,
                "descriptorCount": len(imports),
                "repairedSlots": repaired,
                "skippedSlots": skipped,
                "verified": bool(verified),
                "diagnostics": [] if not skipped else ["Some descriptors lack OriginalFirstThunk and were left unchanged."],
            }
        except Exception as exc:
            return {"ok": False, "errorCode": "IMPORT_FIX_FAILED", "error": str(exc)}

    @mcp.tool()
    def ValidateDump(
        dump_path: str,
        run_isolated: bool = False,
        arguments_json: str = "[]",
        timeout_ms: int = 5000,
        expected_exit_code: int = -1,
        network_policy: str = "deny",
        crash_report_path: str = "",
    ) -> dict:
        """Validate PE structure/imports and optionally run a bounded smoke process.

        The optional isolated run is placed in a kill-on-close Windows Job
        Object so descendants cannot outlive the validation.  ``network_policy``
        remains an explicit policy marker; this process-local harness does not
        pretend to be a firewall sandbox.
        """

        path = Path(os.path.abspath(str(dump_path or "")))
        if not path.is_file():
            return {"ok": False, "errorCode": "INPUT_NOT_FOUND", "error": "dump_path does not exist"}
        try:
            args = json.loads(arguments_json or "[]")
        except (TypeError, ValueError) as exc:
            return {"ok": False, "errorCode": "INVALID_ARGUMENT", "error": str(exc)}
        if not isinstance(args, list) or any(not isinstance(item, (str, int, float)) for item in args):
            return {"ok": False, "errorCode": "INVALID_ARGUMENT", "error": "arguments_json must be a JSON array of scalar values"}
        try:
            pe = pefile.PE(data=path.read_bytes(), fast_load=False) if pefile is not None else None
            if pe is None:
                raise RuntimeError("pefile is unavailable")
            arch = "x64" if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else "x86"
            imports = list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or [])
            file_size = path.stat().st_size
            section_bounds = [
                {
                    "name": section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                    "rawPointer": int(section.PointerToRawData),
                    "rawSize": int(section.SizeOfRawData),
                    "inFile": int(section.PointerToRawData) + int(section.SizeOfRawData) <= file_size,
                }
                for section in pe.sections
            ]
            structural_failures = [item["name"] for item in section_bounds if not item["inFile"]]
            import_count = sum(len(getattr(item, "imports", []) or []) for item in imports)
            iat_directory = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", [])[12]
            structural = not structural_failures and int(pe.OPTIONAL_HEADER.SizeOfImage or 0) > 0
            report: Dict[str, Any] = {
                "ok": structural,
                "schema": "dump-validation-v1",
                "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest().upper(),
                "sizeOnDisk": file_size,
                "architecture": arch,
                "entryRva": f"0x{int(pe.OPTIONAL_HEADER.AddressOfEntryPoint):X}",
                "sizeOfImage": int(pe.OPTIONAL_HEADER.SizeOfImage),
                "sectionCount": len(section_bounds),
                "sections": section_bounds,
                "importDescriptorCount": len(imports),
                "importCount": import_count,
                "iat": {
                    "rva": f"0x{int(iat_directory.VirtualAddress):X}",
                    "size": int(iat_directory.Size),
                    "present": bool(iat_directory.VirtualAddress and iat_directory.Size),
                },
                "structuralFailures": structural_failures,
                "execution": {"requested": bool(run_isolated), "ran": False},
                "diagnostics": [],
            }
            if not report["iat"]["present"] and import_count:
                report["diagnostics"].append("imports_present_but_IAT_directory_empty")
            if run_isolated and structural:
                policy = str(network_policy or "deny").strip().lower()
                if policy not in {"deny", "inherit"}:
                    return {"ok": False, "errorCode": "INVALID_ARGUMENT", "error": "network_policy must be deny or inherit"}
                creation_flags = getattr(__import__("subprocess"), "CREATE_NEW_PROCESS_GROUP", 0)
                import subprocess
                command = [str(path)] + [str(item) for item in args]
                execution: Dict[str, Any] = {
                    "requested": True,
                    "command": command,
                    "networkPolicy": policy,
                    "networkEnforcement": "process-group-timeout-only",
                    "warning": "Windows network isolation is not a firewall sandbox; analyze untrusted files in a disposable VM.",
                }
                process = subprocess.Popen(
                    command,
                    cwd=str(path.parent),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=creation_flags,
                    text=False,
                )
                job_handle = None
                job_error = ""
                if os.name == "nt":
                    try:
                        import ctypes
                        from ctypes import wintypes

                        class _BasicLimitInformation(ctypes.Structure):
                            _fields_ = [
                                ("PerProcessUserTime", ctypes.c_longlong),
                                ("PerJobUserTime", ctypes.c_longlong),
                                ("LimitFlags", ctypes.c_uint32),
                                ("MinimumWorkingSetSize", ctypes.c_size_t),
                                ("MaximumWorkingSetSize", ctypes.c_size_t),
                                ("ActiveProcessLimit", ctypes.c_uint32),
                                ("Affinity", ctypes.c_size_t),
                                ("PriorityClass", ctypes.c_uint32),
                                ("SchedulingClass", ctypes.c_uint32),
                            ]

                        class _IoCounters(ctypes.Structure):
                            _fields_ = [
                                ("ReadOperationCount", ctypes.c_ulonglong),
                                ("WriteOperationCount", ctypes.c_ulonglong),
                                ("OtherOperationCount", ctypes.c_ulonglong),
                                ("ReadTransferCount", ctypes.c_ulonglong),
                                ("WriteTransferCount", ctypes.c_ulonglong),
                                ("OtherTransferCount", ctypes.c_ulonglong),
                            ]

                        class _ExtendedLimitInformation(ctypes.Structure):
                            _fields_ = [
                                ("BasicLimitInformation", _BasicLimitInformation),
                                ("IoInfo", _IoCounters),
                                ("ProcessMemoryLimit", ctypes.c_size_t),
                                ("JobMemoryLimit", ctypes.c_size_t),
                                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                                ("PeakJobMemoryUsed", ctypes.c_size_t),
                            ]

                        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
                        kernel32.AssignProcessToJobObject.argtypes = [
                            wintypes.HANDLE,
                            wintypes.HANDLE,
                        ]
                        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
                        kernel32.SetInformationJobObject.argtypes = [
                            wintypes.HANDLE,
                            ctypes.c_int,
                            ctypes.c_void_p,
                            wintypes.DWORD,
                        ]
                        kernel32.SetInformationJobObject.restype = wintypes.BOOL
                        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
                        kernel32.TerminateJobObject.restype = wintypes.BOOL
                        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
                        kernel32.CloseHandle.restype = wintypes.BOOL
                        job_handle = kernel32.CreateJobObjectW(None, None)
                        if not job_handle:
                            job_error = f"CreateJobObjectW failed: {ctypes.get_last_error()}"
                        else:
                            limits = _ExtendedLimitInformation()
                            # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                            limits.BasicLimitInformation.LimitFlags = 0x2000
                            if not kernel32.SetInformationJobObject(
                                job_handle,
                                9,  # JobObjectExtendedLimitInformation
                                ctypes.byref(limits),
                                ctypes.sizeof(limits),
                            ):
                                job_error = f"SetInformationJobObject failed: {ctypes.get_last_error()}"
                            elif not kernel32.AssignProcessToJobObject(
                                job_handle,
                                wintypes.HANDLE(int(getattr(process, "_handle", 0))),
                            ):
                                job_error = f"AssignProcessToJobObject failed: {ctypes.get_last_error()}"
                            else:
                                execution["jobObject"] = {
                                    "attached": True,
                                    "killOnClose": True,
                                }
                        if job_error and job_handle:
                            kernel32.CloseHandle(job_handle)
                            job_handle = None
                    except Exception as exc:
                        job_error = str(exc)
                execution.setdefault("jobObject", {
                    "attached": False,
                    "killOnClose": False,
                    "error": job_error or None,
                })
                try:
                    stdout, stderr = process.communicate(timeout=max(100, int(timeout_ms)) / 1000.0)
                    execution.update(
                        ran=True,
                        timedOut=False,
                        exitCode=process.returncode,
                        stdout=stdout[:65536].decode(errors="replace"),
                        stderr=stderr[:65536].decode(errors="replace"),
                    )
                except subprocess.TimeoutExpired:
                    if job_handle:
                        try:
                            kernel32.TerminateJobObject(job_handle, 0xC000013A)
                        except Exception:
                            process.kill()
                    else:
                        process.kill()
                    stdout, stderr = process.communicate()
                    execution.update(
                        ran=True,
                        timedOut=True,
                        exitCode=None,
                        stdout=stdout[:65536].decode(errors="replace"),
                        stderr=stderr[:65536].decode(errors="replace"),
                    )
                finally:
                    if job_handle:
                        try:
                            kernel32.CloseHandle(job_handle)
                        except Exception:
                            pass
                report["execution"] = execution
                if execution.get("timedOut") or execution.get("exitCode") is None:
                    report["diagnostics"].append("isolated_execution_timeout")
                elif int(expected_exit_code) >= 0 and execution.get("exitCode") != int(expected_exit_code):
                    report["diagnostics"].append("unexpected_exit_code")
                else:
                    report["execution"]["success"] = True
                crash_path = str(crash_report_path or "").strip()
                crash_like = bool(
                    execution.get("timedOut")
                    or (
                        execution.get("exitCode") is not None
                        and int(execution.get("exitCode")) != 0
                    )
                )
                if crash_path and crash_like:
                    crash_target = Path(os.path.abspath(crash_path))
                    crash_payload = {
                        "schema": "dump-crash-report-v1",
                        "dumpPath": str(path),
                        "sha256": report["sha256"],
                        "command": command,
                        "exitCode": execution.get("exitCode"),
                        "timedOut": bool(execution.get("timedOut")),
                        "stdout": execution.get("stdout", ""),
                        "stderr": execution.get("stderr", ""),
                        "networkPolicy": policy,
                        "jobObject": execution.get("jobObject"),
                        "createdAtUnixNs": time.time_ns(),
                    }
                    temporary = crash_target.with_name(
                        crash_target.name + f".tmp-{os.getpid()}-{time.time_ns()}"
                    )
                    crash_target.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        temporary.write_text(
                            json.dumps(crash_payload, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8",
                        )
                        os.replace(temporary, crash_target)
                        execution["crashReportPath"] = str(crash_target)
                    finally:
                        try:
                            temporary.unlink(missing_ok=True)
                        except OSError:
                            pass
            report["ok"] = bool(report["ok"] and not report["structuralFailures"])
            return report
        except Exception as exc:
            return {"ok": False, "errorCode": "DUMP_VALIDATION_FAILED", "error": str(exc)}

    @mcp.tool()
    def DumpOnEvent(
        event: str,
        output_path: str,
        module: str = "",
        breakpoint_target: str = "",
        timeout_ms: int = 30000,
        dump_kind: str = "module",
        resume_after: bool = False,
        auto_run: bool = True,
        event_evidence_path: str = "",
    ) -> dict:
        """Wait for a supported debugger event and emit a verified dump artifact."""

        event_name = str(event or "").strip().lower()
        if event_name not in {
            "oep",
            "module_load",
            "breakpoint",
            "exception",
            "execute_after_write",
        }:
            return {
                "ok": False,
                "errorCode": "UNSUPPORTED_EVENT",
                "error": "event must be oep, module_load, breakpoint, exception or execute_after_write",
                "supported": [
                    "oep",
                    "module_load",
                    "breakpoint",
                    "exception",
                    "execute_after_write",
                ],
            }
        wait_result: Dict[str, Any]
        if event_name == "oep":
            wait_result = FindOEP(timeout_ms=timeout_ms)
        elif event_name == "module_load":
            wait_result = WaitForModuleLoad(module_name=module, timeout_ms=timeout_ms, poll_ms=100, auto_run=True)
        elif event_name == "breakpoint":
            if not breakpoint_target:
                return {"ok": False, "errorCode": "INVALID_ARGUMENT", "error": "breakpoint_target is required"}
            target_text = str(breakpoint_target).strip()
            is_hex = bool(re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", target_text))
            run_result = DebugRun() if auto_run else {"ok": True, "skipped": True}
            wait_result = WaitForBreakpointDetailed(
                addr=target_text if is_hex else "",
                name="" if is_hex else target_text,
                timeout_ms=timeout_ms,
            )
            wait_result = {**wait_result, "run": run_result}
        elif event_name == "execute_after_write":
            if not breakpoint_target:
                return {
                    "ok": False,
                    "errorCode": "INVALID_ARGUMENT",
                    "error": "breakpoint_target is required as address or address,size",
                }
            target_text = str(breakpoint_target).strip()
            target_parts = [part.strip() for part in target_text.split(",", 1)]
            watch_addr = target_parts[0]
            try:
                watch_size = max(1, int(target_parts[1], 0)) if len(target_parts) == 2 else 1
            except (TypeError, ValueError):
                return {
                    "ok": False,
                    "errorCode": "INVALID_ARGUMENT",
                    "error": "execute_after_write size must be an integer",
                }
            capture_execute_after_write = g.get("CaptureExecuteAfterWrite")
            if not callable(capture_execute_after_write):
                return {
                    "ok": False,
                    "errorCode": "UNSUPPORTED_EVENT",
                    "error": "execute-after-write capture is unavailable",
                }
            wait_result = capture_execute_after_write(
                addr=watch_addr,
                size=watch_size,
                timeout_ms=timeout_ms,
                resume=auto_run,
                evidence_path=event_evidence_path,
                overwrite=True,
            )
            wait_result = {
                **wait_result,
                "event": event_name,
                "watchAddress": watch_addr,
                "watchSize": watch_size,
                "writeEvidence": bool(
                    isinstance(wait_result.get("finalDiff"), dict)
                    and wait_result.get("finalDiff", {}).get("changed")
                    and (wait_result.get("execute") or {}).get(
                        "pointsAtChangedByte"
                    )
                ),
            }
        else:
            history = GetExceptionHistory
            wait_result = {"ok": False, "errorCode": "UNSUPPORTED_EVENT", "error": "exception event polling requires GetExceptionHistory"}
            if callable(history):
                run_result = DebugRun() if auto_run else {"ok": True, "skipped": True}
                deadline = time.monotonic() + max(100, int(timeout_ms)) / 1000.0
                while time.monotonic() < deadline:
                    snapshot = history(limit=1)
                    if isinstance(snapshot, dict) and snapshot.get("history"):
                        wait_result = {
                            "ok": True,
                            "event": snapshot.get("history", [])[0],
                            "history": snapshot,
                            "run": run_result,
                        }
                        break
                    time.sleep(0.1)
        if not isinstance(wait_result, dict) or not wait_result.get("ok"):
            return {"ok": False, "event": event_name, "wait": wait_result}
        kind = str(dump_kind or "module").strip().lower()
        if kind == "module":
            # Event capture is not OEP discovery: preserve the source PE entry,
            # loader/CRT state and imports while overlaying live executable
            # sections. Using the paused RIP as Scylla's new entrypoint would
            # make an execute-after-write dump start inside the generated code.
            dump = DumpModule(
                module=module,
                output_path=output_path,
                find_oep=False,
                verify=True,
                overwrite=True,
                module_strategy="overlay",
            )
        elif kind == "minidump":
            if not callable(WriteMiniDump):
                return {
                    "ok": False,
                    "errorCode": "UNSUPPORTED_DUMP_KIND",
                    "error": "WriteMiniDump is unavailable on the active bridge",
                    "event": event_name,
                    "wait": wait_result,
                }
            dump = WriteMiniDump(output_path=output_path, pause_if_running=False, resume_after=False)
        else:
            return {"ok": False, "errorCode": "INVALID_ARGUMENT", "error": "dump_kind must be module or minidump"}
        resumed = DebugRun() if resume_after else {"ok": True, "skipped": True}
        return {"ok": bool(dump.get("ok")), "event": event_name, "wait": wait_result, "dump": dump, "resumed": resumed}

    def _normalize_exception_code_local(code: Any) -> str:
        raw = str(code or "").strip().strip('"').strip("'")
        parsed = _parse_int(raw)
        if parsed is not None:
            return f"0x{parsed & 0xFFFFFFFF:x}"
        return raw.lower()

    def _parse_exception_codes(codes_json: str) -> List[str]:
        raw = str(codes_json or "").strip()
        if not raw:
            return []
        # Try to parse the WHOLE string as JSON first so a proper array like
        # ["0xE0434352","0x..."] is decoded cleanly. (Stripping the brackets before
        # json.loads broke that and left literal quotes on each code.)
        values: List[Any]
        try:
            decoded = json.loads(raw)
        except Exception:
            decoded = None
        if isinstance(decoded, list):
            values = decoded
        elif decoded is not None:
            values = [decoded]
        else:
            inner = raw
            if inner.startswith("[") and inner.endswith("]"):
                inner = inner[1:-1]
            values = [
                token.strip().strip('"').strip("'")
                for token in re.split(r"[\s,;]+", inner)
                if isinstance(token, str) and token.strip()
            ]
        normalized: List[str] = []
        seen: set[str] = set()
        for item in values:
            code = _normalize_exception_code_local(item)
            if not code or code == "0x0" or code in seen:
                continue
            seen.add(code)
            normalized.append(code)
        return normalized

    def _coerce_ok(payload: Any) -> bool:
        return bool(
            (isinstance(payload, dict) and payload.get("ok"))
            or (isinstance(payload, dict) and payload.get("success"))
            or (isinstance(payload, str) and payload.lower() not in ("", "false", "0"))
        )

    def _default_dump_path(module_record: Dict[str, Any]) -> str:
        path = str(module_record.get("path") or "")
        if not path:
            return os.path.abspath(f"{str(module_record.get('name') or 'dump')}.dump.exe")
        directory = os.path.dirname(path) or os.getcwd()
        stem, ext = os.path.splitext(os.path.basename(path))
        ext = ext or ".exe"
        return os.path.join(directory, f"{stem}.dump{ext}")

    @mcp.tool()
    def GetFunctionArgs(count: int = 4, stack_depth: int = 8) -> dict:
        """
        Fetch likely function arguments using the current calling convention.

        x64: rcx, rdx, r8, r9, then [rsp+0x28], [rsp+0x30]...
        x86: [esp+4], [esp+8]...

        Returns raw hex, plus string interpretation when the value looks like
        a readable ASCII/UTF-16 pointer.
        """
        lean = GetDebugStateLean()
        if not lean.get("paused"):
            return {
                "ok": False,
                "error": "GetFunctionArgs requires a paused debuggee",
                "state": lean,
            }
        regs = _collect_register_dump(log=False) or {}
        is_x64 = "r8" in regs and "r9" in regs
        args: List[Dict[str, Any]] = []
        count = max(1, min(int(count), 12))
        if is_x64:
            reg_order = ["ccx", "cdx", "r8", "r9"]
            for i in range(count):
                if i < len(reg_order):
                    reg = reg_order[i]
                    val = _normalize_hex(regs.get(reg))
                    args.append({"index": i, "source": reg, "value": val})
                else:
                    # shadow space + stack: [rsp + 0x20 + (i-4)*8]
                    stack_offset = 0x20 + (i - 4) * 8
                    rsp = regs.get("csp")
                    if rsp:
                        try:
                            slot_addr = hex(int(rsp, 0) + stack_offset)
                            mem = ReadMemory(addr=slot_addr, size=8, ty="hex", max_chars=0)
                            val = None
                            if isinstance(mem, dict) and mem.get("ok"):
                                raw = mem.get("hex", "")
                                if len(raw) >= 16:
                                    val = hex(
                                        int.from_bytes(bytes.fromhex(raw[:16]), "little")
                                    )
                            args.append(
                                {
                                    "index": i,
                                    "source": f"[rsp+0x{stack_offset:x}]",
                                    "value": val,
                                }
                            )
                        except Exception as e:
                            args.append({"index": i, "source": "stack", "error": str(e)})
                    else:
                        args.append({"index": i, "source": "stack", "error": "no csp"})
        else:
            rsp = regs.get("csp")
            for i in range(count):
                stack_offset = 4 + i * 4
                try:
                    slot_addr = hex(int(rsp, 0) + stack_offset) if rsp else None
                    if slot_addr:
                        mem = ReadMemory(addr=slot_addr, size=4, ty="hex", max_chars=0)
                        val = None
                        if isinstance(mem, dict) and mem.get("ok"):
                            raw = mem.get("hex", "")
                            if len(raw) >= 8:
                                val = hex(
                                    int.from_bytes(bytes.fromhex(raw[:8]), "little")
                                )
                        args.append(
                            {
                                "index": i,
                                "source": f"[esp+0x{stack_offset:x}]",
                                "value": val,
                            }
                        )
                except Exception as e:
                    args.append({"index": i, "source": "stack", "error": str(e)})
        # Best-effort string peek
        for arg in args:
            val = arg.get("value")
            if not val:
                continue
            try:
                asc = ReadMemory(addr=val, size=128, ty="ascii", max_chars=96)
                if isinstance(asc, dict) and asc.get("ok"):
                    text = asc.get("ascii") or asc.get("text") or ""
                    if text and 3 <= len(text) <= 128 and text.isprintable():
                        arg["asAscii"] = text
            except Exception:
                pass
        return {"ok": True, "arch": "x64" if is_x64 else "x86", "args": args}

    @mcp.tool()
    def CaptureStopContextStructured(
        registers_json: str = "",
        expressions_json: str = "",
        ranges_json: str = "",
        stack_slots_json: str = "",
        disasm_before: int = 2,
        disasm_after: int = 4,
        callstack_limit: int = 12,
    ) -> dict:
        """
        Capture a rich, structured snapshot of the current stop — registers, selected
        memory/stack slots, the call stack, and disassembly around the instruction
        pointer — in one payload. Ideal right after a breakpoint hit so the model gets
        full context in a single round-trip.

        Args:
            registers_json: Optional JSON array of register names to include
                            (empty = the standard set).
            expressions_json: Optional JSON array of x64dbg expressions to evaluate.
            ranges_json: Optional JSON array of {label, expr, size, format} memory
                         ranges to read.
            stack_slots_json: Optional JSON array describing stack slots to decode.
            disasm_before: Instructions to disassemble before the IP (default 2).
            disasm_after: Instructions to disassemble after the IP (default 4).
            callstack_limit: Maximum call-stack frames to include (default 12).

        Returns:
            {"ok": bool, "registers": ..., "memory": ..., "callStack": ...,
             "disasm": ...} structured context, or an error envelope.
        """
        payload = _capture_stop_context_structured(
            registers_json=registers_json,
            expressions_json=expressions_json,
            ranges_json=ranges_json,
            stack_slots_json=stack_slots_json,
            disasm_before=disasm_before,
            disasm_after=disasm_after,
            callstack_limit=callstack_limit,
        )
        payload["ok"] = bool(payload.get("ok"))
        return payload

    @mcp.tool()
    def WaitForBreakpointCaptureStructured(
        addr: str = "",
        name: str = "",
        registers_json: str = "",
        expressions_json: str = "",
        ranges_json: str = "",
        stack_slots_json: str = "",
        timeout_ms: int = 10000,
        poll_ms: int = 100,
        disasm_before: int = 2,
        disasm_after: int = 4,
        callstack_limit: int = 12,
    ) -> dict:
        """
        Wait for a breakpoint and capture a structured stop snapshot: regs, stack, call stack, disasm.
        """
        event = WaitForBreakpointDetailed(
            addr=addr, name=name, timeout_ms=timeout_ms, poll_ms=poll_ms
        )
        hit = bool(event.get("matchedRequested", event.get("hit"))) and not bool(
            event.get("timedOut")
        )
        result = {"ok": hit, "event": event}
        if hit:
            result["snapshot"] = _capture_stop_context_structured(
                registers_json=registers_json,
                expressions_json=expressions_json,
                ranges_json=ranges_json,
                stack_slots_json=stack_slots_json,
                disasm_before=disasm_before,
                disasm_after=disasm_after,
                callstack_limit=callstack_limit,
            )
        return result

    @mcp.tool()
    def BatchBreakpointsCapture(
        targets_json: str,
        registers_json: str = "",
        expressions_json: str = "",
        ranges_json: str = "",
        stack_slots_json: str = "",
        timeout_ms: int = 10000,
        delete_after_hit: bool = True,
        resume: bool = True,
        disasm_before: int = 2,
        disasm_after: int = 4,
        callstack_limit: int = 12,
    ) -> dict:
        """
        Set multiple breakpoints, wait for the first one to hit, and capture a structured stop snapshot.
        """
        try:
            decoded = json.loads(targets_json) if targets_json else []
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"bad targets_json: {exc}"}
        if not isinstance(decoded, list) or not decoded:
            return {"ok": False, "error": "targets_json must be a non-empty JSON array"}
        registered: List[Dict[str, Any]] = []
        for index, item in enumerate(decoded):
            if isinstance(item, str):
                target_expr = item
                name = ""
            elif isinstance(item, dict):
                target_expr = str(item.get("addr") or item.get("target") or "")
                name = str(item.get("name") or "")
            else:
                return {"ok": False, "error": f"target {index} is not a string/object"}
            resolved = _resolve_addr(target_expr) if target_expr else None
            if not resolved:
                return {"ok": False, "error": f"could not resolve target {index}: {target_expr!r}"}
            set_result = (
                DebugSetBreakpoint(resolved)
                if callable(DebugSetBreakpoint)
                else safe_get("Debug/SetBreakpoint", {"addr": resolved}, log=False)
            )
            registered.append(
                {
                    "index": index,
                    "requested": target_expr,
                    "resolved": resolved,
                    "resolvedRef": _format_module_ref(resolved),
                    "name": name,
                    "setResult": set_result,
                }
            )
        if resume:
            DebugRun()
        event = WaitForBreakpointDetailed(timeout_ms=timeout_ms)
        matched_addr = _normalize_hex(event.get("addr") or event.get("rip"))
        matched_target = next(
            (
                item
                for item in registered
                if _normalize_hex(item.get("resolved")) == matched_addr
            ),
            None,
        )
        ok = bool(matched_target) and not bool(event.get("timedOut"))
        result = {
            "ok": ok,
            "event": event,
            "matchedTarget": matched_target,
            "targets": registered,
        }
        if ok:
            result["snapshot"] = _capture_stop_context_structured(
                registers_json=registers_json,
                expressions_json=expressions_json,
                ranges_json=ranges_json,
                stack_slots_json=stack_slots_json,
                disasm_before=disasm_before,
                disasm_after=disasm_after,
                callstack_limit=callstack_limit,
            )
        if delete_after_hit and callable(DebugDeleteBreakpoint):
            delete_results = []
            for item in registered:
                delete_results.append(
                    {
                        "addr": item.get("resolved"),
                        "result": DebugDeleteBreakpoint(str(item.get("resolved"))),
                    }
                )
            result["deleteResults"] = delete_results
        return result

    @mcp.tool()
    def WaitForModuleLoad(
        module_name: str,
        timeout_ms: int = 10000,
        poll_ms: int = 100,
        history_limit: int = 48,
        auto_run: bool = False,
    ) -> dict:
        """
        Wait for a specific module/DLL to load, using session history plus the live module list.
        """
        target = str(module_name or "").strip()
        if not target:
            return {"ok": False, "error": "module_name is required"}
        target_tokens = _module_match_tokens(target)
        if not target_tokens:
            return {"ok": False, "error": f"Could not normalize module name {target!r}"}
        existing = _resolve_module_by_name(target)
        if existing:
            return {
                "ok": True,
                "alreadyLoaded": True,
                "module": existing,
                "binding": _get_binding_snapshot(),
            }
        since_seq = 0
        if callable(_get_debug_session_state):
            try:
                session = _get_debug_session_state(include_history=False, history_limit=0)
                since_seq = int((session or {}).get("eventSeq") or 0)
            except Exception:
                since_seq = 0
        if auto_run:
            try:
                lean = GetDebugStateLean()
                if lean.get("paused"):
                    DebugRun()
            except Exception:
                pass
        deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
        last_history: List[Dict[str, Any]] = []
        while time.time() <= deadline:
            module = _resolve_module_by_name(target)
            if module:
                matching_event = None
                for item in reversed(last_history):
                    note = str(item.get("note") or "")
                    if any(token in note.casefold() for token in target_tokens):
                        matching_event = item
                        break
                if matching_event is None and callable(_get_debug_session_state):
                    try:
                        payload = _get_debug_session_state(
                            include_history=True, history_limit=max(8, int(history_limit))
                        )
                    except Exception:
                        payload = {}
                    history = payload.get("history", []) if isinstance(payload, dict) else []
                    for item in reversed(history):
                        note = str((item or {}).get("note") or "")
                        if any(token in note.casefold() for token in target_tokens):
                            matching_event = item
                            break
                return {
                    "ok": True,
                    "alreadyLoaded": False,
                    "module": module,
                    "event": matching_event,
                    "binding": _get_binding_snapshot(),
                }
            if callable(_get_debug_session_state):
                try:
                    payload = _get_debug_session_state(
                        include_history=True, history_limit=max(8, int(history_limit))
                    )
                except Exception:
                    payload = {}
                history = payload.get("history", []) if isinstance(payload, dict) else []
                last_history = [
                    item
                    for item in history
                    if isinstance(item, dict) and int(item.get("eventSeq") or 0) > since_seq
                ]
            time.sleep(max(0.05, int(poll_ms) / 1000.0))
        return {
            "ok": False,
            "timedOut": True,
            "moduleName": target,
            "history": last_history[-8:],
            "binding": _get_binding_snapshot(),
        }

    @mcp.tool()
    def FollowChildProcess(
        parent_pid: int = 0,
        exe_filter: str = "",
        timeout_ms: int = 10000,
        poll_ms: int = 100,
        include_descendants: bool = True,
        only_new: bool = True,
        require_window: bool = False,
        visible_only: bool = True,
        include_console_hosts: bool = False,
        remove_debug_object: bool = True,
        stop_first: bool = True,
        inspect_payload: bool = True,
        require_hollowed: bool = False,
    ) -> dict:
        """
        Wait for the most likely child process, optionally strip a foreign debug object, attach, and bind the session.
        """
        if not callable(WaitForChildProcess) or not callable(AttachToProcess):
            return {"ok": False, "error": "WaitForChildProcess/AttachToProcess are not available"}
        child = WaitForChildProcess(
            parent_pid=parent_pid,
            exe_filter=exe_filter,
            timeout_ms=timeout_ms,
            poll_ms=poll_ms,
            include_descendants=include_descendants,
            only_new=only_new,
            require_window=require_window,
            visible_only=visible_only,
            include_console_hosts=include_console_hosts,
        )
        fallback_wait = None
        if (not child.get("ok")) and only_new:
            fallback_wait = WaitForChildProcess(
                parent_pid=parent_pid,
                exe_filter=exe_filter,
                timeout_ms=max(2000, int(timeout_ms // 2)),
                poll_ms=poll_ms,
                include_descendants=include_descendants,
                only_new=False,
                require_window=require_window,
                visible_only=visible_only,
                include_console_hosts=include_console_hosts,
            )
            if isinstance(fallback_wait, dict) and fallback_wait.get("ok"):
                child = fallback_wait
        candidate = (
            child.get("candidate", {}) if isinstance(child, dict) else {}
        )
        child_pid = int(candidate.get("pid") or 0)
        if not child.get("ok") or not child_pid:
            return {"ok": False, "wait": child, "fallbackWait": fallback_wait}
        debug_status = (
            GetProcessDebugStatus(pid=child_pid) if callable(GetProcessDebugStatus) else {}
        )
        remove_result = None
        if (
            remove_debug_object
            and isinstance(debug_status, dict)
            and debug_status.get("underDebugger")
            and callable(RemoveProcessDebug)
        ):
            remove_result = RemoveProcessDebug(pid=child_pid)
        attach = AttachToProcess(
            pid=child_pid,
            stop_first=stop_first,
            timeout_ms=max(timeout_ms, 5000),
        )
        binding = _get_binding_snapshot()
        attached = bool(isinstance(attach, dict) and attach.get("ok"))
        payload_identity = None
        if attached and inspect_payload:
            try:
                payload_identity = InspectProcessPayload()
            except Exception as exc:
                payload_identity = {
                    "ok": False,
                    "errorCode": "PAYLOAD_INSPECTION_FAILED",
                    "error": str(exc),
                }
        hollowing_confirmed = bool(
            isinstance(payload_identity, dict)
            and payload_identity.get("ok")
            and payload_identity.get("likelyHollowed")
        )
        result_ok = attached and (not require_hollowed or hollowing_confirmed)
        error_code = None
        error = None
        if attached and require_hollowed and not hollowing_confirmed:
            error_code = "HOLLOWING_NOT_CONFIRMED"
            error = (
                "The child was attached, but PID-bound image evidence did not "
                "confirm process hollowing"
            )
        return {
            "ok": result_ok,
            "errorCode": error_code,
            "error": error,
            "wait": child,
            "fallbackWait": fallback_wait,
            "candidate": candidate,
            "debugStatus": debug_status,
            "removeDebugObject": remove_result,
            "attach": attach,
            "binding": binding,
            "payloadIdentity": payload_identity,
            "hollowingConfirmed": hollowing_confirmed,
        }

    @mcp.tool()
    def ExportCapabilityMap(output_path: str = "") -> dict:
        """
        Export the schema-v2 tool catalog, profiles, annotations and side effects.
        """
        if not callable(_get_mcp_tools_registry):
            return {"ok": False, "error": "_get_mcp_tools_registry is not available"}
        catalog = g.get("_TOOL_CATALOG")
        if not isinstance(catalog, dict) or int(catalog.get("schemaVersion") or 0) != 2:
            return {
                "ok": False,
                "error": "The complete schema-v2 tool catalog is unavailable",
            }
        # JSON roundtrip produces a detached, serialization-safe copy so adding
        # outputPath cannot mutate the global discovery policy.
        payload = json.loads(json.dumps(catalog, ensure_ascii=False))
        if output_path:
            target_path = os.path.abspath(str(output_path))
            parent = os.path.dirname(target_path) or os.getcwd()
            if not os.path.isdir(parent):
                return {"ok": False, "error": "Output directory does not exist"}
            temporary_path = (
                target_path + f".tmp-{os.getpid()}-{int(time.time_ns())}"
            )
            try:
                with open(temporary_path, "x", encoding="utf-8", newline="\n") as handle:
                    json.dump(payload, handle, ensure_ascii=False, indent=2)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary_path, target_path)
            finally:
                try:
                    if os.path.exists(temporary_path):
                        os.remove(temporary_path)
                except OSError:
                    pass
            payload["outputPath"] = target_path
        return payload

    @mcp.tool()
    def RunUntilModuleLoad(
        module_name: str,
        timeout_ms: int = 10000,
        poll_ms: int = 100,
    ) -> dict:
        """
        Resume if needed and wait until the requested module/DLL appears.
        """
        payload = WaitForModuleLoad(
            module_name=module_name,
            timeout_ms=timeout_ms,
            poll_ms=poll_ms,
            auto_run=True,
        )
        payload["mode"] = "module_load"
        return payload

    @mcp.tool()
    def RunUntilOEP(timeout_ms: int = 15000) -> dict:
        """
        Drive the current session to the original entry point using the existing OEP helper.
        """
        if not callable(FindOEP):
            return {"ok": False, "error": "FindOEP is not available"}
        payload = FindOEP(timeout_ms=timeout_ms, dump_to_path="")
        state = GetDebugStateLean()
        return {
            "ok": bool(isinstance(payload, dict) and payload.get("ok")),
            "mode": "oep",
            "result": payload,
            "state": state,
            "binding": _get_binding_snapshot(state=state),
        }

    @mcp.tool()
    def RunToUserCode(
        module_name: str = "",
        timeout_ms: int = 10000,
        poll_ms: int = 100,
        max_runs: int = 12,
        skip_startup_exceptions: bool = True,
    ) -> dict:
        """
        Strict variant of WaitForUserCode: only succeeds when paused in user code.
        """
        result = WaitForUserCode(
            module_name=module_name,
            timeout_ms=timeout_ms,
            poll_ms=poll_ms,
            max_runs=max_runs,
            skip_startup_exceptions=skip_startup_exceptions,
        )
        if not isinstance(result, dict):
            return {"ok": False, "error": str(result)}
        if result.get("ok") and result.get("reachedUserCode"):
            result["mode"] = "user_code"
            return result
        return {
            "ok": False,
            "mode": "user_code",
            "error": "Did not reach a stable pause inside user code",
            "result": result,
            "hint": result.get("hint")
            or "The process became interactive before a user-code pause was observed.",
        }

    @mcp.tool()
    def RunUntil(
        target: str = "ret",
        timeout_ms: int = 10000,
        poll_ms: int = 150,
    ) -> dict:
        """
        Run until a condition is met.

        `target`: "ret" (step-out style), "call" (next call instruction),
        a hex/symbolic address, or a module!sym reference.
        """
        target = (target or "").strip().lower()
        if not target:
            return {"ok": False, "error": "target required"}
        if target in ("user_code", "usercode"):
            return RunToUserCode(
                timeout_ms=timeout_ms,
                poll_ms=poll_ms,
                max_runs=max(4, int(timeout_ms / max(poll_ms, 50))),
            )
        if target in ("entry", "module_entry"):
            if callable(_get_current_debuggee_module_base):
                addr = _get_current_debuggee_module_base(want_entry=True)
                if addr:
                    target = str(addr)
        if target in ("oep", "module_oep"):
            if not callable(FindOEP):
                return {"ok": False, "error": "FindOEP is not available"}
            payload = FindOEP(timeout_ms=timeout_ms, dump_to_path="")
            state = GetDebugStateLean()
            return {
                "ok": bool(isinstance(payload, dict) and payload.get("ok")),
                "mode": "oep",
                "result": payload,
                "state": state,
                "binding": _get_binding_snapshot(state=state),
            }
        if target.startswith("module_load:"):
            module_name = target.split(":", 1)[1].strip()
            result = WaitForModuleLoad(
                module_name=module_name,
                timeout_ms=timeout_ms,
                poll_ms=poll_ms,
                auto_run=True,
            )
            result["mode"] = "module_load"
            return result
        if target == "ret":
            payload = _coerce_json_payload(safe_get("Debug/StepOut", log=False))
            paused_state = WaitForPause(timeout_ms=timeout_ms, poll_ms=poll_ms)
            return {
                "ok": isinstance(paused_state, dict) and paused_state.get("paused"),
                "mode": "ret",
                "state": GetDebugStateLean(),
                "raw": payload,
                "binding": _get_binding_snapshot(),
            }
        if target == "call":
            lean = GetDebugStateLean()
            if not lean.get("paused"):
                return {"ok": False, "error": "RunUntil call requires a paused state", "state": lean}
            deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
            steps = 0
            while time.time() < deadline and steps < 4096:
                state = GetDebugStateLean()
                rip = state.get("rip")
                if not rip:
                    break
                insn = _disasm_batch(rip, 1)
                if not insn:
                    break
                ins = str(insn[0].get("instruction") or "").strip().lower()
                if ins.startswith("call"):
                    return {
                        "ok": True,
                        "mode": "call",
                        "stoppedAt": rip,
                        "stoppedAtRef": _format_module_ref(rip),
                        "ins": ins,
                        "binding": _get_binding_snapshot(state=state),
                    }
                DebugStepOver()
                WaitForPause(timeout_ms=min(timeout_ms, 1000), poll_ms=poll_ms)
                steps += 1
            return {
                "ok": False,
                "mode": "call",
                "steps": steps,
                "reason": "not found",
                "binding": _get_binding_snapshot(),
            }
        # Treat as address target.
        addr = _resolve_addr(target)
        if not addr:
            return {"ok": False, "error": f"Cannot resolve {target!r}"}

        def _safe_loader_exception(state: Dict[str, Any]) -> bool:
            """Classify only OS-loader exceptions that are safe to consume.

            This deliberately excludes first-chance breakpoint exceptions in
            the debuggee itself.  Those can be an intentional DebugBreak or an
            anti-debug signal and must remain visible to the reverse engineer.
            The auto-disposition is further limited to address waits whose
            target belongs to the main debuggee image (the entry workflow).
            """

            if not isinstance(state, dict) or not state.get("paused"):
                return False
            code = str(state.get("exceptionCode") or "").strip().casefold()
            if code not in {"0x80000003", "0x4000001f", "0x4000001e"}:
                return False
            if state.get("exceptionFirstChance") is not True:
                return False
            if str(state.get("stopReason") or "").strip().casefold() != "exception":
                return False

            debuggee = str(state.get("debuggeeImage") or "").strip().casefold()
            source_module = str(state.get("module") or "").strip().casefold()
            source_path = str(state.get("modulePath") or "").replace("/", "\\").casefold()
            if not debuggee or not source_module or source_module == debuggee:
                return False

            target_module = _module_for_addr(addr)
            target_name = str((target_module or {}).get("name") or "").strip().casefold()
            if not target_name or target_name != debuggee:
                return False

            system_modules = {
                "ntdll.dll",
                "kernel32.dll",
                "kernelbase.dll",
                "wow64.dll",
                "wow64win.dll",
                "wow64cpu.dll",
            }
            if source_module in system_modules:
                return True

            # Windows can move WOW64 notification stubs between system DLLs.
            # Accept an unfamiliar module only for the WOW64 notification
            # codes and only when the loaded image is under the Windows system
            # directories.  Never apply this path to a regular breakpoint.
            return bool(
                code in {"0x4000001f", "0x4000001e"}
                and source_path
                and ("\\windows\\system32\\" in source_path or "\\windows\\syswow64\\" in source_path)
            )

        had_breakpoint = bool(callable(_breakpoint_exists) and _breakpoint_exists(addr))
        set_result = (
            DebugSetBreakpoint(addr)
            if callable(DebugSetBreakpoint)
            else safe_get("Debug/SetBreakpoint", {"addr": addr}, log=False)
        )
        deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
        paused_state: Dict[str, Any] = {}
        skipped_breakpoints: List[Dict[str, Any]] = []
        skipped_exceptions: List[Dict[str, Any]] = []
        continuation_error: Optional[Dict[str, Any]] = None
        initial_state = GetDebugStateLean()
        if _safe_loader_exception(initial_state):
            if not callable(ContinueException):
                continuation_error = {
                    "ok": False,
                    "errorCode": "EXPLICIT_EXCEPTION_CONTINUATION_UNAVAILABLE",
                    "error": (
                        "RunUntil started at an OS loader exception, but the "
                        "explicit ContinueException contract is unavailable."
                    ),
                }
                paused_state = initial_state
            else:
                continuation = ContinueException(
                    disposition="swallow",
                    expected_event_seq=0,
                    resume=True,
                )
                if not isinstance(continuation, dict) or continuation.get("ok") is not True:
                    continuation_error = (
                        dict(continuation)
                        if isinstance(continuation, dict)
                        else {
                            "ok": False,
                            "errorCode": "EXCEPTION_CONTINUATION_FAILED",
                            "error": str(continuation),
                        }
                    )
                    paused_state = initial_state
                else:
                    skipped_exceptions.append(
                        {
                            "code": initial_state.get("exceptionCode"),
                            "firstChance": True,
                            "rip": initial_state.get("rip"),
                            "module": initial_state.get("module"),
                            "eventSeq": continuation.get("eventSeq"),
                            "disposition": continuation.get("bridgeDisposition")
                            or "handled",
                        }
                    )
        else:
            DebugRun()
        try:
            while continuation_error is None:
                remaining_ms = max(0, int((deadline - time.time()) * 1000))
                if remaining_ms <= 0:
                    paused_state = WaitForPause(timeout_ms=0, poll_ms=poll_ms)
                    break
                event = WaitForBreakpointDetailed(addr=addr, timeout_ms=remaining_ms)
                matched_requested = bool(event.get("matchedRequested", event.get("hit")))
                observed_breakpoint = bool(event.get("observedBreakpoint")) or (
                    str(event.get("stopReason") or "").lower() == "breakpoint"
                    and event.get("addr")
                )
                if matched_requested and not bool(event.get("timedOut")):
                    paused_state = dict(event)
                    paused_state.setdefault("paused", True)
                    break
                if (
                    observed_breakpoint
                    and callable(_is_system_noise_breakpoint)
                    and _is_system_noise_breakpoint(event)
                    and remaining_ms > 0
                ):
                    skipped_breakpoints.append(
                        {
                            "addr": event.get("addr"),
                            "rip": event.get("rip"),
                            "name": event.get("breakpointName"),
                            "module": event.get("breakpointModule"),
                            "eventSeq": event.get("eventSeq"),
                        }
                    )
                    DebugRun()
                    continue

                # Some x64dbg builds emit a loader/system stop through
                # CB_PAUSEDEBUG only.  Preserve real user pauses, but continue
                # past a zero-exception pause in a known system module.
                lean_now = GetDebugStateLean()
                if lean_now.get("paused") and _normalize_hex(lean_now.get("rip")) == addr:
                    paused_state = dict(event)
                    paused_state.setdefault("paused", True)
                    break
                generic_noise = {
                    "breakpointModule": lean_now.get("module"),
                    "breakpointName": lean_now.get("breakpointName"),
                }
                if (
                    lean_now.get("paused")
                    and str(lean_now.get("exceptionCode") or "0").strip().lower()
                    in ("0", "0x0", "none")
                    and callable(_is_system_noise_breakpoint)
                    and _is_system_noise_breakpoint(generic_noise)
                    and remaining_ms > 0
                ):
                    skipped_breakpoints.append(
                        {
                            "addr": lean_now.get("rip"),
                            "rip": lean_now.get("rip"),
                            "name": lean_now.get("breakpointName") or "loader pause",
                            "module": lean_now.get("module"),
                            "eventSeq": lean_now.get("eventSeq"),
                        }
                    )
                    DebugRun()
                    continue
                if _safe_loader_exception(lean_now):
                    if not callable(ContinueException):
                        continuation_error = {
                            "ok": False,
                            "errorCode": "EXPLICIT_EXCEPTION_CONTINUATION_UNAVAILABLE",
                            "error": (
                                "RunUntil reached an OS loader exception, but the "
                                "explicit ContinueException contract is unavailable."
                            ),
                        }
                        paused_state = lean_now
                        break
                    continuation = ContinueException(
                        disposition="swallow",
                        expected_event_seq=0,
                        resume=True,
                    )
                    if not isinstance(continuation, dict) or continuation.get("ok") is not True:
                        continuation_error = (
                            dict(continuation)
                            if isinstance(continuation, dict)
                            else {
                                "ok": False,
                                "errorCode": "EXCEPTION_CONTINUATION_FAILED",
                                "error": str(continuation),
                            }
                        )
                        paused_state = lean_now
                        break
                    skipped_exceptions.append(
                        {
                            "code": lean_now.get("exceptionCode"),
                            "firstChance": True,
                            "rip": lean_now.get("rip"),
                            "module": lean_now.get("module"),
                            "eventSeq": continuation.get("eventSeq"),
                            "disposition": continuation.get("bridgeDisposition")
                            or "handled",
                        }
                    )
                    continue
                paused_state = lean_now if lean_now else dict(event)
                break
        finally:
            # The address breakpoint is owned by this operation.  Never leave a
            # temporary breakpoint behind after timeout/exit/foreign pause.
            if callable(DebugDeleteBreakpoint) and not had_breakpoint:
                try:
                    DebugDeleteBreakpoint(addr)
                except Exception:
                    pass
        lean = GetDebugStateLean()
        return {
            "ok": lean.get("paused") and _normalize_hex(lean.get("rip")) == addr,
            "mode": "addr",
            "target": addr,
            "targetRef": _format_module_ref(addr),
            "state": lean,
            "bpSet": set_result,
            "waitState": paused_state,
            "skippedBreakpoints": skipped_breakpoints,
            "skippedExceptions": skipped_exceptions,
            "continuationError": continuation_error,
            "binding": _get_binding_snapshot(state=lean),
            "hint": None
            if lean.get("paused") and _normalize_hex(lean.get("rip")) == addr
            else (
                "Explicit continuation of an OS loader exception failed."
                if continuation_error
                else "Target was not hit before timeout or the process is still running."
            ),
        }

    @mcp.tool()
    def GetFunctionInfo(addr: str) -> dict:
        """
        Compact single-function report: bounds, size, caller refs, referenced
        strings/constants sampled from the body, and first/last instructions.
        """
        resolved = _resolve_addr(addr)
        if not resolved:
            return {"ok": False, "error": f"cannot resolve {addr!r}"}
        walk = _walk_function(resolved, max_insns=2048)
        instructions = walk.get("instructions", [])
        strings: List[Dict[str, Any]] = []
        callees: List[Dict[str, Any]] = []
        callers: List[Dict[str, Any]] = []
        constants: List[str] = []
        block_starts = {str(walk.get("start") or resolved)}
        for item in instructions:
            ins = str(item.get("ins") or "")
            low = ins.lower()
            if low.startswith("call"):
                match = re.search(r"(0x[0-9A-Fa-f]+)$", ins)
                target_addr = _normalize_hex(match.group(1)) if match else None
                callees.append(
                    {
                        "instruction": ins,
                        "target": target_addr,
                        "name": _lookup_name_for_addr(target_addr) if target_addr else None,
                    }
                )
            if low.startswith(("j", "ret")):
                next_addr = _parse_int(item.get("addr"))
                size = int(item.get("size") or 0)
                if next_addr is not None and size > 0 and not low.startswith(("ret", "jmp")):
                    block_starts.add(_normalize_hex(next_addr + size) or hex(next_addr + size))
                for branch_target in re.findall(r"0x[0-9A-Fa-f]+", ins):
                    block_starts.add(_normalize_hex(branch_target) or branch_target)
            for token in re.findall(r"0x[0-9A-Fa-f]{4,}", ins):
                if token not in constants:
                    constants.append(token)
                    if len(constants) >= 32:
                        break
        if callable(StringGetAt):
            for token in constants[:16]:
                try:
                    res = StringGetAt(addr=token)
                    if isinstance(res, dict) and res.get("found") and res.get("string"):
                        strings.append({"addr": token, "string": str(res.get("string"))})
                except Exception:
                    continue
        if callable(XrefGet):
            try:
                xrefs = XrefGet(addr=resolved)
                refs = xrefs.get("references", []) if isinstance(xrefs, dict) else []
                for ref in refs:
                    if not isinstance(ref, dict):
                        continue
                    if str(ref.get("type") or "").lower() != "call":
                        continue
                    callers.append(
                        {
                            "addr": ref.get("addr"),
                            "type": ref.get("type"),
                            "string": ref.get("string"),
                        }
                    )
            except Exception:
                pass
        module = _module_for_addr(resolved)
        name = _lookup_name_for_addr(resolved) or f"sub_{int(resolved, 0):x}"
        return {
            "ok": True,
            "name": name,
            "start": walk.get("start"),
            "end": walk.get("end"),
            "size": walk.get("size"),
            "insnCount": walk.get("count"),
            "module": (module or {}).get("name") if module else None,
            "basicBlocks": len([item for item in block_starts if item]),
            "callers": callers[:32],
            "callees": callees[:32],
            "constants": constants[:16],
            "strings": strings[:12],
        }

    @mcp.tool()
    def SetExceptionFilter(
        codes_json: str = "",
        action: str = "skip",
        append: bool = False,
        clear: bool = False,
        first_chance_only: bool = True,
    ) -> dict:
        """
        Compatibility adapter for the native session-scoped exception policy.

        Legacy ``skip`` maps to ``handled``, ``pass`` maps to ``not_handled``,
        and ``stop`` maps to ``pause``.  Unlike the historical implementation,
        automatic disposition happens in the native exception callback and is
        therefore independent of WaitForPause/WaitForUserCode polling.
        """
        normalized_action = str(action or "skip").strip().lower()
        if normalized_action not in ("skip", "stop", "pass"):
            return {"ok": False, "error": "action must be one of: skip, stop, pass"}
        set_policy = g.get("SetExceptionPolicy")
        get_policy = g.get("GetExceptionPolicy")
        clear_policy = g.get("ClearExceptionPolicy")
        if callable(clear_policy) and clear:
            result = clear_policy(clear_history=False)
            if isinstance(result, dict) and result.get("ok"):
                result = dict(result)
                result.update(filters=[], count=0, cleared=True, legacyAdapter=True)
            return result
        if clear:
            if not callable(_remember_runtime):
                return {"ok": False, "error": "Runtime state is not writable"}
            _remember_runtime(exceptionFilters=[], nativeExceptionPolicyActive=False)
            return {"ok": True, "filters": [], "count": 0, "cleared": True}
        codes = _parse_exception_codes(codes_json)
        if not codes:
            return {
                "ok": False,
                "error": "codes_json must contain at least one exception code",
            }
        native_action = {
            "skip": "handled",
            "pass": "not_handled",
            "stop": "pause",
        }[normalized_action]
        entry = {
            "ruleId": f"legacy-filter-{time.time_ns():x}",
            "codes": codes,
            "action": native_action,
            "chance": "first" if first_chance_only else "any",
            "priority": 0,
            "enabled": True,
        }
        if callable(set_policy):
            result = set_policy(
                rules_json=json.dumps([entry], separators=(",", ":")),
                enabled=True,
                first_chance_default="pause",
                second_chance_default="pause",
                replace=not bool(append),
            )
            if not isinstance(result, dict) or not result.get("ok"):
                return result
            policy_result = get_policy() if callable(get_policy) else result
            policy = (
                policy_result.get("policy")
                if isinstance(policy_result, dict)
                and isinstance(policy_result.get("policy"), dict)
                else policy_result
            )
            filters = (
                list(policy.get("rules") or []) if isinstance(policy, dict) else []
            )
            adapted = dict(result)
            adapted.update(
                filters=filters,
                count=len(filters),
                added=entry,
                legacyAction=normalized_action,
                legacyAdapter=True,
            )
            return adapted

        # Compatibility with an older bridge during a mixed-version upgrade.
        if not callable(_remember_runtime):
            return {"ok": False, "error": "Runtime state is not writable"}
        current = []
        if callable(_get_runtime_value):
            try:
                raw_current = _get_runtime_value("exceptionFilters", [])
                if isinstance(raw_current, list):
                    current = [item for item in raw_current if isinstance(item, dict)]
            except Exception:
                current = []
        legacy_entry = {
            "codes": codes,
            "action": normalized_action,
            "firstChanceOnly": bool(first_chance_only),
        }
        filters = list(current) if append else []
        filters.append(legacy_entry)
        _remember_runtime(exceptionFilters=filters, nativeExceptionPolicyActive=False)
        return {
            "ok": True,
            "filters": filters,
            "count": len(filters),
            "added": legacy_entry,
            "legacyAdapter": True,
            "nativePolicy": False,
        }

    @mcp.tool()
    def GetExports(module: str = "", offset: int = 0, limit: int = 200) -> dict:
        """
        Return the export table for a loaded module.
        """
        target = module
        if not target:
            main = _resolve_main_module()
            if not main:
                return {"ok": False, "error": "no debuggee module"}
            target = str(main.get("name") or "")
        if not target:
            return {"ok": False, "error": "empty module name"}
        disk_payload = _load_exports_from_disk(target)
        if isinstance(disk_payload, dict) and disk_payload.get("ok"):
            exports = list(disk_payload.get("exports") or [])
            safe_offset = max(0, int(offset or 0))
            safe_limit = max(1, min(int(limit or 200), 5000))
            page = exports[safe_offset : safe_offset + safe_limit]
            next_offset = safe_offset + len(page)
            payload = dict(disk_payload)
            payload.update(
                {
                    "count": len(exports),
                    "offset": safe_offset,
                    "limit": safe_limit,
                    "returned": len(page),
                    "hasMore": next_offset < len(exports),
                    "nextOffset": next_offset if next_offset < len(exports) else None,
                    "exports": page,
                }
            )
            return payload
        if not callable(QuerySymbols):
            return {"ok": False, "error": "QuerySymbols is not available"}
        payload = QuerySymbols(module=target, offset=0, limit=50000)
        symbols = payload.get("symbols", []) if isinstance(payload, dict) else []
        module_record = _resolve_module_by_name(target)
        base = _parse_int((module_record or {}).get("base")) or 0
        exports: List[Dict[str, Any]] = []
        for sym in symbols:
            if not isinstance(sym, dict):
                continue
            if str(sym.get("type") or "").lower() != "export":
                continue
            rva = _parse_int(sym.get("rva"))
            exports.append(
                {
                    "module": str((module_record or {}).get("name") or target),
                    "function": str(sym.get("name") or ""),
                    "address": _normalize_hex(base + rva) if base and rva is not None else None,
                    "rva": _normalize_hex(rva) if rva is not None else None,
                    "ordinal": None,
                    "forwarder": None,
                }
            )
        safe_offset = max(0, int(offset or 0))
        safe_limit = max(1, min(int(limit or 200), 5000))
        page = exports[safe_offset : safe_offset + safe_limit]
        next_offset = safe_offset + len(page)
        return {
            "ok": True,
            "module": str((module_record or {}).get("name") or target),
            "count": len(exports),
            "offset": safe_offset,
            "limit": safe_limit,
            "returned": len(page),
            "hasMore": next_offset < len(exports),
            "nextOffset": next_offset if next_offset < len(exports) else None,
            "exports": page,
        }

    @mcp.tool()
    def TraceApiCalls(
        modules_json: str = "",
        functions_json: str = "",
        duration_ms: int = 5000,
        arg_count: int = 4,
        max_targets: int = 128,
        label: str = "",
    ) -> dict:
        """
        One-shot API trace: configure, run for a short window, then remove breakpoints.
        """
        if not callable(StartApiTrace) or not callable(RunApiTrace):
            return {"ok": False, "error": "API trace tools are not available"}
        start = StartApiTrace(
            modules_json=modules_json,
            filter_json=functions_json,
            arg_count=arg_count,
            label=label,
            max_targets=max_targets,
        )
        if not isinstance(start, dict) or not start.get("ok"):
            return start if isinstance(start, dict) else {"ok": False, "error": str(start)}
        trace_id = str(start.get("traceId") or "")
        run = RunApiTrace(trace_id=trace_id, timeout_ms=duration_ms)
        stop_result = None
        if callable(StopApiTrace):
            try:
                stop_result = StopApiTrace(trace_id=trace_id, delete_breakpoints=True)
            except Exception as exc:
                stop_result = {"ok": False, "error": str(exc), "traceId": trace_id}
        return {
            "ok": bool(isinstance(run, dict) and run.get("ok")),
            "traceId": trace_id,
            "start": start,
            "run": run,
            "stop": stop_result,
        }

    @mcp.tool()
    def TraceInstructionTape(
        steps: int = 32,
        step_kind: str = "in",
        registers_json: str = "",
        expressions_json: str = "",
        ranges_json: str = "",
        stack_slots_json: str = "",
        stop_on_ret: bool = False,
    ) -> dict:
        """
        Record a compact per-instruction execution tape while stepping.
        """
        if not callable(StepWithSnapshot):
            return {"ok": False, "error": "StepWithSnapshot is not available"}
        lean = GetDebugStateLean()
        if not lean.get("paused"):
            return {
                "ok": False,
                "error": "TraceInstructionTape requires a paused debuggee",
                "state": lean,
            }
        safe_steps = max(1, min(int(steps), 512))
        register_payload = registers_json
        if not register_payload:
            regs = _collect_register_dump(log=False) or {}
            if "r8" in regs:
                register_payload = json.dumps(
                    ["cip", "csp", "cbp", "cax", "ccx", "cdx", "r8", "r9"]
                )
            else:
                register_payload = json.dumps(["cip", "csp", "cbp", "cax", "ccx", "cdx"])
        tape: List[Dict[str, Any]] = []
        last_error = None
        stop_reason = "step_limit"

        def _compact_capture(capture: Dict[str, Any]) -> Dict[str, Any]:
            if not isinstance(capture, dict):
                return {}
            return {
                "state": capture.get("state"),
                "registers": capture.get("registers"),
                "expressions": capture.get("expressions"),
                "ranges": capture.get("ranges"),
                "stack": capture.get("stackSlots"),
            }

        for index in range(safe_steps):
            try:
                snapshot = StepWithSnapshot(
                    step_kind=step_kind,
                    registers_json=register_payload,
                    expressions_json=expressions_json,
                    ranges_json=ranges_json,
                    stack_slots_json=stack_slots_json,
                )
            except Exception as exc:
                last_error = str(exc)
                stop_reason = "exception"
                break
            if not isinstance(snapshot, dict):
                last_error = str(snapshot)
                stop_reason = "invalid_snapshot"
                break
            before = snapshot.get("before") if isinstance(snapshot.get("before"), dict) else {}
            after = snapshot.get("after") if isinstance(snapshot.get("after"), dict) else {}
            wait_state = (
                snapshot.get("waitState") if isinstance(snapshot.get("waitState"), dict) else {}
            )
            before_state = before.get("state", {}) if isinstance(before.get("state"), dict) else {}
            after_state = after.get("state", {}) if isinstance(after.get("state"), dict) else {}
            before_ins = snapshot.get("beforeInstruction")
            after_ins = snapshot.get("afterInstruction")
            before_rip = str(before_state.get("ip") or "")
            after_rip = str(after_state.get("ip") or "")
            if not before_ins and before_rip:
                batch = _disasm_batch(before_rip, 1)
                before_ins = batch[0] if batch else None
            if not after_ins and after_rip:
                batch = _disasm_batch(after_rip, 1)
                after_ins = batch[0] if batch else None
            entry = {
                "index": index,
                "stepKind": snapshot.get("stepKind"),
                "beforeRip": before_rip,
                "afterRip": after_rip,
                "beforeInstruction": before_ins,
                "afterInstruction": after_ins,
                "before": _compact_capture(before),
                "after": _compact_capture(after),
                "waitState": {
                    "state": wait_state.get("state"),
                    "stopReason": wait_state.get("stopReason"),
                    "exceptionCode": (
                        (wait_state.get("session") or {}).get("exceptionCode")
                        if isinstance(wait_state.get("session"), dict)
                        else None
                    ),
                },
            }
            tape.append(entry)
            if str(wait_state.get("state") or "").lower() in ("exited", "not_debugging"):
                stop_reason = "exited"
                break
            ins_text = ""
            if isinstance(before_ins, dict):
                ins_text = str(
                    before_ins.get("instruction")
                    or before_ins.get("ins")
                    or before_ins.get("text")
                    or ""
                )
            elif isinstance(before_ins, str):
                ins_text = before_ins
            if stop_on_ret and ins_text.strip().lower().startswith("ret"):
                stop_reason = "ret"
                break
        else:
            stop_reason = "step_limit"
        final_state = GetDebugStateLean()
        return {
            "ok": bool(tape),
            "count": len(tape),
            "stopReason": stop_reason,
            "error": last_error,
            "finalState": final_state,
            "tape": tape,
        }

    @mcp.tool()
    def Checkpoint(label: str = "") -> dict:
        """
        Save a lightweight execution checkpoint (registers plus a small stack
        snapshot) that you can return to later with Rewind. Convenience alias for
        SaveState tuned for quick save/restore loops during exploration.

        Args:
            label: Optional human-readable label. Empty = an auto-generated id.

        Returns:
            {"ok": bool, ...} from SaveState including the snapshot id — pass that id
            to Rewind to restore.
        """
        SaveState = g.get("SaveState")
        if SaveState is None:
            return {"ok": False, "error": "SaveState not available"}
        stack_slots = json.dumps(
            [{"label": "stack", "expr": "csp", "size": 256, "format": "hex"}]
        )
        return SaveState(label=label, ranges_json=stack_slots)

    @mcp.tool()
    def Rewind(snapshot_id: str) -> dict:
        """
        Restore a previously saved checkpoint (registers and captured memory),
        rewinding the debuggee to that state. Convenience alias for RestoreState.

        Args:
            snapshot_id: The id returned by Checkpoint/SaveState. Required.

        Returns:
            {"ok": bool, ...} from RestoreState.
        """
        RestoreState = g.get("RestoreState")
        if RestoreState is None:
            return {"ok": False, "error": "RestoreState not available"}
        return RestoreState(snapshot_id=snapshot_id, restore_memory=True)

    def _memory_int(value: Any, default: int = 0) -> int:
        if value in (None, ""):
            return default
        if isinstance(value, int):
            return value
        text = str(value).strip().replace("`", "")
        try:
            return int(text, 0)
        except (TypeError, ValueError):
            try:
                return int(text, 16)
            except (TypeError, ValueError):
                return default

    def _memory_map_pages(payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict):
            return []
        for key in ("pages", "regions", "memoryMap", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return []

    def _memory_bytes(payload: Any) -> bytes:
        if not isinstance(payload, dict) or not payload.get("ok"):
            return b""
        for key in ("data", "bytes", "hex", "value"):
            value = payload.get(key)
            if isinstance(value, (bytes, bytearray)):
                return bytes(value)
            if isinstance(value, list):
                try:
                    return bytes(int(item) & 0xFF for item in value)
                except (TypeError, ValueError):
                    continue
            if not isinstance(value, str):
                continue
            text = re.sub(r"[^0-9A-Fa-f]", "", value.removeprefix("0x"))
            if text and len(text) % 2 == 0:
                try:
                    return bytes.fromhex(text)
                except ValueError:
                    continue
        return b""

    def _normalize_memory_page(page: Dict[str, Any], index: int) -> Dict[str, Any]:
        base = _memory_int(
            page.get("base")
            or page.get("baseAddress")
            or page.get("address")
            or page.get("addr")
        )
        allocation_base = _memory_int(
            page.get("allocationBase")
            or page.get("allocBase")
            or page.get("allocation")
        )
        size = _memory_int(
            page.get("size")
            or page.get("regionSize")
            or page.get("length")
        )
        info = str(
            page.get("info")
            or page.get("name")
            or page.get("module")
            or ""
        )
        backing = str(
            page.get("path")
            or page.get("file")
            or page.get("mappedFile")
            or ""
        )
        protection = str(
            page.get("protect") or page.get("protection") or page.get("rights") or ""
        )
        region_type = str(page.get("type") or page.get("regionType") or "")
        state = str(page.get("state") or page.get("memoryState") or "")
        module = str(page.get("module") or "")
        if not module and re.search(r"\.(?:exe|dll|sys)(?:\b|$)", info, re.I):
            module = info
        readable = bool(
            protection
            and "---" not in protection
            and "NOACCESS" not in protection.upper()
            and "GUARD" not in protection.upper()
            and ("R" in protection.upper() or protection.upper().startswith("E"))
        )
        return {
            "index": index,
            "base": f"0x{base:X}",
            "allocationBase": (
                f"0x{allocation_base:X}" if allocation_base else None
            ),
            "size": size,
            "end": f"0x{base + size:X}" if base and size else None,
            "protection": protection,
            "state": state,
            "type": region_type,
            "info": info,
            "module": module,
            "backingFile": backing,
            "readable": readable,
            "executable": "E" in protection.upper()
            or "EXECUTE" in protection.upper(),
            "private": region_type.upper() in {"PRV", "PRIVATE", "MEM_PRIVATE"},
            "raw": dict(page),
        }

    @mcp.tool()
    def DumpMemoryMapManifest(
        output_path: str = "",
        include_hashes: bool = False,
        hash_bytes_per_region: int = 4096,
        max_regions: int = 8192,
    ) -> dict:
        """Export a normalized memory-map manifest with bounded provenance hashes."""

        if not callable(GetMemoryMap):
            return {"ok": False, "errorCode": "UNAVAILABLE", "error": "GetMemoryMap is unavailable"}
        raw_map = GetMemoryMap()
        pages = _memory_map_pages(raw_map)
        cap = max(1, min(int(max_regions), 65536))
        normalized = [
            _normalize_memory_page(page, index)
            for index, page in enumerate(pages[:cap])
        ]
        hash_size = max(1, min(int(hash_bytes_per_region), 65536))
        hash_budget = 4 * 1024 * 1024
        hashed = 0
        hash_failures = 0
        if include_hashes:
            for region in normalized:
                if not region["readable"] or not region["size"] or hash_budget <= 0:
                    continue
                requested = min(int(region["size"]), hash_size, hash_budget)
                read = ReadMemory(region["base"], requested, ty="hex", max_chars=0)
                data = _memory_bytes(read)
                if not data:
                    hash_failures += 1
                    region["hashError"] = (
                        read.get("error") if isinstance(read, dict) else "memory read failed"
                    )
                    continue
                region["sampleSha256"] = hashlib.sha256(data).hexdigest().upper()
                region["sampleBytes"] = len(data)
                hash_budget -= len(data)
                hashed += 1
        body = {
            "schema": "memory-map-manifest-v1",
            "regionCount": len(normalized),
            "sourceRegionCount": len(pages),
            "truncated": len(pages) > cap,
            "hashMode": "bounded-prefix" if include_hashes else "none",
            "hashedRegionCount": hashed,
            "hashFailureCount": hash_failures,
            "regions": normalized,
        }
        canonical = json.dumps(
            body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest().upper()
        output = {"written": False, "path": None}
        if str(output_path or "").strip():
            target = Path(os.path.abspath(str(output_path)))
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = {**body, "manifestSha256": digest}
            temporary = target.with_name(target.name + f".tmp-{os.getpid()}-{time.time_ns()}")
            try:
                temporary.write_text(
                    json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                os.replace(temporary, target)
            finally:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
            output = {"written": True, "path": str(target)}
        return {
            "ok": bool(isinstance(raw_map, dict) and raw_map.get("ok", True)),
            "manifest": {**body, "manifestSha256": digest},
            "manifestSha256": digest,
            "output": output,
        }

    @mcp.tool()
    def ScanMemoryForPEImages(
        max_regions: int = 8192,
        max_candidates: int = 256,
        header_bytes: int = 65536,
        include_embedded: bool = True,
        header_template_path: str = "",
        minimum_template_similarity: float = 0.70,
    ) -> dict:
        """
        Find ordinary, embedded reflective/manual-map and template-matched
        headerless PE images without trusting the debugger module list.

        `include_embedded` scans every captured region prefix for valid MZ/PE
        headers, not just offset zero. Supplying `header_template_path` also
        derives candidate image bases from executable section RVAs and reports
        destroyed/headerless images only when immutable section bytes match the
        template above `minimum_template_similarity`.
        """

        if not callable(GetMemoryMap):
            return {"ok": False, "errorCode": "UNAVAILABLE", "error": "GetMemoryMap is unavailable"}
        raw_map = GetMemoryMap()
        pages = _memory_map_pages(raw_map)
        region_cap = max(1, min(int(max_regions), 65536))
        candidate_cap = max(1, min(int(max_candidates), 4096))
        read_cap = max(1024, min(int(header_bytes), 1024 * 1024))
        candidates: List[Dict[str, Any]] = []
        candidate_bases: set[int] = set()
        read_failures = 0
        inspected = 0
        template_path = str(header_template_path or "").strip()
        template_data = b""
        template_layout: Optional[Dict[str, Any]] = None
        template_error = ""
        if template_path:
            try:
                template_data = Path(template_path).read_bytes()
                template_layout = _parse_memory_pe_layout(template_data)
            except Exception as exc:
                template_error = str(exc)
                return {
                    "ok": False,
                    "errorCode": "PE_TEMPLATE_INVALID",
                    "error": template_error,
                    "templatePath": os.path.abspath(template_path),
                }
        normalized_regions: List[Dict[str, Any]] = []
        for index, page in enumerate(pages[:region_cap]):
            region = _normalize_memory_page(page, index)
            normalized_regions.append(region)
            base = _memory_int(region["base"])
            size = int(region.get("size") or 0)
            if not base or size < 64 or not region.get("readable"):
                continue
            inspected += 1
            read_size = min(size, read_cap)
            read = ReadMemory(f"0x{base:X}", read_size, ty="hex", max_chars=0)
            data = _memory_bytes(read)
            if len(data) < 64:
                read_failures += 1
                continue
            offsets = [0]
            if include_embedded:
                cursor = 0
                while len(offsets) < 4096:
                    found = data.find(b"MZ", cursor)
                    if found < 0:
                        break
                    if found not in offsets:
                        offsets.append(found)
                    cursor = found + 2
            for embedded_offset in offsets:
                if embedded_offset + 0x100 > len(data):
                    continue
                try:
                    layout = _parse_memory_pe_layout(data[embedded_offset:])
                    _validate_memory_pe_layout(layout)
                except Exception:
                    continue
                candidate_base = base + embedded_offset
                if candidate_base in candidate_bases:
                    continue
                size_of_headers = int(layout.get("sizeOfHeaders") or 0)
                header_end = min(
                    len(data),
                    embedded_offset + max(size_of_headers, 512),
                )
                manual_map = bool(
                    region.get("private")
                    or embedded_offset
                    or not region.get("module")
                )
                candidate = {
                    "base": f"0x{candidate_base:X}",
                    "regionBase": f"0x{base:X}",
                    "regionSize": size,
                    "embeddedOffset": embedded_offset,
                    "sizeOfImage": int(layout.get("sizeOfImage") or 0),
                    "sizeOfHeaders": size_of_headers,
                    "entryRva": f"0x{int(layout.get('entryRva') or 0):X}",
                    "entryVa": f"0x{candidate_base + int(layout.get('entryRva') or 0):X}",
                    "preferredImageBase": f"0x{int(layout.get('imageBase') or 0):X}",
                    "machine": f"0x{int(layout.get('machine') or 0):04X}",
                    "architecture": layout.get("architecture"),
                    "sectionCount": len(layout.get("sections") or []),
                    "headerSha256": hashlib.sha256(
                        data[embedded_offset:header_end]
                    ).hexdigest().upper(),
                    "headerState": "intact",
                    "imageKind": (
                        "embedded-reflective"
                        if embedded_offset
                        else ("manual-map" if manual_map else "mapped-image")
                    ),
                    "suggestedSourceLayout": (
                        "disk" if embedded_offset else "memory"
                    ),
                    "sourceLayoutConfidence": (
                        "embedded-header-heuristic"
                        if embedded_offset
                        else "region-base-header"
                    ),
                    "manualMapCandidate": manual_map,
                    "confidence": "validated-dos+nt+optional+sections",
                    "provenance": {
                        key: region.get(key)
                        for key in (
                            "allocationBase",
                            "protection",
                            "state",
                            "type",
                            "info",
                            "module",
                            "backingFile",
                            "private",
                            "executable",
                        )
                    },
                }
                candidates.append(candidate)
                candidate_bases.add(candidate_base)
                if len(candidates) >= candidate_cap:
                    break
            if len(candidates) >= candidate_cap:
                break

        template_matches: List[Dict[str, Any]] = []
        template_attempts: List[Dict[str, Any]] = []
        if template_layout is not None and len(candidates) < candidate_cap:
            similarity_floor = max(
                0.50, min(float(minimum_template_similarity), 1.0)
            )
            derived_bases: Dict[int, set[str]] = {}
            executable_sections = [
                section
                for section in template_layout.get("sections", [])
                if int(section.get("characteristics") or 0) & 0x20000000
            ]
            for region in normalized_regions:
                region_base = _memory_int(region.get("base"))
                allocation_base = _memory_int(region.get("allocationBase"))
                if allocation_base:
                    derived_bases.setdefault(allocation_base, set()).add(
                        "allocation-base"
                    )
                if region_base:
                    derived_bases.setdefault(region_base, set()).add("region-base")
                    if region.get("readable") or region.get("executable"):
                        for section in executable_sections:
                            rva = int(section.get("virtualAddress") or 0)
                            if region_base > rva:
                                derived_bases.setdefault(region_base - rva, set()).add(
                                    f"region-minus-{section.get('name') or 'exec'}-rva"
                                )
            for derived_base, reasons in sorted(derived_bases.items()):
                if derived_base in candidate_bases or derived_base <= 0:
                    continue
                probe = _score_template_memory_identity(
                    derived_base,
                    template_data,
                    template_layout,
                    sample_limit_per_section=1,
                )
                if (
                    int(probe.get("comparedBytes") or 0) >= 64
                    and float(probe.get("similarity") or 0.0) >= 0.50
                ):
                    match = _score_template_memory_identity(
                        derived_base,
                        template_data,
                        template_layout,
                    )
                else:
                    match = probe
                template_attempts.append(
                    {
                        "base": f"0x{derived_base:X}",
                        "baseDerivation": sorted(reasons),
                        "comparedBytes": int(match.get("comparedBytes") or 0),
                        "equalBytes": int(match.get("equalBytes") or 0),
                        "similarity": float(match.get("similarity") or 0.0),
                        "readFailures": int(match.get("readFailures") or 0),
                    }
                )
                if (
                    int(match.get("comparedBytes") or 0) < 64
                    or float(match.get("similarity") or 0.0) < similarity_floor
                ):
                    continue
                matching_region = next(
                    (
                        region
                        for region in normalized_regions
                        if _memory_int(region.get("base"))
                        <= derived_base
                        < _memory_int(region.get("base"))
                        + int(region.get("size") or 0)
                    ),
                    {},
                )
                candidate = {
                    "base": f"0x{derived_base:X}",
                    "regionBase": matching_region.get("base"),
                    "regionSize": int(matching_region.get("size") or 0),
                    "embeddedOffset": None,
                    "sizeOfImage": int(template_layout.get("sizeOfImage") or 0),
                    "sizeOfHeaders": int(template_layout.get("sizeOfHeaders") or 0),
                    "entryRva": f"0x{int(template_layout.get('entryRva') or 0):X}",
                    "entryVa": f"0x{derived_base + int(template_layout.get('entryRva') or 0):X}",
                    "preferredImageBase": f"0x{int(template_layout.get('imageBase') or 0):X}",
                    "machine": f"0x{int(template_layout.get('machine') or 0):04X}",
                    "architecture": template_layout.get("architecture"),
                    "sectionCount": len(template_layout.get("sections") or []),
                    "headerSha256": None,
                    "headerState": "destroyed-or-headerless",
                    "imageKind": "template-matched-manual-map",
                    "suggestedSourceLayout": "memory",
                    "sourceLayoutConfidence": "template-section-identity",
                    "manualMapCandidate": True,
                    "confidence": "template-section-identity",
                    "baseDerivation": sorted(reasons),
                    "templateIdentity": match,
                    "provenance": {
                        key: matching_region.get(key)
                        for key in (
                            "allocationBase",
                            "protection",
                            "state",
                            "type",
                            "info",
                            "module",
                            "backingFile",
                            "private",
                            "executable",
                        )
                    },
                }
                candidates.append(candidate)
                template_matches.append(candidate)
                candidate_bases.add(derived_base)
                if len(candidates) >= candidate_cap:
                    break
        return {
            "ok": bool(isinstance(raw_map, dict) and raw_map.get("ok", True)),
            "schema": "memory-pe-scan-v2",
            "sourceRegionCount": len(pages),
            "inspectedRegionCount": inspected,
            "readFailureCount": read_failures,
            "candidateCount": len(candidates),
            "truncated": len(candidates) >= candidate_cap or len(pages) > region_cap,
            "embeddedScan": bool(include_embedded),
            "template": {
                "provided": bool(template_path),
                "path": os.path.abspath(template_path) if template_path else None,
                "sha256": (
                    hashlib.sha256(template_data).hexdigest().upper()
                    if template_data
                    else None
                ),
                "matchCount": len(template_matches),
                "topAttempts": sorted(
                    template_attempts,
                    key=lambda item: (
                        float(item.get("similarity") or 0.0),
                        int(item.get("comparedBytes") or 0),
                    ),
                    reverse=True,
                )[:32],
                "minimumSimilarity": (
                    max(0.50, min(float(minimum_template_similarity), 1.0))
                    if template_path
                    else None
                ),
            },
            "candidates": candidates,
        }

    @mcp.tool()
    def DumpModuleRaw(
        base: str,
        size: int,
        output_path: str,
        chunk_size: int = 1024 * 1024,
        overwrite: bool = False,
    ) -> dict:
        """Atomically dump any readable virtual-memory range, including arbitrary DLLs."""

        base_int = _memory_int(base)
        try:
            size_int = int(size)
        except (TypeError, ValueError):
            size_int = 0
        output_text = str(output_path or "").strip()
        if not base_int or size_int <= 0 or not output_text:
            return {
                "ok": False,
                "errorCode": "INVALID_ARGUMENT",
                "error": "base, positive size and output_path are required",
            }
        if size_int > 512 * 1024 * 1024:
            return {
                "ok": False,
                "errorCode": "SIZE_LIMIT",
                "error": "Raw dumps are bounded to 512 MiB per call",
            }
        target = Path(os.path.abspath(output_text))
        if target.exists() and not overwrite:
            return {
                "ok": False,
                "errorCode": "OUTPUT_EXISTS",
                "error": "output_path already exists; set overwrite=true to replace it",
                "path": str(target),
            }
        target.parent.mkdir(parents=True, exist_ok=True)
        chunk = max(4096, min(int(chunk_size), 4 * 1024 * 1024))
        temporary = target.with_name(target.name + f".tmp-{os.getpid()}-{time.time_ns()}")
        digest = hashlib.sha256()
        written = 0
        chunks = 0
        try:
            with temporary.open("xb") as handle:
                while written < size_int:
                    requested = min(chunk, size_int - written)
                    address = base_int + written
                    read = ReadMemory(f"0x{address:X}", requested, ty="hex", max_chars=0)
                    data = _memory_bytes(read)
                    if len(data) != requested:
                        raise RuntimeError(
                            f"memory read at 0x{address:X} returned {len(data)} of {requested} bytes"
                        )
                    handle.write(data)
                    digest.update(data)
                    written += len(data)
                    chunks += 1
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        except Exception as exc:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            return {
                "ok": False,
                "errorCode": "RAW_DUMP_FAILED",
                "error": str(exc),
                "base": f"0x{base_int:X}",
                "size": size_int,
                "bytesRead": written,
                "chunksRead": chunks,
                "partialArtifactRemoved": not temporary.exists(),
            }
        return {
            "ok": True,
            "schema": "raw-memory-dump-v1",
            "base": f"0x{base_int:X}",
            "size": size_int,
            "path": str(target),
            "exists": target.exists(),
            "sizeOnDisk": target.stat().st_size,
            "sha256": digest.hexdigest().upper(),
            "chunksRead": chunks,
        }

    def _align_up(value: int, alignment: int) -> int:
        alignment = max(1, int(alignment))
        return (int(value) + alignment - 1) // alignment * alignment

    def _parse_memory_pe_layout(data: bytes) -> Dict[str, Any]:
        if len(data) < 0x100 or data[:2] != b"MZ":
            raise ValueError("DOS header is missing")
        nt_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if nt_offset < 0x40 or nt_offset + 24 > len(data):
            raise ValueError("e_lfanew is outside the captured header")
        if data[nt_offset : nt_offset + 4] != b"PE\x00\x00":
            raise ValueError("NT signature is missing")
        machine, section_count, _, _, _, optional_size, characteristics = struct.unpack_from(
            "<HHIIIHH", data, nt_offset + 4
        )
        optional_offset = nt_offset + 24
        section_table = optional_offset + optional_size
        if section_count <= 0 or section_count > 96:
            raise ValueError(f"invalid section count: {section_count}")
        if section_table + section_count * 40 > len(data):
            raise ValueError("section table is outside the captured header")
        magic = struct.unpack_from("<H", data, optional_offset)[0]
        if magic == 0x20B:
            is64 = True
            image_base_offset = optional_offset + 24
            image_base = struct.unpack_from("<Q", data, image_base_offset)[0]
            directory_count_offset = optional_offset + 108
            directory_offset = optional_offset + 112
        elif magic == 0x10B:
            is64 = False
            image_base_offset = optional_offset + 28
            image_base = struct.unpack_from("<I", data, image_base_offset)[0]
            directory_count_offset = optional_offset + 92
            directory_offset = optional_offset + 96
        else:
            raise ValueError(f"unsupported optional-header magic 0x{magic:X}")
        entry_rva = struct.unpack_from("<I", data, optional_offset + 16)[0]
        section_alignment = struct.unpack_from("<I", data, optional_offset + 32)[0]
        file_alignment = struct.unpack_from("<I", data, optional_offset + 36)[0]
        size_of_image = struct.unpack_from("<I", data, optional_offset + 56)[0]
        size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
        checksum_offset = optional_offset + 64
        directory_count = min(
            16,
            struct.unpack_from("<I", data, directory_count_offset)[0],
        )
        directories: List[Dict[str, int]] = []
        for index in range(directory_count):
            entry_offset = directory_offset + index * 8
            if entry_offset + 8 > len(data):
                break
            rva, size = struct.unpack_from("<II", data, entry_offset)
            directories.append({"index": index, "rva": rva, "size": size, "offset": entry_offset})
        sections: List[Dict[str, Any]] = []
        for index in range(section_count):
            header_offset = section_table + index * 40
            raw_name = data[header_offset : header_offset + 8].split(b"\x00", 1)[0]
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
                "<IIII", data, header_offset + 8
            )
            section_characteristics = struct.unpack_from("<I", data, header_offset + 36)[0]
            sections.append(
                {
                    "index": index,
                    "name": raw_name.decode("ascii", "replace"),
                    "headerOffset": header_offset,
                    "virtualSize": virtual_size,
                    "virtualAddress": virtual_address,
                    "rawSize": raw_size,
                    "rawPointer": raw_pointer,
                    "characteristics": section_characteristics,
                }
            )
        return {
            "machine": machine,
            "architecture": "x64" if is64 else "x86",
            "is64": is64,
            "characteristics": characteristics,
            "ntOffset": nt_offset,
            "optionalOffset": optional_offset,
            "optionalSize": optional_size,
            "imageBaseOffset": image_base_offset,
            "imageBase": image_base,
            "entryRva": entry_rva,
            "sectionAlignment": section_alignment,
            "fileAlignment": file_alignment,
            "sizeOfImage": size_of_image,
            "sizeOfHeaders": size_of_headers,
            "checksumOffset": checksum_offset,
            "directoryOffset": directory_offset,
            "directories": directories,
            "sections": sections,
        }

    def _validate_memory_pe_layout(layout: Dict[str, Any]) -> None:
        """Reject syntactically valid-looking headers that cannot describe an image."""

        architecture = str(layout.get("architecture") or "")
        machine = int(layout.get("machine") or 0)
        if architecture == "x64" and machine != 0x8664:
            raise ValueError("PE32+ header has a non-AMD64 machine")
        if architecture == "x86" and machine != 0x14C:
            raise ValueError("PE32 header has a non-I386 machine")
        image_size = int(layout.get("sizeOfImage") or 0)
        header_size = int(layout.get("sizeOfHeaders") or 0)
        entry_rva = int(layout.get("entryRva") or 0)
        section_alignment = int(layout.get("sectionAlignment") or 0)
        file_alignment = int(layout.get("fileAlignment") or 0)
        if image_size < 0x1000 or image_size > 512 * 1024 * 1024:
            raise ValueError("SizeOfImage is outside the supported range")
        if header_size <= 0 or header_size > image_size:
            raise ValueError("SizeOfHeaders is outside the image")
        if entry_rva >= image_size:
            raise ValueError("entry point is outside the image")
        if (
            section_alignment <= 0
            or section_alignment > 0x1000000
            or section_alignment & (section_alignment - 1)
        ):
            raise ValueError("invalid SectionAlignment")
        if (
            file_alignment <= 0
            or file_alignment > 0x10000
            or file_alignment & (file_alignment - 1)
        ):
            raise ValueError("invalid FileAlignment")
        previous_va = -1
        for section in layout.get("sections") or []:
            virtual_address = int(section.get("virtualAddress") or 0)
            virtual_size = int(section.get("virtualSize") or 0)
            raw_size = int(section.get("rawSize") or 0)
            if virtual_address < previous_va:
                raise ValueError("section RVAs are not monotonic")
            previous_va = virtual_address
            span = max(virtual_size, raw_size)
            if virtual_address >= image_size or span > image_size - virtual_address:
                raise ValueError("section span is outside SizeOfImage")

    def _template_section_payload(
        template_data: bytes,
        section: Dict[str, Any],
    ) -> Tuple[bytes, str]:
        raw_pointer = int(section.get("rawPointer") or 0)
        raw_size = int(section.get("rawSize") or 0)
        virtual_address = int(section.get("virtualAddress") or 0)
        virtual_size = int(section.get("virtualSize") or 0)
        disk = b""
        if raw_pointer >= 0 and raw_size > 0 and raw_pointer < len(template_data):
            disk = template_data[
                raw_pointer : min(len(template_data), raw_pointer + raw_size)
            ]
        # Unit fixtures and analyst-supplied snapshots can themselves use
        # memory layout. Prefer the normal disk layout, but fall back to RVA
        # bytes only when the raw span is clearly empty.
        if sum(1 for value in disk[: min(len(disk), 4096)] if value) >= 16:
            return disk, "disk-raw"
        if virtual_address < len(template_data):
            memory = template_data[
                virtual_address : min(
                    len(template_data),
                    virtual_address + max(virtual_size, raw_size),
                )
            ]
            if memory:
                return memory, "memory-rva-fallback"
        return disk, "disk-raw"

    def _template_sample_windows(payload: bytes) -> List[Tuple[int, bytes]]:
        if not payload:
            return []
        window_size = min(192, len(payload))
        positions = {
            0,
            max(0, len(payload) // 4 - window_size // 2),
            max(0, len(payload) // 2 - window_size // 2),
            max(0, (len(payload) * 3) // 4 - window_size // 2),
            max(0, len(payload) - window_size),
        }
        windows: List[Tuple[int, bytes]] = []
        for position in sorted(positions):
            sample = payload[position : position + window_size]
            if len(sample) < 32:
                continue
            non_padding = sum(value not in (0x00, 0xCC) for value in sample)
            if non_padding < max(16, len(sample) // 8):
                continue
            windows.append((position, sample))
        return windows

    def _score_template_memory_identity(
        runtime_base: int,
        template_data: bytes,
        layout: Dict[str, Any],
        sample_limit_per_section: int = 0,
    ) -> Dict[str, Any]:
        section_results: List[Dict[str, Any]] = []
        compared = 0
        equal = 0
        read_failures = 0
        for section in layout.get("sections") or []:
            characteristics = int(section.get("characteristics") or 0)
            # Executable/read-only code is the stable identity source. Writable
            # sections legitimately change after loader fixups and execution.
            if not characteristics & 0x20000000:
                continue
            payload, payload_mode = _template_section_payload(
                template_data, section
            )
            section_compared = 0
            section_equal = 0
            samples = 0
            windows = _template_sample_windows(payload)
            if int(sample_limit_per_section) > 0:
                windows = windows[: int(sample_limit_per_section)]
            for offset, expected in windows:
                address = (
                    runtime_base
                    + int(section.get("virtualAddress") or 0)
                    + offset
                )
                try:
                    actual = _read_memory_exact(address, len(expected), len(expected))
                except Exception:
                    read_failures += 1
                    continue
                sample_equal = sum(
                    left == right for left, right in zip(expected, actual)
                )
                compared += len(expected)
                equal += sample_equal
                section_compared += len(expected)
                section_equal += sample_equal
                samples += 1
            if samples or payload:
                section_results.append(
                    {
                        "name": section.get("name"),
                        "rva": f"0x{int(section.get('virtualAddress') or 0):X}",
                        "payloadMode": payload_mode,
                        "sampleCount": samples,
                        "comparedBytes": section_compared,
                        "equalBytes": section_equal,
                        "similarity": (
                            round(section_equal / section_compared, 6)
                            if section_compared
                            else 0.0
                        ),
                    }
                )
        return {
            "schema": "memory-pe-template-identity-v1",
            "verified": bool(compared >= 64 and equal / compared >= 0.70),
            "runtimeBase": f"0x{runtime_base:X}",
            "templateSha256": hashlib.sha256(template_data).hexdigest().upper(),
            "architecture": layout.get("architecture"),
            "comparedBytes": compared,
            "equalBytes": equal,
            "similarity": round(equal / compared, 6) if compared else 0.0,
            "readFailures": read_failures,
            "sections": section_results,
        }

    def _read_memory_exact(base: int, size: int, chunk_size: int = 1024 * 1024) -> bytes:
        chunks: List[bytes] = []
        offset = 0
        chunk = max(4096, min(int(chunk_size), 4 * 1024 * 1024))
        while offset < size:
            requested = min(chunk, size - offset)
            read = ReadMemory(f"0x{base + offset:X}", requested, ty="hex", max_chars=0)
            data = _memory_bytes(read)
            if len(data) != requested:
                raise RuntimeError(
                    f"memory read at 0x{base + offset:X} returned {len(data)} of {requested} bytes"
                )
            chunks.append(data)
            offset += len(data)
        return b"".join(chunks)

    def _reverse_base_relocations(
        image: bytearray,
        layout: Dict[str, Any],
        runtime_base: int,
        rva_to_offset: Callable[[int], Optional[int]],
        skip_rva: Optional[Callable[[int], bool]] = None,
    ) -> Dict[str, Any]:
        preferred = int(layout.get("imageBase") or 0)
        delta = runtime_base - preferred
        result = {
            "required": bool(delta),
            "delta": delta,
            "directoryRva": 0,
            "directorySize": 0,
            "blocks": 0,
            "entries": 0,
            "patched": 0,
            "skippedTemplate": 0,
            "unsupported": 0,
            "complete": not bool(delta),
        }
        if not delta:
            return result
        directories = {int(item["index"]): item for item in layout.get("directories", [])}
        reloc = directories.get(5) or {}
        directory_rva = int(reloc.get("rva") or 0)
        directory_size = int(reloc.get("size") or 0)
        result.update(directoryRva=directory_rva, directorySize=directory_size)
        directory_offset = rva_to_offset(directory_rva) if directory_rva else None
        if directory_offset is None or directory_size < 8:
            result["error"] = "ASLR delta is non-zero but the base-relocation directory is unavailable"
            return result
        cursor = int(directory_offset)
        end = min(len(image), cursor + directory_size)
        while cursor + 8 <= end:
            page_rva, block_size = struct.unpack_from("<II", image, cursor)
            if not page_rva or block_size < 8 or cursor + block_size > end:
                break
            result["blocks"] += 1
            entry_count = (block_size - 8) // 2
            for index in range(entry_count):
                encoded = struct.unpack_from("<H", image, cursor + 8 + index * 2)[0]
                reloc_type = encoded >> 12
                offset_in_page = encoded & 0xFFF
                if reloc_type == 0:
                    continue
                result["entries"] += 1
                target_rva = page_rva + offset_in_page
                if callable(skip_rva) and skip_rva(target_rva):
                    result["skippedTemplate"] += 1
                    continue
                target_offset = rva_to_offset(target_rva)
                if target_offset is None:
                    result["unsupported"] += 1
                    continue
                if reloc_type == 10 and bool(layout.get("is64")) and target_offset + 8 <= len(image):
                    value = struct.unpack_from("<Q", image, target_offset)[0]
                    struct.pack_into("<Q", image, target_offset, (value - delta) & 0xFFFFFFFFFFFFFFFF)
                    result["patched"] += 1
                elif reloc_type == 3 and not bool(layout.get("is64")) and target_offset + 4 <= len(image):
                    value = struct.unpack_from("<I", image, target_offset)[0]
                    struct.pack_into("<I", image, target_offset, (value - delta) & 0xFFFFFFFF)
                    result["patched"] += 1
                else:
                    result["unsupported"] += 1
            cursor += block_size
        result["complete"] = bool(
            (result["patched"] or result["skippedTemplate"])
            and not result["unsupported"]
        )
        if not result["patched"] and not result["skippedTemplate"]:
            result["error"] = "No supported relocation entries were reversed"
        return result

    @mcp.tool()
    def DumpPeFromMemory(
        base: str,
        output_path: str,
        image_size: int = 0,
        header_template_path: str = "",
        verify_template_identity: bool = True,
        minimum_template_similarity: float = 0.70,
        reset_mutable_sections_from_template: bool = True,
        entry_rva_override: str = "",
        source_layout: str = "auto",
        reverse_relocations: bool = True,
        verify: bool = True,
        overwrite: bool = False,
    ) -> dict:
        """
        Reconstruct a disk-layout PE from a loaded memory-layout image.

        For destroyed/headerless images, `header_template_path` is accepted
        only after executable-section identity verification by default.
        Writable sections are reset from the bound template by default so CRT
        and loader state captured after DllMain cannot poison a later reload.
        `entry_rva_override` is bounded to an executable template section and
        can record a recovered manual-loader OEP without trusting stale headers.
        `source_layout=auto|memory|disk` also supports an embedded reflective
        raw PE staged inside a larger private allocation.
        """

        runtime_base = _memory_int(base)
        output_text = str(output_path or "").strip()
        if not runtime_base or not output_text:
            return {
                "ok": False,
                "errorCode": "INVALID_ARGUMENT",
                "error": "base and output_path are required",
            }
        target = Path(os.path.abspath(output_text))
        if target.exists() and not overwrite:
            return {
                "ok": False,
                "errorCode": "OUTPUT_EXISTS",
                "error": "output_path already exists; set overwrite=true to replace it",
                "path": str(target),
            }
        template_path = str(header_template_path or "").strip()
        source_mode = "memory"
        try:
            if template_path:
                header_source = Path(template_path).read_bytes()
                source_mode = "template"
            else:
                header_source = _read_memory_exact(runtime_base, 4096, 4096)
            try:
                layout = _parse_memory_pe_layout(header_source)
                _validate_memory_pe_layout(layout)
            except ValueError as first_error:
                if source_mode != "memory":
                    raise
                try:
                    header_source = _read_memory_exact(runtime_base, 65536, 65536)
                    layout = _parse_memory_pe_layout(header_source)
                    _validate_memory_pe_layout(layout)
                except Exception:
                    raise first_error
        except Exception as exc:
            return {
                "ok": False,
                "errorCode": "PE_HEADERS_UNRECOVERABLE",
                "error": str(exc),
                "hint": "Provide header_template_path for destroyed or headerless images.",
            }
        template_identity: Optional[Dict[str, Any]] = None
        if source_mode == "template":
            similarity_floor = max(
                0.50, min(float(minimum_template_similarity), 1.0)
            )
            template_identity = _score_template_memory_identity(
                runtime_base,
                header_source,
                layout,
            )
            template_identity["minimumSimilarity"] = similarity_floor
            template_identity["verified"] = bool(
                int(template_identity.get("comparedBytes") or 0) >= 64
                and float(template_identity.get("similarity") or 0.0)
                >= similarity_floor
            )
            if verify_template_identity and not template_identity["verified"]:
                compared = int(template_identity.get("comparedBytes") or 0)
                return {
                    "ok": False,
                    "errorCode": (
                        "PE_TEMPLATE_UNVERIFIABLE"
                        if compared < 64
                        else "PE_TEMPLATE_MISMATCH"
                    ),
                    "error": (
                        "The template could not be bound to enough executable "
                        "bytes in the runtime image."
                        if compared < 64
                        else "The template executable sections do not match the runtime image."
                    ),
                    "base": f"0x{runtime_base:X}",
                    "templatePath": os.path.abspath(template_path),
                    "templateIdentity": template_identity,
                    "hint": (
                        "Use the exact original/packed image template, or set "
                        "verify_template_identity=false only for an explicitly "
                        "reviewed manual reconstruction."
                    ),
                }
        requested_source_layout = str(source_layout or "auto").strip().lower()
        if requested_source_layout not in {"auto", "memory", "disk"}:
            return {
                "ok": False,
                "errorCode": "INVALID_ARGUMENT",
                "error": "source_layout must be auto, memory, or disk",
            }
        resolved_source_layout = requested_source_layout
        source_layout_evidence: Dict[str, Any] = {
            "requested": requested_source_layout,
            "resolved": requested_source_layout,
            "reason": "explicit",
        }
        if source_mode == "template":
            if requested_source_layout == "disk":
                return {
                    "ok": False,
                    "errorCode": "INVALID_ARGUMENT",
                    "error": "header templates describe memory-layout reconstruction, not raw disk staging",
                }
            resolved_source_layout = "memory"
            source_layout_evidence.update(
                resolved="memory", reason="header-template"
            )
        elif requested_source_layout == "auto":
            resolved_source_layout = "memory"
            source_layout_evidence.update(
                resolved="memory", reason="region-base-or-unavailable-map"
            )
            if callable(GetMemoryMap):
                try:
                    map_payload = GetMemoryMap()
                    for region_index, page in enumerate(_memory_map_pages(map_payload)):
                        region = _normalize_memory_page(page, region_index)
                        region_base = _memory_int(region.get("base"))
                        region_size = int(region.get("size") or 0)
                        if region_base <= runtime_base < region_base + region_size:
                            if runtime_base != region_base and region.get("private"):
                                resolved_source_layout = "disk"
                                source_layout_evidence.update(
                                    resolved="disk",
                                    reason="embedded-private-region-header",
                                    regionBase=f"0x{region_base:X}",
                                    offsetInRegion=runtime_base - region_base,
                                )
                            else:
                                source_layout_evidence.update(
                                    regionBase=f"0x{region_base:X}",
                                    offsetInRegion=runtime_base - region_base,
                                )
                            break
                except Exception as exc:
                    source_layout_evidence["mapError"] = str(exc)
        requested_image_size = int(image_size or 0)
        memory_image_size = requested_image_size or int(layout.get("sizeOfImage") or 0)
        if memory_image_size <= 0 or memory_image_size > 512 * 1024 * 1024:
            return {
                "ok": False,
                "errorCode": "SIZE_LIMIT",
                "error": "SizeOfImage must be between 1 byte and 512 MiB",
            }
        entry_override_text = str(entry_rva_override or "").strip()
        if entry_override_text:
            entry_override = _memory_int(entry_override_text)
            executable_owner = next(
                (
                    section
                    for section in layout.get("sections") or []
                    if int(section.get("characteristics") or 0) & 0x20000000
                    and int(section.get("virtualAddress") or 0)
                    <= entry_override
                    < int(section.get("virtualAddress") or 0)
                    + max(
                        int(section.get("virtualSize") or 0),
                        int(section.get("rawSize") or 0),
                    )
                ),
                None,
            )
            if (
                entry_override <= 0
                or entry_override >= memory_image_size
                or executable_owner is None
            ):
                return {
                    "ok": False,
                    "errorCode": "INVALID_ENTRY_RVA",
                    "error": "entry_rva_override must point inside an executable section",
                    "entryRvaOverride": entry_override_text,
                    "sizeOfImage": memory_image_size,
                }
            layout["entryRva"] = entry_override
        if resolved_source_layout == "disk":
            raw_extent = int(layout.get("sizeOfHeaders") or 0)
            for section in layout.get("sections") or []:
                raw_pointer = int(section.get("rawPointer") or 0)
                raw_size = int(section.get("rawSize") or 0)
                if raw_pointer > 512 * 1024 * 1024 or raw_size > 512 * 1024 * 1024:
                    return {
                        "ok": False,
                        "errorCode": "SIZE_LIMIT",
                        "error": "raw section span exceeds the 512 MiB reconstruction limit",
                    }
                raw_extent = max(raw_extent, raw_pointer + raw_size)
            directories = {
                int(item["index"]): item for item in layout.get("directories", [])
            }
            security = directories.get(4) or {}
            raw_extent = max(
                raw_extent,
                int(security.get("rva") or 0) + int(security.get("size") or 0),
            )
            if raw_extent <= 0 or raw_extent > 512 * 1024 * 1024:
                return {
                    "ok": False,
                    "errorCode": "SIZE_LIMIT",
                    "error": "raw PE extent is outside the supported range",
                }
            try:
                disk_image = bytearray(_read_memory_exact(runtime_base, raw_extent))
            except Exception as exc:
                return {
                    "ok": False,
                    "errorCode": "DISK_LAYOUT_READ_FAILED",
                    "error": str(exc),
                    "base": f"0x{runtime_base:X}",
                    "rawExtent": raw_extent,
                    "sourceLayout": source_layout_evidence,
                }
            struct.pack_into(
                "<I",
                disk_image,
                int(layout.get("optionalOffset") or 0) + 16,
                int(layout.get("entryRva") or 0),
            )
            checksum_offset = int(layout.get("checksumOffset") or 0)
            if checksum_offset and checksum_offset + 4 <= len(disk_image):
                struct.pack_into("<I", disk_image, checksum_offset, 0)
            verification: Dict[str, Any]
            try:
                if pefile is None:
                    raise RuntimeError("pefile is unavailable")
                parsed = pefile.PE(data=bytes(disk_image), fast_load=False)
                verification = {
                    "ok": True,
                    "structural": True,
                    "architecture": layout["architecture"],
                    "sectionCount": len(parsed.sections),
                    "parsedSections": len(parsed.sections),
                    "entryRva": f"0x{int(parsed.OPTIONAL_HEADER.AddressOfEntryPoint):X}",
                    "sizeOfImage": int(parsed.OPTIONAL_HEADER.SizeOfImage),
                }
            except Exception as exc:
                verification = {"ok": False, "structural": False, "error": str(exc)}
            if verify and not verification.get("ok"):
                return {
                    "ok": False,
                    "errorCode": "PE_VERIFY_FAILED",
                    "error": verification.get("error") or "raw staged PE validation failed",
                    "verification": verification,
                    "sourceLayout": source_layout_evidence,
                }
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(
                target.name + f".tmp-{os.getpid()}-{time.time_ns()}"
            )
            try:
                with temporary.open("xb") as handle:
                    handle.write(disk_image)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, target)
            except Exception as exc:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
                return {"ok": False, "errorCode": "PE_WRITE_FAILED", "error": str(exc)}
            digest = hashlib.sha256(disk_image).hexdigest().upper()
            return {
                "ok": bool(verification.get("ok")) if verify else True,
                "schema": "memory-pe-reconstruction-v2",
                "path": str(target),
                "exists": target.exists(),
                "sizeOnDisk": target.stat().st_size,
                "sha256": digest,
                "base": f"0x{runtime_base:X}",
                "preferredImageBase": f"0x{int(layout.get('imageBase') or 0):X}",
                "sourceMode": "memory",
                "sourceLayout": source_layout_evidence,
                "templateIdentity": None,
                "architecture": layout["architecture"],
                "entryRva": f"0x{int(layout.get('entryRva') or 0):X}",
                "sizeOfImage": int(layout.get("sizeOfImage") or 0),
                "rawExtent": raw_extent,
                "sections": [
                    {
                        "name": section.get("name"),
                        "rva": f"0x{int(section.get('virtualAddress') or 0):X}",
                        "rawSize": int(section.get("rawSize") or 0),
                        "rawPointer": int(section.get("rawPointer") or 0),
                    }
                    for section in layout.get("sections") or []
                ],
                "relocations": {
                    "required": False,
                    "complete": True,
                    "skipped": True,
                    "reason": "raw-disk-staging-image-was-not-relocated",
                },
                "securityDirectoryCleared": False,
                "verification": verification,
                "reloadable": bool(verification.get("ok")),
                "diagnostics": [
                    "Overlay bytes beyond the final declared section/certificate extent cannot be inferred from a memory allocation."
                ],
            }
        file_alignment = int(layout.get("fileAlignment") or 0x200)
        if file_alignment <= 0 or file_alignment > 0x10000 or file_alignment & (file_alignment - 1):
            file_alignment = 0x200
        size_of_headers = max(
            int(layout.get("sizeOfHeaders") or 0),
            max((int(item["headerOffset"]) + 40 for item in layout["sections"]), default=0),
        )
        header_disk_size = _align_up(size_of_headers, file_alignment)
        if source_mode == "memory":
            header_bytes = header_source[:size_of_headers]
        else:
            header_bytes = header_source[:size_of_headers]
        image = bytearray(header_disk_size)
        image[: min(len(header_bytes), size_of_headers)] = header_bytes[:size_of_headers]
        struct.pack_into(
            "<I",
            image,
            int(layout.get("optionalOffset") or 0) + 16,
            int(layout.get("entryRva") or 0),
        )
        section_results: List[Dict[str, Any]] = []
        next_raw = header_disk_size
        rva_spans: List[Tuple[int, int, int]] = []
        template_sourced_spans: List[Tuple[int, int]] = []
        try:
            for section in layout["sections"]:
                rva = int(section["virtualAddress"])
                virtual_size = int(section["virtualSize"])
                original_raw_size = int(section["rawSize"])
                available = max(0, memory_image_size - rva)
                capture_size = min(max(virtual_size, original_raw_size), available)
                raw_size = _align_up(capture_size, file_alignment) if capture_size else 0
                raw_pointer = next_raw if raw_size else 0
                section_source = "runtime-memory"
                if raw_size:
                    reset_from_template = bool(
                        source_mode == "template"
                        and reset_mutable_sections_from_template
                        and int(section.get("characteristics") or 0) & 0x80000000
                    )
                    if reset_from_template:
                        template_payload, _payload_mode = _template_section_payload(
                            header_source,
                            section,
                        )
                        reset_data = bytearray(capture_size)
                        reset_data[: min(len(template_payload), capture_size)] = (
                            template_payload[:capture_size]
                        )
                        memory_data = bytes(reset_data)
                        section_source = "template-mutable-reset"
                        template_sourced_spans.append((rva, rva + capture_size))
                    else:
                        memory_data = _read_memory_exact(
                            runtime_base + rva, capture_size
                        )
                    required = raw_pointer + raw_size
                    if len(image) < required:
                        image.extend(b"\x00" * (required - len(image)))
                    image[raw_pointer : raw_pointer + capture_size] = memory_data
                    rva_spans.append((rva, rva + capture_size, raw_pointer))
                    next_raw += raw_size
                header_offset = int(section["headerOffset"])
                struct.pack_into("<I", image, header_offset + 16, raw_size)
                struct.pack_into("<I", image, header_offset + 20, raw_pointer)
                section_results.append(
                    {
                        "name": section["name"],
                        "rva": f"0x{rva:X}",
                        "virtualSize": virtual_size,
                        "capturedSize": capture_size,
                        "rawSize": raw_size,
                        "rawPointer": raw_pointer,
                        "source": section_source,
                    }
                )
        except Exception as exc:
            return {
                "ok": False,
                "errorCode": "SECTION_READ_FAILED",
                "error": str(exc),
                "sections": section_results,
            }

        def rva_to_offset(rva: int) -> Optional[int]:
            if 0 <= rva < size_of_headers:
                return rva
            for start, end, pointer in rva_spans:
                if start <= rva < end:
                    return pointer + (rva - start)
            return None

        relocations = {
            "required": runtime_base != int(layout.get("imageBase") or 0),
            "complete": runtime_base == int(layout.get("imageBase") or 0),
            "skipped": not reverse_relocations,
        }
        if reverse_relocations:
            relocations = _reverse_base_relocations(
                image,
                layout,
                runtime_base,
                rva_to_offset,
                skip_rva=(
                    lambda candidate_rva: any(
                        start <= candidate_rva < end
                        for start, end in template_sourced_spans
                    )
                )
                if template_sourced_spans
                else None,
            )
        # The certificate table uses a file offset and is absent from a mapped
        # image. Clear it rather than preserving a dangling pointer.
        directories = {int(item["index"]): item for item in layout.get("directories", [])}
        security = directories.get(4)
        security_cleared = False
        if security and int(security.get("offset") or 0) + 8 <= len(image):
            struct.pack_into("<II", image, int(security["offset"]), 0, 0)
            security_cleared = True
        checksum_offset = int(layout.get("checksumOffset") or 0)
        if checksum_offset and checksum_offset + 4 <= len(image):
            struct.pack_into("<I", image, checksum_offset, 0)
        verification: Dict[str, Any] = {
            "ok": True,
            "structural": True,
            "architecture": layout["architecture"],
            "sectionCount": len(section_results),
        }
        if verify:
            try:
                if pefile is None:
                    raise RuntimeError("pefile is unavailable")
                parsed = pefile.PE(data=bytes(image), fast_load=False)
                verification.update(
                    entryRva=f"0x{int(parsed.OPTIONAL_HEADER.AddressOfEntryPoint):X}",
                    sizeOfImage=int(parsed.OPTIONAL_HEADER.SizeOfImage),
                    parsedSections=len(parsed.sections),
                )
            except Exception as exc:
                verification = {"ok": False, "structural": False, "error": str(exc)}
        reloadable = bool(
            verification.get("ok")
            and (
                not relocations.get("required")
                or bool(relocations.get("complete"))
                or not reverse_relocations
            )
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + f".tmp-{os.getpid()}-{time.time_ns()}")
        try:
            with temporary.open("xb") as handle:
                handle.write(image)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        except Exception as exc:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            return {"ok": False, "errorCode": "PE_WRITE_FAILED", "error": str(exc)}
        digest = hashlib.sha256(image).hexdigest().upper()
        return {
            "ok": bool(verification.get("ok")),
            "schema": "memory-pe-reconstruction-v1",
            "path": str(target),
            "exists": target.exists(),
            "sizeOnDisk": target.stat().st_size,
            "sha256": digest,
            "base": f"0x{runtime_base:X}",
            "preferredImageBase": f"0x{int(layout.get('imageBase') or 0):X}",
            "sourceMode": source_mode,
            "sourceLayout": source_layout_evidence,
            "templateIdentity": template_identity,
            "architecture": layout["architecture"],
            "entryRva": f"0x{int(layout.get('entryRva') or 0):X}",
            "sizeOfImage": memory_image_size,
            "sections": section_results,
            "relocations": relocations,
            "securityDirectoryCleared": security_cleared,
            "verification": verification,
            "reloadable": reloadable,
            "diagnostics": []
            if reloadable
            else [
                "The structural dump was written, but relocation reversal is incomplete; use the raw/structured evidence for manual repair."
            ],
        }

    @mcp.tool()
    def InspectProcessPayload(
        minimum_code_similarity: float = 0.70,
        scan_candidates: bool = True,
        max_candidates: int = 128,
    ) -> dict:
        """
        Compare the attached process image in memory with its on-disk identity
        and select a likely hollowed/manual child payload using PID-bound
        module, memory-map, PE-header and immutable-code evidence.
        """

        state = GetDebugStateLean()
        pid = int(state.get("pid") or state.get("debuggeePid") or 0)
        if not pid:
            return {
                "ok": False,
                "errorCode": "NO_DEBUG_SESSION",
                "error": "InspectProcessPayload requires an attached debuggee",
            }
        main_module = _resolve_main_module()
        if not isinstance(main_module, dict):
            return {
                "ok": False,
                "errorCode": "MAIN_MODULE_UNAVAILABLE",
                "error": "The debugger did not expose a main module",
                "pid": pid,
            }
        runtime_base = _memory_int(main_module.get("base"))
        module_size = _memory_int(main_module.get("size"))
        disk_path_text = str(
            main_module.get("path") or state.get("debuggeePath") or ""
        ).strip()
        disk_path = Path(disk_path_text) if disk_path_text else None
        if not runtime_base or disk_path is None or not disk_path.is_file():
            return {
                "ok": False,
                "errorCode": "IMAGE_IDENTITY_UNAVAILABLE",
                "error": "A runtime module base and readable on-disk image are required",
                "pid": pid,
                "base": f"0x{runtime_base:X}" if runtime_base else None,
                "path": disk_path_text,
            }
        try:
            disk_data = disk_path.read_bytes()
            disk_layout = _parse_memory_pe_layout(disk_data)
            _validate_memory_pe_layout(disk_layout)
        except Exception as exc:
            return {
                "ok": False,
                "errorCode": "DISK_IMAGE_INVALID",
                "error": str(exc),
                "pid": pid,
                "path": str(disk_path),
            }
        runtime_header = b""
        runtime_layout: Optional[Dict[str, Any]] = None
        runtime_header_error = ""
        try:
            runtime_header = _read_memory_exact(runtime_base, 4096, 4096)
            runtime_layout = _parse_memory_pe_layout(runtime_header)
            _validate_memory_pe_layout(runtime_layout)
        except Exception as first_exc:
            try:
                runtime_header = _read_memory_exact(runtime_base, 65536, 65536)
                runtime_layout = _parse_memory_pe_layout(runtime_header)
                _validate_memory_pe_layout(runtime_layout)
            except Exception:
                runtime_header_error = str(first_exc)
                runtime_layout = None

        similarity_floor = max(0.50, min(float(minimum_code_similarity), 1.0))
        code_identity = _score_template_memory_identity(
            runtime_base,
            disk_data,
            disk_layout,
        )
        code_identity["minimumSimilarity"] = similarity_floor
        code_identity["matches"] = bool(
            int(code_identity.get("comparedBytes") or 0) >= 64
            and float(code_identity.get("similarity") or 0.0) >= similarity_floor
        )

        memory_region: Dict[str, Any] = {}
        try:
            memory_map = GetMemoryMap()
            for index, page in enumerate(_memory_map_pages(memory_map)):
                normalized = _normalize_memory_page(page, index)
                base_value = _memory_int(normalized.get("base"))
                size_value = int(normalized.get("size") or 0)
                if base_value <= runtime_base < base_value + size_value:
                    memory_region = normalized
                    break
        except Exception:
            memory_region = {}

        disk_section_signature = [
            {
                "name": section.get("name"),
                "rva": int(section.get("virtualAddress") or 0),
                "characteristics": int(section.get("characteristics") or 0),
            }
            for section in disk_layout.get("sections") or []
        ]
        runtime_section_signature = [
            {
                "name": section.get("name"),
                "rva": int(section.get("virtualAddress") or 0),
                "characteristics": int(section.get("characteristics") or 0),
            }
            for section in (runtime_layout or {}).get("sections") or []
        ]
        layout_comparison = {
            "runtimeHeadersAvailable": runtime_layout is not None,
            "runtimeHeaderError": runtime_header_error or None,
            "architectureMatches": bool(
                runtime_layout
                and runtime_layout.get("architecture") == disk_layout.get("architecture")
            ),
            "machineMatches": bool(
                runtime_layout
                and int(runtime_layout.get("machine") or 0)
                == int(disk_layout.get("machine") or 0)
            ),
            "entryRvaMatches": bool(
                runtime_layout
                and int(runtime_layout.get("entryRva") or 0)
                == int(disk_layout.get("entryRva") or 0)
            ),
            "sizeOfImageMatches": bool(
                runtime_layout
                and int(runtime_layout.get("sizeOfImage") or 0)
                == int(disk_layout.get("sizeOfImage") or 0)
            ),
            "sectionsMatch": bool(
                runtime_layout and runtime_section_signature == disk_section_signature
            ),
            "disk": {
                "architecture": disk_layout.get("architecture"),
                "entryRva": f"0x{int(disk_layout.get('entryRva') or 0):X}",
                "sizeOfImage": int(disk_layout.get("sizeOfImage") or 0),
                "sections": disk_section_signature,
            },
            "runtime": {
                "architecture": (runtime_layout or {}).get("architecture"),
                "entryRva": (
                    f"0x{int((runtime_layout or {}).get('entryRva') or 0):X}"
                    if runtime_layout
                    else None
                ),
                "sizeOfImage": int((runtime_layout or {}).get("sizeOfImage") or 0),
                "sections": runtime_section_signature,
            },
        }
        disk_header_size = min(
            len(disk_data), max(512, int(disk_layout.get("sizeOfHeaders") or 0))
        )
        header_identity = {
            "diskSha256": hashlib.sha256(
                disk_data[:disk_header_size]
            ).hexdigest().upper(),
            "runtimeSha256": (
                hashlib.sha256(runtime_header[:disk_header_size]).hexdigest().upper()
                if len(runtime_header) >= disk_header_size
                else None
            ),
        }
        header_identity["matches"] = bool(
            header_identity["runtimeSha256"]
            and header_identity["runtimeSha256"] == header_identity["diskSha256"]
        )

        classification = _classify_process_payload_evidence(
            runtime_headers_available=runtime_layout is not None,
            layout_comparison=layout_comparison,
            code_compared_bytes=int(code_identity.get("comparedBytes") or 0),
            code_matches=bool(code_identity.get("matches")),
            main_region_private=bool(memory_region.get("private")),
            header_matches=bool(header_identity.get("matches")),
        )
        strong_signals = list(classification["signals"])

        scan: Dict[str, Any] = {"ok": True, "skipped": True, "candidates": []}
        if scan_candidates:
            scan = ScanMemoryForPEImages(
                max_regions=8192,
                max_candidates=max(1, min(int(max_candidates), 1024)),
                # Hollowed main images begin at an allocation base.  A 4 KiB
                # header pass keeps child-follow latency bounded; reflective
                # staging scans remain available through ScanMemoryForPEImages.
                header_bytes=4096,
                include_embedded=False,
            )
        candidates = [
            item for item in scan.get("candidates", []) if isinstance(item, dict)
        ]
        ranked_candidates: List[Dict[str, Any]] = []
        for candidate in candidates:
            candidate_base = _memory_int(candidate.get("base"))
            score = 0
            reasons: List[str] = []
            if candidate_base == runtime_base:
                score += 100
                reasons.append("main-runtime-base")
            if candidate.get("manualMapCandidate"):
                score += 30
                reasons.append("manual-map-provenance")
            if (candidate.get("provenance") or {}).get("private"):
                score += 25
                reasons.append("private-memory")
            if candidate.get("imageKind") == "embedded-reflective":
                score += 10
                reasons.append("embedded-reflective")
            ranked_candidates.append({**candidate, "payloadScore": score, "selectionReasons": reasons})
        ranked_candidates.sort(
            key=lambda item: (
                int(item.get("payloadScore") or 0),
                -_memory_int(item.get("base")),
            ),
            reverse=True,
        )
        selected = ranked_candidates[0] if ranked_candidates else None
        ambiguous = bool(
            len(ranked_candidates) > 1
            and int(ranked_candidates[0].get("payloadScore") or 0)
            == int(ranked_candidates[1].get("payloadScore") or 0)
        )
        likely_hollowed = bool(classification["likelyHollowed"])
        confidence = str(classification["confidence"])
        return {
            "ok": True,
            "schema": "process-payload-identity-v1",
            "pid": pid,
            "mainModule": {
                "name": main_module.get("name"),
                "path": str(disk_path),
                "fileSha256": hashlib.sha256(disk_data).hexdigest().upper(),
                "runtimeBase": f"0x{runtime_base:X}",
                "moduleSize": module_size,
                "memoryRegion": memory_region,
            },
            "headerIdentity": header_identity,
            "layout": layout_comparison,
            "codeIdentity": code_identity,
            "signals": strong_signals,
            "likelyHollowed": likely_hollowed,
            "confidence": confidence,
            "selection": {
                "selected": selected,
                "ambiguous": ambiguous,
                "candidateCount": len(ranked_candidates),
                "candidates": ranked_candidates[:16],
            },
            "scan": {
                "ok": scan.get("ok"),
                "schema": scan.get("schema"),
                "candidateCount": scan.get("candidateCount", len(candidates)),
                "readFailureCount": scan.get("readFailureCount"),
                "truncated": scan.get("truncated"),
            },
        }

    @mcp.tool()
    def DumpModule(
        module: str = "",
        output_path: str = "",
        find_oep: bool = True,
        timeout_ms: int = 30000,
        fix_imports: bool = True,
        verify: bool = True,
        overwrite: bool = False,
        keep_raw_dump: bool = False,
        advanced_iat_search: bool = False,
        create_new_iat: bool = False,
        iat_start: str = "",
        iat_size: int = 0,
        module_strategy: str = "auto",
        timeline_path: str = "",
    ) -> dict:
        """
        Produce a VERIFIED unpacked dump of a module to disk. With find_oep=True
        (default) this drives the packer-agnostic OEP engine (FindOEP) — which
        works for the unpack-in-memory-then-jump class (UPX, ASPack, FSG, MPRESS,
        PECompact, Petite, simple crypters) — then dumps via Scylla and VERIFIES
        the result before reporting ok: the entry must have moved out of the
        packer stub to the real OEP, the IAT must resolve cleanly (no garbage
        descriptors), and the imports must be non-trivial. A dump that merely
        landed on disk is NOT a success. On failure it returns ok:false with a
        reason and keeps the raw memory dump for manual recovery. Virtualizing
        protectors have no generic recoverable OEP contract here and are reported
        honestly (isLikelyVirtualized), never faked. The optional virtualization
        research backend is disabled in this build.

        find_oep=False dumps the selected loaded module at the current/module
        entry. It still performs independent PE/IAT verification by default and
        never treats mere file creation as success.

        Args:
            module: Module name to dump (e.g. "target.exe"). Empty = the main
                    debuggee module.
            output_path: Destination path for the dumped file. Empty = a default
                         path derived from the module.
            find_oep: When True (default) find + verify the OEP before dumping;
                      when False dump from the current state (no verification).
            timeout_ms: Budget for OEP discovery (default 30000).
            fix_imports: Reconstruct imports with Scylla (default true).
            verify: Require independent PE/IAT verification (default true).
            overwrite: Explicitly authorize replacing dump artifacts.
            keep_raw_dump: Preserve Scylla's pre-IAT raw image.
            iat_start/iat_size: Optional exact live IAT range; both are required together.
            module_strategy: auto, overlay, or scylla. Auto uses a reloadable
                source-backed executable overlay for non-main DLLs.
            timeline_path: Optional `unpack-workflow-v1` JSON path. When OEP
                discovery is enabled and omitted, `<output>.workflow.json` is
                written automatically.

        Returns:
            {"ok": bool, "verified": bool, "path": str, "exists": bool, "size": int,
             "module": str, "findOep": bool, "oep"?: str, "confidence"?: str,
             "reason"?: str, "isLikelyVirtualized"?: bool, "rawDumpPath"?: str,
             "result": ..., "hint"?: str}.
        """
        if not callable(FindOEP):
            return {"ok": False, "error": "FindOEP is not available"}
        if not callable(_scylla_dump_module):
            return {"ok": False, "error": "Native Scylla dump helper is not available"}
        state = GetDebugStateLean()
        recovery: Optional[Dict[str, Any]] = None
        if not bool(state.get("pid")):
            recovery = _recover_fast_target_debug_session(timeout_ms=timeout_ms)
            if not isinstance(recovery, dict) or not recovery.get("ok"):
                return {
                    "ok": False,
                    "error": "DumpModule requires an active debug session",
                    "hint": (
                        recovery.get("hint")
                        if isinstance(recovery, dict)
                        else "The target exited before a stable debug session was available."
                    ),
                    "recovery": recovery,
                }
            state = (
                recovery.get("state")
                if isinstance(recovery.get("state"), dict)
                else GetDebugStateLean()
            )
        main_module = _resolve_main_module()
        if not main_module:
            return {
                "ok": False,
                "error": "Could not resolve the main module",
                "recovery": recovery,
            }
        target_module = _resolve_module_by_name(module) if module else main_module
        if not target_module:
            return {"ok": False, "error": f"Could not resolve module {module!r}"}
        main_tokens = _module_match_tokens(main_module.get("name") or main_module.get("path") or "")
        target_tokens = _module_match_tokens(
            target_module.get("name") or target_module.get("path") or ""
        )
        if find_oep and module and not (main_tokens & target_tokens):
            return {
                "ok": False,
                "error": "Automatic OEP discovery is supported only for the main debuggee module; use find_oep=false for another loaded module",
                "requestedModule": module,
                "mainModule": main_module.get("name"),
                "recovery": recovery,
            }
        dump_path = os.path.abspath(output_path or _default_dump_path(target_module))
        os.makedirs(os.path.dirname(dump_path), exist_ok=True)
        strategy = str(module_strategy or "auto").strip().lower()
        if strategy not in ("auto", "overlay", "scylla"):
            return {"ok": False, "error": "module_strategy must be auto, overlay, or scylla"}
        if os.path.exists(dump_path) and not overwrite:
            return {
                "ok": False,
                "error": "Dump output already exists; set overwrite=true to replace it",
                "path": dump_path,
            }
        is_main_module = bool(main_tokens & target_tokens)
        if (
            not find_oep
            and callable(DumpLoadedModule)
            and (strategy == "overlay" or (strategy == "auto" and not is_main_module))
        ):
            overlay_result = DumpLoadedModule(
                module=str(target_module.get("name") or module or ""),
                output_path=dump_path,
                overwrite=overwrite,
                verify=verify,
            )
            if isinstance(overlay_result, dict):
                overlay_result.setdefault("findOep", False)
                overlay_result.setdefault("moduleStrategy", "overlay")
                overlay_result.setdefault("recovery", recovery)
            return overlay_result
        if find_oep and overwrite:
            directory, filename = os.path.split(dump_path)
            stem, extension = os.path.splitext(filename)
            raw_candidate = os.path.join(directory, f"{stem}.raw{extension or '.bin'}")
            for candidate in (dump_path, raw_candidate):
                if os.path.exists(candidate):
                    try:
                        os.remove(candidate)
                    except OSError as exc:
                        return {
                            "ok": False,
                            "error": f"Failed to replace existing dump artifact: {exc}",
                            "path": candidate,
                        }
        explicit_iat_start = _normalize_hex(iat_start)
        try:
            explicit_iat_size = max(0, int(iat_size or 0))
        except (TypeError, ValueError):
            return {"ok": False, "error": "iat_size must be an integer"}
        if bool(explicit_iat_start) != bool(explicit_iat_size):
            return {
                "ok": False,
                "error": "iat_start and iat_size must be supplied together",
            }
        iat_source = "explicit" if explicit_iat_start else "scylla_search"
        source_path = str(target_module.get("path") or "")
        if (
            fix_imports
            and not find_oep
            and not explicit_iat_start
            and callable(_parse_pe_layout)
            and source_path
            and os.path.isfile(source_path)
        ):
            try:
                source_layout = _parse_pe_layout(source_path)
                source_iat = source_layout.get("iatDirectory") or {}
                evidence = (
                    _pe_import_evidence(source_layout)
                    if callable(_pe_import_evidence)
                    else {"functionCount": 0, "badDllNames": []}
                )
                iat_rva = _parse_int(source_iat.get("rva")) or 0
                iat_length = int(source_iat.get("size") or 0)
                runtime_base = _parse_int(target_module.get("base")) or 0
                if (
                    runtime_base
                    and iat_rva > 0
                    and iat_length > 0
                    and int(evidence.get("functionCount") or 0) > 0
                    and not evidence.get("badDllNames")
                ):
                    explicit_iat_start = f"0x{runtime_base + iat_rva:x}"
                    explicit_iat_size = iat_length
                    iat_source = "source_pe_directory"
            except Exception:
                pass
        early_dump_result = None
        # The fast-target early dump uses the on-disk entry (= packer stub) and is
        # only valid when the caller explicitly does NOT want OEP discovery.
        if (not find_oep) and recovery and state.get("debugging") and not state.get("paused"):
            early_entry = _normalize_hex(target_module.get("entry") or target_module.get("base"))
            if early_entry:
                early_dump_result = _scylla_dump_module(
                    target_module,
                    entrypoint=early_entry,
                    output_path=dump_path,
                    search_start=early_entry,
                    source_path=source_path,
                    keep_raw_dump=keep_raw_dump,
                    fix_imports=fix_imports,
                    advanced_search=advanced_iat_search,
                    create_new_iat=create_new_iat,
                    iat_start=explicit_iat_start or "",
                    iat_size=explicit_iat_size,
                    overwrite=overwrite,
                )
                if isinstance(early_dump_result, dict):
                    early_dump_result["strategy"] = "fast_target_relaunch"
                    early_dump_result["recoveredSession"] = True
                    early_dump_result["entrypointSource"] = "module_entry"
                if isinstance(early_dump_result, dict) and early_dump_result.get("ok") and os.path.exists(dump_path):
                    size = os.path.getsize(dump_path)
                    early_verification = (
                        VerifyPEDump(
                            dump_path,
                            source_path=source_path,
                            expected_entrypoint=early_entry,
                            module_base=str(target_module.get("base") or ""),
                            require_imports=True,
                            strict_source_imports=True,
                            check_dependencies=True,
                        )
                        if verify and callable(VerifyPEDump)
                        else None
                    )
                    early_verified = bool(
                        not verify
                        or (
                            isinstance(early_verification, dict)
                            and early_verification.get("verified")
                        )
                    )
                    return {
                        "ok": bool(_coerce_ok(early_dump_result) and early_verified),
                        "verified": early_verified if verify else None,
                        "path": dump_path,
                        "exists": True,
                        "size": size,
                        "module": str(target_module.get("name") or ""),
                        "findOep": bool(find_oep),
                        "commandSucceeded": _coerce_ok(early_dump_result),
                        "verification": early_verification,
                        "iatSource": iat_source,
                        "result": early_dump_result,
                        "recovery": recovery,
                        "hint": None,
                    }
        if not state.get("paused"):
            DebugPause()
            paused = WaitForPause(timeout_ms=5000, poll_ms=100)
            if not isinstance(paused, dict) or not paused.get("paused"):
                return {
                    "ok": False,
                    "error": "Failed to pause the debuggee before dumping",
                    "state": paused,
                    "recovery": recovery,
                    "earlyDumpAttempt": early_dump_result,
                    "hint": (
                        "The target appears to be short-lived. DumpModule re-launched it, "
                        "but it still exited before a stable pause."
                        if recovery
                        else None
                    ),
                }
            state = paused
        detailed_state = _build_debug_state_patched(
            include_console=True, include_callstack=True, max_console_chars=4000
        )
        if find_oep:
            # Go straight to the OEP engine, which finds the real OEP, dumps, and
            # VERIFIES before reporting ok. No stub-entry shortcut, and no
            # fall-back to the on-disk (packed) entry — that only produces broken
            # dumps and false "success".
            workflow_path = str(timeline_path or "").strip() or (
                dump_path + ".workflow.json"
            )
            dump_result = FindOEP(
                timeout_ms=timeout_ms,
                dump_to_path=dump_path,
                timeline_to_path=workflow_path,
            )
        else:
            entrypoint = _normalize_hex(state.get("rip"))
            module_at_rip = _module_for_addr(entrypoint or "")
            if not entrypoint or not module_at_rip or not (
                _module_match_tokens(module_at_rip.get("name") or module_at_rip.get("path") or "")
                & target_tokens
            ):
                entrypoint = _normalize_hex(
                    target_module.get("entry") or target_module.get("base")
                )
            dump_result = _scylla_dump_module(
                target_module,
                entrypoint=entrypoint or "",
                output_path=dump_path,
                search_start=entrypoint or "",
                source_path=source_path,
                keep_raw_dump=keep_raw_dump,
                fix_imports=fix_imports,
                advanced_search=advanced_iat_search,
                create_new_iat=create_new_iat,
                iat_start=explicit_iat_start or "",
                iat_size=explicit_iat_size,
                overwrite=overwrite,
            )
        exists = os.path.exists(dump_path)
        size = os.path.getsize(dump_path) if exists else 0
        if find_oep:
            # dump_result is FindOEP's envelope: its `ok` already reflects a
            # VERIFIED unpack (real OEP + resolved IAT + entry out of the packer
            # section). Do NOT treat a mere file-on-disk as success.
            fo = dump_result if isinstance(dump_result, dict) else {}
            verified = bool(fo.get("verified"))
            raw_dump = fo.get("rawDumpPath") or (fo.get("dumpResult") or {}).get("rawDumpPath")
            return {
                "ok": bool(fo.get("ok")) and verified,
                "verified": verified,
                "path": dump_path,
                "exists": exists,
                "size": size,
                "module": str(target_module.get("name") or ""),
                "findOep": True,
                "oep": fo.get("oepAddr"),
                "confidence": fo.get("confidence"),
                "reason": fo.get("reason"),
                "isLikelyVirtualized": bool(fo.get("isLikelyVirtualized")),
                "rawDumpPath": raw_dump,
                "status": fo.get("status"),
                "workflowId": fo.get("workflowId"),
                "timelineArtifact": fo.get("timelineArtifact"),
                "stages": fo.get("stages") or [],
                "artifacts": fo.get("artifacts") or [],
                "unsupported": fo.get("unsupported"),
                "commandSucceeded": _coerce_ok(fo.get("dumpResult") or fo),
                "result": dump_result,
                "recovery": recovery,
                "hint": None
                if verified
                else (
                    "OEP/unpack verification failed; the raw memory dump was kept for "
                    "manual recovery. Virtualizing-protector research is disabled; "
                    "use the raw dump for an explicitly reviewed manual workflow."
                ),
            }
        # find_oep=False: dump from the current/explicit entry (advanced, manual).
        command_succeeded = _coerce_ok(dump_result)
        manual_verification = (
            VerifyPEDump(
                dump_path,
                source_path=source_path,
                expected_entrypoint=entrypoint or "",
                module_base=str(target_module.get("base") or ""),
                require_imports=True,
                strict_source_imports=True,
                check_dependencies=True,
            )
            if verify and exists and callable(VerifyPEDump)
            else None
        )
        manual_verified = bool(
            not verify
            or (
                isinstance(manual_verification, dict)
                and manual_verification.get("verified")
            )
        )
        return {
            "ok": bool(exists and command_succeeded and manual_verified),
            "verified": manual_verified if verify else None,
            "path": dump_path,
            "exists": exists,
            "size": size,
            "module": str(target_module.get("name") or ""),
            "findOep": False,
            "commandSucceeded": command_succeeded,
            "result": dump_result,
            "verification": manual_verification,
            "iatSource": iat_source,
            "iatStart": explicit_iat_start or None,
            "iatSize": explicit_iat_size,
            "recovery": recovery,
            "hint": None
            if exists and manual_verified
            else (
                "The dump was kept, but independent PE/IAT verification rejected it."
                if exists
                else "No dump file was created on disk."
            ),
        }

    @mcp.tool()
    def ExportPatchedFile(output_path: str, module: str = "", verify: bool = True) -> dict:
        """
        Write a patched copy of a module's on-disk file, applying every byte patch
        made in the current x64dbg session. This turns in-debugger patches into a
        standalone patched executable (the classic final step of a crack/fix).

        Patches are read from GetPatchList; each runtime address is converted to a
        file offset via the module's PE section table (pefile), so the bytes land
        at the correct on-disk location regardless of ASLR.

        Args:
            output_path: Destination path for the patched file. Required. Parent
                         directories are created if missing.
            module: Module name whose patches to apply (e.g. "target.exe"). Empty
                    infers the module: if all patches belong to one module that one
                    is used, otherwise the main debuggee module. Specify explicitly
                    when patches span multiple modules.
            verify: When True (default), compare each patch's recorded original byte
                    against the source file and report mismatches. A mismatch usually
                    means the module base was resolved incorrectly; the byte is still
                    written but flagged so you can double-check.

        Returns:
            {"ok": bool, "output": str, "module": str, "sourcePath": str,
             "patchesApplied": int, "patchesTotal": int, "patchesForModule": int,
             "mismatches": [...], "skipped": [...], "hint"?: str, "error"?: str}
        """
        if pefile is None:
            return {"ok": False, "error": "pefile is not installed; run: pip install pefile"}
        if not callable(GetPatchList):
            return {"ok": False, "error": "GetPatchList is unavailable on the bridge"}
        output_path = str(output_path or "").strip()
        if not output_path:
            return {"ok": False, "error": "output_path is required"}

        def _coerce_byte(value: Any) -> Optional[int]:
            if value is None:
                return None
            if isinstance(value, int):
                return value & 0xFF
            text = str(value).strip()
            if not text:
                return None
            for base in (0, 16):
                try:
                    return int(text, base) & 0xFF
                except Exception:
                    continue
            return None

        def _module_for_name(name: str) -> Optional[Dict[str, Any]]:
            want = str(name or "").strip().lower()
            if not want:
                return None
            result = GetModuleList()
            modules = result.get("modules", []) if isinstance(result, dict) else []
            if not isinstance(modules, list):
                return None
            for mod in modules:
                if not isinstance(mod, dict):
                    continue
                mn = str(mod.get("name") or "").lower()
                mp = os.path.basename(str(mod.get("path") or "")).lower()
                if want in (mn, mp):
                    return mod
            for mod in modules:
                if isinstance(mod, dict) and want in str(mod.get("name") or "").lower():
                    return mod
            return None

        patch_payload = GetPatchList()
        if not isinstance(patch_payload, dict):
            return {"ok": False, "error": "Failed to read patch list", "raw": str(patch_payload)[:500]}
        patches = patch_payload.get("patches") or []
        if not isinstance(patches, list) or not patches:
            return {"ok": False, "error": "No patches in the current session", "patchesTotal": 0}

        module_name = str(module or "").strip()
        target_module: Optional[Dict[str, Any]] = None
        if module_name:
            target_module = _module_for_name(module_name)
        else:
            patch_modules = {
                str(p.get("module") or "").strip()
                for p in patches
                if isinstance(p, dict)
            }
            patch_modules.discard("")
            if len(patch_modules) == 1:
                module_name = next(iter(patch_modules))
                target_module = _module_for_name(module_name)
            if target_module is None:
                target_module = _resolve_main_module()
                module_name = str((target_module or {}).get("name") or module_name)
        if not target_module:
            return {
                "ok": False,
                "error": f"Could not resolve module '{module_name or '(main)'}'; pass module= explicitly",
            }

        base_hex = _normalize_hex(target_module.get("base") or "")
        try:
            module_base = int(base_hex, 0) if base_hex else 0
        except Exception:
            module_base = 0
        source_path = str(target_module.get("path") or "").strip()
        if not source_path or not os.path.exists(source_path):
            return {"ok": False, "error": f"Source file not found on disk: {source_path or '(unknown)'}"}
        if not module_base:
            return {"ok": False, "error": "Could not determine module base for RVA mapping"}

        try:
            pe = pefile.PE(source_path, fast_load=True)
        except Exception as exc:
            return {"ok": False, "error": f"pefile could not parse {source_path}: {exc}"}

        try:
            with open(source_path, "rb") as fh:
                data = bytearray(fh.read())

            filtered = [
                p
                for p in patches
                if isinstance(p, dict)
                and (not module_name or str(p.get("module") or "").strip().lower() == module_name.lower())
            ]
            applied = 0
            mismatches: List[Dict[str, Any]] = []
            skipped: List[Dict[str, Any]] = []
            for p in filtered:
                addr_hex = _normalize_hex(p.get("address"))
                try:
                    va = int(addr_hex, 0)
                except Exception:
                    skipped.append({"address": p.get("address"), "reason": "unparseable address"})
                    continue
                rva = va - module_base
                if rva < 0:
                    skipped.append({"address": addr_hex, "reason": "address below module base"})
                    continue
                try:
                    off = pe.get_offset_from_rva(rva)
                except Exception as exc:
                    skipped.append({"address": addr_hex, "reason": f"RVA not in any section: {exc}"})
                    continue
                new_byte = _coerce_byte(p.get("newByte"))
                if new_byte is None:
                    skipped.append({"address": addr_hex, "reason": "missing/invalid newByte"})
                    continue
                if off >= len(data):
                    skipped.append({"address": addr_hex, "reason": "file offset beyond EOF"})
                    continue
                old_byte = _coerce_byte(p.get("oldByte"))
                if verify and old_byte is not None and data[off] != old_byte:
                    mismatches.append(
                        {"address": addr_hex, "fileByte": data[off], "expectedOld": old_byte}
                    )
                data[off] = new_byte
                applied += 1
        finally:
            try:
                pe.close()
            except Exception:
                pass

        try:
            out_dir = os.path.dirname(os.path.abspath(output_path))
            if out_dir and not os.path.isdir(out_dir):
                os.makedirs(out_dir, exist_ok=True)
            with open(output_path, "wb") as fh:
                fh.write(bytes(data))
        except Exception as exc:
            return {"ok": False, "error": f"Failed to write {output_path}: {exc}"}

        _log_event(
            "export_patched_file",
            module=module_name,
            applied=applied,
            output=output_path,
        )
        return {
            "ok": applied > 0,
            "output": output_path,
            "module": module_name or str(target_module.get("name") or ""),
            "sourcePath": source_path,
            "patchesApplied": applied,
            "patchesTotal": len(patches),
            "patchesForModule": len(filtered),
            "mismatches": mismatches,
            "skipped": skipped,
            "hint": (
                "Some original bytes did not match the source file — the module base "
                "may be wrong; double-check GetModuleList."
            )
            if mismatches
            else None,
        }

    @mcp.tool()
    def ScanMemoryStrings(
        addr: str = "",
        size: int = 0,
        min_length: int = 4,
        encodings: str = "ascii,utf16",
        max_bytes: int = 4 * 1024 * 1024,
        max_hits: int = 500,
        chunk_size: int = 65536,
    ) -> dict:
        """
        Scan process memory for printable ASCII and/or UTF-16LE strings. Reads raw
        memory, so unlike SearchStrings (which only finds code-referenced `strref`
        strings in one module) it also surfaces strings in decrypted/unpacked heap
        or private buffers.

        Args:
            addr: Start address/expression of a single region to scan. Empty walks
                  the whole readable committed memory map.
            size: Size of the single region (required when addr is given).
            min_length: Minimum string length to report (default 4).
            encodings: Comma list of "ascii" and/or "utf16" (default both).
            max_bytes: Total byte budget across all regions (default 4 MiB).
            max_hits: Maximum strings to return (default 500).
            chunk_size: Read granularity in bytes (default 64 KiB).

        Returns:
            {"ok", "count", "strings": [{"addr","encoding","length","text"}],
             "scannedBytes", "regionsScanned", "truncated", "truncatedReason"?}.
            Requires an active debug session.
        """
        wanted = {e.strip().lower() for e in str(encodings or "").split(",") if e.strip()}
        if not wanted:
            wanted = {"ascii", "utf16"}
        min_len = max(1, int(min_length or 1))
        budget = max(0, int(max_bytes or 0))
        cap = max(1, int(max_hits or 1))
        chunk = max(4096, int(chunk_size or 65536))

        regions: List[Tuple[int, int]] = []
        if str(addr or "").strip():
            base = _normalize_hex(addr) or str(addr)
            try:
                base_i = int(base, 0)
            except Exception:
                return {"ok": False, "error": f"Could not parse addr: {addr}"}
            if int(size or 0) <= 0:
                return {"ok": False, "error": "size is required when addr is given"}
            regions.append((base_i, int(size)))
        else:
            if not callable(GetMemoryMap):
                return {"ok": False, "error": "GetMemoryMap is unavailable on the bridge"}
            mm = GetMemoryMap()
            pages = mm.get("pages", []) if isinstance(mm, dict) else []
            for p in pages if isinstance(pages, list) else []:
                if not isinstance(p, dict):
                    continue
                if "R" not in str(p.get("protect") or "").upper():
                    continue  # not readable
                try:
                    b = int(str(p.get("base")), 0)
                    s = int(str(p.get("size")), 0)
                except Exception:
                    continue
                if b and s > 0:
                    regions.append((b, s))

        ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)

        def _extract(buf: bytes, region_base: int, hits: List[Dict[str, Any]]) -> None:
            if "ascii" in wanted:
                for mobj in ascii_re.finditer(buf):
                    if len(hits) >= cap:
                        return
                    text = mobj.group().decode("ascii", "replace")
                    hits.append({
                        "addr": f"0x{region_base + mobj.start():x}",
                        "encoding": "ascii",
                        "length": len(text),
                        "text": text[:512],
                    })
            if "utf16" in wanted:
                for mobj in utf16_re.finditer(buf):
                    if len(hits) >= cap:
                        return
                    text = mobj.group()[::2].decode("ascii", "replace")
                    hits.append({
                        "addr": f"0x{region_base + mobj.start():x}",
                        "encoding": "utf16",
                        "length": len(text),
                        "text": text[:512],
                    })

        hits: List[Dict[str, Any]] = []
        scanned = 0
        regions_scanned = 0
        truncated = False
        reason = ""
        for (rb, rs) in regions:
            if len(hits) >= cap:
                truncated = True; reason = "max_hits reached"; break
            if scanned >= budget:
                truncated = True; reason = "max_bytes budget reached"; break
            regions_scanned += 1
            off = 0
            while off < rs:
                if scanned >= budget:
                    truncated = True; reason = "max_bytes budget reached"; break
                this = min(chunk, rs - off, budget - scanned)
                if this <= 0:
                    break
                r = ReadMemory(addr=f"0x{rb + off:x}", size=this, ty="hex")
                hexstr = r.get("hex") if isinstance(r, dict) else None
                if hexstr:
                    try:
                        buf = bytes.fromhex(hexstr)
                    except Exception:
                        buf = b""
                    if buf:
                        _extract(buf, rb + off, hits)
                        scanned += len(buf)
                off += this
                if len(hits) >= cap:
                    truncated = True; reason = "max_hits reached"; break

        result = {
            "ok": True,
            "count": len(hits),
            "strings": hits[:cap],
            "scannedBytes": scanned,
            "regionsScanned": regions_scanned,
            "truncated": truncated,
        }
        if truncated:
            result["truncatedReason"] = reason
            _log_event("scan_memory_strings_truncated", reason=reason, scanned=scanned, hits=len(hits))
        return result

    # Expose tools to the main module's globals so the CLI registry
    # (_get_mcp_tools_registry) can see them. Rewrite __module__ so the
    # registry filter accepts the callables.
    main_module_name = g.get("__name__", "x64dbg")
    exported = [
        GetDebugStateLean,
        GetSessionBinding,
        BindSessionTarget,
        ClearSessionBinding,
        EnsureReady,
        SearchStrings,
        DisasmFunction,
        DisasmRange,
        ReadMemoryBatch,
        GetImports,
        InspectRuntimeIAT,
        FindIATCandidates,
        ValidateIAT,
        FixDumpImports,
        ValidateDump,
        DumpOnEvent,
        GetExports,
        GetFunctionArgs,
        CaptureStopContextStructured,
        WaitForBreakpointCaptureStructured,
        BatchBreakpointsCapture,
        WaitForModuleLoad,
        FollowChildProcess,
        ExportCapabilityMap,
        RunUntilModuleLoad,
        RunUntilOEP,
        RunToUserCode,
        RunUntil,
        GetFunctionInfo,
        SetExceptionFilter,
        TraceApiCalls,
        TraceInstructionTape,
        Checkpoint,
        Rewind,
        DumpMemoryMapManifest,
        ScanMemoryForPEImages,
        DumpModuleRaw,
        DumpPeFromMemory,
        InspectProcessPayload,
        DumpModule,
        ExportPatchedFile,
        ScanMemoryStrings,
    ]
    for fn in exported:
        try:
            fn.__module__ = main_module_name
        except Exception:
            pass
        g[fn.__name__] = fn

    _log_event("ext_tools_loaded", count=len(exported))
