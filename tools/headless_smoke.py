import argparse
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import traceback
from datetime import datetime, timezone


def load_bridge(path: str):
    spec = importlib.util.spec_from_file_location("x64dbg_bridge", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load bridge module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _memory_write_ok(result) -> bool:
    if isinstance(result, dict):
        return bool(result.get("ok")) and bool(result.get("verified", True))
    return isinstance(result, str) and "success" in result.lower()


def _arch_gate(mod, exe_path: str) -> dict | None:
    active_info = getattr(mod, "_get_active_debugger_info", lambda: {})()
    target_info = mod.AnalyzeExecutablePacking(exe_path)
    active_arch = str((active_info or {}).get("arch") or "").lower()
    target_arch = str((target_info or {}).get("arch") or "").lower()
    if active_arch in ("x86", "x64") and target_arch in ("x86", "x64") and active_arch != target_arch:
        return {
            "ok": False,
            "skipped": True,
            "reason": f"Active debugger arch is {active_arch}, but target arch is {target_arch}",
            "activeDebugger": active_info,
            "target": target_info,
        }
    return None


def _smoke_files_dir() -> Path:
    """Directory holding the crackme corpus used by smoke scenarios.

    Override with the ``X64DBG_MCP_SMOKE_DIR`` environment variable so the
    scenarios are runnable on any machine (default keeps the historical
    ``C:\\test-files`` layout)."""
    return Path(os.environ.get("X64DBG_MCP_SMOKE_DIR", r"C:\test-files"))


def _smoke_file(name: str) -> str:
    return str(_smoke_files_dir() / name)


def _x64dbg_root() -> Path:
    return Path(os.environ.get("X64DBG_ROOT", r"C:\x64dbg"))


def _system_exe(name: str) -> str:
    windir = os.environ.get("SystemRoot", r"C:\Windows")
    return str(Path(windir) / "System32" / name)


def _default_exe_for_scenario(mod, scenario: str) -> str | None:
    active_info = getattr(mod, "_get_active_debugger_info", lambda: {})() or {}
    active_arch = str((active_info or {}).get("arch") or "").lower()
    notepad = _system_exe("notepad.exe")
    crackme_v1 = _smoke_file("CRACKMEV1.exe")
    easy_crackme = _smoke_file("Easy_CrackMe.exe")
    defaults = {
        "gui_easy_crackme": easy_crackme,
        "gui_seawolf": crackme_v1,
        "console_cmd": _system_exe("cmd.exe"),
        "console_crackme": _smoke_file("crackme.exe"),
        "packer_triage": _smoke_file("crack.exe"),
        "uia_easy_crackme": easy_crackme,
        "raw_input_easy_crackme": easy_crackme,
        "raw_visual_notepad": notepad,
    }
    # Scenarios that just need "some valid target of the active arch".
    generic_arch_scenarios = {
        "re_context",
        "plugin_status",
        "self_check",
        "decoder_suite",
        "trace_summary",
        "health_benchmark",
        "symbolic_bridge",
    }
    if scenario in generic_arch_scenarios:
        return notepad if active_arch == "x64" else crackme_v1
    if scenario == "scyllahide_auto":
        scylla = _x64dbg_root() / "ScyllaHide"
        return str(scylla / ("ScyllaTest_x64.exe" if active_arch == "x64" else "ScyllaTest_x86.exe"))
    if scenario == "memory_watchpoint":
        return _ensure_watch_target_exe(active_arch or "x64")
    if scenario == "dump_main":
        return _ensure_watch_target_exe(active_arch or "x64")
    if scenario == "api_trace_sleep":
        return _ensure_watch_target_exe(active_arch or "x64")
    if scenario == "checkpoint_rewind":
        return _ensure_watch_target_exe(active_arch or "x64")
    if scenario == "heap_trace_live":
        return r"C:\Windows\System32\notepad.exe"
    return defaults.get(scenario)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _find_vsdevcmd() -> Path:
    common_candidates = [
        Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"),
        Path(r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"),
    ]
    for candidate in common_candidates:
        if candidate.exists():
            return candidate
    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.exists():
        raise RuntimeError(f"vswhere not found: {vswhere}")
    completed = subprocess.run(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-find",
            r"**\VsDevCmd.bat",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    lines = [line.strip().strip('"') for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("Could not locate VsDevCmd.bat")
    return Path(lines[0])


def _ensure_watch_target_exe(active_arch: str) -> str:
    arch = "x64" if str(active_arch or "").lower() == "x64" else "x86"
    repo_root = _repo_root()
    source = repo_root / "tools" / "watch_target.c"
    out_dir = repo_root / "tools" / "bin"
    out_dir.mkdir(parents=True, exist_ok=True)
    exe_path = out_dir / f"watch_target_{arch}.exe"
    if exe_path.exists() and exe_path.stat().st_mtime >= source.stat().st_mtime:
        return str(exe_path)
    vsdevcmd = _find_vsdevcmd()
    arch_arg = "x64" if arch == "x64" else "x86"
    cmd_exe = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
    stdout_log = out_dir / f"watch_target_{arch}.build.stdout.log"
    stderr_log = out_dir / f"watch_target_{arch}.build.stderr.log"
    wrapper_path = out_dir / f"build_watch_target_{arch}.cmd"
    wrapper_path.write_text(
        "\n".join(
            [
                "@echo off",
                f'call "{vsdevcmd}" -arch={arch_arg} >nul',
                "if errorlevel 1 exit /b %errorlevel%",
                f'cl /nologo /O2 /TC /D_CRT_SECURE_NO_WARNINGS /Fo".\\\\" /Fe:"{exe_path.name}" "{source}" /link user32.lib kernel32.lib',
            ]
        ),
        encoding="utf-8",
    )
    with open(stdout_log, "w", encoding="utf-8", errors="replace") as stdout_handle, open(
        stderr_log, "w", encoding="utf-8", errors="replace"
    ) as stderr_handle:
        completed = subprocess.run(
            [cmd_exe, "/d", "/c", str(wrapper_path)],
            cwd=str(out_dir),
            stdin=subprocess.DEVNULL,
            stdout=stdout_handle,
            stderr=stderr_handle,
            check=False,
        )
    if completed.returncode != 0 or not exe_path.exists():
        stdout_text = stdout_log.read_text(encoding="utf-8", errors="replace") if stdout_log.exists() else ""
        stderr_text = stderr_log.read_text(encoding="utf-8", errors="replace") if stderr_log.exists() else ""
        raise RuntimeError(f"Failed to build watch_target_{arch}: {stdout_text}\n{stderr_text}")
    return str(exe_path)


def _pack_ptr(value: int, arch: str) -> bytes:
    return struct.pack("<Q" if arch == "x64" else "<I", int(value))


def _resolve_target_module(mod, exe_path: str, modules: dict | None = None) -> dict:
    payload = modules if isinstance(modules, dict) else mod.GetModuleList()
    items = payload.get("modules", []) if isinstance(payload, dict) else []
    image_name = Path(exe_path).name.lower()
    target = next(
        (
            item
            for item in items
            if str((item or {}).get("name") or "").lower() == image_name
        ),
        {},
    )
    if not target and items:
        target = items[0]
    return target if isinstance(target, dict) else {}


def _is_hex_address(value: str | None) -> bool:
    text = str(value or "").strip()
    if not text.lower().startswith("0x"):
        return False
    try:
        return int(text, 0) > 0
    except Exception:
        return False


def _extract_instruction_items(payload) -> list[dict]:
    if isinstance(payload, dict):
        items = payload.get("instructions")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        if any(key in payload for key in ("address", "instruction", "size")):
            return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _find_watch_buffer_address(mod, exe_path: str, modules: dict | None = None) -> tuple[str, dict]:
    payload = modules if isinstance(modules, dict) else mod.GetModuleList()
    target_module = _resolve_target_module(mod, exe_path, modules=payload)
    base = str(target_module.get("base") or "")
    size_decimal = (
        str(int(str(target_module.get("size") or "0"), 0))
        if target_module.get("size")
        else "0"
    )
    pattern = "57 41 54 43 48 30 30 31 AA BB CC DD 11 22 33 44"
    watch_addr = ""
    symbols = mod.QuerySymbols(str(target_module.get("name") or Path(exe_path).name), limit=2000)
    symbol_items = list((symbols or {}).get("symbols", [])) if isinstance(symbols, dict) else []
    watch_symbol = next(
        (
            item
            for item in symbol_items
            if str(item.get("name") or "").lower() == "g_watch_bytes"
        ),
        {},
    )
    if watch_symbol:
        try:
            watch_addr = hex(int(str(base), 0) + int(str(watch_symbol.get("rva") or "0"), 0))
        except Exception:
            watch_addr = ""
    if _is_hex_address(watch_addr):
        probe = mod.ReadMemory(addr=watch_addr, size=16, ty="hex", max_chars=0)
        if not bool((probe or {}).get("ok")):
            watch_addr = ""
    if not watch_addr:
        watch_addr = mod.PatternFindMem(base, size_decimal, pattern)
    if not (
        isinstance(watch_addr, str)
        and watch_addr.lower().startswith("0x")
        and watch_addr.lower() != "0xffffffffffffffff"
    ):
        module_read = mod.ReadMemory(base, int(size_decimal), ty="hex", max_chars=0)
        module_hex = str((module_read or {}).get("hex") or "")
        try:
            module_bytes = bytes.fromhex(module_hex)
            needle = bytes.fromhex(pattern)
            offset = module_bytes.find(needle)
            if offset >= 0:
                watch_addr = hex(int(str(base), 0) + int(offset))
        except ValueError:
            pass
    return watch_addr, {"modules": payload, "symbols": symbols, "targetModule": target_module}


def scenario_gui_easy_crackme(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    auto_result = mod.AutoRespondToDebuggeeGui(
        text="Ea5yR3versing",
        timeout_ms=8000,
        poll_ms=150,
        visible_only=True,
    )
    state = mod.GetDebugState(include_console=True, include_callstack=True, max_console_chars=1200)
    return {
        "init": init_result,
        "auto": auto_result,
        "state": state,
        "ok": bool(auto_result.get("ok")),
    }


def scenario_gui_seawolf(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    dismiss_result = mod.AutoRespondToDebuggeeGui(
        timeout_ms=12000,
        poll_ms=150,
        visible_only=True,
    )
    auto_result = mod.AutoRespondToDebuggeeGui(
        texts_json=json.dumps({"NAME": "alice", "SERIAL": "4E7036CE4063481"}),
        timeout_ms=12000,
        poll_ms=150,
        visible_only=True,
    )
    interaction = mod.AnalyzeDebuggeeInteraction(visible_only=True, max_depth=5, max_console_chars=1200)
    gui = mod.GetDebuggeeWindows(include_children=True, visible_only=True, max_depth=5)
    return {
        "init": init_result,
        "dismiss": dismiss_result,
        "auto": auto_result,
        "interaction": interaction,
        "gui": gui,
        "ok": bool(auto_result.get("ok")),
    }


def scenario_console_cmd(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    binding = init_result.get("binding") if isinstance(init_result, dict) else {}
    state = init_result.get("state") if isinstance(init_result, dict) else {}
    target_pid = int(
        ((binding or {}).get("pid") or (state or {}).get("debuggeePid") or 0) or 0
    )
    auto_result = mod.AutoRespondToDebuggeeConsole(
        text="echo codex_console_smoke",
        timeout_ms=10000,
        poll_ms=150,
        pid=target_pid,
        submit=True,
        probe_pause=True,
    )
    auto_state = auto_result.get("state") if isinstance(auto_result, dict) else {}
    send_result = auto_result.get("sendResult") if isinstance(auto_result, dict) else {}
    live_pid = int(
        (
            (send_result or {}).get("pid")
            or (auto_state or {}).get("debuggeePid")
            or target_pid
            or 0
        )
        or 0
    )
    console = mod.ReadDebuggeeConsole(pid=live_pid, max_chars=1200)
    exit_result = mod.AutoRespondToDebuggeeConsole(
        text="exit",
        timeout_ms=10000,
        poll_ms=150,
        pid=live_pid,
        submit=True,
        probe_pause=True,
    )
    wait_exit = mod.WaitForExit(timeout_ms=8000, poll_ms=100)
    state = mod.GetDebugState(include_console=False, include_callstack=False, max_console_chars=0)
    return {
        "init": init_result,
        "autoEcho": auto_result,
        "autoExit": exit_result,
        "waitExit": wait_exit,
        "state": state,
        "console": console,
        "ok": bool(auto_result.get("ok")) and bool(exit_result.get("ok")) and bool(wait_exit.get("exited")),
    }


def scenario_uia_easy_crackme(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    run_attempts = []
    window = {"ok": False}
    gui = {"summary": {}, "analysis": {}}
    for _ in range(8):
        run_attempts.append(mod.DebugRun())
        window = mod.WaitForDebuggeeWindow(title_contains="Easy CrackMe", timeout_ms=2000, poll_ms=100, visible_only=True)
        gui = mod.GetDebuggeeWindows(include_children=True, visible_only=True, max_depth=5)
        if window.get("ok"):
            break
        if (gui.get("analysis") or {}).get("hasEdit"):
            break
    pause_result = mod.DebugPause()
    wait_pause = mod.WaitForPause(timeout_ms=3000, poll_ms=100)
    uia = mod.GetDebuggeeUiAutomation(visible_only=True, max_depth=6)
    analysis = mod.AnalyzeDebuggeeUiAutomation(visible_only=True, max_depth=6)
    set_value = None
    read_back = None
    if ((analysis.get("analysis") or {}).get("suggestedValueHwnd")):
        target_hwnd = str((analysis.get("analysis") or {}).get("suggestedValueHwnd") or "")
        set_value = mod.SetUiAutomationValue("codex uia smoke", hwnd=target_hwnd)
        read_back = mod.ReadControlText(target_hwnd)
    input_history = mod.GetInputHistory(limit=10)
    interaction_history = mod.GetInteractionHistory(limit=20)
    return {
        "init": init_result,
        "runAttempts": run_attempts,
        "window": window,
        "gui": gui,
        "pauseResult": pause_result,
        "waitPause": wait_pause,
        "uia": uia,
        "analysis": analysis,
        "setValue": set_value,
        "readBack": read_back,
        "inputHistory": input_history,
        "interactionHistory": interaction_history,
        "ok": bool(window.get("ok"))
        and bool(wait_pause.get("paused"))
        and bool((uia.get("analysis") or {}).get("hasValueElement"))
        and bool((analysis.get("analysis") or {}).get("hasValueElement"))
        and bool(set_value and set_value.get("ok"))
        and bool(read_back and read_back.get("ok")),
    }


def scenario_raw_input_easy_crackme(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    run_attempts = []
    window = {"ok": False}
    gui = {"summary": {}, "analysis": {}}
    for _ in range(4):
        run_attempts.append(mod.DebugRun())
        window = mod.WaitForDebuggeeWindow(title_contains="Easy CrackMe", timeout_ms=2000, poll_ms=100, visible_only=True)
        gui = mod.GetDebuggeeWindows(include_children=True, visible_only=True, max_depth=5)
        if window.get("ok") and (gui.get("analysis") or {}).get("suggestedEditHwnd"):
            break
    ready = mod.WaitForDebuggeeWindowReady(title_contains="Easy CrackMe", timeout_ms=2500, poll_ms=80, visible_only=True)
    focus = mod.FocusDebuggeeWindow(timeout_ms=3000)
    edit_hwnd = str((gui.get("analysis") or {}).get("suggestedEditHwnd") or "")
    top_window = (window.get("window") or {}) if isinstance(window, dict) else {}
    top_rect = (top_window.get("rect") or {}) if isinstance(top_window, dict) else {}
    edit_node = next((item for item in gui.get("controls", []) if str(item.get("hwnd") or "") == edit_hwnd), {})
    edit_rect = (edit_node.get("rect") or {}) if isinstance(edit_node, dict) else {}
    click = None
    send = None
    read_back = None
    before_capture = None
    before_meta = None
    visual_change = None
    direct_compare = None
    if edit_hwnd and top_rect and edit_rect:
        rel_x = max(5, int(edit_rect.get("left", 0)) - int(top_rect.get("left", 0)) + 8)
        rel_y = max(5, int(edit_rect.get("top", 0)) - int(top_rect.get("top", 0)) + max(8, int(edit_rect.get("height", 0)) // 2))
        before_capture = mod.CaptureDebuggeeWindow(
            hwnd=str((top_window or {}).get("hwnd") or ""),
            client_only=True,
            focus_window=False,
            timeout_ms=1500,
        )
        before_meta = mod.GetWindowCapture(str((before_capture or {}).get("captureId") or ""))
        click = mod.ClickActiveWindow(x=rel_x, y=rel_y)
        send = mod.SendForegroundKeys(json.dumps(list("codexraw")), delay_ms=10)
        visual_change = mod.WaitForWindowVisualChange(
            hwnd=str((top_window or {}).get("hwnd") or ""),
            baseline_capture_id=str((before_capture or {}).get("captureId") or ""),
            client_only=True,
            focus_window=False,
            timeout_ms=3000,
            poll_ms=120,
            min_changed_pixels=64,
        )
        after_capture = (visual_change or {}).get("afterCapture") or {}
        if (before_capture or {}).get("captureId") and after_capture.get("captureId"):
            direct_compare = mod.CompareWindowCaptures(
                str((before_capture or {}).get("captureId") or ""),
                str(after_capture.get("captureId") or ""),
            )
        read_back = mod.ReadControlText(edit_hwnd)
    input_history = mod.GetInputHistory(limit=20)
    interaction_history = mod.GetInteractionHistory(limit=20)
    window_captures = mod.GetWindowCaptureHistory(limit=10)
    return {
        "init": init_result,
        "runAttempts": run_attempts,
        "window": window,
        "ready": ready,
        "gui": gui,
        "focus": focus,
        "beforeCapture": before_capture,
        "beforeMeta": before_meta,
        "click": click,
        "send": send,
        "visualChange": visual_change,
        "directCompare": direct_compare,
        "readBack": read_back,
        "inputHistory": input_history,
        "interactionHistory": interaction_history,
        "windowCaptures": window_captures,
        "ok": bool(window.get("ok"))
        and bool(ready.get("ok"))
        and bool(focus.get("ok"))
        and bool(before_capture and before_capture.get("ok"))
        and bool(before_meta and before_meta.get("ok"))
        and bool(click and click.get("ok"))
        and bool(send and send.get("ok"))
        and bool(visual_change and visual_change.get("ok"))
        and bool(direct_compare and direct_compare.get("ok") and direct_compare.get("hashChanged"))
        and bool(read_back and read_back.get("ok") and str(read_back.get("text") or "") == "codexraw"),
    }


def scenario_raw_visual_notepad(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    mod.ClearRuntimeHistory(clear_trace=True, clear_breakpoints=True)
    run_attempts = []
    window = {"ok": False}
    for _ in range(6):
        run_attempts.append(mod.DebugRun())
        window = mod.WaitForDebuggeeWindow(timeout_ms=2500, poll_ms=100, visible_only=True)
        if window.get("ok"):
            break
    ready = mod.WaitForDebuggeeWindowReady(timeout_ms=3000, poll_ms=80, visible_only=True)
    window_payload = (window or {}).get("window") or {}
    ready_payload = (ready or {}).get("window") or {}
    binding = init_result.get("binding") if isinstance(init_result, dict) else {}
    state = init_result.get("state") if isinstance(init_result, dict) else {}
    target_pid = int(
        (
            (window_payload or {}).get("pid")
            or (ready_payload or {}).get("pid")
            or (binding or {}).get("pid")
            or (state or {}).get("debuggeePid")
            or 0
        )
        or 0
    )
    focus = mod.FocusDebuggeeWindow(pid=target_pid, timeout_ms=3000)
    before = mod.CaptureDebuggeeWindow(
        pid=target_pid,
        client_only=True,
        focus_window=False,
        timeout_ms=2000,
    )
    before_meta = mod.GetWindowCapture(str((before or {}).get("captureId") or ""))
    click = mod.ClickDebuggeeWindow(
        pid=target_pid,
        x=120,
        y=120,
        client_only=True,
        focus_window=False,
    )
    raw_tokens = []
    for index in range(18):
        raw_tokens.extend(list(f"line{index:02d}"))
        raw_tokens.append("ENTER")
    send = mod.SendForegroundKeys(json.dumps(raw_tokens), delay_ms=6)
    scan_enter = mod.SendForegroundKeys(json.dumps(["ENTER"]), delay_ms=6, mode="scan")
    visual_change = mod.WaitForWindowVisualChange(
        pid=target_pid,
        baseline_capture_id=str((before or {}).get("captureId") or ""),
        client_only=True,
        focus_window=False,
        timeout_ms=4000,
        poll_ms=120,
        min_changed_pixels=64,
    )
    after_capture = (visual_change or {}).get("afterCapture") or {}
    direct_compare = None
    if (before or {}).get("captureId") and after_capture.get("captureId"):
        direct_compare = mod.CompareWindowCaptures(
            str((before or {}).get("captureId") or ""),
            str(after_capture.get("captureId") or ""),
        )
    drag = mod.DragDebuggeeWindow(
        pid=target_pid,
        start_x=120,
        start_y=120,
        end_x=260,
        end_y=120,
        client_only=True,
        focus_window=False,
        steps=18,
        step_delay_ms=8,
    )
    drag_change = mod.WaitForWindowVisualChange(
        pid=target_pid,
        baseline_capture_id=str((after_capture or {}).get("captureId") or ""),
        client_only=True,
        focus_window=False,
        timeout_ms=3000,
        poll_ms=120,
        min_changed_pixels=8,
    )
    drag_after = (drag_change or {}).get("afterCapture") or {}
    wheel = mod.ScrollDebuggeeWindow(
        pid=target_pid,
        delta=-360,
        x=180,
        y=180,
        client_only=True,
        focus_window=False,
        timeout_ms=2000,
    )
    wheel_change = mod.WaitForWindowVisualChange(
        pid=target_pid,
        baseline_capture_id=str((drag_after or {}).get("captureId") or ""),
        client_only=True,
        focus_window=False,
        timeout_ms=3000,
        poll_ms=120,
        min_changed_pixels=12,
    )
    captures = mod.GetWindowCaptureHistory(limit=12)
    inputs = mod.GetInputHistory(limit=20)
    interaction = mod.AnalyzeDebuggeeInteraction(visible_only=True, max_depth=5, max_console_chars=600)
    return {
        "init": init_result,
        "runAttempts": run_attempts,
        "window": window,
        "ready": ready,
        "focus": focus,
        "before": before,
        "beforeMeta": before_meta,
        "click": click,
        "send": send,
        "scanEnter": scan_enter,
        "visualChange": visual_change,
        "directCompare": direct_compare,
        "drag": drag,
        "dragChange": drag_change,
        "wheel": wheel,
        "wheelChange": wheel_change,
        "windowCaptures": captures,
        "inputHistory": inputs,
        "interaction": interaction,
        "ok": bool(window.get("ok"))
        and bool(ready.get("ok"))
        and bool(focus.get("ok"))
        and bool(before.get("ok"))
        and bool(before_meta.get("ok"))
        and bool(click.get("ok"))
        and bool(send.get("ok"))
        and bool(scan_enter.get("ok"))
        and bool(visual_change.get("ok"))
        and bool(direct_compare and direct_compare.get("ok") and direct_compare.get("hashChanged"))
        and bool(drag.get("ok"))
        and bool(drag_change.get("ok"))
        and bool(wheel.get("ok"))
        and bool(wheel_change.get("ok")),
    }


def scenario_console_crackme(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    auto_result = mod.AutoRespondToDebuggeeConsole(
        text="-559038737",
        timeout_ms=12000,
        poll_ms=150,
        submit=True,
        probe_pause=True,
    )
    state = mod.GetDebugState(include_console=True, include_callstack=True, max_console_chars=1600)
    console = mod.ReadDebuggeeConsole(max_chars=1600)
    return {
        "init": init_result,
        "auto": auto_result,
        "state": state,
        "console": console,
        "ok": bool(auto_result.get("ok")),
    }


def scenario_packer_triage(mod, exe_path: str) -> dict:
    triage = mod.AnalyzeExecutablePacking(exe_path)
    return {
        "triage": triage,
        "ok": bool(triage.get("ok"))
        and bool(triage.get("entrySection"))
        and int(triage.get("sectionCount", 0)) >= 1
        and isinstance((triage.get("packerSignals") or []), list),
    }


def scenario_plugin_status(mod, exe_path: str) -> dict:
    status = mod.GetDebuggerPluginStatus(exe_path=exe_path, probe_commands=False)
    scy = status.get("scyllaHide", {}) if isinstance(status.get("scyllaHide"), dict) else {}
    return {
        "status": status,
        "ok": bool(status.get("ok"))
        and bool(scy.get("installed"))
        and bool(isinstance((scy.get("availableProfiles") or []), list) and len(scy.get("availableProfiles", [])) >= 2),
    }


def scenario_scyllahide_auto(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    analysis = mod.AnalyzeAntiDebugSurface(exe_path)
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="auto")
    if not init_result.get("ok"):
        return {"analysis": analysis, "init": init_result, "ok": False}
    status = mod.GetScyllaHideStatus(exe_path=exe_path)
    scylla = init_result.get("scyllaHide", {}) if isinstance(init_result.get("scyllaHide"), dict) else {}
    return {
        "analysis": analysis,
        "init": init_result,
        "status": status,
        "ok": bool(analysis.get("ok"))
        and bool(init_result.get("ok"))
        and bool(status.get("installed"))
        and bool((status.get("hookInjected") or scylla.get("skipped") or scylla.get("ok")))
        and bool((scylla.get("ok") or scylla.get("skipped") is True)),
    }


def scenario_re_context(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    mod.ClearRuntimeHistory(clear_trace=True, clear_breakpoints=True)
    mod.DebugPause()
    pause_state = mod.WaitForPause(timeout_ms=6000, poll_ms=100)
    modules = mod.GetModuleList()
    image_name = Path(exe_path).name.lower()
    target_module = next((item for item in modules.get("modules", []) if str(item.get("name", "")).lower() == image_name), {})
    if not target_module and modules.get("modules"):
        target_module = modules.get("modules", [])[0]
    module_expr = str(target_module.get("name") or image_name)
    entry = target_module.get("entry", "")
    base = target_module.get("base", "")
    try:
        base_int = int(str(base), 0)
    except Exception:
        base_int = 0
    is_64 = base_int > 0xFFFFFFFF
    ip_reg = "rip" if is_64 else "eip"
    sp_reg = "rsp" if is_64 else "esp"
    bp_reg = "rbp" if is_64 else "ebp"
    general_regs = [ip_reg, sp_reg, bp_reg, "rax", "rbx", "rcx", "rdx", "r8", "r9", "r10"] if is_64 else [ip_reg, sp_reg, bp_reg, "eax", "ebx", "ecx", "edx", "esi", "edi"]
    exprs = (
        [ip_reg, sp_reg, bp_reg, f"[{sp_reg}]", f"[{sp_reg}+8]", f"[{sp_reg}+0x10]", f"[{sp_reg}+0x18]"]
        if is_64
        else [ip_reg, sp_reg, bp_reg, f"[{sp_reg}]", f"[{sp_reg}+4]", f"[{sp_reg}+8]", f"[{sp_reg}+0xc]"]
    )
    stack_specs = (
        [
            {"label": "slot0", "expr": sp_reg, "size": 8, "format": "u64"},
            {"label": "slot1", "expr": f"{sp_reg}+8", "size": 8, "format": "u64"},
            {"label": "slot2", "expr": f"{sp_reg}+0x10", "size": 8, "format": "u64"},
            {"label": "slot3", "expr": f"{sp_reg}+0x18", "size": 8, "format": "u64"},
        ]
        if is_64
        else [
            {"label": "slot0", "expr": sp_reg, "size": 4, "format": "u32"},
            {"label": "slot1", "expr": f"{sp_reg}+4", "size": 4, "format": "u32"},
            {"label": "slot2", "expr": f"{sp_reg}+8", "size": 4, "format": "u32"},
            {"label": "slot3", "expr": f"{sp_reg}+0xc", "size": 4, "format": "u32"},
        ]
    )
    bp_capture = mod.SetBreakpointWithCapture(
        addr=entry,
        registers_json=json.dumps(general_regs),
        expressions_json=json.dumps(exprs),
        ranges_json=json.dumps([
            {"label": "ip_bytes", "expr": ip_reg, "size": 32, "format": "hex"},
            {"label": "stack_head", "expr": sp_reg, "size": 64 if is_64 else 32, "format": "bytes"},
            {"label": "entry_bytes", "expr": entry, "size": 32, "format": "hex"},
        ]),
        stack_slots_json=json.dumps(stack_specs),
        timeout_ms=10000,
        delete_after_hit=False,
        resume=True,
    )
    breakpoint_history = mod.GetBreakpointCaptureHistory(limit=8)
    memory_reads = {str(size): mod.ReadMemory(base, size, ty="hex", max_chars=0) for size in (16, 64, 256, 1024)}
    eval_batch = mod.EvalBatch(json.dumps([f"{module_expr}+0x0", f"{module_expr}+0x10", ip_reg, sp_reg, f"[{sp_reg}]", exprs[4], entry]))
    legacy_parse_native = mod.safe_get("Misc/ParseExpression", {"expression": exprs[4], "format": "json"}, log=False)
    legacy_parse_csp = mod.safe_get("Misc/ParseExpression", {"expression": "[csp+0x8]", "format": "json"}, log=False)
    tool_parse_native = mod.MiscParseExpression(exprs[4])
    tool_parse_csp = mod.MiscParseExpression("[csp+0x8]")
    disasm_range = mod.DisasmGetInstructionRange(entry, 3)
    disasm_items = _extract_instruction_items(disasm_range)
    step_disasm = mod.StepInWithDisasm()
    alloc = mod.MemoryRemoteAlloc("0x40")
    alloc_addr = str(alloc.get("address", "")) if isinstance(alloc, dict) else ""
    alloc_snapshot_before = None
    alloc_write = None
    alloc_read = None
    alloc_snapshot_after = None
    alloc_snapshot_diff = None
    alloc_free = None
    if alloc_addr:
        alloc_snapshot_before = mod.CaptureMemorySnapshot(json.dumps([{"label": "alloc", "expr": alloc_addr, "size": 7, "format": "bytes"}]), label="alloc_before")
        alloc_write = mod.MemoryWrite(alloc_addr, "41424300444546")
        alloc_read = mod.ReadMemory(alloc_addr, 7, ty="hex", max_chars=0)
        alloc_snapshot_after = mod.CaptureMemorySnapshot(json.dumps([{"label": "alloc", "expr": alloc_addr, "size": 7, "format": "bytes"}]), label="alloc_after")
        alloc_snapshot_diff = mod.CompareMemorySnapshots(str((alloc_snapshot_before or {}).get("snapshotId", "")), str((alloc_snapshot_after or {}).get("snapshotId", "")))
        alloc_free = mod.MemoryRemoteFree(alloc_addr)
    local = mod.ReadLocalBuffer(ptr=base, length=2, ty="utf8", max_bytes=8)
    frame = mod.ReadFrame(
        base_expr=sp_reg,
        slots_json=json.dumps(stack_specs),
        expressions_json=json.dumps(exprs[:4]),
        ranges_json=json.dumps([{"label": "frame_head", "expr": sp_reg, "size": 32 if is_64 else 16, "format": "hex"}]),
        registers_json=json.dumps(general_regs[:3]),
    )
    for _ in range(10):
        mod.StepWithSnapshot(
            step_kind="over",
            registers_json=json.dumps([ip_reg, sp_reg, "rax", "rcx"] if is_64 else [ip_reg, sp_reg, "eax", "ecx"]),
            expressions_json=json.dumps([f"[{sp_reg}]"]),
            ranges_json=json.dumps([{"label": "ip_bytes", "expr": ip_reg, "size": 16, "format": "hex"}]),
            stack_slots_json=json.dumps([{"label": "ret0", "expr": sp_reg, "size": 8 if is_64 else 4, "format": "u64" if is_64 else "u32"}]),
        )
    trace = mod.GetTraceHistory(limit=20)
    interaction_history = mod.GetInteractionHistory(limit=40)
    return {
        "init": init_result,
        "pause": pause_state,
        "modules": modules,
        "arch": "x64" if is_64 else "x86",
        "breakpointCapture": bp_capture,
        "breakpointHistory": breakpoint_history,
        "memoryReads": memory_reads,
        "evalBatch": eval_batch,
        "miscParseExpression": {
            "legacyNative": legacy_parse_native,
            "legacyCsp": legacy_parse_csp,
            "toolNative": tool_parse_native,
            "toolCsp": tool_parse_csp,
        },
        "disasmRange": disasm_range,
        "stepInWithDisasm": step_disasm,
        "allocRoundtrip": {
            "alloc": alloc,
            "snapshotBefore": alloc_snapshot_before,
            "write": alloc_write,
            "read": alloc_read,
            "snapshotAfter": alloc_snapshot_after,
            "snapshotDiff": alloc_snapshot_diff,
            "free": alloc_free,
        },
        "frame": frame,
        "trace": trace,
        "interactionHistory": interaction_history,
        "localBuffer": local,
        "ok": bool(bp_capture.get("ok"))
        and int(breakpoint_history.get("count", 0)) >= 1
        and bool((breakpoint_history.get("entries", [{}])[-1] or {}).get("eventSeq"))
        and all(bool(item.get("ok")) and bool(item.get("complete")) for item in memory_reads.values())
        and bool(eval_batch.get("ok"))
        and all(bool(item.get("success")) for item in eval_batch.get("items", []))
        and isinstance(legacy_parse_native, dict)
        and bool(legacy_parse_native.get("ok"))
        and bool(legacy_parse_native.get("value"))
        and isinstance(legacy_parse_csp, dict)
        and bool(legacy_parse_csp.get("ok"))
        and bool(legacy_parse_csp.get("value"))
        and isinstance(tool_parse_native, str)
        and str(tool_parse_native).lower().startswith("0x")
        and isinstance(tool_parse_csp, str)
        and str(tool_parse_csp).lower().startswith("0x")
        and len(disasm_items) >= 1
        and all(isinstance(item, dict) and item.get("instruction") for item in disasm_items)
        and isinstance(step_disasm, dict)
        and bool((step_disasm.get("instruction") or {}).get("instruction"))
        and bool(isinstance(alloc, dict) and alloc.get("address"))
        and _memory_write_ok(alloc_write)
        and bool(isinstance(alloc_read, dict) and alloc_read.get("ok") and alloc_read.get("complete"))
        and str((alloc_read or {}).get("hex", "")).lower().startswith("41424300444546")
        and bool(isinstance(alloc_snapshot_diff, dict) and alloc_snapshot_diff.get("ok"))
        and int(len((alloc_snapshot_diff or {}).get("changedRanges", []))) >= 1
        and bool(isinstance(alloc_free, dict) and alloc_free.get("success"))
        and bool(frame.get("ok"))
        and bool((frame.get("frameBase") or {}).get("success"))
        and len(frame.get("stackSlots", [])) >= 4
        and bool(local.get("ok"))
        and int(interaction_history.get("count", 0)) >= 5
        and int(trace.get("count", 0)) >= 10,
    }


def scenario_self_check(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    check = mod.RunBridgeSelfCheck(source_root=str(_repo_root()), include_hashes=True)
    drifts = list(check.get("drifts") or [])
    return {
        "init": init_result,
        "check": check,
        "ok": bool(init_result.get("ok"))
        and bool(check.get("ok"))
        and bool((check.get("signatures", {}).get("liveBridge") or {}).get("exists"))
        and bool((check.get("comparisons", {}).get("sourceVsLive") or {}).get("sameSha256"))
        and "live_cache_python_mismatch" not in drifts
        and "vendor_runtime_dp32_mismatch" not in drifts
        and "vendor_runtime_dp64_mismatch" not in drifts,
    }


def scenario_decoder_suite(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    mod.DebugPause()
    pause_state = mod.WaitForPause(timeout_ms=6000, poll_ms=100)
    active_arch = str((getattr(mod, "_get_active_debugger_info", lambda: {})() or {}).get("arch") or "x64").lower()
    ptr_size = 8 if active_arch == "x64" else 4
    alloc = mod.MemoryRemoteAlloc("0x400")
    base = int(str((alloc or {}).get("address") or "0"), 0) if isinstance(alloc, dict) and alloc.get("address") else 0
    if not base:
        return {"init": init_result, "pause": pause_state, "alloc": alloc, "ok": False}

    unicode_bytes = "Codex UTF16".encode("utf-16le")
    ansi_bytes = b"codex-ansi\x00"
    rust_bytes = b"rust-layout"
    cpp_bytes = b"cpp-layout"
    sockaddr_bytes = struct.pack("<H", 2) + struct.pack(">H", 31337) + bytes([127, 0, 0, 1]) + (b"\x00" * 8)
    rect_bytes = struct.pack("<iiii", 10, 20, 110, 220)
    target_dt = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    filetime_value = int((target_dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)
    filetime_bytes = struct.pack("<Q", filetime_value)

    unicode_buf_addr = base + 0x180
    ansi_buf_addr = base + 0x1C0
    rust_buf_addr = base + 0x200
    cpp_buf_addr = base + 0x240
    sockaddr_addr = base + 0x280
    rect_addr = base + 0x2C0
    filetime_addr = base + 0x300

    unicode_struct = (
        struct.pack("<HH", len(unicode_bytes), len(unicode_bytes) + 2)
        + (b"\x00" * 4 if ptr_size == 8 else b"")
        + _pack_ptr(unicode_buf_addr, active_arch)
    )
    ansi_struct = (
        struct.pack("<HH", len(ansi_bytes) - 1, len(ansi_bytes))
        + (b"\x00" * 4 if ptr_size == 8 else b"")
        + _pack_ptr(ansi_buf_addr, active_arch)
    )
    rust_struct = _pack_ptr(rust_buf_addr, active_arch) + _pack_ptr(len(rust_bytes), active_arch) + _pack_ptr(len(rust_bytes) + 8, active_arch)
    cpp_struct = _pack_ptr(cpp_buf_addr, active_arch) + _pack_ptr(len(cpp_bytes), active_arch) + _pack_ptr(len(cpp_bytes) + 8, active_arch)

    writes = [
        mod.MemoryWrite(hex(base + 0x00), unicode_struct.hex()),
        mod.MemoryWrite(hex(base + 0x30), ansi_struct.hex()),
        mod.MemoryWrite(hex(base + 0x60), rust_struct.hex()),
        mod.MemoryWrite(hex(base + 0x90), cpp_struct.hex()),
        mod.MemoryWrite(hex(unicode_buf_addr), unicode_bytes.hex()),
        mod.MemoryWrite(hex(ansi_buf_addr), ansi_bytes.hex()),
        mod.MemoryWrite(hex(rust_buf_addr), rust_bytes.hex()),
        mod.MemoryWrite(hex(cpp_buf_addr), cpp_bytes.hex()),
        mod.MemoryWrite(hex(sockaddr_addr), sockaddr_bytes.hex()),
        mod.MemoryWrite(hex(rect_addr), rect_bytes.hex()),
        mod.MemoryWrite(hex(filetime_addr), filetime_bytes.hex()),
    ]

    decoded_unicode = mod.DecodeStructuredValue("unicode_string", hex(base + 0x00), ty="utf16")
    decoded_ansi = mod.DecodeStructuredValue("ansi_string", hex(base + 0x30), ty="ascii")
    decoded_rust = mod.DecodeStructuredValue("rust_string", hex(base + 0x60), ty="utf8")
    decoded_cpp = mod.DecodeStructuredValue("cpp_string_simple", hex(base + 0x90), ty="utf8")
    decoded_sockaddr = mod.DecodeStructuredValue("sockaddr", hex(sockaddr_addr))
    decoded_rect = mod.DecodeStructuredValue("rect", hex(rect_addr))
    decoded_filetime = mod.DecodeStructuredValue("filetime", hex(filetime_addr))
    free_result = mod.MemoryRemoteFree(hex(base))

    return {
        "init": init_result,
        "pause": pause_state,
        "alloc": alloc,
        "writes": writes,
        "unicode": decoded_unicode,
        "ansi": decoded_ansi,
        "rust": decoded_rust,
        "cpp": decoded_cpp,
        "sockaddr": decoded_sockaddr,
        "rect": decoded_rect,
        "filetime": decoded_filetime,
        "free": free_result,
        "ok": bool(pause_state.get("paused"))
        and all(_memory_write_ok(item) for item in writes)
        and bool(decoded_unicode.get("ok"))
        and str(((decoded_unicode.get("buffer") or {}).get("text") or "")) == "Codex UTF16"
        and bool(decoded_ansi.get("ok"))
        and str(((decoded_ansi.get("buffer") or {}).get("text") or "")) == "codex-ansi"
        and bool(decoded_rust.get("ok"))
        and str(((decoded_rust.get("buffer") or {}).get("text") or "")) == "rust-layout"
        and bool(decoded_cpp.get("ok"))
        and str(((decoded_cpp.get("buffer") or {}).get("text") or "")) == "cpp-layout"
        and bool(decoded_sockaddr.get("ok"))
        and str(decoded_sockaddr.get("address") or "") == "127.0.0.1"
        and int(decoded_sockaddr.get("port") or 0) == 31337
        and bool(decoded_rect.get("ok"))
        and int(decoded_rect.get("width") or 0) == 100
        and int(decoded_rect.get("height") or 0) == 200
        and bool(decoded_filetime.get("ok"))
        and str(decoded_filetime.get("isoUtc") or "").startswith("2024-01-02T03:04:05")
        and bool(isinstance(free_result, dict) and free_result.get("success")),
    }


def scenario_trace_summary(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    mod.DebugPause()
    pause_state = mod.WaitForPause(timeout_ms=6000, poll_ms=100)
    active_arch = str((getattr(mod, "_get_active_debugger_info", lambda: {})() or {}).get("arch") or "x64").lower()
    ip_reg = "rip" if active_arch == "x64" else "eip"
    sp_reg = "rsp" if active_arch == "x64" else "esp"
    mod.ClearRuntimeHistory(clear_trace=True, clear_breakpoints=True)
    steps = []
    for _ in range(6):
        steps.append(
            mod.StepWithSnapshot(
                step_kind="over",
                registers_json=json.dumps([ip_reg, sp_reg, "rax" if active_arch == "x64" else "eax"]),
                expressions_json=json.dumps([f"[{sp_reg}]"]),
                ranges_json=json.dumps([{"label": "ip_bytes", "expr": ip_reg, "size": 16, "format": "hex"}]),
                stack_slots_json=json.dumps([{"label": "ret0", "expr": sp_reg, "size": 8 if active_arch == "x64" else 4, "format": "hex"}]),
            )
        )
    trace = mod.GetTraceHistory(limit=10)
    summary = mod.SummarizeTraceHistory(limit=10, include_breakpoints=True)
    return {
        "init": init_result,
        "pause": pause_state,
        "steps": steps,
        "trace": trace,
        "summary": summary,
        "ok": bool(pause_state.get("paused"))
        and int(trace.get("count", 0)) >= 6
        and bool(summary.get("ok"))
        and int((summary.get("summary") or {}).get("entryCount", 0)) >= 6
        and int((summary.get("summary") or {}).get("uniqueRipCount", 0)) >= 2
        and isinstance((summary.get("summary") or {}).get("registerChanges"), list),
    }


def scenario_health_benchmark(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    benchmark = mod.BenchmarkBridge(iterations=2, include_gui=True, include_uia=False)
    return {
        "init": init_result,
        "benchmark": benchmark,
        "ok": bool(init_result.get("ok"))
        and bool(benchmark.get("ok"))
        and int(len(benchmark.get("cases", []))) >= 4
        and all(float(case.get("avgMs", 0.0)) >= 0.0 for case in benchmark.get("cases", [])),
    }


def scenario_symbolic_bridge(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True)
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    modules = mod.GetModuleList()
    if not (isinstance(modules, dict) and modules.get("modules")):
        mod.DebugRun()
        mod.WaitForPause(timeout_ms=4000, poll_ms=100)
        modules = mod.GetModuleList()
    image_name = Path(exe_path).name.lower()
    target_module = next((item for item in modules.get("modules", []) if str(item.get("name", "")).lower() == image_name), {})
    if not target_module and modules.get("modules"):
        target_module = modules.get("modules", [])[0]
    module_name = str(target_module.get("name") or image_name)
    entry = int(str(target_module.get("entry") or "0"), 0)
    base = int(str(target_module.get("base") or "0"), 0)
    offset = max(0, entry - base)
    symbolic = f"{module_name}+0x{offset:X}"
    active_arch = str((getattr(mod, "_get_active_debugger_info", lambda: {})() or {}).get("arch") or "x64").lower()
    ip_reg = "rip" if active_arch == "x64" else "eip"
    sp_reg = "rsp" if active_arch == "x64" else "esp"
    result = mod.CaptureSymbolicBreakpoint(
        target=symbolic,
        registers_json=json.dumps([ip_reg, sp_reg]),
        expressions_json=json.dumps([f"[{sp_reg}]"]),
        ranges_json=json.dumps([{"label": "entry_bytes", "expr": symbolic, "size": 32, "format": "hex"}]),
        stack_slots_json=json.dumps([{"label": "ret0", "expr": sp_reg, "size": 8 if active_arch == "x64" else 4, "format": "hex"}]),
        timeout_ms=10000,
        delete_after_hit=True,
        resume=True,
        source="smoke",
        symbol_name="module_entry",
    )
    return {
        "init": init_result,
        "modules": modules,
        "symbolic": symbolic,
        "capture": result,
        "ok": bool(init_result.get("ok"))
        and bool(result.get("ok"))
        and str(result.get("resolvedAddr") or "").lower() == hex(entry).lower()
        and bool((result.get("capture") or {}).get("ok")),
    }


def scenario_memory_watchpoint(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    # Establish a deterministic paused user-code location before installing a
    # page watchpoint. Installing one while the x86 target is already running
    # races the fixture's only write and can produce a false negative.
    entry = mod.RunUntil(target="entry", timeout_ms=10000, poll_ms=100)
    run_attempts = [entry.get("runResult")] if isinstance(entry, dict) else []
    pause_state = (
        entry.get("state")
        if isinstance(entry, dict) and isinstance(entry.get("state"), dict)
        else {}
    )
    watch_addr, watch_meta = _find_watch_buffer_address(mod, exe_path)
    active_arch = str((getattr(mod, "_get_active_debugger_info", lambda: {})() or {}).get("arch") or "x64").lower()
    sp_reg = "rsp" if active_arch == "x64" else "esp"
    watch = mod.SetMemoryWatchpointWithCapture(
        addr=str(watch_addr),
        size=16,
        access_type="write",
        registers_json=json.dumps(["rip" if active_arch == "x64" else "eip", sp_reg, "rax" if active_arch == "x64" else "eax"]),
        expressions_json=json.dumps([f"[{sp_reg}]"]),
        ranges_json=json.dumps([{"label": "watched_range", "expr": str(watch_addr), "size": 16, "format": "hex"}]),
        stack_slots_json=json.dumps([{"label": "ret0", "expr": sp_reg, "size": 8 if active_arch == "x64" else 4, "format": "hex"}]),
        timeout_ms=12000,
        resume=True,
        delete_after_hit=True,
        singleshot=True,
    )
    wait_exit = mod.WaitForExit(timeout_ms=6000, poll_ms=100)
    return {
        "init": init_result,
        "entry": entry,
        "runAttempts": run_attempts,
        "pause": pause_state,
        "modules": watch_meta.get("modules"),
        "symbols": watch_meta.get("symbols"),
        "watchAddr": watch_addr,
        "watch": watch,
        "waitExit": wait_exit,
        "ok": bool(init_result.get("ok"))
        and bool(entry.get("ok"))
        and bool(pause_state.get("paused"))
        and isinstance(watch_addr, str)
        and str(watch_addr).lower().startswith("0x")
        and bool(watch.get("ok"))
        and bool((watch.get("causeInstruction") or {}).get("instruction"))
        and int(((watch.get("diff") or {}).get("changedRanges") or [{}])[0].get("changedCount", 0)) >= 1,
    }


def scenario_dump_main(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    entry = mod.RunUntil(target="entry", timeout_ms=8000, poll_ms=100)
    dump_dir = _repo_root() / "tools" / "dump_outputs"
    dump_dir.mkdir(parents=True, exist_ok=True)
    dump_path = dump_dir / f"{Path(exe_path).stem}.dump.exe"
    if dump_path.exists():
        dump_path.unlink()
    dump = mod.DumpModule(
        output_path=str(dump_path),
        find_oep=False,
        timeout_ms=25000,
    )
    return {
        "init": init_result,
        "entry": entry,
        "dump": dump,
        "dumpPath": str(dump_path),
        "ok": bool(entry.get("ok"))
        and bool(dump.get("ok"))
        and dump_path.exists()
        and dump_path.stat().st_size > 0,
    }


def scenario_unpack_verify(mod, exe_path: str) -> dict:
    """End-to-end unpack proof: OEP discovery -> Scylla dump -> VERIFY the dump
    actually runs. Point it at a packed sample via X64DBG_MCP_PACKED_EXE (falls
    back to exe_path). Set X64DBG_MCP_EXPECT_MARKER / X64DBG_MCP_EXPECT_EXIT for a
    strict output/exit-code assertion (otherwise "runs without a loader/crash
    code" is the pass condition). A dump that merely exists is NOT a pass."""
    import os as _os
    import subprocess as _sp

    packed = _os.environ.get("X64DBG_MCP_PACKED_EXE") or exe_path
    if not packed or not _os.path.exists(packed):
        return {"ok": False, "skipped": True,
                "reason": "no packed sample; set X64DBG_MCP_PACKED_EXE to a packed exe"}
    dump_dir = _repo_root() / "tools" / "dump_outputs"
    dump_dir.mkdir(parents=True, exist_ok=True)
    dump_path = dump_dir / f"{Path(packed).stem}.unpacked.exe"
    if dump_path.exists():
        dump_path.unlink()
    # Launch the target under the matching-arch debugger, advanced to its entry
    # (auto-detects x86/x64 from the PE), then run the OEP-driven verified dump.
    init_result = mod.LaunchFileUnderDebugger(
        exe_path=packed, arch="auto", restart_debugger=True, timeout_ms=45000,
        use_scyllahide="off", advance_to_entry=False,
    )
    dump = mod.DumpModule(output_path=str(dump_path), find_oep=True, timeout_ms=75000)

    run_info: dict = {"attempted": False}
    marker_ok = exit_ok = True
    if bool(dump.get("verified")) and dump_path.exists():
        expect_marker = _os.environ.get("X64DBG_MCP_EXPECT_MARKER")
        expect_exit = _os.environ.get("X64DBG_MCP_EXPECT_EXIT")
        try:
            proc = _sp.run(
                [str(dump_path)],
                stdin=_sp.DEVNULL,
                stdout=_sp.PIPE,
                stderr=_sp.PIPE,
                creationflags=getattr(_sp, "CREATE_NEW_PROCESS_GROUP", 0),
                timeout=20,
            )
            out = proc.stdout.decode("latin1", "replace")
            # crash / loader-failure codes: access violation, DLL/entry not found
            crash_codes = {0xC0000005, 0xC0000135, 0xC0000139, 0xC000007B}
            ran_clean = (proc.returncode & 0xFFFFFFFF) not in crash_codes
            run_info = {"attempted": True, "exit": proc.returncode,
                        "stdoutHead": out[:120], "ranClean": ran_clean}
            if expect_marker is not None:
                marker_ok = expect_marker in out
            if expect_exit is not None:
                exit_ok = (proc.returncode == int(expect_exit))
            if expect_marker is None and expect_exit is None:
                marker_ok = exit_ok = ran_clean
        except Exception as exc:
            run_info = {"attempted": True, "error": f"{type(exc).__name__}: {exc}"}
            marker_ok = exit_ok = False

    return {
        "packed": packed,
        "init": init_result,
        "dump": {k: dump.get(k) for k in
                 ("ok", "verified", "oep", "confidence", "reason", "isLikelyVirtualized", "rawDumpPath")},
        "dumpPath": str(dump_path),
        "run": run_info,
        "ok": bool(dump.get("ok")) and bool(dump.get("verified"))
        and dump_path.exists() and run_info.get("attempted") and marker_ok and exit_ok,
    }


def scenario_api_trace_sleep(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    entry = mod.RunUntil(target="entry", timeout_ms=8000, poll_ms=100)
    trace = mod.TraceApiCalls(
        modules_json=json.dumps(["kernel32.dll", "kernelbase.dll"]),
        functions_json=json.dumps(["sleep"]),
        # x86 may hit kernel32!Sleep -> kernelbase!Sleep -> SleepEx before
        # returning. Each bridge callback is serialized, so allow enough
        # budget for the complete entry/return sequence.
        duration_ms=15000,
        label="sleep-smoke",
    )
    run_payload = trace.get("run", {}) if isinstance(trace, dict) else {}
    native_evidence = (
        mod.GetNativeApiTraceEvidence(
            str(trace.get("traceId") or ""),
            after_seq=0,
            limit=5000,
        )
        if isinstance(trace, dict)
        and trace.get("traceId")
        and callable(getattr(mod, "GetNativeApiTraceEvidence", None))
        else {"ok": False, "skipped": True}
    )
    native_events = (
        native_evidence.get("events")
        if isinstance(native_evidence, dict)
        and isinstance(native_evidence.get("events"), list)
        else []
    )
    native_entry_events = [
        event for event in native_events
        if isinstance(event, dict) and event.get("kind") == "entry"
    ]
    native_return_events = [
        event for event in native_events
        if isinstance(event, dict) and event.get("kind") == "return"
    ]
    first_native_seq = int(
        (native_events[0] or {}).get("seq") or 0
    ) if native_events and isinstance(native_events[0], dict) else 0
    latest_native_seq = int(native_evidence.get("latestSeq") or 0)
    native_cursor_page = (
        mod.GetNativeApiTraceEvidence(
            str(trace.get("traceId") or ""),
            after_seq=first_native_seq,
            limit=1,
        )
        if first_native_seq > 0
        else {"ok": False, "error": "No native cursor anchor."}
    )
    cursor_events = (
        native_cursor_page.get("events")
        if isinstance(native_cursor_page, dict)
        and isinstance(native_cursor_page.get("events"), list)
        else []
    )
    native_tail = (
        mod.GetNativeApiTraceEvidence(
            str(trace.get("traceId") or ""),
            after_seq=latest_native_seq,
            limit=10,
        )
        if latest_native_seq > 0
        else {"ok": False, "error": "No native tail cursor."}
    )
    native_clear = (
        mod.ClearNativeApiTraceEvidence(str(trace.get("traceId") or ""))
        if callable(getattr(mod, "ClearNativeApiTraceEvidence", None))
        else {"ok": False, "skipped": True}
    )
    native_after_clear = (
        mod.GetNativeApiTraceEvidence(
            str(trace.get("traceId") or ""),
            after_seq=0,
            limit=10,
        )
        if native_clear.get("ok")
        else {"ok": False, "skipped": True}
    )
    cursor_ok = bool(
        native_cursor_page.get("ok")
        and len(cursor_events) == 1
        and int((cursor_events[0] or {}).get("seq") or 0) > first_native_seq
    )
    tail_ok = bool(
        native_tail.get("ok")
        and native_tail.get("events") == []
        and int(native_tail.get("nextAfterSeq") or 0) == latest_native_seq
    )
    abi_entry_ok = any(
        int(event.get("callId") or 0) > 0
        and int(event.get("entrySeq") or 0) > 0
        and isinstance(event.get("arguments"), list)
        and len(event.get("arguments")) >= 4
        and str(event.get("returnAddress") or "") not in {"", "0x0"}
        and bool(event.get("api"))
        for event in native_entry_events
    )
    matched_return_ok = any(
        bool(event.get("matchedReturn"))
        and int(event.get("callId") or 0) > 0
        and str(event.get("returnValue") or "").startswith("0x")
        for event in native_return_events
    )
    native_finalized = (
        (trace.get("stop") or {}).get("nativeFinalized")
        if isinstance(trace, dict)
        else None
    )
    finalized_ok = bool(
        isinstance(native_finalized, dict)
        and native_finalized.get("ok")
        and int(native_evidence.get("finalizedPendingCalls") or 0)
        == int(native_finalized.get("finalizedPendingCalls") or 0)
    )
    clear_ok = bool(
        native_clear.get("ok")
        and int(native_clear.get("cleared") or 0) == len(native_events)
        and native_after_clear.get("ok")
        and int(native_after_clear.get("eventCount") or 0) == 0
        and int(native_after_clear.get("pendingCalls") or 0) == 0
    )
    return {
        "init": init_result,
        "entry": entry,
        "trace": trace,
        "nativeEvidence": native_evidence,
        "nativeCursorPage": native_cursor_page,
        "nativeTail": native_tail,
        "nativeClear": native_clear,
        "nativeAfterClear": native_after_clear,
        "ok": bool(entry.get("ok"))
        and bool(trace.get("ok"))
        and int(run_payload.get("totalCalls", run_payload.get("callsRecorded", 0)) or 0) >= 1
        and bool(native_evidence.get("ok"))
        and len(native_entry_events) >= 1
        and len(native_return_events) >= 1
        and int(native_evidence.get("pendingCalls") or 0) == 0
        and cursor_ok
        and tail_ok
        and abi_entry_ok
        and matched_return_ok
        and finalized_ok
        and clear_ok,
    }


def scenario_checkpoint_rewind(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    entry = mod.RunUntil(target="entry", timeout_ms=8000, poll_ms=100)
    watch_addr, watch_meta = _find_watch_buffer_address(mod, exe_path)
    if not _is_hex_address(watch_addr):
        return {
            "init": init_result,
            "entry": entry,
            "watchAddr": watch_addr,
            "modules": watch_meta.get("modules"),
            "symbols": watch_meta.get("symbols"),
            "ok": False,
            "error": "Failed to resolve watch buffer address",
        }
    before = mod.ReadMemory(addr=str(watch_addr), size=16, ty="hex", max_chars=0)
    checkpoint = mod.SaveState(
        label="checkpoint_rewind",
        ranges_json=json.dumps(
            [{"label": "watch_buffer", "expr": str(watch_addr), "size": 16, "format": "hex"}]
        ),
    )
    overwrite = mod.MemoryWrite(str(watch_addr), "00" * 16)
    mutated = mod.ReadMemory(addr=str(watch_addr), size=16, ty="hex", max_chars=0)
    rewind = mod.Rewind(str(checkpoint.get("snapshotId") or ""))
    restored = mod.ReadMemory(addr=str(watch_addr), size=16, ty="hex", max_chars=0)
    return {
        "init": init_result,
        "entry": entry,
        "watchAddr": watch_addr,
        "modules": watch_meta.get("modules"),
        "symbols": watch_meta.get("symbols"),
        "before": before,
        "checkpoint": checkpoint,
        "overwrite": overwrite,
        "mutated": mutated,
        "rewind": rewind,
        "restored": restored,
        "ok": bool(entry.get("ok"))
        and bool(checkpoint.get("ok"))
        and int(checkpoint.get("rangeCount", 0) or 0) >= 1
        and _memory_write_ok(overwrite)
        and str((before or {}).get("hex") or "") != str((mutated or {}).get("hex") or "")
        and "watch_buffer" in list(((rewind or {}).get("restored") or {}).get("ranges") or [])
        and str((before or {}).get("hex") or "") == str((restored or {}).get("hex") or ""),
    }


def scenario_heap_trace_live(mod, exe_path: str) -> dict:
    gated = _arch_gate(mod, exe_path)
    if gated:
        return gated
    init_result = mod.InitDebuggee(exe_path, timeout_ms=20000, retries=2, stop_first=True, use_scyllahide="off")
    if not init_result.get("ok"):
        return {"init": init_result, "ok": False}
    # x86 commonly has additional loader/TLS breakpoints. Establish a stable
    # user entry stop before installing heap API breakpoints so the trace does
    # not terminate on a foreign entry breakpoint before main executes.
    entry = mod.RunUntil(target="entry", timeout_ms=10000, poll_ms=100)
    if not entry.get("ok"):
        return {"init": init_result, "entry": entry, "ok": False}
    start = mod.StartHeapTrace(label="heap-smoke")
    api_trace_id = str(start.get("apiTraceId") or "")
    heap_trace_id = str(start.get("heapTraceId") or "")
    if heap_trace_id and hasattr(mod, "RunHeapTrace"):
        run = mod.RunHeapTrace(
            heap_trace_id,
            timeout_ms=5000,
            expected_allocations=1,
            stop_when_live_zero=False,
            stop_on_complete=True,
        )
    elif api_trace_id:
        run = mod.RunApiTrace(api_trace_id, timeout_ms=5000, max_calls=64)
    else:
        run = {"ok": False, "error": "missing heap/api trace identity"}
    state = mod.GetHeapState(str(start.get("heapTraceId") or ""))
    stop = run.get("stop") if isinstance(run, dict) else None
    if not isinstance(stop, dict):
        stop = mod.StopApiTrace(api_trace_id, delete_breakpoints=True) if api_trace_id else {"ok": False, "error": "missing apiTraceId"}
    observed = int(state.get("allocCount") or 0) + int(state.get("freeCount") or 0)
    return {
        "init": init_result,
        "entry": entry,
        "start": start,
        "run": run,
        "state": state,
        "stop": stop,
        "ok": bool(start.get("ok"))
        and bool(run.get("ok"))
        and bool(state.get("ok"))
        and bool(stop.get("ok"))
        and observed > 0,
    }


SCENARIOS = {
    "gui_easy_crackme": scenario_gui_easy_crackme,
    "gui_seawolf": scenario_gui_seawolf,
    "console_cmd": scenario_console_cmd,
    "console_crackme": scenario_console_crackme,
    "packer_triage": scenario_packer_triage,
    "plugin_status": scenario_plugin_status,
    "scyllahide_auto": scenario_scyllahide_auto,
    "uia_easy_crackme": scenario_uia_easy_crackme,
    "raw_input_easy_crackme": scenario_raw_input_easy_crackme,
    "raw_visual_notepad": scenario_raw_visual_notepad,
    "re_context": scenario_re_context,
    "self_check": scenario_self_check,
    "decoder_suite": scenario_decoder_suite,
    "trace_summary": scenario_trace_summary,
    "health_benchmark": scenario_health_benchmark,
    "symbolic_bridge": scenario_symbolic_bridge,
    "memory_watchpoint": scenario_memory_watchpoint,
    "dump_main": scenario_dump_main,
    "unpack_verify": scenario_unpack_verify,
    "api_trace_sleep": scenario_api_trace_sleep,
    "checkpoint_rewind": scenario_checkpoint_rewind,
    "heap_trace_live": scenario_heap_trace_live,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run headless smoke scenarios against the local x64dbg bridge.")
    parser.add_argument(
        "--bridge",
        default=str(Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"),
    )
    parser.add_argument("--scenario", choices=sorted(SCENARIOS.keys()), required=True)
    parser.add_argument("--exe")
    parser.add_argument("--out")
    args = parser.parse_args()

    bridge = load_bridge(args.bridge)
    scenario = SCENARIOS[args.scenario]

    exe_path = args.exe or _default_exe_for_scenario(bridge, args.scenario)
    if not exe_path:
        raise SystemExit(f"--exe is required for scenario {args.scenario}")

    try:
        result = scenario(bridge, exe_path)
        if not isinstance(result, dict):
            result = {
                "ok": False,
                "error": "Scenario returned a non-object result",
                "resultType": type(result).__name__,
                "rawResult": repr(result),
            }
    except Exception as exc:
        result = {
            "ok": False,
            "error": str(exc),
            "exceptionType": type(exc).__name__,
            "traceback": traceback.format_exc(),
        }

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "bridge": os.path.abspath(args.bridge),
        "scenario": args.scenario,
        "exePath": exe_path,
        "result": result,
    }

    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.buffer.write(text.encode("utf-8", errors="replace"))
        sys.stdout.buffer.write(b"\n")
    return 0 if bool(result.get("ok")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
