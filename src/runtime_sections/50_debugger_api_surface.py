@mcp.tool()
def BenchmarkBridge(
    iterations: int = 3, include_gui: bool = False, include_uia: bool = False
) -> dict:
    """
    Measure latency of core bridge operations on the current debug session.
    """
    safe_iterations = max(1, min(int(iterations), 8))
    state = _build_debug_state(
        include_console=False, include_callstack=False, max_console_chars=0
    )
    if not state.get("debugging"):
        return {
            "ok": False,
            "error": "No debuggee is active.",
            "state": state,
            "logPath": LOG_PATH,
        }
    if not state.get("paused"):
        pause_result = DebugPause()
        paused_state = WaitForPause(timeout_ms=5000, poll_ms=100)
        state = paused_state if isinstance(paused_state, dict) else state
        if not state.get("paused"):
            return {
                "ok": False,
                "error": "Benchmark requires a paused debuggee.",
                "pauseResult": pause_result,
                "state": state,
                "logPath": LOG_PATH,
            }
    ip = str(state.get("rip") or state.get("session", {}).get("ip") or "0")
    sp = "rsp" if _get_runtime_arch() == "x64" else "esp"
    bp = "rbp" if _get_runtime_arch() == "x64" else "ebp"
    cases: List[Dict[str, Any]] = []

    def run_case(name: str, callback: Callable[[], Any]) -> None:
        timings: List[float] = []
        last_result: Any = None
        for _ in range(safe_iterations):
            started = time.perf_counter()
            last_result = callback()
            timings.append((time.perf_counter() - started) * 1000.0)
        cases.append(
            {
                "name": name,
                "iterations": safe_iterations,
                "avgMs": round(sum(timings) / len(timings), 3),
                "minMs": round(min(timings), 3),
                "maxMs": round(max(timings), 3),
                "lastResultSummary": _json_safe(last_result, limit=240),
            }
        )

    run_case("ReadMemory", lambda: ReadMemory(ip, 64, ty="hex"))
    run_case("WaitForPause", lambda: WaitForPause(timeout_ms=50, poll_ms=10))
    run_case(
        "CaptureContext",
        lambda: CaptureContext(
            registers_json=json.dumps(
                [sp, bp, "rip" if _get_runtime_arch() == "x64" else "eip"]
            ),
            expressions_json=json.dumps([f"[{sp}]"]),
            ranges_json=json.dumps(
                [{"label": "ip_bytes", "expr": ip, "size": 32, "format": "hex"}]
            ),
            stack_slots_json=json.dumps(
                [
                    {
                        "label": "ret0",
                        "expr": sp,
                        "size": 8 if _get_runtime_arch() == "x64" else 4,
                        "format": "hex",
                    }
                ]
            ),
        ),
    )
    if include_gui:
        run_case(
            "GetDebuggeeWindows",
            lambda: GetDebuggeeWindows(
                include_children=True, visible_only=True, max_depth=4
            ),
        )
    if include_uia:
        run_case(
            "GetDebuggeeUiAutomation",
            lambda: GetDebuggeeUiAutomation(
                visible_only=True, max_depth=4, timeout_ms=4000
            ),
        )
    slowest = max(cases, key=lambda item: item.get("avgMs", 0.0)) if cases else None
    return {
        "ok": True,
        "iterations": safe_iterations,
        "state": state,
        "cases": cases,
        "slowest": slowest,
        "logPath": LOG_PATH,
    }


@mcp.tool()
def AnalyzeDebuggeeInput(
    pid: int = 0, max_console_chars: int = 4000, include_callstack: bool = True
) -> dict:
    """
    Analyze whether the debuggee likely waits for console input.
    """
    state = _build_debug_state(
        include_console=True,
        include_callstack=include_callstack,
        max_console_chars=max_console_chars,
    )
    if pid and state.get("debuggeePid") not in (None, pid):
        state["requestedPid"] = pid
    return {
        "debuggeePid": state.get("debuggeePid"),
        "state": state.get("state"),
        "waitingForInput": state.get("waitingForInput"),
        "confidence": state.get("inputConfidence"),
        "reason": state.get("inputReason"),
        "signals": state.get("inputSignals"),
        "promptText": state.get("promptText"),
        "shouldAutoSubmit": state.get("shouldAutoSubmit"),
        "consoleLines": state.get("console", {}).get("lines", [])[-8:],
        "rip": state.get("rip"),
        "stopReason": state.get("stopReason"),
        "logPath": state.get("logPath"),
    }


@mcp.tool()
def AutoRespondToDebuggeeConsole(
    text: str,
    timeout_ms: int = 3000,
    poll_ms: int = 150,
    pid: int = 0,
    submit: bool = True,
    probe_pause: bool = True,
) -> dict:
    """
    Wait for a console prompt and only then send text to the debuggee.
    """
    primed = _advance_debuggee_toward_interaction(
        mode="console",
        timeout_ms=timeout_ms,
        poll_ms=poll_ms,
        pid=pid,
        visible_only=True,
        max_depth=4,
    )
    last_analysis = primed.get("analysis", {}) if isinstance(primed, dict) else {}
    last_state = primed.get("state", {}) if isinstance(primed, dict) else {}
    was_running = bool(last_state.get("running")) or primed.get("autoRuns", 0) > 0
    if last_state.get("state") in ("exited", "not_debugging"):
        return {
            "ok": False,
            "analysis": last_analysis,
            "state": last_state,
            "reason": "Target exited before a reliable input prompt was detected.",
            "timedOut": False,
            "autoRuns": primed.get("autoRuns", 0),
            "autoBypasses": primed.get("autoBypasses", []),
            "removedBreakpoints": primed.get("removedBreakpoints", []),
        }
    gui_snapshot = GetDebuggeeWindows(
        pid=pid or int(last_state.get("debuggeePid") or 0),
        include_children=True,
        visible_only=True,
        max_depth=5,
    )
    gui_analysis = (
        gui_snapshot.get("analysis", {}) if isinstance(gui_snapshot, dict) else {}
    )
    if gui_analysis.get("hasEdit") and gui_analysis.get("hasButton"):
        return {
            "ok": False,
            "analysis": last_analysis,
            "state": last_state,
            "gui": gui_snapshot,
            "reason": "A GUI form was detected. Use AutoRespondToDebuggeeGui for this target.",
            "redirectSuggested": "gui",
            "timedOut": False,
            "autoRuns": primed.get("autoRuns", 0),
            "autoBypasses": primed.get("autoBypasses", []),
            "removedBreakpoints": primed.get("removedBreakpoints", []),
        }
    if primed.get("ready"):
        result = SendTextToDebuggeeConsole(text=text, submit=submit, pid=pid)
        _log_event(
            "auto_respond_sent",
            pid=result.get("pid"),
            promptText=last_analysis.get("promptText"),
            confidence=last_analysis.get("confidence"),
            responseMode=result.get("mode"),
            autoRuns=primed.get("autoRuns", 0),
        )
        return {
            "ok": True,
            "mode": "direct_prompt",
            "analysis": last_analysis,
            "state": last_state,
            "sendResult": result,
            "reason": "Prompt detected without requiring a pause probe.",
            "timedOut": False,
            "autoRuns": primed.get("autoRuns", 0),
            "autoBypasses": primed.get("autoBypasses", []),
            "removedBreakpoints": primed.get("removedBreakpoints", []),
        }

    if probe_pause and was_running:
        pause_result = DebugPause()
        paused_state = WaitForPause(2000, 100)
        if paused_state.get("shouldAutoSubmit") or (
            paused_state.get("waitingForInput")
            and paused_state.get("inputConfidence") in ("high", "medium")
        ):
            send_result = SendTextToDebuggeeConsole(text=text, submit=submit, pid=pid)
            resume_result = DebugRun()
            _log_event(
                "auto_respond_pause_probe_sent",
                pid=send_result.get("pid"),
                promptText=paused_state.get("promptText"),
                confidence=paused_state.get("inputConfidence"),
            )
            return {
                "ok": True,
                "mode": "pause_probe",
                "analysis": paused_state,
                "state": paused_state,
                "sendResult": send_result,
                "pauseResult": pause_result,
                "resumeResult": resume_result,
                "reason": "Prompt was confirmed by pausing and inspecting console/stack state.",
                "timedOut": False,
                "usedPauseProbe": True,
                "autoRuns": primed.get("autoRuns", 0),
                "autoBypasses": primed.get("autoBypasses", []),
                "removedBreakpoints": primed.get("removedBreakpoints", []),
            }
        if paused_state.get("state") == "paused":
            resume_result = DebugRun()
        else:
            resume_result = None
        _log_event(
            "auto_respond_pause_probe_no_send",
            pauseResult=pause_result,
            pausedState=paused_state.get("state"),
            confidence=paused_state.get("inputConfidence"),
            reason=paused_state.get("inputReason"),
        )
        return {
            "ok": False,
            "analysis": paused_state,
            "reason": "No reliable input wait was detected, even after pausing to inspect the stack.",
            "timedOut": True,
            "usedPauseProbe": True,
            "pauseResult": pause_result,
            "resumeResult": resume_result,
            "autoRuns": primed.get("autoRuns", 0),
            "autoBypasses": primed.get("autoBypasses", []),
            "removedBreakpoints": primed.get("removedBreakpoints", []),
        }

    _log_event(
        "auto_respond_timeout",
        timeoutMs=timeout_ms,
        analysis=last_analysis,
        state=last_state.get("state"),
        autoRuns=primed.get("autoRuns", 0),
        autoBypasses=primed.get("autoBypasses", []),
        removedBreakpoints=primed.get("removedBreakpoints", []),
    )
    return {
        "ok": False,
        "analysis": last_analysis,
        "state": last_state,
        "reason": "Timed out waiting for a confident input prompt.",
        "timedOut": bool(primed.get("timedOut", True)),
        "autoRuns": primed.get("autoRuns", 0),
        "autoBypasses": primed.get("autoBypasses", []),
        "removedBreakpoints": primed.get("removedBreakpoints", []),
    }


@mcp.tool()
def SendTextToActiveWindow(text: str, submit: bool = False, delay_ms: int = 0) -> dict:
    """
    Type text into the current foreground window using WinAPI SendInput.

    Args:
        text: The text to type.
        submit: When true, also presses Enter after typing.
        delay_ms: Optional delay between characters in milliseconds.

    Returns:
        Dictionary with the target hwnd, pid, title, and the number of sent events.
    """
    try:
        result = _type_text_to_foreground(text, submit, delay_ms)
        _append_input_history({"kind": "active_window_text", **result})
        _log_event(
            "send_text_active_window",
            title=result.get("title"),
            pid=result.get("pid"),
            submitted=submit,
            text=text,
        )
        return result
    except Exception as e:
        _log_event(
            "send_text_active_window_error", submitted=submit, text=text, error=str(e)
        )
        return {"ok": False, "error": str(e)}


@mcp.tool()
def SendTextToDebuggeeWindow(
    text: str, submit: bool = False, delay_ms: int = 0, pid: int = 0
) -> dict:
    """
    Focus the debuggee window (or its console host when applicable) and type text into it.

    Args:
        text: The text to type.
        submit: When true, also presses Enter after typing.
        delay_ms: Optional delay before focusing and between characters in milliseconds.
        pid: Optional debuggee PID. When omitted, the newest child process of x64dbg/x32dbg is used.

    Returns:
        Dictionary describing the targeted window and the sent input events.
    """
    try:
        result = _type_text_to_debuggee_window(text, submit, delay_ms, pid)
        _append_input_history({"kind": "debuggee_window_text", **result})
        _log_event(
            "send_text_debuggee_window",
            pid=result.get("pid"),
            submitted=submit,
            text=text,
        )
        return result
    except Exception as e:
        _log_event(
            "send_text_debuggee_window_error",
            pid=pid,
            submitted=submit,
            text=text,
            error=str(e),
        )
        return {"ok": False, "error": str(e)}


@mcp.tool()
def SendTextToDebuggeeConsole(text: str, submit: bool = True, pid: int = 0) -> dict:
    """
    Write text into the console input buffer of the debugged process.

    This works even when the console window is not focused. It is especially useful
    for console crackmes or CLI tools launched under x64dbg.

    Args:
        text: The text to inject into stdin.
        submit: When true, appends Enter to the injected input.
        pid: Optional debuggee PID. When omitted, the newest child process of x64dbg/x32dbg is used.

    Returns:
        Dictionary with the target PID, optional conhost PID, and written event count.
    """
    try:
        result = _write_console_text(pid, text, submit)
        _append_input_history({"kind": "debuggee_console_text", **result})
        _log_event(
            "send_text_debuggee_console",
            pid=result.get("pid"),
            submitted=submit,
            mode=result.get("mode"),
            text=text,
        )
        return result
    except Exception as e:
        _log_event(
            "send_text_debuggee_console_error",
            pid=pid,
            submitted=submit,
            text=text,
            error=str(e),
        )
        return {"ok": False, "error": str(e)}


@mcp.tool()
def GetForegroundWindowInfo() -> dict:
    """
    Return the current foreground window title/class/pid.
    """
    return _foreground_window_info()


@mcp.tool()
def FocusDebuggeeWindow(pid: int = 0, timeout_ms: int = 2500) -> dict:
    """
    Focus the main debuggee window or its console host.
    """
    target_pid = _infer_debuggee_pid(pid)
    ready = _wait_for_resolved_window_ready(
        pid=target_pid,
        timeout_ms=timeout_ms,
        poll_ms=80,
        stable_polls=2,
        require_input_idle=True,
        client_only=False,
    )
    hwnd = (
        _parse_hwnd_value(ready.get("hwnd"))
        if isinstance(ready, dict) and ready.get("ok")
        else 0
    )
    if not hwnd:
        conhost_pid = _wait_for_conhost_pid(target_pid, timeout_ms=timeout_ms)
        if conhost_pid:
            hwnd = _wait_for_top_window(conhost_pid, timeout_ms=timeout_ms)
    if not hwnd:
        return {
            "ok": False,
            "pid": target_pid,
            "error": "No focusable window was found for the debuggee",
            "windowReady": ready,
        }
    focused = _focus_window(hwnd)
    info = _foreground_window_info()
    _append_input_history(
        {
            "kind": "focus_window",
            "targetHwnd": f"0x{hwnd:X}",
            "targetPid": target_pid,
            "focused": focused,
            **info,
        }
    )
    _log_event(
        "focus_debuggee_window", pid=target_pid, hwnd=f"0x{hwnd:X}", focused=focused
    )
    return {
        "ok": bool(focused),
        "targetHwnd": f"0x{hwnd:X}",
        "targetPid": target_pid,
        "foreground": info,
        "windowReady": ready,
    }


@mcp.tool()
def WaitForForegroundChange(
    previous_hwnd: str = "", timeout_ms: int = 4000, poll_ms: int = 100
) -> dict:
    """
    Wait until the foreground window changes.
    """
    baseline = (
        _normalize_hex(previous_hwnd)
        if previous_hwnd
        else _normalize_hex((_foreground_window_info() or {}).get("hwnd"))
    )
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    last = _foreground_window_info()
    while time.time() <= deadline:
        last = _foreground_window_info()
        current = _normalize_hex(last.get("hwnd"))
        if current and current != baseline:
            return {
                "ok": True,
                "timedOut": False,
                "window": last,
                "previousHwnd": baseline,
            }
        time.sleep(max(poll_ms, 20) / 1000.0)
    return {"ok": False, "timedOut": True, "window": last, "previousHwnd": baseline}


@mcp.tool()
def SendForegroundKeys(
    keys_json: str, delay_ms: int = 0, mode: str = "auto", event: str = "tap"
) -> dict:
    """
    Send one or more key presses/combinations to the current foreground window.
    """
    sequences = _normalize_name_items(keys_json)
    if not sequences:
        return {"ok": False, "error": "No key sequence was provided"}
    info = _foreground_window_info()
    total_sent = 0
    for sequence in sequences:
        total_sent += _send_key_combo(
            sequence, delay_ms=delay_ms, mode=mode, event=event
        )
    result = {
        "ok": True,
        "target": info,
        "keys": sequences,
        "eventsSent": total_sent,
        "mode": str(mode or "auto"),
        "event": str(event or "tap"),
    }
    _append_input_history({"kind": "foreground_keys", **result})
    _log_event(
        "send_foreground_keys",
        hwnd=info.get("hwnd"),
        pid=info.get("pid"),
        keys=sequences,
        eventsSent=total_sent,
        mode=mode,
        event=event,
    )
    return result


@mcp.tool()
def ClickActiveWindow(
    x: int = 10, y: int = 10, button: str = "left", double_click: bool = False
) -> dict:
    """
    Click inside the current foreground window using SendInput mouse events.
    """
    info = _foreground_window_info()
    hwnd_hex = info.get("hwnd")
    if not hwnd_hex:
        return {"ok": False, "error": "No foreground window is available"}
    parsed_hwnd = _parse_hwnd_value(hwnd_hex)
    rect = RECT()
    if not user32.GetWindowRect(parsed_hwnd, ctypes.byref(rect)):
        return {
            "ok": False,
            "error": f"GetWindowRect failed: {ctypes.get_last_error()}",
        }
    target_x = int(rect.left) + int(x)
    target_y = int(rect.top) + int(y)
    if not user32.SetCursorPos(target_x, target_y):
        return {"ok": False, "error": f"SetCursorPos failed: {ctypes.get_last_error()}"}
    button_name = str(button or "left").strip().lower()
    if button_name == "right":
        down_flag, up_flag = MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP
    else:
        button_name = "left"
        down_flag, up_flag = MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP
    click_count = 2 if double_click else 1
    total_sent = 0
    for _ in range(click_count):
        total_sent += _send_input_records(_mouse_inputs(down_flag))
        total_sent += _send_input_records(_mouse_inputs(up_flag))
    result = {
        "ok": True,
        "target": info,
        "x": target_x,
        "y": target_y,
        "button": button_name,
        "doubleClick": bool(double_click),
        "eventsSent": total_sent,
    }
    _append_input_history({"kind": "foreground_click", **result})
    _log_event(
        "click_active_window",
        hwnd=info.get("hwnd"),
        pid=info.get("pid"),
        x=target_x,
        y=target_y,
        button=button_name,
        doubleClick=double_click,
    )
    return result


@mcp.tool()
def ScrollActiveWindow(delta: int = -120, x: int = 10, y: int = 10) -> dict:
    """
    Send a mouse wheel event to the current foreground window.
    """
    info = _foreground_window_info()
    hwnd_hex = info.get("hwnd")
    if not hwnd_hex:
        return {"ok": False, "error": "No foreground window is available"}
    parsed_hwnd = _parse_hwnd_value(hwnd_hex)
    rect = RECT()
    if not user32.GetWindowRect(parsed_hwnd, ctypes.byref(rect)):
        return {
            "ok": False,
            "error": f"GetWindowRect failed: {ctypes.get_last_error()}",
        }
    target_x = int(rect.left) + int(x)
    target_y = int(rect.top) + int(y)
    if not user32.SetCursorPos(target_x, target_y):
        return {"ok": False, "error": f"SetCursorPos failed: {ctypes.get_last_error()}"}
    total_sent = _send_input_records(_mouse_wheel_inputs(delta))
    result = {
        "ok": True,
        "target": info,
        "x": target_x,
        "y": target_y,
        "delta": int(delta),
        "eventsSent": total_sent,
    }
    _append_input_history({"kind": "foreground_wheel", **result})
    _log_event(
        "scroll_active_window",
        hwnd=info.get("hwnd"),
        pid=info.get("pid"),
        x=target_x,
        y=target_y,
        delta=delta,
    )
    return result


@mcp.tool()
def ClickDebuggeeWindow(
    pid: int = 0,
    hwnd: str = "",
    title_contains: str = "",
    class_name: str = "",
    x: int = 10,
    y: int = 10,
    button: str = "left",
    double_click: bool = False,
    client_only: bool = True,
    focus_window: bool = True,
    timeout_ms: int = 2500,
    visible_only: bool = True,
) -> dict:
    """
    Click inside a resolved debuggee window using coordinates relative to its client or window rect.
    """
    try:
        target = _wait_for_resolved_window_ready(
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
        if not target.get("ok"):
            target = _resolve_target_window(
                pid=pid,
                hwnd=hwnd,
                title_contains=title_contains,
                class_name=class_name,
                visible_only=visible_only,
                timeout_ms=timeout_ms,
            )
        target_hwnd = _parse_hwnd_value(target.get("hwnd"))
        if focus_window:
            _focus_window(target_hwnd)
            time.sleep(0.05)
        result = _click_window_relative(
            target_hwnd,
            x=x,
            y=y,
            button=button,
            double_click=double_click,
            client_only=client_only,
        )
        result["targetPid"] = int(target.get("pid") or 0)
        result["windowTitle"] = str((target.get("window") or {}).get("title") or "")
        _append_input_history({"kind": "debuggee_window_click", **result})
        _log_event(
            "click_debuggee_window",
            pid=result.get("targetPid"),
            hwnd=result.get("hwnd"),
            x=result.get("x"),
            y=result.get("y"),
            clientOnly=client_only,
        )
        return result
    except Exception as e:
        _log_event("click_debuggee_window_error", pid=pid, hwnd=hwnd, error=str(e))
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def ScrollDebuggeeWindow(
    pid: int = 0,
    hwnd: str = "",
    title_contains: str = "",
    class_name: str = "",
    x: int = 10,
    y: int = 10,
    delta: int = -120,
    client_only: bool = True,
    focus_window: bool = True,
    timeout_ms: int = 2500,
    visible_only: bool = True,
) -> dict:
    """
    Send a mouse wheel event to a resolved debuggee window.
    """
    try:
        target = _wait_for_resolved_window_ready(
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
        if not target.get("ok"):
            target = _resolve_target_window(
                pid=pid,
                hwnd=hwnd,
                title_contains=title_contains,
                class_name=class_name,
                visible_only=visible_only,
                timeout_ms=timeout_ms,
            )
        target_hwnd = _parse_hwnd_value(target.get("hwnd"))
        if focus_window:
            _focus_window(target_hwnd)
            time.sleep(0.05)
        bounds = _window_bounds(target_hwnd, client_only=client_only)
        target_x = int(bounds["left"]) + int(x)
        target_y = int(bounds["top"]) + int(y)
        if not user32.SetCursorPos(target_x, target_y):
            raise OSError(f"SetCursorPos failed: {ctypes.get_last_error()}")
        total_sent = _send_input_records(_mouse_wheel_inputs(delta))
        result = {
            "ok": True,
            "hwnd": f"0x{int(target_hwnd):X}",
            "targetPid": int(target.get("pid") or 0),
            "windowTitle": str((target.get("window") or {}).get("title") or ""),
            "x": target_x,
            "y": target_y,
            "relativeX": int(x),
            "relativeY": int(y),
            "delta": int(delta),
            "eventsSent": total_sent,
            "clientOnly": bool(client_only),
        }
        _append_input_history({"kind": "debuggee_window_wheel", **result})
        _log_event(
            "scroll_debuggee_window",
            pid=result.get("targetPid"),
            hwnd=result.get("hwnd"),
            x=target_x,
            y=target_y,
            delta=delta,
            clientOnly=client_only,
        )
        return result
    except Exception as e:
        _log_event("scroll_debuggee_window_error", pid=pid, hwnd=hwnd, error=str(e))
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def DragDebuggeeWindow(
    pid: int = 0,
    hwnd: str = "",
    title_contains: str = "",
    class_name: str = "",
    start_x: int = 10,
    start_y: int = 10,
    end_x: int = 120,
    end_y: int = 10,
    button: str = "left",
    client_only: bool = True,
    focus_window: bool = True,
    timeout_ms: int = 2500,
    visible_only: bool = True,
    steps: int = 18,
    step_delay_ms: int = 8,
) -> dict:
    """
    Drag the mouse inside a resolved debuggee window using coordinates relative to its client or window rect.
    """
    try:
        target = _wait_for_resolved_window_ready(
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
        if not target.get("ok"):
            target = _resolve_target_window(
                pid=pid,
                hwnd=hwnd,
                title_contains=title_contains,
                class_name=class_name,
                visible_only=visible_only,
                timeout_ms=timeout_ms,
            )
        target_hwnd = _parse_hwnd_value(target.get("hwnd"))
        if focus_window:
            _focus_window(target_hwnd)
            time.sleep(0.05)
        result = _drag_window_relative(
            target_hwnd,
            start_x=start_x,
            start_y=start_y,
            end_x=end_x,
            end_y=end_y,
            button=button,
            client_only=client_only,
            steps=steps,
            step_delay_ms=step_delay_ms,
        )
        result["targetPid"] = int(target.get("pid") or 0)
        result["windowTitle"] = str((target.get("window") or {}).get("title") or "")
        _append_input_history({"kind": "debuggee_window_drag", **result})
        _log_event(
            "drag_debuggee_window",
            pid=result.get("targetPid"),
            hwnd=result.get("hwnd"),
            start=result.get("start"),
            end=result.get("end"),
            clientOnly=client_only,
            steps=steps,
        )
        return result
    except Exception as e:
        _log_event("drag_debuggee_window_error", pid=pid, hwnd=hwnd, error=str(e))
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


_REGISTER_FAMILIES = {
    "a": ("rax", "eax", "cax", "ax"),
    "b": ("rbx", "ebx", "cbx", "bx"),
    "c": ("rcx", "ecx", "ccx", "cx"),
    "d": ("rdx", "edx", "cdx", "dx"),
    "sp": ("rsp", "esp", "csp", "sp"),
    "bp": ("rbp", "ebp", "cbp", "bp"),
    "si": ("rsi", "esi", "csi", "si"),
    "di": ("rdi", "edi", "cdi", "di"),
    "ip": ("rip", "eip", "cip", "ip"),
    "flags": ("rflags", "eflags", "cflags", "flags"),
}
_REGISTER_DUMP_KEY = {
    "a": "cax", "b": "cbx", "c": "ccx", "d": "cdx", "sp": "csp",
    "bp": "cbp", "si": "csi", "di": "cdi", "ip": "cip", "flags": "eflags",
}


def _register_family(name: str) -> Optional[str]:
    n = (name or "").strip().lower()
    for fam, members in _REGISTER_FAMILIES.items():
        if n in members:
            return fam
    return None


def _register_name_candidates(name: str) -> List[str]:
    """
    Accept arch-neutral (cax/cbp/cip), 32-bit (eax/ebp/eip), 64-bit (rax/rbp/rip)
    and bare (ax/bp/ip) register forms interchangeably. Returns candidate names to
    try against the bridge in a sensible order so callers never have to guess the
    right spelling for the target architecture.
    """
    n = (name or "").strip().lower()
    candidates: List[str] = [n] if n else []
    fam = _register_family(n)
    if fam:
        for member in _REGISTER_FAMILIES[fam]:
            if member not in candidates:
                candidates.append(member)
    return candidates or [name]


def _is_register_error(result: Any) -> bool:
    if not isinstance(result, str):
        return False
    low = result.strip().lower()
    return (
        low.startswith("error")
        or low.startswith("request failed")
        or "unknown register" in low
    )


def _register_from_dump(name: str) -> Optional[str]:
    """Resolve a register from the full dump (arch-neutral keys) as a fallback."""
    try:
        dump = GetRegisterDump()
    except Exception:
        return None
    if not isinstance(dump, dict):
        return None
    keys: List[str] = []
    fam = _register_family(name)
    if fam:
        keys.append(_REGISTER_DUMP_KEY[fam])
    keys.append((name or "").strip().lower())  # segments, dr0-7, r8-r15
    for key in keys:
        if key in dump and not isinstance(dump[key], (dict, list)):
            return str(dump[key])
    return None


@mcp.tool()
def RegisterGet(register: str) -> str:
    """
    Get a register value. Register names are normalized: arch-neutral
    (cax/cbp/cip), 32-bit (eax/ebp/eip), 64-bit (rax/rbp/rip) and bare (bp/ip)
    forms all work regardless of the target architecture. If the bridge rejects
    the direct query, the value is recovered from the full register dump.

    Parameters:
        register: Register name (e.g. "eip", "rip", "cip", "ebp", "cbp").

    Returns:
        Register value in hex format.
    """
    last: Any = None
    for candidate in _register_name_candidates(register):
        result = safe_get("Register/Get", {"register": candidate})
        if not _is_register_error(result):
            return result
        last = result
    fallback = _register_from_dump(register)
    if fallback is not None:
        return fallback
    return last if last is not None else f"Unknown register: {register}"


@mcp.tool()
def RegisterSet(register: str, value: str) -> str:
    """
    Set a register value. Register names are normalized across arch-neutral,
    32-bit, 64-bit and bare forms (see RegisterGet).

    Parameters:
        register: Register name (e.g. "eip", "rip", "cip", "ebp", "cbp").
        value: Value to set (in hex format, e.g. "0x1000").

    Returns:
        Status message
    """
    last: Any = None
    for candidate in _register_name_candidates(register):
        result = safe_get("Register/Set", {"register": candidate, "value": value})
        if not _is_register_error(result):
            return result
        last = result
    return last if last is not None else f"Unknown register: {register}"


@mcp.tool()
def MemoryRead(addr: str, size: str) -> str:
    """
    Read memory using enhanced Script API

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        size: Number of bytes to read

    Returns:
        Hexadecimal string representing the memory contents
    """
    payload = ReadMemory(
        addr=addr, size=int(_parse_int(size, 0) or 0), ty="hex", max_chars=0
    )
    if isinstance(payload, dict):
        if payload.get("ok"):
            return str(payload.get("hex", ""))
        return str(payload.get("error", "Failed to read memory"))
    return str(payload)


@mcp.tool()
def MemoryWrite(addr: str, data: str) -> dict | str:
    """
    Write memory using enhanced Script API

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        data: Hexadecimal string representing the data to write

    Returns:
        Structured write/verification result from bridge v2 (legacy bridges may
        still return a status string).
    """
    # POST keeps large patches out of the request-target/header limit. The
    # bridge parses the complete form body before touching target memory.
    return safe_post("Memory/Write", {"addr": addr, "data": data})


@mcp.tool()
def MemoryIsValidPtr(addr: str) -> bool:
    """
    Check if memory address is valid

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")

    Returns:
        True if valid, False otherwise
    """
    result = safe_get("Memory/IsValidPtr", {"addr": addr})
    if isinstance(result, str):
        return result.lower() == "true"
    return False


@mcp.tool()
def MemoryGetProtect(addr: str) -> str:
    """
    Get memory protection flags

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")

    Returns:
        Protection flags in hex format
    """
    return safe_get("Memory/GetProtect", {"addr": addr})


@mcp.tool()
def DebugRun(exception_mode: str = "normal") -> str:
    """
    Resume execution without blocking the MCP HTTP server.

    This intentionally uses a non-blocking debugger command path so the
    bridge can continue to service Pause/Status requests while the target
    is running.

    Returns:
        Status message
    """
    normalized_mode = str(exception_mode or "normal").strip().lower()
    if normalized_mode not in ("normal", "pass", "swallow"):
        return "Error: exception_mode must be normal, pass, or swallow"
    session_before = _get_debug_session_state(include_history=False, history_limit=0)
    before_seq = int(session_before.get("eventSeq") or 0) if session_before else 0
    result = safe_get("Debug/Run", {"exceptionMode": normalized_mode})
    session = _get_debug_session_state(include_history=False, history_limit=0)
    if session:
        _remember_runtime(
            lastResumeSeq=before_seq,
            lastSessionEventSeq=int(session.get("eventSeq") or 0),
        )
    else:
        _remember_runtime(lastResumeSeq=before_seq)
    _log_event("debug_run", result=result, exceptionMode=normalized_mode)
    return result


@mcp.tool()
def DebugRunBlocking(
    exception_mode: str = "normal", timeout_ms: int = 30000, poll_ms: int = 100
) -> dict:
    """
    Resume execution and wait until x64dbg pauses again.

    Use this only when you explicitly want a blocking wait for the next
    breakpoint, exception, or pause event.

    The bridge itself only performs short wait slices so status/pause requests
    from another client remain responsive; this tool owns the overall timeout.
    """
    normalized_mode = str(exception_mode or "normal").strip().lower()
    if normalized_mode not in ("normal", "pass", "swallow"):
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "exception_mode must be normal, pass, or swallow",
        }
    submitted = DebugRun(exception_mode=normalized_mode)
    submitted_ok, submitted_error = _mutation_result_ok(submitted)
    if not submitted_ok:
        return {
            "ok": False,
            "submitted": submitted,
            "error": submitted_error or "Run submission failed",
        }
    state = WaitForPause(timeout_ms=timeout_ms, poll_ms=poll_ms)
    result = {
        "ok": not bool(state.get("timedOut")),
        "submitted": submitted,
        "state": state,
        "timedOut": bool(state.get("timedOut")),
        "timeoutMs": int(timeout_ms),
        "exceptionMode": normalized_mode,
    }
    _log_event("debug_run_blocking", result=result, exceptionMode=normalized_mode)
    return result


def _exception_contract_failure(
    envelope: BridgeEnvelope, fallback_code: str, fallback_message: str
) -> Dict[str, Any]:
    error = envelope.error
    return {
        "ok": False,
        "errorCode": error.code if error else fallback_code,
        "error": error.message if error else fallback_message,
        "retryable": bool(error.retryable) if error else False,
        "details": dict(error.details) if error and error.details else {},
        "meta": dict(envelope.meta or {}),
    }


def _current_exception_policy_event() -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    state = _get_debug_session_state(include_history=False, history_limit=0)
    if not isinstance(state, dict) or not state.get("debugging"):
        return None, {
            "ok": False,
            "errorCode": "NO_DEBUG_SESSION",
            "error": "Exception policy mutations require an active debug session",
        }
    event_seq = int(state.get("eventSeq") or 0)
    if event_seq <= 0:
        return None, {
            "ok": False,
            "errorCode": "EVENT_IDENTITY_UNAVAILABLE",
            "error": "The active debug session has no event sequence",
        }
    return state, None


def _exception_success_payload(
    envelope: BridgeEnvelope, fallback_key: str
) -> Dict[str, Any]:
    """Unwrap both canonical v3 and legacy flat bridge success responses.

    The exception-policy endpoints use the canonical
    ``{ok, data, error, meta}`` envelope.  Older bridge builds and unit-test
    adapters return the payload directly.  Keeping this compatibility shim
    local avoids changing the response shape of unrelated legacy tools before
    the public-envelope migration in stage 1D.
    """

    raw = envelope.data
    native_meta: Dict[str, Any] = {}
    if isinstance(raw, dict) and raw.get("ok") is True and "data" in raw:
        nested = raw.get("data")
        raw_meta = raw.get("meta")
        if isinstance(raw_meta, dict):
            native_meta = dict(raw_meta)
        raw = nested
    payload = dict(raw) if isinstance(raw, dict) else {fallback_key: raw}
    payload["ok"] = True
    # Native metadata is authoritative for commit-time session/event identity;
    # transport metadata supplies client request timing and IDs when absent.
    merged_meta = dict(envelope.meta or {})
    merged_meta.update(native_meta)
    payload["meta"] = merged_meta
    return payload


@mcp.tool()
def SetExceptionPolicy(
    rules_json: str = "[]",
    enabled: bool = True,
    first_chance_default: str = "pause",
    second_chance_default: str = "pause",
    replace: bool = True,
) -> dict:
    """Atomically configure session-scoped first/second-chance exception policy.

    ``rules_json`` is a JSON rule object or array. Each rule accepts ``ruleId``,
    ``codes`` (exact codes, ``value/mask`` selectors, or ``*``), ``chance``
    (first/second/any), ``action`` (pause/handled/not_handled), integer
    ``priority`` and boolean ``enabled``. Exact selectors outrank masked
    selectors, which outrank wildcard rules; priority breaks equal-specificity
    ties. The native bridge applies handled/not_handled policy directly from the
    exception callback, so it does not depend on an active WaitForPause call.
    """

    normalized_rules = _normalize_exception_policy_rules(rules_json)
    if not normalized_rules.get("ok"):
        return normalized_rules
    first_default = _normalize_exception_policy_action(first_chance_default)
    second_default = _normalize_exception_policy_action(second_chance_default)
    if first_default is None or second_default is None:
        return {
            "ok": False,
            "errorCode": "INVALID_EXCEPTION_POLICY_DEFAULT",
            "error": (
                "first_chance_default and second_chance_default must be pause, "
                "handled, or not_handled"
            ),
        }
    state, state_error = _current_exception_policy_event()
    if state_error:
        return state_error
    assert state is not None
    rules = list(normalized_rules.get("rules") or [])
    form: Dict[str, Any] = {
        "enabled": "true" if enabled else "false",
        "firstChanceDefault": first_default,
        "secondChanceDefault": second_default,
        "replace": "true" if replace else "false",
        "ruleCount": str(len(rules)),
    }
    for index, rule in enumerate(rules):
        prefix = f"rule{index}"
        form[f"{prefix}Id"] = rule["ruleId"]
        form[f"{prefix}Codes"] = ",".join(rule["codes"])
        form[f"{prefix}Chance"] = rule["chance"]
        form[f"{prefix}Action"] = rule["action"]
        form[f"{prefix}Priority"] = str(rule["priority"])
        form[f"{prefix}Enabled"] = "true" if rule["enabled"] else "false"
    envelope = _bridge_request(
        "POST",
        "Debug/ExceptionPolicy/Set",
        form_data=form,
        log=True,
        timeout_sec=5.0,
        guard="session",
        expected_event_seq=int(state.get("eventSeq") or 0),
        idempotent=False,
    )
    if not envelope.ok:
        return _exception_contract_failure(
            envelope,
            "EXCEPTION_POLICY_SET_FAILED",
            "Failed to set exception policy",
        )
    payload = _exception_success_payload(envelope, "policy")
    _remember_runtime(
        nativeExceptionPolicyActive=bool(enabled),
        exceptionFilters=[],
    )
    _log_event(
        "exception_policy_set",
        enabled=bool(enabled),
        ruleCount=len(rules),
        replace=bool(replace),
        revision=payload.get("revision"),
    )
    return payload


@mcp.tool()
def GetExceptionPolicy() -> dict:
    """Return the native exception policy and the session identity it is bound to."""

    envelope = _bridge_request(
        "GET",
        "Debug/ExceptionPolicy/Get",
        log=False,
        timeout_sec=5.0,
        guard="none",
        idempotent=True,
    )
    if not envelope.ok:
        return _exception_contract_failure(
            envelope,
            "EXCEPTION_POLICY_GET_FAILED",
            "Failed to read exception policy",
        )
    payload = _exception_success_payload(envelope, "policy")
    policy = payload.get("policy")
    if isinstance(policy, dict):
        _remember_runtime(nativeExceptionPolicyActive=bool(policy.get("enabled")))
    return payload


@mcp.tool()
def ClearExceptionPolicy(clear_history: bool = False) -> dict:
    """Disable and clear the active session's exception policy atomically."""

    state, state_error = _current_exception_policy_event()
    if state_error:
        return state_error
    assert state is not None
    envelope = _bridge_request(
        "POST",
        "Debug/ExceptionPolicy/Clear",
        form_data={"clearHistory": "true" if clear_history else "false"},
        log=True,
        timeout_sec=5.0,
        guard="session",
        expected_event_seq=int(state.get("eventSeq") or 0),
        idempotent=False,
    )
    if not envelope.ok:
        return _exception_contract_failure(
            envelope,
            "EXCEPTION_POLICY_CLEAR_FAILED",
            "Failed to clear exception policy",
        )
    payload = _exception_success_payload(envelope, "result")
    _remember_runtime(nativeExceptionPolicyActive=False, exceptionFilters=[])
    _log_event("exception_policy_clear", clearHistory=bool(clear_history))
    return payload


@mcp.tool()
def GetExceptionHistory(after_seq: int = 0, limit: int = 100) -> dict:
    """Read cursor-paginated causal exception history for the current session."""

    try:
        cursor = int(after_seq)
        page_limit = int(limit)
    except (TypeError, ValueError):
        return {
            "ok": False,
            "errorCode": "INVALID_EXCEPTION_HISTORY_PAGE",
            "error": "after_seq and limit must be integers",
        }
    if cursor < 0 or page_limit < 1 or page_limit > 256:
        return {
            "ok": False,
            "errorCode": "INVALID_EXCEPTION_HISTORY_PAGE",
            "error": "after_seq must be non-negative and limit must be between 1 and 256",
        }
    envelope = _bridge_request(
        "GET",
        "Debug/ExceptionHistory/Get",
        params={"afterSeq": cursor, "limit": page_limit},
        log=False,
        timeout_sec=5.0,
        guard="none",
        idempotent=True,
    )
    if not envelope.ok:
        return _exception_contract_failure(
            envelope,
            "EXCEPTION_HISTORY_GET_FAILED",
            "Failed to read exception history",
        )
    payload = _exception_success_payload(envelope, "history")
    if "records" in payload and "history" not in payload:
        payload["history"] = list(payload.get("records") or [])
    return payload


@mcp.tool()
def ClearExceptionHistory() -> dict:
    """Clear exception history for the guarded current session without changing policy."""

    state, state_error = _current_exception_policy_event()
    if state_error:
        return state_error
    assert state is not None
    envelope = _bridge_request(
        "POST",
        "Debug/ExceptionHistory/Clear",
        form_data={},
        log=True,
        timeout_sec=5.0,
        guard="session",
        expected_event_seq=int(state.get("eventSeq") or 0),
        idempotent=False,
    )
    if not envelope.ok:
        return _exception_contract_failure(
            envelope,
            "EXCEPTION_HISTORY_CLEAR_FAILED",
            "Failed to clear exception history",
        )
    payload = _exception_success_payload(envelope, "result")
    _log_event("exception_history_clear")
    return payload


@mcp.tool()
def ContinueException(
    disposition: str = "pass",
    expected_event_seq: int = 0,
    resume: bool = True,
) -> dict:
    """Continue the current exception with explicit debugger semantics.

    ``pass`` sends DBG_EXCEPTION_NOT_HANDLED to the debuggee; ``swallow`` sends
    DBG_CONTINUE. ``normal`` uses the debugger's ordinary run policy.  The
    exception event sequence is guarded atomically by the bridge so a delayed
    agent call can never handle a newer exception accidentally.
    """

    normalized = str(disposition or "pass").strip().lower()
    aliases = {
        "handled": "swallow",
        "not_handled": "pass",
        "not-handled": "pass",
        "default": "normal",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in ("normal", "pass", "swallow"):
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "disposition must be normal, pass, or swallow",
        }
    state = _get_debug_session_state(include_history=False, history_limit=0)
    event_seq = int(expected_event_seq or state.get("eventSeq") or 0)
    if normalized == "normal":
        result = DebugRun(exception_mode="normal") if resume else "normal"
        ok, error = _mutation_result_ok(result)
        return {
            "ok": ok,
            "disposition": normalized,
            "eventSeq": event_seq,
            "resumed": bool(resume and ok),
            "result": result,
            "error": error or None,
        }
    if not bool(state.get("paused")) or not state.get("exceptionCode") or str(
        state.get("exceptionCode")
    ) in ("0", "0x0"):
        return {
            "ok": False,
            "errorCode": "NO_CURRENT_EXCEPTION",
            "error": "ContinueException requires the current paused event to be an exception.",
            "state": state,
        }
    if not event_seq:
        return {
            "ok": False,
            "errorCode": "EVENT_IDENTITY_UNAVAILABLE",
            "error": "The current exception has no event sequence.",
        }
    bridge_disposition = "handled" if normalized == "swallow" else "not_handled"
    envelope = _bridge_request(
        "GET",
        "Debug/ContinueException",
        params={
            "disposition": bridge_disposition,
            "resume": "true" if resume else "false",
        },
        log=True,
        timeout_sec=5.0,
        guard="session",
        expected_event_seq=event_seq,
        idempotent=False,
    )
    if not envelope.ok:
        return {
            "ok": False,
            "disposition": normalized,
            "eventSeq": event_seq,
            "resumed": False,
            "errorCode": envelope.error.code if envelope.error else "BRIDGE_ERROR",
            "error": envelope.error.message if envelope.error else "Exception continuation failed.",
            "meta": envelope.meta,
        }
    data = envelope.data
    payload = dict(data) if isinstance(data, dict) else {"result": data}
    payload.update(
        {
            "ok": True,
            "disposition": normalized,
            "bridgeDisposition": bridge_disposition,
            "eventSeq": event_seq,
            "resumed": bool(resume),
            "meta": envelope.meta,
        }
    )
    # WaitForBreakpointDetailed uses lastResumeSeq as an exclusive event
    # cursor.  A disposition+resume is a real resume operation just like
    # DebugRun, so retaining the pre-disposition cursor can make the next wait
    # observe the same exception again.  Advance the local cursor only after
    # the bridge accepted the event-guarded disposition.
    if resume:
        _remember_runtime(
            lastResumeSeq=event_seq,
            lastSessionEventSeq=event_seq,
        )
    return payload


@mcp.tool()
def DebugPause() -> str:
    """
    Pause execution without blocking the MCP HTTP server.

    Returns:
        Status message
    """
    result = safe_get("Debug/Pause")
    session = _get_debug_session_state(include_history=False, history_limit=0)
    if session:
        _remember_runtime(
            lastPauseRequestSeq=int(session.get("eventSeq") or 0),
            lastSessionEventSeq=int(session.get("eventSeq") or 0),
        )
    _log_event("debug_pause", result=result)
    return result


@mcp.tool()
def DebugStop() -> str:
    """
    Stop debugging using Script API

    Returns:
        Status message
    """
    hidemain_cleanup = None
    cleanup_hidemain = globals().get("_cleanup_hidemain_target")
    if callable(cleanup_hidemain):
        try:
            hidemain_cleanup = cleanup_hidemain()
        except Exception as exc:
            hidemain_cleanup = {"ok": False, "error": str(exc)}
    result = safe_get("Debug/Stop")
    _wait_for_debugger_idle(timeout_ms=2500, poll_ms=125)
    _restore_pending_scyllahide_profile(force=False)
    _log_event("debug_stop", result=result, hideMainCleanup=hidemain_cleanup)
    return result


@mcp.tool()
def DebugStepIn() -> dict:
    """
    Step into the next instruction without blocking the MCP HTTP server.

    Returns:
        Command execution result
    """
    return _debug_step_via_exec_command("sti", "debug_step_in")


@mcp.tool()
def DebugStepOver() -> dict:
    """
    Step over the next instruction without blocking the MCP HTTP server.

    Returns:
        Command execution result
    """
    return _debug_step_via_exec_command("sto", "debug_step_over")


@mcp.tool()
def DebugStepOut() -> dict:
    """
    Step out of the current function without blocking the MCP HTTP server.

    Returns:
        Command execution result
    """
    return _debug_step_via_exec_command("rtr", "debug_step_out")


@mcp.tool()
def DebugSetBreakpoint(addr: str) -> str:
    """
    Set breakpoint at address using Script API

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")

    Returns:
        Status message
    """
    return safe_get("Debug/SetBreakpoint", {"addr": addr})


@mcp.tool()
def DebugDeleteBreakpoint(addr: str) -> str:
    """
    Delete breakpoint at address using Script API

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")

    Returns:
        Status message
    """
    normalized = _normalize_hex(addr)
    if not normalized:
        return "Breakpoint already absent"
    before_present = _breakpoint_exists(normalized)
    if before_present is False:
        return "Breakpoint already absent"
    try:
        return safe_get("Debug/DeleteBreakpoint", {"addr": normalized})
    except Exception as exc:
        after_present = _breakpoint_exists(normalized)
        if before_present is False or after_present is False:
            message = "Breakpoint already absent"
            _log_event(
                "debug_delete_breakpoint_soft_absent",
                addr=normalized,
                previousState=before_present,
                error=str(exc),
            )
            return message
        raise


@mcp.tool()
def AssemblerAssemble(addr: str, instruction: str) -> dict:
    """
    Assemble instruction at address using Script API

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        instruction: Assembly instruction (e.g. "mov eax, 1")

    Returns:
        Dictionary with assembly result
    """
    result = safe_get("Assembler/Assemble", {"addr": addr, "instruction": instruction})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse assembly result", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def AssemblerAssembleMem(addr: str, instruction: str) -> str:
    """
    Assemble instruction directly into memory using Script API

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        instruction: Assembly instruction (e.g. "mov eax, 1")

    Returns:
        Status message
    """
    return safe_get("Assembler/AssembleMem", {"addr": addr, "instruction": instruction})


@mcp.tool()
def StackPop() -> str:
    """
    Pop value from stack using Script API

    Returns:
        Popped value in hex format
    """
    return safe_get("Stack/Pop")


@mcp.tool()
def StackPush(value: str) -> str:
    """
    Push value to stack using Script API

    Parameters:
        value: Value to push (in hex format, e.g. "0x1000")

    Returns:
        Previous top value in hex format
    """
    return safe_get("Stack/Push", {"value": value})


@mcp.tool()
def StackPeek(offset: str = "0") -> str:
    """
    Peek at stack value using Script API

    Parameters:
        offset: Stack offset (default: "0")

    Returns:
        Stack value in hex format
    """
    return safe_get("Stack/Peek", {"offset": offset})


@mcp.tool()
def FlagGet(flag: str) -> bool:
    """
    Get CPU flag value using TitanEngine

    Parameters:
        flag: Flag name (ZF, OF, CF, PF, SF, TF, AF, DF, IF)

    Returns:
        Flag value (True/False)
    """
    result = safe_get("Flag/Get", {"flag": flag})
    if isinstance(result, bool):
        return result
    if isinstance(result, str):
        return result.lower() == "true"
    return False


@mcp.tool()
def FlagSet(flag: str, value: bool) -> str:
    """
    Set CPU flag value using Script API

    Parameters:
        flag: Flag name (ZF, OF, CF, PF, SF, TF, AF, DF, IF)
        value: Flag value (True/False)

    Returns:
        Status message
    """
    return safe_get("Flag/Set", {"flag": flag, "value": "true" if value else "false"})


@mcp.tool()
def PatternFindMem(start: str, size: str, pattern: str) -> str:
    """
    Find pattern in memory using Script API

    Parameters:
        start: Start address (in hex format, e.g. "0x1000")
        size: Size to search IN DECIMAL
        pattern: Pattern to find (e.g. "48 8B 05 ?? ?? ?? ??")

    Returns:
        Found address in hex format or error message
    """
    return safe_get(
        "Pattern/FindMem", {"start": start, "size": size, "pattern": pattern}
    )


@mcp.tool()
def MiscParseExpression(expression: str) -> str:
    """
    Parse expression using Script API (numeric / duint result only NO STRINGS).

    Parameters:
        expression: Expression to parse (e.g. "[rsp+8]" or "cip")

    Returns:
        Parsed value in hex format
    """
    payload = _coerce_json_payload(
        safe_get(
            "Misc/ParseExpression",
            {"expression": expression, "format": "json"},
            log=False,
        )
    )
    if isinstance(payload, dict) and payload.get("ok") and payload.get("value"):
        return str(payload.get("value"))

    batch_payload = EvalBatch(json.dumps([expression]))
    if isinstance(batch_payload, dict):
        items = batch_payload.get("items") or []
        if (
            items
            and isinstance(items[0], dict)
            and items[0].get("success")
            and items[0].get("value")
        ):
            return str(items[0].get("value"))

    raw = safe_get("Misc/ParseExpression", {"expression": expression}, log=False)
    return str(raw)


@mcp.tool()
def MiscRemoteGetProcAddress(module: str, api: str) -> str:
    """
    Get remote procedure address using Script API

    Parameters:
        module: Module name (e.g. "kernel32.dll")
        api: API name (e.g. "GetProcAddress")

    Returns:
        Function address in hex format
    """
    return safe_get("Misc/RemoteGetProcAddress", {"module": module, "api": api})


@mcp.tool()
def DisasmGetInstructionRange(addr: str, count: int = 1) -> dict:
    """
    Get disassembly of multiple instructions starting at the specified address

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        count: Number of instructions to disassemble (default: 1, max: 100)

    Returns:
        Dict with address, count, and instructions[] list
    """
    payload = _coerce_json_payload(
        safe_get(
            "Disasm/GetInstructionRange", {"addr": addr, "count": str(count)}, log=False
        )
    )
    items: List[Dict[str, Any]] = []
    if isinstance(payload, list):
        items = [item for item in payload if isinstance(item, dict)]
    elif isinstance(payload, dict):
        if isinstance(payload.get("items"), list):
            items = [i for i in payload["items"] if isinstance(i, dict)]
        elif isinstance(payload.get("instructions"), list):
            items = [i for i in payload["instructions"] if isinstance(i, dict)]
        elif any(key in payload for key in ("address", "instruction", "size")):
            items = [payload]
    return {
        "ok": bool(items),
        "addr": addr,
        "requestedCount": int(count),
        "count": len(items),
        "instructions": items,
    }


@mcp.tool()
def StepInWithDisasm(timeout_ms: int = 5000) -> dict:
    """
    Step into the next instruction and return both step result and current instruction disassembly.

    Returns:
        Dictionary containing step result and current instruction info
    """
    step_result = DebugStepIn()
    wait_state = WaitForPause(timeout_ms=max(250, int(timeout_ms)), poll_ms=50)
    rip = None
    if isinstance(wait_state, dict):
        rip = wait_state.get("rip")
        if not rip:
            state_payload = wait_state.get("state")
            if isinstance(state_payload, dict):
                rip = state_payload.get("ip") or state_payload.get("address")
    instruction = _current_instruction(rip)
    return {
        "ok": bool(step_result.get("ok", True))
        and isinstance(wait_state, dict)
        and str(wait_state.get("state") or "").lower() == "paused",
        "stepResult": step_result,
        "waitState": wait_state,
        "rip": _normalize_hex(rip),
        "instruction": instruction,
    }


def _parse_module_list_payload(result: Any) -> Optional[List[Dict[str, Any]]]:
    """Normalize HTTP/MCP payloads into a list of module dicts."""
    if isinstance(result, list):
        return [m for m in result if isinstance(m, dict)]
    if isinstance(result, str):
        try:
            data = json.loads(result)
            return (
                [m for m in data if isinstance(m, dict)]
                if isinstance(data, list)
                else None
            )
        except json.JSONDecodeError:
            return None
    if isinstance(result, dict):
        if "data" in result:
            nested = _parse_module_list_payload(result.get("data"))
            if nested is not None:
                return nested
        if "raw" in result and isinstance(result["raw"], str):
            try:
                data = json.loads(result["raw"])
                if isinstance(data, list):
                    return [m for m in data if isinstance(m, dict)]
            except json.JSONDecodeError:
                pass
        if "modules" in result and isinstance(result["modules"], list):
            return [m for m in result["modules"] if isinstance(m, dict)]
    return None


@mcp.tool()
def GetModuleList() -> dict:
    """
    Get list of loaded modules.

    Returns:
        Dictionary with count, modules (list of objects), and summary (human-readable lines).
    """
    attempts = 0
    result: Any = None
    modules: Optional[List[Dict[str, Any]]] = None
    while attempts < 4:
        attempts += 1
        result = safe_get("GetModuleList")
        modules = _parse_module_list_payload(result)
        if modules is None or modules:
            break
        debugging_payload = safe_get("Is_Debugging", log=False)
        debugging = bool(
            isinstance(debugging_payload, dict)
            and debugging_payload.get("isDebugging") is True
        )
        if not debugging:
            break
        time.sleep(0.05 * attempts)

    if modules is None:
        return {
            "error": "Failed to get or parse module list",
            "detail": str(result)[:2000] if result is not None else None,
            "attempts": attempts,
        }

    lines: List[str] = []
    for m in modules:
        name = m.get("name", "?")
        base = m.get("base", "")
        size = m.get("size", "")
        entry = m.get("entry", "")
        path = m.get("path", "")
        lines.append(f"{name:<40} base={base:<14} size={size:<14} entry={entry}")
        if path:
            lines.append(f"  path: {path}")

    return {
        "count": len(modules),
        "modules": modules,
        "summary": "\n".join(lines),
        "attempts": attempts,
        "ready": bool(modules),
        "reason": None if modules else "No modules are currently available.",
    }


@mcp.tool()
def QuerySymbols(module: str, offset: int = 0, limit: int = 5000) -> dict:
    """
    Enumerate symbols for a specific module. Use GetModuleList first to discover module names.
    Returns imports, exports, and user-defined function symbols for the given module.

    Args:
        module: Module name to query symbols for (e.g. "kernel32.dll", "ntdll.dll"). Required.
        offset: Pagination offset - number of symbols to skip (default: 0)
        limit: Maximum number of symbols to return per page (default: 5000, max: 50000)

    Returns:
        Dictionary with:
        - total: Total number of symbols in the module
        - module: The module name queried
        - offset: Current offset
        - limit: Current limit
        - symbols: List of symbol objects with rva, name, manual, type fields
    """
    params = {
        "module": module,
        "offset": str(offset),
        "limit": str(limit),
    }

    result = safe_get("SymbolEnum", params)

    # Parse JSON response if it's a string
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}

    if isinstance(result, dict) and result.get("symbols"):
        return result

    # Script::Symbol::GetList is allowed to return no PE exports on freshly
    # loaded images even though expression resolution already knows them.
    # Recover the named export table from the exact loaded module on disk. This
    # is read-only, ASLR-safe (RVAs), and also works after symbol servers fail.
    requested = Path(str(module or "")).name.casefold()
    requested_stem = Path(requested).stem
    module_record: Dict[str, Any] = {}
    module_payload = GetModuleList()
    for candidate in (
        module_payload.get("modules", [])
        if isinstance(module_payload, dict)
        else []
    ):
        if not isinstance(candidate, dict):
            continue
        candidate_name = Path(
            str(candidate.get("name") or candidate.get("path") or "")
        ).name.casefold()
        if candidate_name == requested or Path(candidate_name).stem == requested_stem:
            module_record = candidate
            break
    module_path = str(module_record.get("path") or "")
    if module_path and os.path.isfile(module_path):
        try:
            static_exports = [
                {
                    "rva": item.get("rva"),
                    "name": item.get("name"),
                    "manual": False,
                    "type": "export",
                    "ordinal": item.get("ordinal"),
                    "forwarder": item.get("forwarder"),
                    "source": "pe_export_directory",
                }
                for item in (_parse_pe_layout(module_path).get("exports") or [])
                if isinstance(item, dict) and item.get("name")
            ]
            safe_offset = max(0, int(offset))
            safe_limit = max(1, min(int(limit), 50000))
            page = static_exports[safe_offset : safe_offset + safe_limit]
            return {
                "ok": True,
                "total": len(static_exports),
                "module": str(module or ""),
                "offset": safe_offset,
                "limit": safe_limit,
                "symbols": page,
                "hasMore": safe_offset + len(page) < len(static_exports),
                "fallback": "pe_export_directory",
            }
        except Exception as exc:
            if isinstance(result, dict):
                result = dict(result)
                result["staticExportFallbackError"] = str(exc)

    return result


@mcp.tool()
def GetThreadList() -> dict:
    """
    Get list of all threads in the debugged process with detailed information.

    Returns:
        Dictionary with:
        - count: Number of threads
        - currentThread: Index of the currently focused thread
        - threads: List of thread objects with threadNumber, threadId, threadName,
          startAddress, localBase, cip, suspendCount, priority, waitReason,
          lastError, cycles
    """
    result = safe_get("GetThreadList")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse thread list", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetTebAddress(tid: str) -> dict:
    """
    Get the Thread Environment Block (TEB) address for a specific thread.
    Use GetThreadList first to discover thread IDs.

    Args:
        tid: Thread ID (decimal integer string, e.g. "1234")

    Returns:
        Dictionary with tid and tebAddress fields
    """
    result = safe_get("GetTebAddress", {"tid": tid})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse TEB response", "raw": result}
    return {"error": "Unexpected response format"}


def _exec_command_action(cmd: str, timeout_sec: float = 15.0) -> Dict[str, Any]:
    """Run a side-effecting x64dbg command through the bridge and normalize the result.

    Used by the typed convenience tools (thread control, conditional tracing,
    symbol loading) that wrap raw x64dbg commands. Returns a uniform envelope:
        {"ok": bool, "command": str, "success": bool, "error"?: str, "raw"?: ...}
    """
    cmd = str(cmd or "").strip()
    if not cmd:
        return {"ok": False, "command": cmd, "error": "Empty command"}
    result = safe_get("ExecCommand", {"cmd": cmd, "offset": 0, "limit": 1}, timeout_sec=timeout_sec)
    if isinstance(result, dict):
        success = bool(result.get("success"))
        payload: Dict[str, Any] = {"ok": success, "command": cmd, "success": success}
        if not success and result.get("error"):
            payload["error"] = str(result.get("error"))
        return payload
    if isinstance(result, str):
        return {"ok": False, "command": cmd, "error": result}
    return {"ok": False, "command": cmd, "error": "Unexpected response format", "raw": str(result)[:500]}


def _x64dbg_thread_id_expr(tid: str) -> str:
    """Normalize a thread id to a 0x-hex literal for x64dbg commands.

    GetThreadList reports thread ids in decimal, but x64dbg's command/expression
    parser treats bare numbers as HEX by default, so passing the decimal id
    silently targets the wrong (or no) thread. Convert to an explicit 0x-hex
    literal so the exact value is used. Accepts decimal or 0x-hex input.
    """
    s = str(tid or "").strip()
    if not s:
        return ""
    try:
        if s.lower().startswith("0x"):
            n = int(s, 16)
        elif s.isdigit():
            n = int(s, 10)
        else:
            n = int(s, 16)
        return f"0x{n:x}"
    except Exception:
        return s


@mcp.tool()
def SuspendThread(tid: str = "") -> dict:
    """
    Suspend a thread in the debuggee (increments its Windows suspend count).

    Args:
        tid: Thread ID (decimal, as GetThreadList reports it, or 0x-prefixed hex).
             Empty string suspends the currently active thread.

    Returns:
        Uniform action envelope: {"ok", "command", "success", "error"?}.
        Undo with ResumeThread. Requires an active debug session.
    """
    return _exec_command_action(f"suspendthread {_x64dbg_thread_id_expr(tid)}".strip())


@mcp.tool()
def ResumeThread(tid: str = "") -> dict:
    """
    Resume a previously suspended thread (decrements its suspend count).

    Args:
        tid: Thread ID (decimal, as GetThreadList reports it, or 0x-hex). Empty
             string resumes the currently active thread.

    Returns:
        Uniform action envelope: {"ok", "command", "success", "error"?}.
    """
    return _exec_command_action(f"resumethread {_x64dbg_thread_id_expr(tid)}".strip())


@mcp.tool()
def SuspendAllThreads() -> dict:
    """
    Suspend every thread in the debuggee at once (freeze the target).

    Returns:
        Uniform action envelope: {"ok", "command", "success", "error"?}.
        Undo with ResumeAllThreads.
    """
    return _exec_command_action("suspendallthreads")


@mcp.tool()
def ResumeAllThreads() -> dict:
    """
    Resume every previously suspended thread in the debuggee.

    Returns:
        Uniform action envelope: {"ok", "command", "success", "error"?}.
    """
    return _exec_command_action("resumeallthreads")


@mcp.tool()
def SwitchThread(tid: str) -> dict:
    """
    Make the given thread the active/current thread so register reads/writes and
    stepping operate on it. Combine with RegisterSet to modify a specific thread's
    context (x64dbg has no single set-thread-context command).

    Args:
        tid: Thread ID (decimal, as GetThreadList reports it, or 0x-hex). Required.

    Returns:
        Uniform action envelope: {"ok", "command", "success", "error"?}.
    """
    tid = str(tid or "").strip()
    if not tid:
        return {"ok": False, "error": "tid is required"}
    return _exec_command_action(f"switchthread {_x64dbg_thread_id_expr(tid)}")


@mcp.tool()
def SetThreadPriority(tid: str, priority: str) -> dict:
    """
    Set a thread's scheduling priority.

    Args:
        tid: Thread ID (decimal, as GetThreadList reports it, or 0x-hex). Required.
        priority: One of "Normal", "AboveNormal", "BelowNormal", "Highest", "Lowest",
                  "Idle", "TimeCritical" (or an integer Windows priority value).

    Returns:
        Uniform action envelope: {"ok", "command", "success", "error"?}.
    """
    tid = str(tid or "").strip()
    priority = str(priority or "").strip()
    if not tid or not priority:
        return {"ok": False, "error": "Both tid and priority are required"}
    return _exec_command_action(f"setthreadpriority {_x64dbg_thread_id_expr(tid)}, {priority}")


def _conditional_trace(
    step_cmd: str,
    condition: str,
    log_text: str = "",
    log_file: str = "",
    max_steps: int = 0,
) -> Dict[str, Any]:
    condition = str(condition or "").strip()
    if not condition:
        return {"ok": False, "error": "condition is required"}
    commands: List[str] = []
    if str(log_file or "").strip():
        commands.append(f'TraceSetLogFile "{str(log_file).strip()}"')
    if str(log_text or "").strip():
        commands.append(f'TraceSetLog "{str(log_text).strip()}"')
    trace_arg = f'"{condition}"'
    try:
        steps = int(max_steps)
    except Exception:
        steps = 0
    if steps > 0:
        # x64dbg parses the count as hex by default; emit an explicit 0x literal.
        trace_arg += f", 0x{steps:x}"
    commands.append(f"{step_cmd} {trace_arg}")
    results: List[Dict[str, Any]] = []
    ok = True
    for c in commands:
        r = _exec_command_action(c)
        results.append(r)
        if not r.get("ok"):
            ok = False
            break
    return {"ok": ok, "command": commands[-1], "commandsRun": commands, "results": results}


@mcp.tool()
def TraceIntoConditional(
    condition: str, log_text: str = "", log_file: str = "", max_steps: int = 0
) -> dict:
    """
    Start a step-INTO trace that runs until a break condition is true, optionally
    logging an expression at every traced step (x64dbg 'ticnd').

    This is x64dbg's classic conditional trace: it single-steps INTO calls while
    the break condition is false and stops the moment it becomes true. Add a log
    expression to record register/memory state along the way, and a log file to
    persist it.

    Args:
        condition: x64dbg expression that stops the trace when non-zero, e.g.
                   "eip==0x401000" or "eax==0". Required.
        log_text: Optional log format string evaluated each step and appended to
                  the trace log, e.g. "{eax} {ecx}".
        log_file: Optional path to also write the trace log to a file.
        max_steps: Optional cap on the number of steps (0 = rely on x64dbg's
                   configured maximum).

    Returns:
        {"ok", "command", "commandsRun", "results"}. Requires an active, paused
        debug session; inspect results afterwards via the trace record/log tools.
    """
    return _conditional_trace("TraceIntoConditional", condition, log_text, log_file, max_steps)


@mcp.tool()
def TraceOverConditional(
    condition: str, log_text: str = "", log_file: str = "", max_steps: int = 0
) -> dict:
    """
    Start a step-OVER trace that runs until a break condition is true, optionally
    logging an expression at every traced step (x64dbg 'tocnd').

    Same as TraceIntoConditional but steps OVER calls instead of into them — use
    this to trace within the current function without descending into callees.

    Args:
        condition: x64dbg expression that stops the trace when non-zero. Required.
        log_text: Optional per-step log format string, e.g. "{eax} {ecx}".
        log_file: Optional path to also write the trace log to a file.
        max_steps: Optional cap on the number of steps (0 = configured maximum).

    Returns:
        {"ok", "command", "commandsRun", "results"}. Requires an active, paused
        debug session.
    """
    return _conditional_trace("TraceOverConditional", condition, log_text, log_file, max_steps)


@mcp.tool()
def LoadSymbolsForModule(module: str = "", symbol_store: str = "", download: bool = True) -> dict:
    """
    Download and/or load debug symbols (PDB) for a module, so that later symbol
    queries and disassembly resolve function/variable names.

    Args:
        module: Module name, with or without extension (e.g. "target.exe",
                "ntdll"). Empty applies to all loaded modules.
        symbol_store: Optional symbol-store URL. Empty uses x64dbg's configured
                      default store (typically the Microsoft symbol server).
        download: When True (default) run 'symdownload' to fetch symbols from the
                  store first; when False only 'symload' already-present symbols.

    Returns:
        {"ok", "commandsRun", "results"}. Query resolved symbols afterwards with
        QuerySymbols. Requires an active debug session.
    """
    module = str(module or "").strip()
    symbol_store = str(symbol_store or "").strip()
    commands: List[str] = []
    if download:
        cmd = "symdownload"
        if symbol_store:
            cmd += f" {module}, {symbol_store}"
        elif module:
            cmd += f" {module}"
        commands.append(cmd)
    commands.append(f"symload {module}".strip())
    results: List[Dict[str, Any]] = []
    ok = True
    for c in commands:
        r = _exec_command_action(c)
        results.append(r)
        if not r.get("ok"):
            ok = False
    return {"ok": ok, "commandsRun": commands, "results": results}


@mcp.tool()
def SaveMemoryRegionToFile(output_path: str, addr: str, size: int) -> dict:
    """
    Dump an arbitrary memory region of the debuggee to a file on disk (x64dbg
    'savedata'). Use this to extract a decrypted/unpacked payload, injected
    shellcode, a config blob, or any private/heap buffer — unlike DumpModule,
    which dumps a whole PE module via Scylla.

    Args:
        output_path: Destination file path (on the debugger machine). Required.
        addr: Start address (hex "0x..." or an x64dbg expression). Required.
        size: Number of bytes to save. Required, must be > 0.

    Returns:
        {"ok", "output", "addr", "size", "exists", "sizeOnDisk", "command", ...}.
        `ok` is true only if the file was actually written. Requires an active session.
    """
    output_path = str(output_path or "").strip()
    addr = str(addr or "").strip()
    try:
        size_i = int(size)
    except Exception:
        size_i = 0
    if not output_path or not addr or size_i <= 0:
        return {"ok": False, "error": "output_path, addr and a positive size are required"}
    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir and not os.path.isdir(out_dir):
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception:
            pass
    # x64dbg parses command numbers as hex by default, so pass the size as an
    # explicit 0x-hex literal (a bare "4096" would be read as 0x4096 = 16534).
    result = _exec_command_action(f'savedata "{output_path}", {addr}, 0x{size_i:x}')
    exists = os.path.exists(output_path)
    result.update(
        {
            "output": output_path,
            "addr": addr,
            "size": size_i,
            "exists": exists,
            "sizeOnDisk": os.path.getsize(output_path) if exists else 0,
        }
    )
    result["ok"] = bool(result.get("ok") and exists)
    return result


_MINIDUMP_STREAM_NAMES = {
    0: "UnusedStream",
    1: "ReservedStream0",
    2: "ReservedStream1",
    3: "ThreadListStream",
    4: "ModuleListStream",
    5: "MemoryListStream",
    6: "ExceptionStream",
    7: "SystemInfoStream",
    8: "ThreadExListStream",
    9: "Memory64ListStream",
    10: "CommentStreamA",
    11: "CommentStreamW",
    12: "HandleDataStream",
    13: "FunctionTableStream",
    14: "UnloadedModuleListStream",
    15: "MiscInfoStream",
    16: "MemoryInfoListStream",
    17: "ThreadInfoListStream",
    18: "HandleOperationListStream",
    19: "TokenStream",
    20: "JavaScriptDataStream",
    21: "SystemMemoryInfoStream",
    22: "ProcessVmCountersStream",
    23: "IptTraceStream",
    24: "ThreadNamesStream",
}

_MINIDUMP_PROFILES = {
    "normal": {
        "flags": 0x00000000,
        "description": "Small standard dump: threads, modules and selected stack memory.",
    },
    "triage": {
        "flags": 0x000A1924,
        "description": "Compact reverse-engineering triage dump with handles, unloaded modules, thread and module metadata.",
    },
    "analysis": {
        "flags": 0x000A3B65,
        "description": "Recommended dump with private read/write, indirect, code/data, handle, thread and module metadata.",
    },
    "full": {
        "flags": 0x000F3B67,
        "description": "Full-memory dump plus analysis metadata; can be as large as the target address space in use.",
    },
}


def _resolve_minidump_type(dump_type: str, custom_flags: str = "") -> Dict[str, Any]:
    raw_custom = str(custom_flags or "").strip()
    requested = str(dump_type or "analysis").strip().lower()
    if raw_custom:
        requested = "custom"
        raw_value = raw_custom
    elif requested in _MINIDUMP_PROFILES:
        value = int(_MINIDUMP_PROFILES[requested]["flags"])
        return {
            "ok": True,
            "profile": requested,
            "flags": value,
            "flagsHex": f"0x{value:x}",
            "description": _MINIDUMP_PROFILES[requested]["description"],
        }
    else:
        raw_value = requested
        requested = "custom"
    try:
        value = int(raw_value, 0)
    except (TypeError, ValueError):
        return {
            "ok": False,
            "error": "dump_type must name a known profile or be a 32-bit numeric mask",
            "requested": dump_type,
            "customFlags": custom_flags or None,
        }
    if value < 0 or value > 0xFFFFFFFF:
        return {"ok": False, "error": "MiniDump type flags must fit in 32 bits"}
    return {
        "ok": True,
        "profile": requested,
        "flags": value,
        "flagsHex": f"0x{value:x}",
        "description": "Caller-supplied MINIDUMP_TYPE bitmask.",
    }


def _minidump_range_valid(offset: int, size: int, file_size: int) -> bool:
    return (
        isinstance(offset, int)
        and isinstance(size, int)
        and offset >= 0
        and size >= 0
        and offset <= file_size
        and size <= file_size - offset
    )


def _read_minidump_string(handle: Any, rva: int, file_size: int) -> Optional[str]:
    if not _minidump_range_valid(int(rva), 4, file_size):
        return None
    handle.seek(int(rva))
    raw_length = handle.read(4)
    if len(raw_length) != 4:
        return None
    byte_length = struct.unpack("<I", raw_length)[0]
    if byte_length > 1_048_576 or byte_length % 2:
        return None
    if not _minidump_range_valid(int(rva) + 4, byte_length, file_size):
        return None
    raw = handle.read(byte_length)
    if len(raw) != byte_length:
        return None
    return raw.decode("utf-16-le", errors="replace").rstrip("\x00")


def _inspect_minidump_file(path: str, max_modules: int = 256) -> Dict[str, Any]:
    resolved = os.path.abspath(str(path or ""))
    if not resolved or not os.path.isfile(resolved):
        return {"ok": False, "valid": False, "path": resolved, "error": "MiniDump file not found"}
    file_size = os.path.getsize(resolved)
    errors: List[str] = []
    warnings_list: List[str] = []
    streams: List[Dict[str, Any]] = []
    modules: List[Dict[str, Any]] = []
    architecture = "unknown"
    thread_count: Optional[int] = None
    module_count: Optional[int] = None
    memory_range_count: Optional[int] = None
    flags = 0
    timestamp = 0
    version = 0
    try:
        with open(resolved, "rb") as handle:
            header = handle.read(32)
            if len(header) != 32:
                return {
                    "ok": False,
                    "valid": False,
                    "path": resolved,
                    "size": file_size,
                    "error": "MiniDump header is truncated",
                }
            signature, version, stream_count, directory_rva, checksum, timestamp, flags = struct.unpack(
                "<IIIIIIQ", header
            )
            if signature != 0x504D444D:
                errors.append("Invalid MDMP signature")
            if stream_count > 65536:
                errors.append("Unreasonable stream count")
            directory_size = int(stream_count) * 12
            if not _minidump_range_valid(int(directory_rva), directory_size, file_size):
                errors.append("Stream directory is outside the file")
                stream_count = 0
            directory: List[Tuple[int, int, int]] = []
            if stream_count:
                handle.seek(int(directory_rva))
                raw_directory = handle.read(directory_size)
                if len(raw_directory) != directory_size:
                    errors.append("Stream directory is truncated")
                else:
                    for index in range(int(stream_count)):
                        stream_type, data_size, rva = struct.unpack_from(
                            "<III", raw_directory, index * 12
                        )
                        in_bounds = _minidump_range_valid(int(rva), int(data_size), file_size)
                        entry = {
                            "index": index,
                            "type": int(stream_type),
                            "name": _MINIDUMP_STREAM_NAMES.get(
                                int(stream_type), f"UnknownStream{int(stream_type)}"
                            ),
                            "rva": f"0x{int(rva):x}",
                            "size": int(data_size),
                            "inBounds": in_bounds,
                        }
                        streams.append(entry)
                        directory.append((int(stream_type), int(data_size), int(rva)))
                        if not in_bounds:
                            errors.append(f"{entry['name']} points outside the file")

            by_type: Dict[int, Tuple[int, int]] = {}
            for stream_type, data_size, rva in directory:
                if stream_type in by_type:
                    warnings_list.append(
                        f"Duplicate {_MINIDUMP_STREAM_NAMES.get(stream_type, stream_type)} stream"
                    )
                by_type.setdefault(stream_type, (data_size, rva))

            system_stream = by_type.get(7)
            if system_stream and system_stream[0] >= 2:
                handle.seek(system_stream[1])
                raw_arch = handle.read(2)
                if len(raw_arch) == 2:
                    arch_value = struct.unpack("<H", raw_arch)[0]
                    architecture = {0: "x86", 5: "arm", 6: "ia64", 9: "x64", 12: "arm64"}.get(
                        arch_value, f"unknown_{arch_value}"
                    )
            elif system_stream:
                errors.append("SystemInfoStream is truncated")

            thread_stream = by_type.get(3) or by_type.get(8)
            if thread_stream:
                data_size, rva = thread_stream
                if data_size < 4:
                    errors.append("Thread list stream is truncated")
                else:
                    handle.seek(rva)
                    thread_count = struct.unpack("<I", handle.read(4))[0]
                    if thread_count > 1_000_000 or 4 + thread_count * 48 > data_size:
                        errors.append("Thread list entries exceed the stream bounds")

            module_stream = by_type.get(4)
            if module_stream:
                data_size, rva = module_stream
                if data_size < 4:
                    errors.append("ModuleListStream is truncated")
                else:
                    handle.seek(rva)
                    module_count = struct.unpack("<I", handle.read(4))[0]
                    required = 4 + int(module_count) * 108
                    if module_count > 1_000_000 or required > data_size:
                        errors.append("Module list entries exceed the stream bounds")
                    else:
                        read_count = min(int(module_count), max(0, min(int(max_modules), 4096)))
                        handle.seek(rva + 4)
                        records = handle.read(read_count * 108)
                        for index in range(read_count):
                            record = records[index * 108 : (index + 1) * 108]
                            if len(record) != 108:
                                errors.append("Module record is truncated")
                                break
                            base, image_size, module_checksum, module_timestamp, name_rva = struct.unpack_from(
                                "<QIIII", record, 0
                            )
                            name = _read_minidump_string(handle, int(name_rva), file_size)
                            if name is None:
                                warnings_list.append(f"Module {index} has an invalid name RVA")
                            modules.append(
                                {
                                    "index": index,
                                    "name": name,
                                    "base": f"0x{int(base):x}",
                                    "size": int(image_size),
                                    "checksum": f"0x{int(module_checksum):x}",
                                    "timestamp": int(module_timestamp),
                                }
                            )

            memory_stream = by_type.get(5)
            if memory_stream:
                data_size, rva = memory_stream
                if data_size < 4:
                    errors.append("MemoryListStream is truncated")
                else:
                    handle.seek(rva)
                    memory_range_count = struct.unpack("<I", handle.read(4))[0]
                    if memory_range_count > 10_000_000 or 4 + memory_range_count * 16 > data_size:
                        errors.append("Memory list entries exceed the stream bounds")
            memory64_stream = by_type.get(9)
            if memory64_stream:
                data_size, rva = memory64_stream
                if data_size < 16:
                    errors.append("Memory64ListStream is truncated")
                else:
                    handle.seek(rva)
                    raw_memory64 = handle.read(16)
                    range_count, base_rva = struct.unpack("<QQ", raw_memory64)
                    memory_range_count = int(range_count)
                    if range_count > 10_000_000 or 16 + range_count * 16 > data_size:
                        errors.append("Memory64 list entries exceed the stream bounds")
                    elif base_rva > file_size:
                        errors.append("Memory64 data base is outside the file")
    except (OSError, struct.error, OverflowError) as exc:
        errors.append(str(exc))

    stream_types = {int(item["type"]) for item in streams if item.get("inBounds")}
    valid = not errors
    analysis_ready = bool(
        valid
        and architecture != "unknown"
        and (module_count or 0) > 0
        and (thread_count or 0) > 0
        and bool(stream_types & {5, 9, 16})
    )
    try:
        timestamp_iso = datetime.fromtimestamp(int(timestamp), timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        timestamp_iso = None
    return {
        "ok": valid,
        "valid": valid,
        "analysisReady": analysis_ready,
        "path": resolved,
        "size": file_size,
        "version": f"0x{int(version):x}",
        "flags": f"0x{int(flags):x}",
        "timestamp": int(timestamp),
        "timestampIso": timestamp_iso,
        "architecture": architecture,
        "streamCount": len(streams),
        "streams": streams,
        "threadCount": thread_count,
        "moduleCount": module_count,
        "modulesReturned": len(modules),
        "modules": modules,
        "memoryRangeCount": memory_range_count,
        "exceptionStreamPresent": 6 in stream_types,
        "errors": errors,
        "warnings": warnings_list,
    }


@mcp.tool()
def GetMiniDumpProfiles() -> dict:
    """List supported MiniDump presets and their exact MINIDUMP_TYPE masks."""
    profiles = [
        {
            "name": name,
            "flags": f"0x{int(profile['flags']):x}",
            "description": profile["description"],
        }
        for name, profile in _MINIDUMP_PROFILES.items()
    ]
    return {"ok": True, "default": "analysis", "profiles": profiles}


@mcp.tool()
def VerifyMiniDump(path: str, compute_sha256: bool = True, max_modules: int = 256) -> dict:
    """Independently validate an MDMP file and summarize streams/modules without loading it."""
    result = _inspect_minidump_file(path, max_modules=max_modules)
    if compute_sha256 and result.get("valid"):
        result["sha256"] = _sha256_file(str(result.get("path") or path))
    else:
        result["sha256"] = None
    return result


@mcp.tool()
def WriteMiniDump(
    output_path: str,
    dump_type: str = "analysis",
    overwrite: bool = False,
    pause_if_running: bool = True,
    resume_after: bool = False,
    compute_sha256: bool = True,
    custom_flags: str = "",
    timeout_ms: int = 120000,
) -> dict:
    """Write and verify a guarded process MiniDump from the active debug session.

    ``dump_type`` is normal, triage, analysis (recommended), full, or a numeric
    MINIDUMP_TYPE mask. ``custom_flags`` supplies an exact mask and overrides
    the preset. The native bridge requires a paused target for a coherent dump;
    this tool can pause it and only resumes when ``resume_after`` is explicit.
    """
    requested_path = str(output_path or "").strip()
    if not requested_path:
        return {"ok": False, "error": "output_path is required"}
    lowered_path = requested_path.replace("/", "\\").lower()
    if lowered_path.startswith("\\\\.\\") or lowered_path.startswith("\\\\?\\globalroot"):
        return {"ok": False, "error": "Device paths are not valid MiniDump destinations"}
    resolved_path = os.path.abspath(requested_path)
    if not os.path.splitext(resolved_path)[1]:
        resolved_path += ".dmp"
    dump_spec = _resolve_minidump_type(dump_type, custom_flags)
    if not dump_spec.get("ok"):
        return dump_spec
    if os.path.exists(resolved_path) and not overwrite:
        return {
            "ok": False,
            "error": "Output file already exists; set overwrite=true to replace it",
            "outputPath": resolved_path,
        }
    try:
        os.makedirs(os.path.dirname(resolved_path), exist_ok=True)
    except OSError as exc:
        return {"ok": False, "error": str(exc), "outputPath": resolved_path}

    hello = BridgeHello(refresh=True)
    hello_payload = hello.get("payload") if isinstance(hello, dict) else {}
    capabilities = hello_payload.get("capabilities") if isinstance(hello_payload, dict) else {}
    if not isinstance(capabilities, dict) or not capabilities.get("minidump"):
        return {
            "ok": False,
            "unsupported": True,
            "error": "The active debugger plugin does not advertise guarded MiniDump support",
            "bridge": hello,
        }
    state = _build_debug_state(include_console=False, include_callstack=False, max_console_chars=0)
    if not state.get("debugging"):
        return {"ok": False, "error": "WriteMiniDump requires an active debug session", "state": state}
    paused_by_tool = False
    if not state.get("paused"):
        if not pause_if_running:
            return {
                "ok": False,
                "error": "Target must be paused (or set pause_if_running=true)",
                "state": state,
            }
        pause_result = DebugPause()
        paused_state = WaitForPause(timeout_ms=min(max(int(timeout_ms), 1000), 10000), poll_ms=50)
        if not isinstance(paused_state, dict) or not paused_state.get("paused"):
            return {
                "ok": False,
                "error": "Failed to pause the target before MiniDump creation",
                "pause": pause_result,
                "state": paused_state,
            }
        paused_by_tool = True

    native: Any = None
    verification: Dict[str, Any] = {}
    resume_result: Any = None
    try:
        native = _coerce_json_payload(
            safe_post(
                "Dump/MiniDump",
                {
                    "outputPath": resolved_path,
                    "dumpType": dump_spec["flagsHex"],
                    "overwrite": str(bool(overwrite)).lower(),
                },
                log=False,
                timeout_sec=max(5.0, min(float(timeout_ms) / 1000.0, 600.0)),
            )
        )
        if os.path.isfile(resolved_path):
            verification = VerifyMiniDump(
                resolved_path,
                compute_sha256=compute_sha256,
                max_modules=256,
            )
    finally:
        if paused_by_tool and resume_after:
            resume_result = DebugRun()

    native_ok = bool(isinstance(native, dict) and native.get("ok"))
    verified = bool(verification.get("valid"))
    result = {
        "ok": native_ok and verified,
        "outputPath": resolved_path,
        "profile": dump_spec["profile"],
        "dumpType": dump_spec["flagsHex"],
        "pausedByTool": paused_by_tool,
        "resumed": bool(paused_by_tool and resume_after),
        "resumeResult": resume_result,
        "native": native,
        "verification": verification or None,
    }
    if not native_ok:
        result["error"] = (
            native.get("error") if isinstance(native, dict) else str(native)
        ) or "Native MiniDump creation failed"
    elif not verified:
        result["error"] = "MiniDump was written but failed independent structural verification"
    return result


@mcp.tool()
def LoadLibraryInDebuggee(path: str) -> dict:
    """
    Load a DLL into the debuggee via x64dbg's 'loadlib' (it runs a small stub that
    calls LoadLibrary inside the target). Useful to force-load a helper /
    instrumentation DLL or a delay-loaded dependency.

    Args:
        path: DLL name or full path to load into the target. Required.

    Returns:
        {"ok", "command", "success", "error"?}. Confirm the library appeared with
        GetModuleList. Requires an active, paused debug session.
    """
    path = str(path or "").strip()
    if not path:
        return {"ok": False, "error": "path is required"}
    return _exec_command_action(f'loadlib "{path}"')


@mcp.tool()
def StartRunTraceToFile(output_path: str) -> dict:
    """
    Begin a full run trace to a reloadable .trace file (x64dbg 'StartRunTrace').
    Records executed instructions plus register deltas as the target runs/steps —
    far richer than the in-memory bitmap coverage (StartTraceRecord) or the
    step-limited TraceInstructionTape. After starting, run or step the target,
    then call StopRunTrace to flush the file.

    Args:
        output_path: Destination trace file. If it has no extension, the correct
                     '.trace64'/'.trace32' for the active arch is appended.

    Returns:
        {"ok", "output", "command", ...}. Requires an active, paused debug session.
    """
    output_path = str(output_path or "").strip()
    if not output_path:
        return {"ok": False, "error": "output_path is required"}
    if not os.path.splitext(output_path)[1]:
        arch = str((_get_active_debugger_info() or {}).get("arch") or "").lower()
        output_path += ".trace32" if arch == "x86" else ".trace64"
    out_dir = os.path.dirname(os.path.abspath(output_path))
    if out_dir and not os.path.isdir(out_dir):
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception:
            pass
    result = _exec_command_action(f'StartRunTrace "{output_path}"')
    result["output"] = output_path
    return result


@mcp.tool()
def StopRunTrace() -> dict:
    """
    Stop the run trace started with StartRunTraceToFile and flush the .trace file
    to disk (x64dbg 'StopRunTrace'). Open the resulting file in x64dbg's Trace view
    to replay the recorded instructions and register history.

    Returns:
        {"ok", "command", "success", "error"?}.
    """
    return _exec_command_action("StopRunTrace")


@mcp.tool()
def MemoryBase(addr: str) -> dict:
    """
    Find the base address and size of a module containing the given address

    Parameters:
        addr: Memory address (in hex format, e.g. "0x7FF12345")

    Returns:
        Dictionary containing base_address and size of the module
    """
    try:
        # Make the request to the endpoint
        result = safe_get("MemoryBase", {"addr": addr})

        # Handle different response types
        if isinstance(result, dict):
            return result
        elif isinstance(result, str):
            try:
                # Try to parse the string as JSON
                return json.loads(result)
            except Exception:
                # Fall back to string parsing if needed
                if "," in result:
                    parts = result.split(",")
                    return {"base_address": parts[0], "size": parts[1]}
                return {"raw_response": result}

        return {"error": "Unexpected response format"}

    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def SetPageRights(addr: str, rights: str) -> bool:
    """
    Set memory page protection rights at a given address

    Args:
        addr: Virtual address (hex string, e.g. "0x401000")
        rights: Rights string (e.g. "rwx", "rx", "rw")

    Returns:
        True if successful, False otherwise
    """
    params = {"addr": addr, "rights": rights}

    result = safe_post("Memory/SetPageRights", params)

    if isinstance(result, dict):
        return result.get("success", False) is True

    if isinstance(result, str):
        try:
            import json

            parsed = json.loads(result)
            return parsed.get("success", False) is True
        except Exception:
            return result.strip().lower() in ("ok", "true", "success")

    return False


@mcp.tool()
def StringGetAt(addr: str) -> dict:
    """
    Retrieve the string at a given address in the debugged process.
    Uses x64dbg's internal string detection (same as the disassembly view).

    Parameters:
        addr: Memory address (in hex format, e.g. "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - found: Whether a string was detected at that address
        - string: The string content (empty if not found)
    """
    result = safe_get("String/GetAt", {"addr": addr})
    payload = result if isinstance(result, dict) else None
    if payload is None and isinstance(result, str):
        try:
            payload = json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    if not isinstance(payload, dict):
        return {"error": "Unexpected response format"}
    # Filter bytes that x64dbg flagged as a string but are obviously instruction
    # bytes / binary noise. Common culprits: x86/x64 function prologues like
    # "UVWSHРјhHРЊl$`HР—E" (push rbp/rsi/rdi/rbx + sub rsp,... + mov to stack)
    # that happen to contain enough printable chars to fool x64dbg's heuristic.
    s = str(payload.get("string", "") or "")
    if s and payload.get("found"):
        reject_reason: Optional[str] = None
        printable = sum(1 for c in s if 32 <= ord(c) < 127)
        ratio = printable / max(len(s), 1)
        if ratio < 0.6:
            reject_reason = "low_printable_ratio"
        else:
            # Mojibake detection: mixed cyrillic + latin from bad UTF-8 decode.
            cyr = sum(1 for c in s if 0x400 < ord(c) < 0x500)
            latin = sum(1 for c in s if c.isalpha() and ord(c) < 128)
            if cyr >= 2 and latin >= 2:
                reject_reason = "mojibake_mix"
            else:
                # Instruction-prologue heuristic: x86/x64 prologues decoded as
                # ASCII start with uppercase register-push sequences (UVWSH =
                # push rbp/rsi/rdi/rbx + sub). >=4 consecutive uppercase at
                # start + any non-ASCII = almost certainly code bytes.
                head_upper = 0
                for c in s:
                    if 65 <= ord(c) <= 90:
                        head_upper += 1
                    else:
                        break
                has_nonascii = any(ord(c) >= 128 for c in s)
                if head_upper >= 4 and has_nonascii:
                    reject_reason = "instruction_prologue_pattern"
        if reject_reason:
            payload["found"] = False
            payload["rejected"] = True
            payload["rejectReason"] = reject_reason
            payload["originalString"] = s
            payload["string"] = ""
    return payload


@mcp.tool()
def XrefGet(
    addr: str,
    offset: int = 0,
    limit: int = 100,
    detail: str = "",
) -> dict:
    """
    Get all cross-references (xrefs) TO the specified address.
    Returns the list of addresses that reference the target address,
    along with the type of each reference (data, jmp, call).

    Note: Results depend on x64dbg's analysis database. Run analysis
    first for comprehensive results.

    Parameters:
        addr: Target address to find references to (hex format, e.g. "0x1400010a0")
        offset: Zero-based reference offset for compatibility pagination.
        limit: Maximum references to return (1..5000).
        detail: summary or full. Empty inherits the active tool profile.

    Returns:
        Dictionary with:
        - address: The queried target address
        - refcount: Number of cross-references found
        - references: List of reference objects, each with:
          - addr: Address of the referrer (the instruction that references the target)
          - type: Reference type ("data", "jmp", "call", or "none")
          - string: Optional string context at the referrer address
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
    result = safe_get(
        "Xref/Get",
        {"addr": addr, "offset": str(safe_offset), "limit": str(safe_limit)},
    )
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    if not isinstance(result, dict):
        return {"error": "Unexpected response format"}

    references = [
        dict(item)
        for item in (result.get("references") or [])
        if isinstance(item, dict)
    ]
    native_paging = any(
        key in result for key in ("offset", "returned", "hasMore", "nextOffset")
    )
    total = int(result.get("refcount") or len(references))
    if native_paging:
        page = references[:safe_limit]
        page_offset = int(result.get("offset") or safe_offset)
    else:
        # Older bridges ignore the new query parameters. Keep compatibility by
        # applying the exact same page contract at the Python boundary.
        page_offset = safe_offset
        page = references[page_offset : page_offset + safe_limit]
    returned = len(page)
    has_more = bool(result.get("hasMore")) if native_paging else page_offset + returned < total
    next_offset = (
        int(result.get("nextOffset") or (page_offset + returned))
        if has_more
        else None
    )

    module_payload = GetModuleList()
    modules = (
        module_payload.get("modules", [])
        if isinstance(module_payload, dict)
        and isinstance(module_payload.get("modules"), list)
        else []
    )

    def _module_location(value: Any) -> Dict[str, Any]:
        address = _parse_int(value, None)
        if address is None:
            return {}
        for module in modules:
            if not isinstance(module, dict):
                continue
            base = _parse_int(module.get("base"), None)
            size = _parse_int(module.get("size"), 0) or 0
            if base is not None and size > 0 and base <= address < base + size:
                return {
                    "module": module.get("name"),
                    "moduleBase": _normalize_hex(base),
                    "rva": f"0x{address - base:X}",
                }
        return {}

    enriched: List[Dict[str, Any]] = []
    for item in page:
        row = dict(item)
        row.update(_module_location(row.get("addr")))
        row["source"] = "x64dbg_analysis_database"
        row["confidence"] = "analyzed"
        enriched.append(row)

    payload: Dict[str, Any] = dict(result) if detail_level == "full" else {}
    payload.update(
        {
            # Preserve an application-level native failure even when the
            # legacy bridge returned a JSON object without a string ``error``.
            # Older bridges often omit ``ok`` on success, so the default stays
            # permissive while an explicit false is never upgraded to true.
            "ok": bool(result.get("ok", True)) and "error" not in result,
            "address": result.get("address") or _normalize_hex(addr) or addr,
            "target": _module_location(result.get("address") or addr),
            "refcount": total,
            "offset": page_offset,
            "returned": returned,
            "pageSize": returned,
            "hasMore": has_more,
            "nextCursor": str(next_offset) if next_offset is not None else None,
            "references": enriched,
            "source": "x64dbg_analysis_database",
            "analysisDependent": True,
        }
    )
    if detail_level == "summary":
        payload["availableDetails"] = ["nativeAnalyzerPayload"]
    return payload


@mcp.tool()
def XrefCount(addr: str) -> dict:
    """
    Get the count of cross-references to the specified address.
    This is a lightweight check that doesn't fetch the full reference list.

    Parameters:
        addr: Target address to count references for (hex format, e.g. "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - count: Number of cross-references
    """
    result = safe_get("Xref/Count", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetMemoryMap() -> dict:
    """
    Get the full virtual memory map of the debugged process.
    Returns all memory pages with their base address, size, protection, type, and info.

    Returns:
        Dictionary with:
        - count: Number of memory pages
        - pages: List of page objects with base, size, protect (ERW/ER-/-RW/-R-/E--/---),
          type (IMG/MAP/PRV), and info (module name or description)
    """
    result = safe_get("MemoryMap")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def MemoryRemoteAlloc(size: str, addr: str = "0") -> dict:
    """
    Allocate memory in the debuggee's address space.
    Useful for code injection, shellcode testing, or creating data buffers.

    Parameters:
        size: Size in bytes to allocate (hex format, e.g. "0x1000")
        addr: Preferred base address (hex format, default "0" for any address)

    Returns:
        Dictionary with:
        - address: The allocated memory address
        - size: The requested size
    """
    result = safe_get("Memory/RemoteAlloc", {"addr": addr, "size": size})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def MemoryRemoteFree(addr: str) -> dict:
    """
    Free memory previously allocated in the debuggee's address space via MemoryRemoteAlloc.

    Parameters:
        addr: Address of the memory to free (hex format, e.g. "0x1000")

    Returns:
        Dictionary with success status
    """
    result = safe_get("Memory/RemoteFree", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetBranchDestination(addr: str) -> dict:
    """
    Get the destination address of a branch instruction (jmp, call, jcc, etc.).
    Resolves where the branch at the given address would jump/call to.

    Parameters:
        addr: Address of the branch instruction (hex format, e.g. "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried instruction address
        - destination: The resolved target address
        - resolved: Whether the destination was successfully resolved
    """
    result = safe_get("GetBranchDestination", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetCallStack() -> dict:
    """
    Get the current call stack of the debugged thread.
    Returns the full stack trace with addresses, return addresses, and comments.

    Returns:
        Dictionary with:
        - total: Number of stack frames
        - entries: List of call stack entries, each with:
          - addr: Current address in the frame
          - from: Return address (caller)
          - to: Called address (callee)
          - comment: Auto-generated comment (function name, etc.)
    """
    result = safe_get("GetCallStack")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetBreakpointList(type: str = "all") -> dict:
    """
    Get list of all breakpoints currently set in the debugger.

    Parameters:
        type: Breakpoint type filter - "all" (default), "normal", "hardware", "memory", "dll", "exception"

    Returns:
        Dictionary with:
        - count: Number of breakpoints
        - breakpoints: List of breakpoint objects with type, addr, enabled, singleshoot,
          active, name, module, hitCount, fastResume, silent, breakCondition, logText, commandText
    """
    result = safe_get("Breakpoint/List", {"type": type})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def AcquireBreakpointLease(
    addr: str,
    workflow_id: str = "",
    breakpoint_type: str = "normal",
    lease_ms: int = 30000,
    size: int = 1,
    access_type: str = "write",
    condition: str = "",
    name: str = "",
) -> dict:
    """
    Acquire a session-bound, reference-counted breakpoint lease.

    A lease may share an address only with the same workflow.  If the
    breakpoint already existed before acquisition it is marked preexisting and
    is never removed by Release/expiry.  Breakpoints created by this workflow
    are compare-and-deleted only when their x64dbg record still matches the
    acquisition fingerprint.
    """

    normalized = _normalize_hex(addr)
    managed_type = _normalize_managed_breakpoint_type(breakpoint_type)
    if not normalized:
        return {"ok": False, "errorCode": "INVALID_ADDRESS", "error": "Invalid breakpoint address"}
    if not managed_type:
        return {
            "ok": False,
            "errorCode": "INVALID_BREAKPOINT_TYPE",
            "error": "breakpoint_type must be normal, conditional, hardware or memory",
        }
    identity = _breakpoint_lease_identity()
    if not identity.get("bridgeInstanceId") or not identity.get("sessionId") or not int(identity.get("debuggeePid") or 0):
        return {
            "ok": False,
            "errorCode": "SESSION_IDENTITY_UNAVAILABLE",
            "error": "A live Bridge/Hello debuggee session is required for breakpoint ownership.",
            "identity": identity,
        }
    workflow = str(workflow_id or "").strip() or f"workflow-{uuid.uuid4().hex[:16]}"
    if len(workflow) > 128:
        return {"ok": False, "errorCode": "INVALID_WORKFLOW_ID", "error": "workflow_id is too long"}
    ttl = max(_BREAKPOINT_LEASE_MIN_MS, min(int(lease_ms), _BREAKPOINT_LEASE_MAX_MS))
    key = f"{managed_type}:{normalized}"
    with _MUTATION_TRANSACTION_LOCK:
        _prune_breakpoint_leases()
        with _RUNTIME_LOCK:
            leases = {
                str(k): dict(v)
                for k, v in (_RUNTIME_STATE.get("breakpointLeases") or {}).items()
                if isinstance(v, dict)
            }
        now_ms = int(time.monotonic() * 1000)
        record = leases.get(key)
        if record:
            if _breakpoint_lease_identity_key(record.get("identity") or {}) != _breakpoint_lease_identity_key(identity):
                leases.pop(key, None)
                record = None
            elif str(record.get("workflowId") or "") != workflow:
                return {
                    "ok": False,
                    "errorCode": "BREAKPOINT_LEASE_CONFLICT",
                    "error": "Breakpoint is owned by another workflow.",
                    "addr": normalized,
                    "breakpointType": managed_type,
                    "ownerWorkflowId": record.get("workflowId"),
                    "refCount": int(record.get("refCount") or 0),
                }
        if record:
            token = f"bpl-{uuid.uuid4().hex}"
            tokens = dict(record.get("tokens") or {})
            tokens[token] = {"workflowId": workflow, "acquiredAtMs": now_ms, "expiresAtMs": now_ms + ttl}
            record["tokens"] = tokens
            record["refCount"] = len(tokens)
            record["lastRenewedAtMs"] = now_ms
            leases[key] = record
            _remember_runtime(breakpointLeases=leases)
            return {
                "ok": True,
                "leaseId": token,
                "addr": normalized,
                "breakpointType": managed_type,
                "workflowId": workflow,
                "referenceCount": len(tokens),
                "preexisting": bool(record.get("preexisting")),
                "createdByWorkflow": bool(record.get("createdByWorkflow")),
                "expiresAtMs": now_ms + ttl,
                "reused": True,
            }
        existing = _managed_breakpoint_snapshot_record(normalized, managed_type)
        if existing is not None and managed_type == "conditional" and condition:
            current_condition = str(
                existing.get("breakCondition") or existing.get("condition") or ""
            )
            if current_condition and current_condition != condition:
                return {
                    "ok": False,
                    "errorCode": "BREAKPOINT_LEASE_CONFLICT",
                    "error": "An incompatible conditional breakpoint already exists.",
                    "addr": normalized,
                    "currentCondition": current_condition,
                }
        set_result: Any = None
        created = existing is None
        if created:
            set_result = _managed_breakpoint_set(
                normalized,
                managed_type,
                size=size,
                access_type=access_type,
                condition=condition,
                name=name,
            )
            if not bool(isinstance(set_result, dict) and set_result.get("ok")):
                return {
                    "ok": False,
                    "errorCode": "BREAKPOINT_SET_FAILED",
                    "error": "x64dbg rejected the managed breakpoint.",
                    "addr": normalized,
                    "breakpointType": managed_type,
                    "setResult": set_result,
                }
            existing = _managed_breakpoint_snapshot_record(normalized, managed_type)
            if existing is None:
                # Do not create an un-deletable lease without a before-image.
                return {
                    "ok": False,
                    "errorCode": "BREAKPOINT_VERIFY_FAILED",
                    "error": "Breakpoint was set but could not be verified in Breakpoint/List.",
                    "addr": normalized,
                    "breakpointType": managed_type,
                    "setResult": set_result,
                }
        token = f"bpl-{uuid.uuid4().hex}"
        record = {
            "addr": normalized,
            "breakpointType": managed_type,
            "workflowId": workflow,
            "identity": identity,
            "createdByWorkflow": bool(created),
            "preexisting": not created,
            "fingerprint": _managed_breakpoint_fingerprint(existing),
            "tokens": {
                token: {
                    "workflowId": workflow,
                    "acquiredAtMs": now_ms,
                    "expiresAtMs": now_ms + ttl,
                }
            },
            "refCount": 1,
            "createdAtMs": now_ms,
            "lastRenewedAtMs": now_ms,
        }
        if len(leases) >= _BREAKPOINT_LEASE_MAX_ENTRIES:
            return {
                "ok": False,
                "errorCode": "BREAKPOINT_LEASE_CAPACITY",
                "error": "Breakpoint lease table is full; release stale workflows first.",
            }
        leases[key] = record
        _remember_runtime(breakpointLeases=leases)
    _log_event(
        "breakpoint_lease_acquired",
        addr=normalized,
        breakpointType=managed_type,
        workflowId=workflow,
        createdByWorkflow=created,
    )
    return {
        "ok": True,
        "leaseId": token,
        "addr": normalized,
        "breakpointType": managed_type,
        "workflowId": workflow,
        "referenceCount": 1,
        "preexisting": not created,
        "createdByWorkflow": created,
        "expiresAtMs": now_ms + ttl,
        "setResult": set_result,
    }


@mcp.tool()
def RenewBreakpointLease(lease_id: str, lease_ms: int = 30000) -> dict:
    """Renew one breakpoint lease without changing its ownership or reference count."""

    token = str(lease_id or "").strip()
    ttl = max(_BREAKPOINT_LEASE_MIN_MS, min(int(lease_ms), _BREAKPOINT_LEASE_MAX_MS))
    if not token:
        return {"ok": False, "errorCode": "INVALID_LEASE_ID", "error": "lease_id is required"}
    identity = _breakpoint_lease_identity()
    with _MUTATION_TRANSACTION_LOCK:
        _prune_breakpoint_leases()
        with _RUNTIME_LOCK:
            leases = {
                str(k): dict(v)
                for k, v in (_RUNTIME_STATE.get("breakpointLeases") or {}).items()
                if isinstance(v, dict)
            }
        now_ms = int(time.monotonic() * 1000)
        for key, record in leases.items():
            tokens = dict(record.get("tokens") or {})
            if token not in tokens:
                continue
            if _breakpoint_lease_identity_key(record.get("identity") or {}) != _breakpoint_lease_identity_key(identity):
                return {
                    "ok": False,
                    "errorCode": "STALE_SESSION",
                    "error": "Breakpoint lease belongs to a different debugger session.",
                }
            tokens[token] = {
                **dict(tokens[token]),
                "expiresAtMs": now_ms + ttl,
                "renewedAtMs": now_ms,
            }
            record["tokens"] = tokens
            record["lastRenewedAtMs"] = now_ms
            leases[key] = record
            _remember_runtime(breakpointLeases=leases)
            return {
                "ok": True,
                "leaseId": token,
                "addr": record.get("addr"),
                "breakpointType": record.get("breakpointType"),
                "workflowId": record.get("workflowId"),
                "referenceCount": int(record.get("refCount") or len(tokens)),
                "expiresAtMs": now_ms + ttl,
            }
    return {"ok": False, "errorCode": "LEASE_NOT_FOUND", "error": "Breakpoint lease not found or expired"}


@mcp.tool()
def ReleaseBreakpointLease(lease_id: str, force: bool = False) -> dict:
    """
    Release one reference.  The final reference compare-deletes only a
    workflow-created breakpoint; preexisting or user-modified points are kept.
    """

    token = str(lease_id or "").strip()
    if not token:
        return {"ok": False, "errorCode": "INVALID_LEASE_ID", "error": "lease_id is required"}
    identity = _breakpoint_lease_identity()
    cleanup_record: Optional[Dict[str, Any]] = None
    with _MUTATION_TRANSACTION_LOCK:
        _prune_breakpoint_leases()
        with _RUNTIME_LOCK:
            leases = {
                str(k): dict(v)
                for k, v in (_RUNTIME_STATE.get("breakpointLeases") or {}).items()
                if isinstance(v, dict)
            }
        for key, record in list(leases.items()):
            tokens = dict(record.get("tokens") or {})
            if token not in tokens:
                continue
            if _breakpoint_lease_identity_key(record.get("identity") or {}) != _breakpoint_lease_identity_key(identity):
                return {
                    "ok": False,
                    "errorCode": "STALE_SESSION",
                    "error": "Breakpoint lease belongs to a different debugger session.",
                }
            tokens.pop(token, None)
            record["tokens"] = tokens
            record["refCount"] = len(tokens)
            final = not tokens
            if final:
                leases.pop(key, None)
                if bool(record.get("createdByWorkflow")):
                    cleanup_record = record
            else:
                leases[key] = record
            _remember_runtime(breakpointLeases=leases)
            break
        else:
            # Idempotent release is safe for a caller that timed out after the
            # bridge completed the mutation; it never attempts a delete by addr.
            return {"ok": True, "leaseId": token, "alreadyReleased": True, "deleted": False}
    cleanup = (
        _compare_delete_managed_breakpoint(cleanup_record)
        if cleanup_record is not None
        else {"status": "reference_remaining", "deleted": False}
    )
    _log_event(
        "breakpoint_lease_released",
        addr=(cleanup_record or {}).get("addr"),
        breakpointType=(cleanup_record or {}).get("breakpointType"),
        cleanup=cleanup,
        force=bool(force),
    )
    return {
        "ok": cleanup.get("status") not in {"delete_failed", "delete_unverified"},
        "leaseId": token,
        "alreadyReleased": False,
        "deleted": bool(cleanup.get("deleted")),
        "cleanup": cleanup,
    }


@mcp.tool()
def ListBreakpointLeases(include_tokens: bool = False) -> dict:
    """List active workflow breakpoint leases and ownership/cleanup metadata."""

    _prune_breakpoint_leases()
    identity = _breakpoint_lease_identity()
    with _RUNTIME_LOCK:
        leases = list(
            (value for value in (_RUNTIME_STATE.get("breakpointLeases") or {}).values())
        )
    items = []
    for record in leases:
        if not isinstance(record, dict):
            continue
        item = {
            "addr": record.get("addr"),
            "breakpointType": record.get("breakpointType"),
            "workflowId": record.get("workflowId"),
            "referenceCount": int(record.get("refCount") or 0),
            "preexisting": bool(record.get("preexisting")),
            "createdByWorkflow": bool(record.get("createdByWorkflow")),
            "identity": dict(record.get("identity") or {}),
            "sessionMatches": _breakpoint_lease_identity_key(record.get("identity") or {}) == _breakpoint_lease_identity_key(identity),
            "expiresAtMs": max(
                (
                    int(token.get("expiresAtMs") or 0)
                    for token in (record.get("tokens") or {}).values()
                    if isinstance(token, dict)
                ),
                default=0,
            ),
        }
        if include_tokens:
            item["leases"] = [
                {
                    "leaseId": str(token),
                    "workflowId": value.get("workflowId"),
                    "expiresAtMs": value.get("expiresAtMs"),
                }
                for token, value in (record.get("tokens") or {}).items()
                if isinstance(value, dict)
            ]
        items.append(item)
    return {"ok": True, "count": len(items), "leases": items}


@mcp.tool()
def LabelSet(addr: str, text: str, manual: bool = True) -> dict:
    """
    Set a label at the specified address in x64dbg.
    Labels appear in the disassembly view and are useful for marking important addresses.

    Parameters:
        addr: Address to set the label at (hex format, e.g. "0x1400010a0")
        text: Label text (e.g. "main_decrypt_loop")

    Returns:
        Dictionary with success status, address, and label text
    """
    result = safe_post(
        "Label/Set",
        {"addr": addr, "text": text, "manual": "true" if manual else "false"},
    )
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def LabelDelete(addr: str) -> dict:
    """Delete the label at an absolute runtime address.

    The operation is session-guarded and idempotent by resulting debugger state.
    ``deleted`` is false when no label existed.
    """
    result = safe_post("Label/Delete", {"addr": addr})
    payload = _coerce_json_payload(result)
    return payload if isinstance(payload, dict) else {
        "ok": False,
        "error": "Failed to parse label-delete response",
        "raw": str(result),
    }


@mcp.tool()
def LabelGet(addr: str) -> dict:
    """
    Get the label at the specified address.

    Parameters:
        addr: Address to query (hex format, e.g. "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - found: Whether a label exists at that address
        - label: The label text (empty if not found)
    """
    result = safe_get("Label/Get", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def LabelList() -> dict:
    """
    Get all labels defined in the current debugging session.

    Returns:
        Dictionary with:
        - count: Number of labels
        - labels: List of label objects with module, rva, text, and manual fields
    """
    result = safe_get("Label/List")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def CommentSet(addr: str, text: str, manual: bool = True) -> dict:
    """
    Set a comment at the specified address in x64dbg.
    Comments appear in the disassembly view next to the instruction.

    Parameters:
        addr: Address to set the comment at (hex format, e.g. "0x1400010a0")
        text: Comment text

    Returns:
        Dictionary with success status and address
    """
    result = safe_post(
        "Comment/Set",
        {"addr": addr, "text": text, "manual": "true" if manual else "false"},
    )
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def CommentDelete(addr: str) -> dict:
    """Delete the comment at an absolute runtime address.

    The operation is session-guarded and idempotent by resulting debugger state.
    ``deleted`` is false when no comment existed.
    """
    result = safe_post("Comment/Delete", {"addr": addr})
    payload = _coerce_json_payload(result)
    return payload if isinstance(payload, dict) else {
        "ok": False,
        "error": "Failed to parse comment-delete response",
        "raw": str(result),
    }


@mcp.tool()
def CommentGet(addr: str) -> dict:
    """
    Get the comment at the specified address.

    Parameters:
        addr: Address to query (hex format, e.g. "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - found: Whether a comment exists
        - comment: The comment text
    """
    result = safe_get("Comment/Get", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def CommentList(module: str = "", offset: int = 0, limit: int = 500) -> dict:
    """Enumerate comments, optionally filtered by module, with pagination."""
    result = safe_get(
        "Comment/List",
        {
            "module": str(module or ""),
            "offset": str(max(0, int(offset))),
            "limit": str(max(1, min(int(limit), 5000))),
        },
    )
    payload = _coerce_json_payload(result)
    if isinstance(payload, dict) and isinstance(payload.get("comments"), list):
        # Script::Comment::CommentInfo reuses MAX_LABEL_SIZE (256 bytes), while
        # Comment/Get exposes MAX_COMMENT_SIZE (512). Re-read only entries that
        # are at/near the list buffer boundary. Doing this as separate requests
        # avoids nesting Script API database calls inside the native list route.
        candidates = [
            item
            for item in payload.get("comments", [])
            if isinstance(item, dict)
            and len(str(item.get("text") or "").encode("utf-8", errors="replace")) >= 250
        ]
        if candidates:
            modules_payload = GetModuleList()
            loaded_modules = (
                modules_payload.get("modules", [])
                if isinstance(modules_payload, dict)
                else []
            )
            for item in candidates:
                loaded = next(
                    (
                        candidate
                        for candidate in loaded_modules
                        if isinstance(candidate, dict)
                        and _analysis_module_name_matches(
                            item.get("module"), candidate.get("name") or candidate.get("path")
                        )
                    ),
                    None,
                )
                base = _parse_int((loaded or {}).get("base"), None)
                rva = _parse_int(item.get("rva"), None)
                if base is None or rva is None:
                    continue
                detail = CommentGet(f"0x{base + rva:X}")
                if isinstance(detail, dict) and detail.get("found"):
                    item["text"] = str(detail.get("comment") or "")
                    item["fullTextRead"] = True
        return payload
    return {
        "ok": False,
        "error": "Failed to parse comment list",
        "raw": str(result),
    }


@mcp.tool()
def BookmarkSet(addr: str, manual: bool = True) -> dict:
    """Set a bookmark at an absolute runtime address."""
    result = safe_post(
        "Bookmark/Set",
        {"addr": addr, "manual": "true" if manual else "false"},
    )
    payload = _coerce_json_payload(result)
    return payload if isinstance(payload, dict) else {
        "ok": False,
        "error": "Failed to parse bookmark response",
        "raw": str(result),
    }


@mcp.tool()
def BookmarkDelete(addr: str) -> dict:
    """Delete the bookmark at an absolute runtime address.

    The operation is session-guarded and idempotent by resulting debugger state.
    ``deleted`` is false when no bookmark existed.
    """
    result = safe_post("Bookmark/Delete", {"addr": addr})
    payload = _coerce_json_payload(result)
    return payload if isinstance(payload, dict) else {
        "ok": False,
        "error": "Failed to parse bookmark-delete response",
        "raw": str(result),
    }


@mcp.tool()
def BookmarkGet(addr: str) -> dict:
    """Get bookmark information for an absolute runtime address."""
    result = safe_get("Bookmark/Get", {"addr": addr})
    payload = _coerce_json_payload(result)
    return payload if isinstance(payload, dict) else {
        "ok": False,
        "error": "Failed to parse bookmark response",
        "raw": str(result),
    }


@mcp.tool()
def BookmarkList(module: str = "", offset: int = 0, limit: int = 500) -> dict:
    """Enumerate bookmarks, optionally filtered by module, with pagination."""
    result = safe_get(
        "Bookmark/List",
        {
            "module": str(module or ""),
            "offset": str(max(0, int(offset))),
            "limit": str(max(1, min(int(limit), 5000))),
        },
    )
    payload = _coerce_json_payload(result)
    return payload if isinstance(payload, dict) else {
        "ok": False,
        "error": "Failed to parse bookmark list",
        "raw": str(result),
    }


@mcp.tool()
def FunctionAdd(
    start: str,
    end: str,
    manual: bool = True,
    instruction_count: int = 0,
) -> dict:
    """Add an x64dbg function range; ``end`` is inclusive."""
    result = safe_post(
        "Function/Add",
        {
            "start": start,
            "end": end,
            "manual": "true" if manual else "false",
            "instructionCount": str(max(0, int(instruction_count))),
        },
    )
    payload = _coerce_json_payload(result)
    return payload if isinstance(payload, dict) else {
        "ok": False,
        "error": "Failed to parse function response",
        "raw": str(result),
    }


@mcp.tool()
def FunctionDelete(addr: str) -> dict:
    """Delete the x64dbg function range containing an absolute address.

    The operation is session-guarded and idempotent by resulting debugger state.
    ``deleted`` is false when no function range existed.
    """
    result = safe_post("Function/Delete", {"addr": addr})
    payload = _coerce_json_payload(result)
    return payload if isinstance(payload, dict) else {
        "ok": False,
        "error": "Failed to parse function-delete response",
        "raw": str(result),
    }


@mcp.tool()
def FunctionList(module: str = "", offset: int = 0, limit: int = 500) -> dict:
    """Enumerate x64dbg function ranges; returned ends are inclusive."""
    result = safe_get(
        "Function/List",
        {
            "module": str(module or ""),
            "offset": str(max(0, int(offset))),
            "limit": str(max(1, min(int(limit), 5000))),
        },
    )
    payload = _coerce_json_payload(result)
    return payload if isinstance(payload, dict) else {
        "ok": False,
        "error": "Failed to parse function list",
        "raw": str(result),
    }


@mcp.tool()
def GetRegisterDump() -> dict:
    """
    Get a complete dump of all CPU registers in one call.
    Returns general purpose registers, segment registers, debug registers,
    flags, and last error/status information.

    Much more efficient than reading registers individually.

    Returns:
        Dictionary with all register values (cax/ccx/cdx/cbx/csp/cbp/csi/cdi,
        r8-r15 on x64, cip, eflags, segment regs, debug regs, flags object,
        lastError, lastStatus)
    """
    result = safe_get("RegisterDump")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def SetHardwareBreakpoint(addr: str, type: str = "execute") -> dict:
    """
    Set a hardware breakpoint at the specified address.
    Hardware breakpoints use CPU debug registers (limited to 4 simultaneous).

    Parameters:
        addr: Address to set the breakpoint at (hex format, e.g. "0x1400010a0")
        type: Breakpoint type - "execute" (default), "access" (read/write), or "write" (write only)

    Returns:
        Dictionary with success status and address
    """
    result = safe_get("Debug/SetHardwareBreakpoint", {"addr": addr, "type": type})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def DeleteHardwareBreakpoint(addr: str) -> dict:
    """
    Delete a hardware breakpoint at the specified address.

    Parameters:
        addr: Address of the hardware breakpoint to delete (hex format)

    Returns:
        Dictionary with success status and address
    """
    result = safe_get("Debug/DeleteHardwareBreakpoint", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def EnumTcpConnections() -> dict:
    """
    Enumerate all TCP connections of the debugged process.
    Useful for analyzing network activity, identifying C2 connections, etc.

    Returns:
        Dictionary with:
        - count: Number of connections
        - connections: List of connection objects with remoteAddress, remotePort,
          localAddress, localPort, and state
    """
    result = safe_get("EnumTcpConnections")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetPatchList() -> dict:
    """
    Enumerate all memory patches applied in the current debugging session.
    Shows original and patched byte values for each patched address.

    Returns:
        Dictionary with:
        - count: Number of patches
        - patches: List of patch objects with module, address, oldByte, newByte
    """
    result = safe_get("Patch/List")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetPatchAt(addr: str) -> dict:
    """
    Check if a specific address has been patched and get patch details.

    Parameters:
        addr: Address to check (hex format, e.g. "0x1400010a0")

    Returns:
        Dictionary with:
        - address: The queried address
        - patched: Whether the address is patched
        - module: Module name (if patched)
        - oldByte: Original byte value (if patched)
        - newByte: Patched byte value (if patched)
    """
    result = safe_get("Patch/Get", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


# ---------------------------------------------------------------------------
# Portable analysis evidence (x64dbg <-> IDA and other static-analysis tools)
# ---------------------------------------------------------------------------
