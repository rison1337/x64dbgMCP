@mcp.tool()
def ExecCommand(
    cmd: str,
    offset: int = 0,
    limit: int = 100,
    continuation_token: str = "",
    max_output_chars: int = 12000,
) -> dict:
    """
    Execute a command in x64dbg and return its output

    Ensure that if the command has arguments, you comma separate the values, but not the command itself I.E. findallmem findallmem 0x140001000,CC,20480

    Parameters for commands that use the Reference View:
        cmd: Command to execute
        offset: Pagination offset for reference view results (default: 0)
        limit: Maximum number of reference view rows to return (default: 100, max: 5000)

    Returns:
        Dictionary with:
        - success: Whether the command executed successfully
        - refView: References tab data populated by the command (if any), with:
          - rowCount: Total number of rows in the references view
          - rows: List of rows (paginated), where each row is a list of cell strings
                  (typically [address, disassembly] or [address, disassembly, string_address, string])
    """
    def _decode_exec_continuation(token: str) -> Dict[str, Any]:
        raw = str(token or "").strip()
        if not raw:
            return {}
        padded = raw + ("=" * (-len(raw) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        payload = json.loads(decoded)
        return payload if isinstance(payload, dict) else {}

    def _encode_exec_continuation(next_cmd: str, next_offset: int, next_limit: int) -> str:
        payload = {
            "cmd": str(next_cmd or ""),
            "offset": max(0, int(next_offset)),
            "limit": max(1, min(int(next_limit), 5000)),
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).decode("ascii")
        return encoded.rstrip("=")

    if continuation_token:
        try:
            continuation = _decode_exec_continuation(continuation_token)
            cmd = str(continuation.get("cmd") or cmd or "")
            offset = int(continuation.get("offset") or offset or 0)
            limit = int(continuation.get("limit") or limit or 100)
        except Exception as exc:
            return {"success": False, "error": f"Invalid continuation_token: {exc}"}

    repaired_cmd = _repair_text_mojibake(str(cmd or ""))
    # Auto-scope bare `strref`/`refs`/`modcallfind` to the debuggee module so
    # users don't unknowingly scan ntdll (~3000 rows of unrelated strings).
    stripped = repaired_cmd.strip()
    stripped_lower = stripped.lower()
    if stripped_lower in ("strref", "refs", "refsearch"):
        addr = _get_current_debuggee_module_base(want_entry=True)
        if addr:
            repaired_cmd = f"{stripped} {addr}"
    timeout_sec = 15.0
    result = safe_get(
        "ExecCommand",
        {"cmd": repaired_cmd, "offset": offset, "limit": limit},
        timeout_sec=timeout_sec,
    )
    if not isinstance(result, dict):
        return result
    ref_view = result.get("refView")
    if not isinstance(ref_view, dict):
        return result
    rows = ref_view.get("rows")
    if not isinstance(rows, list):
        return result

    safe_limit = max(1, min(int(limit or 100), 5000))
    total_rows = int(ref_view.get("rowCount") or len(rows))
    returned_rows = []
    for row in rows:
        if not isinstance(row, list):
            continue
        repaired_row = []
        for cell in row:
            if isinstance(cell, str):
                repaired_row.append(_repair_text_mojibake(cell))
            else:
                repaired_row.append(cell)
        returned_rows.append(repaired_row)
    char_budget = max(0, int(max_output_chars or 0))
    trimmed_rows: List[List[Any]] = []
    consumed_chars = 0
    truncated = False
    if char_budget > 0:
        for row in returned_rows:
            row_chars = len(json.dumps(row, ensure_ascii=False))
            separator_chars = 1 if trimmed_rows else 0
            if trimmed_rows and consumed_chars + row_chars + separator_chars > char_budget:
                truncated = True
                break
            if not trimmed_rows and row_chars > char_budget:
                trimmed_rows.append(row)
                consumed_chars += row_chars
                truncated = len(returned_rows) > 1 or total_rows > offset + 1
                break
            trimmed_rows.append(row)
            consumed_chars += row_chars + separator_chars
    else:
        trimmed_rows = returned_rows

    if len(trimmed_rows) < len(returned_rows):
        truncated = True
    if total_rows > offset + len(trimmed_rows):
        truncated = True

    if truncated:
        next_offset = offset + len(trimmed_rows)
        ref_view = dict(ref_view)
        ref_view["rows"] = trimmed_rows
        result = dict(result)
        result["refView"] = ref_view
        result["truncated"] = True
        result["returnedRows"] = len(trimmed_rows)
        result["nextOffset"] = next_offset
        result["remainingRows"] = max(0, total_rows - next_offset)
        if next_offset < total_rows:
            result["continuationToken"] = _encode_exec_continuation(
                repaired_cmd, next_offset, safe_limit
            )
    return result


def _get_current_debuggee_module_base(want_entry: bool = False) -> Optional[str]:
    """Return hex base (or entry) address of the current debuggee's main module."""
    try:
        image = _get_current_debuggee_image_name()
        if not image:
            return None
        modules = safe_get("GetModuleList", log=False)
        if isinstance(modules, dict) and isinstance(modules.get("modules"), list):
            modules = modules["modules"]
        if not isinstance(modules, list):
            return None
        target = str(image).lower()
        for mod in modules:
            if isinstance(mod, dict) and str(mod.get("name", "")).lower() == target:
                # x64dbg's `strref <addr>` scans the entire module that owns
                # <addr>. Both base and entry work, but entry is always inside
                # the code section which is what users want scanned anyway.
                if want_entry:
                    entry = _normalize_hex(mod.get("entry"))
                    if entry and entry != "0x0":
                        return entry
                base = _normalize_hex(mod.get("base"))
                if base:
                    return base
    except Exception:
        return None
    return None


@mcp.tool()
def IsDebugActive() -> bool:
    """
    Check if debugger is active (running)

    Returns:
        True if running, False otherwise
    """
    result = safe_get("IsDebugActive")
    if isinstance(result, dict) and "isRunning" in result:
        return result["isRunning"] is True
    if isinstance(result, str):
        try:
            import json

            parsed = json.loads(result)
            return parsed.get("isRunning", False) is True
        except Exception:
            return False
    return False


@mcp.tool()
def IsDebugging() -> bool:
    """
    Check if x64dbg is debugging a process

    Returns:
        True if debugging, False otherwise
    """
    result = safe_get("Is_Debugging")
    if isinstance(result, dict) and "isDebugging" in result:
        return result["isDebugging"] is True
    if isinstance(result, str):
        try:
            import json

            parsed = json.loads(result)
            return parsed.get("isDebugging", False) is True
        except Exception:
            return False
    return False


@mcp.tool()
def GetRecentLog(lines: int = 80) -> dict:
    """
    Return the most recent bridge log lines.

    Args:
        lines: Maximum number of log lines to return.
    """
    tail = [line.rstrip("\r\n") for line in _tail_log(limit=lines)]
    return {
        "logPath": LOG_PATH,
        "count": len(tail),
        "lines": tail,
    }


@mcp.tool()
def EnsureDebugger(
    arch: str = "auto", timeout_ms: int = 15000, restart: bool = False
) -> dict:
    """
    Ensure that the requested x64dbg/x32dbg instance is running and its HTTP bridge is reachable.

    Args:
        arch: Desired debugger architecture: auto, x64, or x86.
        timeout_ms: Maximum time to wait for the debugger bridge.
        restart: When true, terminate existing debugger processes before launching a fresh one.
    """
    desired_arch = _normalize_debugger_arch(arch)
    stop_result = None
    if restart:
        hidemain_cleanup = None
        cleanup_hidemain = globals().get("_cleanup_hidemain_target")
        if callable(cleanup_hidemain):
            try:
                hidemain_cleanup = cleanup_hidemain()
            except Exception as exc:
                hidemain_cleanup = {"ok": False, "error": str(exc)}
        stop_result = _stop_debugger_processes(
            "auto", timeout_ms=min(max(timeout_ms, 0), 10000) or 10000
        )
        if isinstance(stop_result, dict):
            stop_result = dict(stop_result)
            stop_result["hideMainCleanup"] = hidemain_cleanup
    active = _get_active_debugger_info()
    active_arch = str(active.get("arch") or "").lower()
    active_pid = int(active.get("pid") or 0)
    if active_pid and active_arch and active_arch != desired_arch:
        return {
            "ok": False,
            "error": f"Active debugger arch is {active_arch}, but {desired_arch} is required.",
            "requestedArch": desired_arch,
            "activeDebugger": active,
            "restartRecommended": True,
            "restartResult": stop_result,
            "logPath": LOG_PATH,
        }
    if active_pid and active_arch == desired_arch:
        ready = _wait_for_debugger_bridge_ready(
            arch=desired_arch,
            expected_pid=active_pid,
            timeout_ms=min(max(timeout_ms, 0), 3000) or 3000,
            poll_ms=150,
        )
        if ready.get("ok"):
            dialog_result = _dismiss_scyllahide_dialog(timeout_ms=400, poll_ms=75)
            return {
                "ok": True,
                "requestedArch": desired_arch,
                "activeDebugger": ready.get("activeDebugger") or active,
                "bridge": ready.get("bridge"),
                "alreadyRunning": True,
                "launched": False,
                "restartResult": stop_result,
                "dismissedDialog": dialog_result
                if dialog_result.get("found")
                else None,
                "logPath": LOG_PATH,
            }
        return {
            "ok": False,
            "error": "Debugger process exists but the MCP HTTP bridge is not reachable.",
            "requestedArch": desired_arch,
            "activeDebugger": active,
            "bridge": ready.get("bridge"),
            "restartRecommended": True,
            "restartResult": stop_result,
            "logPath": LOG_PATH,
        }
    launch = _start_debugger_process(desired_arch)
    if not launch.get("ok"):
        payload = dict(launch)
        payload["requestedArch"] = desired_arch
        payload["restartResult"] = stop_result
        payload["logPath"] = LOG_PATH
        return payload
    ready = _wait_for_debugger_bridge_ready(
        arch=desired_arch,
        expected_pid=int(launch.get("pid") or 0),
        timeout_ms=timeout_ms,
        poll_ms=200,
    )
    dialog_result = _dismiss_scyllahide_dialog(timeout_ms=500, poll_ms=75)
    return {
        "ok": bool(ready.get("ok")),
        "requestedArch": desired_arch,
        "launch": launch,
        "activeDebugger": ready.get("activeDebugger"),
        "bridge": ready.get("bridge"),
        "alreadyRunning": False,
        "launched": True,
        "restartResult": stop_result,
        "dismissedDialog": dialog_result if dialog_result.get("found") else None,
        "error": ready.get("error") if not ready.get("ok") else "",
        "logPath": LOG_PATH,
    }


@mcp.tool()
def RestartDebugger(
    arch: str = "auto", timeout_ms: int = 20000, reload_target: bool = True
) -> dict:
    """
    Restart x64dbg/x32dbg and, by default, reload the target that was being
    debugged so the debug session comes back. Without reload the debugger app
    restarts with no target loaded, leaving a 'not_debugging' state.

    Args:
        arch: Desired debugger architecture after restart: auto, x64, or x86.
        timeout_ms: Maximum time to wait for the restarted debugger bridge.
        reload_target: When true (default), re-launch the previously debugged
            target after the debugger restarts, paused at its entry point.
    """
    # Capture the current target before tearing the session down so the debug
    # session can be brought back, not merely the debugger process.
    previous_launch_spec = _get_runtime_value("lastLaunchSpec")
    if not isinstance(previous_launch_spec, dict):
        previous_launch_spec = {}
    prev_target = str(
        previous_launch_spec.get("exePath")
        or _get_runtime_value("lastDebuggeePath")
        or ""
    )
    previous_hidemain = _get_runtime_value("lastHideMain")
    if not prev_target:
        try:
            _st = _build_debug_state(
                include_console=False, include_callstack=False, max_console_chars=0
            )
            prev_target = str((_st or {}).get("debuggeePath") or "")
        except Exception:
            prev_target = ""
    _restore_pending_scyllahide_profile(force=True)
    hidemain_cleanup = None
    cleanup_hidemain = globals().get("_cleanup_hidemain_target")
    if callable(cleanup_hidemain):
        try:
            hidemain_cleanup = cleanup_hidemain()
        except Exception as exc:
            hidemain_cleanup = {"ok": False, "error": str(exc)}
    desired_arch = _normalize_debugger_arch(arch)
    stop_timeout = min(max(timeout_ms, 0), 10000) or 10000
    stopped = _stop_debugger_processes("auto", timeout_ms=stop_timeout)
    ensured = EnsureDebugger(arch=desired_arch, timeout_ms=timeout_ms, restart=False)
    payload = (
        dict(ensured)
        if isinstance(ensured, dict)
        else {"ok": False, "error": str(ensured)}
    )
    retry_payload = None
    if not payload.get("ok"):
        time.sleep(0.35)
        stopped_retry = _stop_debugger_processes("auto", timeout_ms=stop_timeout)
        ensured_retry = EnsureDebugger(
            arch=desired_arch, timeout_ms=timeout_ms, restart=False
        )
        retry_payload = (
            dict(ensured_retry)
            if isinstance(ensured_retry, dict)
            else {"ok": False, "error": str(ensured_retry)}
        )
        retry_payload["restartResult"] = stopped_retry
        if retry_payload.get("ok"):
            payload = retry_payload
    payload["requestedArch"] = desired_arch
    payload["restartResult"] = stopped
    if retry_payload is not None:
        payload["retry"] = retry_payload
    # Bring the debug session back by reloading the previous target. The reload
    # passes restart_debugger=False so it cannot recurse back into a restart.
    if (
        reload_target
        and payload.get("ok")
        and prev_target
        and os.path.exists(prev_target)
    ):
        relaunch_kwargs: Dict[str, Any] = {
            "exe_path": prev_target,
            "arch": desired_arch,
            "restart_debugger": False,
            "timeout_ms": min(max(timeout_ms, 0), 20000) or 20000,
            "stop_first": True,
            "use_hidemain": (
                "auto"
                if isinstance(previous_hidemain, dict)
                and int(previous_hidemain.get("pid") or 0) > 0
                else "off"
            ),
        }
        if previous_launch_spec.get("arguments"):
            relaunch_kwargs["arguments"] = list(previous_launch_spec.get("arguments") or [])
        elif previous_launch_spec.get("rawCommandLine"):
            relaunch_kwargs["command_line"] = str(
                previous_launch_spec.get("rawCommandLine") or ""
            )
        if previous_launch_spec.get("workingDirectory"):
            relaunch_kwargs["working_directory"] = str(
                previous_launch_spec.get("workingDirectory") or ""
            )
        if previous_launch_spec.get("environment"):
            relaunch_kwargs["environment"] = dict(
                previous_launch_spec.get("environment") or {}
            )
        if previous_launch_spec.get("inheritEnvironment") is False:
            relaunch_kwargs["inherit_environment"] = False
        relaunch_kwargs["detail"] = "full"
        relaunch = LaunchFileUnderDebugger(**relaunch_kwargs)
        payload["reloadedTarget"] = prev_target
        payload["reload"] = relaunch
        payload["ok"] = bool(isinstance(relaunch, dict) and relaunch.get("ok"))
    payload["logPath"] = LOG_PATH
    payload["hideMainCleanup"] = hidemain_cleanup
    return payload


def _should_auto_restart_debugger(ensure_result: Any) -> bool:
    if not isinstance(ensure_result, dict) or ensure_result.get("ok"):
        return False
    active = ensure_result.get("activeDebugger")
    bridge = ensure_result.get("bridge")
    if not isinstance(active, dict) or not int(active.get("pid") or 0):
        return False
    if not isinstance(bridge, dict) or bridge.get("ok"):
        return False
    combined = " ".join(
        [str(ensure_result.get("error") or ""), str(bridge.get("error") or "")]
    ).lower()
    return any(
        marker in combined
        for marker in (
            "not reachable",
            "timed out",
            "timeout",
            "connection aborted",
            "connection reset",
            "connection refused",
        )
    )


def _ensure_init_debugger_bridge(exe_path: str, timeout_ms: int) -> Dict[str, Any]:
    """Ensure and freshly identify the bridge for a direct InitDebuggee call."""

    target_arch = _detect_pe_arch(exe_path)
    desired_arch = _normalize_debugger_arch("auto", exe_path=exe_path)
    wait_budget = min(max(int(timeout_ms or 0), 1000), 20000)
    ensured = EnsureDebugger(
        arch=desired_arch,
        timeout_ms=wait_budget,
        restart=False,
    )
    recovery = None
    if not isinstance(ensured, dict) or not ensured.get("ok"):
        if _should_auto_restart_debugger(ensured):
            recovery = RestartDebugger(
                arch=desired_arch,
                timeout_ms=wait_budget,
                reload_target=False,
            )
            if isinstance(recovery, dict) and recovery.get("ok"):
                ensured = recovery
    if not isinstance(ensured, dict) or not ensured.get("ok"):
        error = (
            str((ensured or {}).get("error") or "")
            if isinstance(ensured, dict)
            else str(ensured or "")
        )
        return {
            "ok": False,
            "errorCode": "BRIDGE_UNAVAILABLE",
            "error": error or "The matching x64dbg bridge could not be started or reached.",
            "targetArch": target_arch,
            "requestedArch": desired_arch,
            "ensureDebugger": ensured,
            "recoveryDebugger": recovery,
        }

    hello = _bridge_request(
        "GET",
        "Bridge/Hello",
        log=False,
        timeout_sec=max(1.0, min(3.0, wait_budget / 1000.0)),
        guard="none",
        idempotent=True,
    )
    if not hello.ok:
        message = hello.error.message if hello.error else "Bridge/Hello failed."
        return {
            "ok": False,
            "errorCode": "BRIDGE_UNAVAILABLE",
            "error": message,
            "targetArch": target_arch,
            "requestedArch": desired_arch,
            "ensureDebugger": ensured,
            "recoveryDebugger": recovery,
        }
    identity = _cache_bridge_identity(hello.data)
    if not identity.get("bridgeInstanceId"):
        return {
            "ok": False,
            "errorCode": "BRIDGE_IDENTITY_UNAVAILABLE",
            "error": "Bridge/Hello did not return an authoritative bridge identity.",
            "targetArch": target_arch,
            "requestedArch": desired_arch,
            "ensureDebugger": ensured,
            "recoveryDebugger": recovery,
        }
    return {
        "ok": True,
        "targetArch": target_arch,
        "requestedArch": desired_arch,
        "ensureDebugger": ensured,
        "recoveryDebugger": recovery,
        "identity": identity,
    }


def _refresh_state_after_session_binding(fallback: Any) -> Dict[str, Any]:
    """Return a state snapshot whose embedded binding matches the live binding."""

    try:
        refreshed = _build_debug_state(
            include_console=False,
            include_callstack=False,
            max_console_chars=0,
        )
    except Exception:
        refreshed = {}
    state = dict(refreshed) if isinstance(refreshed, dict) and refreshed else dict(
        fallback if isinstance(fallback, dict) else {}
    )
    binding_state = _describe_bound_session_match(state=state)
    state["binding"] = binding_state
    session = state.get("session")
    if isinstance(session, dict):
        session = dict(session)
        session["binding"] = binding_state
        state["session"] = session
    return state


def _is_stale_launch_contract_error(result: Any) -> bool:
    """Return True only for the safe-to-retry stale launch-contract failure.

    A reachable legacy plugin is intentionally accepted by the general bridge
    readiness probe so read-only compatibility calls still work. A typed
    process launch, however, needs the current launch contract. High-level
    launch workflows may restart the matching debugger once when the active
    instance advertises an older launch version; all other capability failures
    remain explicit and fail closed.
    """

    if not isinstance(result, dict) or result.get("ok"):
        return False
    if str(result.get("errorCode") or "").strip().upper() != "UNSUPPORTED_CAPABILITY":
        return False
    capability = str(result.get("capability") or "").strip().casefold()
    if capability == "launch.version":
        return True
    message = str(result.get("error") or result.get("reason") or "").casefold()
    return "launch contract version" in message and "bridge/hello" in message


def _run_to_entry_point(timeout_ms: int = 8000, poll_ms: int = 100) -> Dict[str, Any]:
    """
    Resume from the initial loader stops until the target image entry point is
    reached.  A plain ``run`` followed by the first pause is insufficient:
    recent Windows builds can expose loader/system-DLL TLS callback breakpoints
    before the executable entry point.  Prefer the address-based ``RunUntil``
    workflow because it owns a temporary entry breakpoint and skips known
    loader/TLS noise without deleting foreign breakpoints.
    """
    run_until = globals().get("RunUntil")
    if callable(run_until):
        deadline = time.time() + (max(0, int(timeout_ms)) / 1000.0)
        skipped: List[Dict[str, Any]] = []
        last_result: Dict[str, Any] = {}
        # RunUntil normally consumes loader noise itself.  Keep a small outer
        # recovery loop for x64dbg builds that report a loader/system stop only
        # through CB_PAUSEDEBUG (without a matching CB_BREAKPOINT event).
        for _attempt in range(8):
            remaining_ms = max(0, int((deadline - time.time()) * 1000))
            if remaining_ms <= 0:
                break
            try:
                result = run_until(
                    target="entry",
                    timeout_ms=remaining_ms,
                    poll_ms=max(20, int(poll_ms)),
                )
            except Exception as e:
                return {"ok": False, "error": str(e), "mode": "entry_breakpoint"}
            if not isinstance(result, dict):
                return {
                    "ok": False,
                    "error": "RunUntil(entry) returned a non-object result.",
                    "mode": "entry_breakpoint",
                }
            last_result = result
            skipped.extend(
                item
                for item in result.get("skippedBreakpoints", [])
                if isinstance(item, dict)
            )
            state = result.get("state") if isinstance(result.get("state"), dict) else {}
            if result.get("ok"):
                break
            noise_event = {
                "breakpointModule": state.get("module"),
                "breakpointName": state.get("breakpointName"),
            }
            noise_classifier = globals().get("_is_system_noise_breakpoint")
            safe_loader_pause = bool(
                state.get("paused")
                and str(state.get("exceptionCode") or "0").strip().lower()
                in ("0", "0x0", "none")
                and callable(noise_classifier)
                and noise_classifier(noise_event)
            )
            if not safe_loader_pause:
                break
            skipped.append(
                {
                    "addr": state.get("rip"),
                    "rip": state.get("rip"),
                    "name": state.get("breakpointName") or "loader pause",
                    "module": state.get("module"),
                    "eventSeq": state.get("eventSeq"),
                }
            )

        result = last_result
        state = result.get("state") if isinstance(result.get("state"), dict) else {}
        return {
            "ok": bool(result.get("ok")),
            "rip": state.get("rip"),
            "ripRef": state.get("ripRef") or result.get("targetRef"),
            "module": state.get("module"),
            "state": state.get("state"),
            "target": result.get("target"),
            "mode": "entry_breakpoint",
            "skippedBreakpoints": skipped,
            "error": result.get("error"),
            "hint": result.get("hint"),
        }

    # Minimal compatibility fallback for deployments that intentionally omit
    # ext_tools.py.  It preserves the historical one-run behavior, while the
    # full bridge always takes the guarded entry-breakpoint path above.
    try:
        DebugRun()
    except Exception as e:
        return {"ok": False, "error": str(e)}
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    state: Dict[str, Any] = {}
    while time.time() < deadline:
        try:
            state = _build_debug_state(
                include_console=False, include_callstack=False, max_console_chars=0
            )
        except Exception:
            state = {}
        if isinstance(state, dict) and (
            state.get("paused") or state.get("state") == "paused"
        ):
            return {
                "ok": True,
                "rip": state.get("rip"),
                "ripRef": state.get("ripRef"),
                "module": state.get("module"),
                "state": state.get("state"),
            }
        if isinstance(state, dict) and state.get("state") in (
            "terminated",
            "not_debugging",
        ):
            return {"ok": False, "state": state.get("state")}
        time.sleep(max(poll_ms, 20) / 1000.0)
    return {
        "ok": False,
        "timedOut": True,
        "state": state.get("state") if isinstance(state, dict) else None,
    }


def _target_requires_elevation(path: str) -> bool:
    """Best-effort check for a requireAdministrator/highestAvailable manifest so a
    launch failure can point at UAC rather than looking like a generic error."""
    try:
        if not path or not os.path.exists(path) or os.path.getsize(path) > 200 * 1024 * 1024:
            return False
        with open(path, "rb") as fh:
            data = fh.read()
        return b"requireAdministrator" in data or b"highestAvailable" in data
    except Exception:
        return False


def _summarize_launch_failure(target_path: str, init_result: Any):
    """Build a clear (error, hint) pair for a failed LaunchFileUnderDebugger so the
    caller does not have to dig into nested init state to learn what went wrong."""
    attempts = init_result.get("attempts") if isinstance(init_result, dict) else None
    detail = "the debugger did not enter a debugging state"
    state = init_result.get("state") if isinstance(init_result, dict) else None
    if isinstance(state, dict) and not state.get("debugging"):
        detail = "the target process never started (debugger stayed in 'not_debugging')"
    error = (
        f"Failed to launch target under the debugger after {attempts or 'several'} "
        f"attempt(s): {detail}."
    )
    if _target_requires_elevation(target_path):
        hint = (
            "The target's manifest requests elevation "
            "(requireAdministrator/highestAvailable); a non-elevated debugger cannot "
            "launch it. Start x64dbg/x32dbg as administrator and retry."
        )
    else:
        hint = (
            "Common causes: the target needs administrator elevation, is an "
            "installer/DRM/anti-debug-protected binary, or expects command-line "
            "arguments or a specific working directory. Check the x64dbg Log tab "
            "for the underlying load error."
        )
    return error, hint


def _prepare_hidemain_workflow(
    mode: str = "off",
    target_arch: str = "",
    root: str = "",
    allow_system_changes: bool = False,
    allow_unsigned: bool = False,
    acknowledge_kernel_risk: bool = False,
) -> Dict[str, Any]:
    requested = str(mode or "off").strip().lower()
    if requested not in ("off", "auto", "force"):
        return {"ok": False, "mode": requested, "error": f"Unknown HideMain mode: {mode}"}
    if requested == "off":
        return {
            "ok": True,
            "mode": requested,
            "skipped": True,
            "reason": "HideMain policy disabled.",
        }
    normalized_arch = str(target_arch or "").strip().lower()
    if normalized_arch in ("x86", "x32"):
        payload: Dict[str, Any] = {
            "ok": requested != "force",
            "mode": requested,
            "skipped": requested != "force",
            "unsupported": True,
            "error": "HideMain safe-v2 supports x64 targets only.",
        }
        if payload.get("skipped"):
            payload["reason"] = payload.pop("error")
        return payload
    prepare = globals().get("_prepare_hidemain_policy")
    if not callable(prepare):
        return {
            "ok": requested != "force",
            "mode": requested,
            "skipped": requested != "force",
            "error": "HideMain MCP extension is unavailable.",
            "extension": dict(globals().get("_HIDEMAIN_TOOLS_STATUS") or {}),
        }
    return prepare(
        mode=requested,
        root=root,
        allow_system_changes=allow_system_changes,
        allow_unsigned=allow_unsigned,
        acknowledge_kernel_risk=acknowledge_kernel_risk,
    )


def _apply_hidemain_workflow(
    pid: int,
    mode: str = "off",
    root: str = "",
    allow_system_changes: bool = False,
    allow_unsigned: bool = False,
    acknowledge_kernel_risk: bool = False,
) -> Dict[str, Any]:
    requested = str(mode or "off").strip().lower()
    if requested == "off":
        return {
            "ok": True,
            "mode": requested,
            "skipped": True,
            "reason": "HideMain policy disabled.",
        }
    apply_policy = globals().get("_apply_hidemain_policy")
    if not callable(apply_policy):
        return {
            "ok": requested != "force",
            "mode": requested,
            "skipped": requested != "force",
            "error": "HideMain MCP extension is unavailable.",
            "extension": dict(globals().get("_HIDEMAIN_TOOLS_STATUS") or {}),
        }
    return apply_policy(
        pid=int(pid or 0),
        mode=requested,
        root=root,
        allow_system_changes=allow_system_changes,
        allow_unsigned=allow_unsigned,
        acknowledge_kernel_risk=acknowledge_kernel_risk,
    )


@mcp.tool()
def LaunchFileUnderDebugger(
    exe_path: str,
    arch: str = "auto",
    restart_debugger: bool = False,
    timeout_ms: int = 20000,
    retries: int = 5,
    stop_first: bool = True,
    use_scyllahide: str = "auto",
    scyllahide_profile: str = "",
    use_hidemain: str = "off",
    hidemain_root: str = "",
    hidemain_allow_system_changes: bool = False,
    hidemain_allow_unsigned_driver: bool = False,
    hidemain_acknowledge_kernel_risk: bool = False,
    advance_to_entry: bool = True,
    arguments: Optional[List[str]] = None,
    command_line: str = "",
    working_directory: str = "",
    environment: Optional[Dict[str, Optional[str]]] = None,
    inherit_environment: bool = True,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
    child_policy: str = "none",
    capture_limit_bytes: int = _DEFAULT_CAPTURE_LIMIT_BYTES,
    detail: str = "",
) -> dict:
    """
    Ensure the right debugger is running and launch a target executable under it.

    Args:
        exe_path: Absolute path to the target executable.
        arch: Desired debugger architecture. Auto prefers the target PE architecture.
        restart_debugger: When true, restart the debugger before launching the target.
        timeout_ms: Maximum total wait budget.
        retries: Maximum init attempts for the target.
        stop_first: When true, stop the active debug session before launching the target.
        use_scyllahide: auto, off, or force.
        scyllahide_profile: Optional explicit ScyllaHide profile.
        use_hidemain: off, auto, or force. Default off. Auto only uses an
            already-running driver; force fails before launch unless the safe-v2
            x64-only driver is ready (or explicitly allowed to start).
        hidemain_root: Optional HideMain distribution root (otherwise HIDEMAIN_ROOT).
        hidemain_allow_system_changes: Allow starting an already-installed service.
        hidemain_allow_unsigned_driver: Explicitly allow the supplied unsigned driver.
        hidemain_acknowledge_kernel_risk: Acknowledge general kernel-driver/BSOD risk.
        arguments: Argument vector excluding argv[0].
        command_line: Explicit Windows command-line tail (mutually exclusive with arguments).
        working_directory: Target process current directory.
        environment: Per-launch environment overrides; rejected explicitly when unsupported.
        inherit_environment: Inherit the debugger environment when supported.
        stdin: Typed stdin object. Modes: inherit/null/file/bytes/pipe.
        stdout: Typed stdout object. Modes: inherit/null/file/pipe.
        stderr: Typed stderr object. Modes: inherit/null/file/pipe. When any
            stream is supplied, all three must be supplied explicitly.
        child_policy: none, attach-first, attach-all, or break-on-create.
        capture_limit_bytes: Per-pipe bounded retention/queue capacity.
        detail: summary or full. Empty inherits the active tool profile.
        advance_to_entry: When true (default), resume once from the initial system
            breakpoint so the target lands paused at its entry point -- the
            conventional post-launch state, so a single later DebugRun starts the
            program instead of first stopping again at the entry breakpoint.
    """
    detail_level, detail_error = _resolve_response_detail(detail)
    if detail_error:
        return detail_error

    def _launch_response(value: Dict[str, Any]) -> Dict[str, Any]:
        return _compact_launch_result(value) if detail_level == "summary" else value

    target_path = _resolve_target_exe_path(exe_path)
    if not target_path:
        return _launch_response({
            "ok": False,
            "error": "Target executable path is required.",
            "logPath": LOG_PATH,
        })
    if not os.path.exists(target_path):
        return _launch_response({
            "ok": False,
            "error": f"Target executable was not found: {target_path}",
            "exePath": target_path,
            "logPath": LOG_PATH,
        })
    requested_hidemain = str(use_hidemain or "off").strip().lower()
    if requested_hidemain not in ("off", "auto", "force"):
        return _launch_response({
            "ok": False,
            "exePath": target_path,
            "error": f"Unknown HideMain mode: {use_hidemain}",
            "hideMain": {"ok": False, "mode": requested_hidemain},
            "logPath": LOG_PATH,
        })
    desired_arch = _normalize_debugger_arch(arch, exe_path=target_path)
    ensure_result = EnsureDebugger(
        arch=desired_arch,
        timeout_ms=min(max(timeout_ms, 0), 15000) or 15000,
        restart=restart_debugger,
    )
    recovery_result = None
    if (not isinstance(ensure_result, dict) or not ensure_result.get("ok")) and (
        not restart_debugger
    ):
        if _should_auto_restart_debugger(ensure_result):
            recovery_result = RestartDebugger(
                arch=desired_arch,
                timeout_ms=min(max(timeout_ms, 0), 20000) or 20000,
                reload_target=False,
            )
            if isinstance(recovery_result, dict) and recovery_result.get("ok"):
                ensure_result = recovery_result
    if not isinstance(ensure_result, dict) or not ensure_result.get("ok"):
        return _launch_response({
            "ok": False,
            "exePath": target_path,
            "requestedArch": desired_arch,
            "ensureDebugger": ensure_result,
            "recoveryDebugger": recovery_result,
            "logPath": LOG_PATH,
        })
    remaining_timeout = max(5000, int(timeout_ms) - 1500)
    def _init_target() -> Dict[str, Any]:
        return InitDebuggee(
            target_path,
            timeout_ms=remaining_timeout,
            retries=retries,
            stop_first=stop_first,
            use_scyllahide=use_scyllahide,
            scyllahide_profile=scyllahide_profile,
            use_hidemain=use_hidemain,
            hidemain_root=hidemain_root,
            hidemain_allow_system_changes=hidemain_allow_system_changes,
            hidemain_allow_unsigned_driver=hidemain_allow_unsigned_driver,
            hidemain_acknowledge_kernel_risk=hidemain_acknowledge_kernel_risk,
            arguments=arguments,
            command_line=command_line,
            working_directory=working_directory,
            environment=environment,
            inherit_environment=inherit_environment,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            child_policy=child_policy,
            capture_limit_bytes=capture_limit_bytes,
        )

    init_result = _init_target()
    initial_init_result = None
    if (
        not restart_debugger
        and recovery_result is None
        and _is_stale_launch_contract_error(init_result)
    ):
        initial_init_result = init_result
        recovery_result = RestartDebugger(
            arch=desired_arch,
            timeout_ms=min(max(timeout_ms, 0), 20000) or 20000,
            reload_target=False,
        )
        if isinstance(recovery_result, dict) and recovery_result.get("ok"):
            ensure_result = recovery_result
            init_result = _init_target()
            _log_event(
                "launch_stale_bridge_recovered",
                exePath=target_path,
                arch=desired_arch,
                recovered=bool(init_result.get("ok"))
                if isinstance(init_result, dict)
                else False,
            )
    advance_state = None
    if advance_to_entry and isinstance(init_result, dict) and init_result.get("ok"):
        advance_state = _run_to_entry_point(
            timeout_ms=min(max(remaining_timeout, 2000), 8000)
        )
        _log_event("launch_advance_to_entry", result=advance_state)
    advance_failed = bool(
        advance_to_entry
        and isinstance(advance_state, dict)
        and not advance_state.get("ok")
    )
    if advance_failed and isinstance(init_result, dict):
        scylla_state = init_result.get("scyllaHide")
        if isinstance(scylla_state, dict):
            scylla_state["ok"] = False
            scylla_state["runtimeVerification"] = {
                "ok": False,
                "reason": (
                    "The requested entry-point advance did not complete; "
                    "protection remains unverified."
                ),
                "advance": advance_state,
            }
    launch_ok = bool(
        isinstance(init_result, dict)
        and init_result.get("ok")
        and not advance_failed
    )
    payload = {
        "ok": launch_ok,
        "exePath": target_path,
        "requestedArch": desired_arch,
        "ensureDebugger": ensure_result,
        "recoveryDebugger": recovery_result,
        "init": init_result,
        "advanceToEntry": advance_state,
        "logPath": LOG_PATH,
    }
    if initial_init_result is not None:
        payload["initialInit"] = initial_init_result
    if not launch_ok:
        if advance_failed:
            payload["error"] = (
                "Target launched, but advancing to its entry point failed."
            )
            payload["hint"] = (
                (advance_state or {}).get("hint")
                or (advance_state or {}).get("error")
                or "Inspect the current exception and runtime protection status."
            )
        else:
            payload["error"], payload["hint"] = _summarize_launch_failure(
                target_path, init_result
            )
    return _launch_response(payload)


@mcp.tool()
def LaunchAndOpenDebuggee(
    exe_path: str,
    arch: str = "auto",
    restart_debugger: bool = False,
    timeout_ms: int = 20000,
    retries: int = 5,
    stop_first: bool = True,
    use_scyllahide: str = "auto",
    scyllahide_profile: str = "",
    use_hidemain: str = "off",
    hidemain_root: str = "",
    hidemain_allow_system_changes: bool = False,
    hidemain_allow_unsigned_driver: bool = False,
    hidemain_acknowledge_kernel_risk: bool = False,
    advance_to_entry: bool = True,
    arguments: Optional[List[str]] = None,
    command_line: str = "",
    working_directory: str = "",
    environment: Optional[Dict[str, Optional[str]]] = None,
    inherit_environment: bool = True,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
    child_policy: str = "none",
    capture_limit_bytes: int = _DEFAULT_CAPTURE_LIMIT_BYTES,
    detail: str = "",
) -> dict:
    """
    Preferred one-shot entrypoint for opening a target under x64dbg/x32dbg.

    This tool is intentionally explicit for agents: it ensures the matching debugger
    is running, opens the target executable under it, and returns the resulting
    debug-session payload. Use this before falling back to any shell-based debugger
    discovery.

    Args:
        exe_path: Absolute path to the target executable.
        arch: Desired debugger architecture. Auto prefers the target PE architecture.
        restart_debugger: When true, restart the debugger before opening the target.
        timeout_ms: Maximum total wait budget.
        retries: Maximum init attempts for the target.
        stop_first: When true, stop the active debug session before opening the target.
        use_scyllahide: auto, off, or force.
        scyllahide_profile: Optional explicit ScyllaHide profile.
        use_hidemain: off, auto, or force (default off).
        hidemain_root: Optional HideMain distribution root.
        hidemain_allow_system_changes: Allow starting an installed driver service.
        hidemain_allow_unsigned_driver: Explicit unsigned-driver acknowledgement.
        hidemain_acknowledge_kernel_risk: Explicit general kernel-driver/BSOD acknowledgement.
        advance_to_entry: When true (default), leave the target paused at its entry
            point after opening (see LaunchFileUnderDebugger).
        detail: summary or full. Empty inherits the active tool profile.
    """
    launch_kwargs: Dict[str, Any] = {
        "exe_path": exe_path,
        "arch": arch,
        "restart_debugger": restart_debugger,
        "timeout_ms": timeout_ms,
        "retries": retries,
        "stop_first": stop_first,
        "use_scyllahide": use_scyllahide,
        "scyllahide_profile": scyllahide_profile,
        "use_hidemain": use_hidemain,
        "hidemain_root": hidemain_root,
        "hidemain_allow_system_changes": hidemain_allow_system_changes,
        "hidemain_allow_unsigned_driver": hidemain_allow_unsigned_driver,
        "hidemain_acknowledge_kernel_risk": hidemain_acknowledge_kernel_risk,
        "advance_to_entry": advance_to_entry,
    }
    # Preserve the exact legacy delegation shape when no v2 launch options were
    # supplied; direct Python integrations commonly mock this call.
    if arguments is not None:
        launch_kwargs["arguments"] = arguments
    if command_line:
        launch_kwargs["command_line"] = command_line
    if working_directory:
        launch_kwargs["working_directory"] = working_directory
    if environment is not None:
        launch_kwargs["environment"] = environment
    if not inherit_environment:
        launch_kwargs["inherit_environment"] = False
    if any(value is not None for value in (stdin, stdout, stderr)):
        launch_kwargs.update({"stdin": stdin, "stdout": stdout, "stderr": stderr})
    if child_policy != "none":
        launch_kwargs["child_policy"] = child_policy
    if capture_limit_bytes != _DEFAULT_CAPTURE_LIMIT_BYTES:
        launch_kwargs["capture_limit_bytes"] = capture_limit_bytes
    if detail:
        launch_kwargs["detail"] = detail
    result = LaunchFileUnderDebugger(**launch_kwargs)
    payload = dict(result) if isinstance(result, dict) else {"ok": False, "error": str(result)}
    payload["entrypointTool"] = "LaunchAndOpenDebuggee"
    payload["legacyAlias"] = "LaunchFileUnderDebugger"
    return payload


def _normalize_launch_id(value: Any) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
    if not isinstance(value, str):
        return None, {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "launch_id must be a string",
        }
    if (
        not value
        or len(value) > _MAX_LAUNCH_ID_LENGTH
        or value != value.strip()
        or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value)
    ):
        return None, {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": (
                "launch_id must contain 1..128 printable ASCII characters "
                "without surrounding whitespace"
            ),
        }
    return value, None


def _launch_bridge_tool_result(
    envelope: BridgeEnvelope, default_error_code: str, default_message: str
) -> Dict[str, Any]:
    if envelope.ok:
        data = envelope.data
        payload = dict(data) if isinstance(data, dict) else {"data": data}
        payload.setdefault("ok", True)
        payload["meta"] = envelope.meta
        return payload
    error = envelope.error
    return {
        "ok": False,
        "errorCode": error.code if error else default_error_code,
        "error": error.message if error else default_message,
        "retryable": bool(error.retryable) if error else False,
        "meta": envelope.meta,
    }


@mcp.tool()
def GetLaunchState(launch_id: str) -> dict:
    """Return process, stream, child-policy, and cleanup state for one launch."""

    normalized_id, invalid = _normalize_launch_id(launch_id)
    if invalid:
        return invalid
    envelope = _bridge_request(
        "GET",
        "Debug/Launch/State",
        params={"launchId": normalized_id},
        log=False,
        timeout_sec=5.0,
        guard="bridge",
        idempotent=True,
    )
    return _launch_bridge_tool_result(
        envelope, "LAUNCH_STATE_FAILED", "Failed to read launch state."
    )


@mcp.tool()
def ReadLaunchStream(
    launch_id: str,
    stream: str = "stdout",
    cursor: int = 0,
    max_bytes: int = 65536,
    wait_ms: int = 0,
) -> dict:
    """Read binary-safe captured stdout/stderr using an absolute ring cursor."""

    normalized_id, invalid = _normalize_launch_id(launch_id)
    if invalid:
        return invalid
    if not isinstance(stream, str) or stream.casefold() not in {"stdout", "stderr"}:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "stream must be stdout or stderr",
        }
    normalized_stream = stream.casefold()
    cursor_value, cursor_error = _strict_int(cursor, "cursor")
    max_value, max_error = _strict_int(max_bytes, "max_bytes")
    wait_value, wait_error = _strict_int(wait_ms, "wait_ms")
    if cursor_error or max_error or wait_error:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": cursor_error or max_error or wait_error,
        }
    assert cursor_value is not None and max_value is not None and wait_value is not None
    if cursor_value < 0 or cursor_value > 0xFFFFFFFFFFFFFFFF:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "cursor must be between 0 and 18446744073709551615",
        }
    if not 1 <= max_value <= _MAX_LAUNCH_IO_CHUNK_BYTES:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "max_bytes must be between 1 and 1048576",
        }
    if not 0 <= wait_value <= _MAX_LAUNCH_WAIT_MS:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "wait_ms must be between 0 and 60000",
        }
    started = time.monotonic()
    deadline = started + (wait_value / 1000.0)
    slices = 0
    envelope: Optional[BridgeEnvelope] = None
    while True:
        slices += 1
        if wait_value:
            # Preserve the caller's exact first slice.  Computing the
            # remaining deadline after a few Python instructions can shave a
            # millisecond and makes the wire contract timing-dependent.
            if slices == 1:
                slice_wait = min(_MAX_LAUNCH_NATIVE_WAIT_SLICE_MS, wait_value)
            else:
                remaining_ms = max(0, int(math.ceil((deadline - time.monotonic()) * 1000)))
                slice_wait = min(_MAX_LAUNCH_NATIVE_WAIT_SLICE_MS, remaining_ms)
        else:
            slice_wait = 0
        envelope = _bridge_request(
            "GET",
            "Debug/Launch/Stream/Read",
            params={
                "launchId": normalized_id,
                "stream": normalized_stream,
                "cursor": cursor_value,
                "maxBytes": max_value,
                "waitMs": slice_wait,
            },
            log=False,
            timeout_sec=max(5.0, slice_wait / 1000.0 + 2.0),
            guard="bridge",
            idempotent=True,
        )
        if not envelope.ok:
            break
        data = envelope.data if isinstance(envelope.data, dict) else {}
        encoded = data.get("dataBase64")
        if not isinstance(encoded, str):
            # A successful lifecycle response without the stream field is a
            # malformed/legacy bridge response; do not spin waiting on it.
            break
        has_bytes = isinstance(encoded, str) and bool(encoded)
        if (
            not wait_value
            or has_bytes
            or data.get("eof") is True
            or data.get("closed") is True
            or data.get("cursorTruncated") is True
            or time.monotonic() >= deadline
        ):
            break
        # A zero-length non-EOF response means the native 750 ms slice elapsed
        # without new output.  Reissue the same absolute cursor until the
        # caller's requested deadline, never advancing it speculatively.
        if slice_wait <= 0:
            break
    payload = _launch_bridge_tool_result(
        envelope,
        "LAUNCH_STREAM_READ_FAILED",
        "Failed to read launch stream.",
    )
    payload["clientWaitMs"] = wait_value
    payload["clientWaitedMs"] = min(
        wait_value, max(0, int((time.monotonic() - started) * 1000))
    )
    payload["clientWaitSlices"] = slices
    payload["clientWaitAggregated"] = slices > 1
    return payload


@mcp.tool()
def WriteLaunchStdin(
    launch_id: str,
    data_base64: str,
    wait_ms: int = 0,
    close_after_write: bool = False,
) -> dict:
    """Write one canonical-base64 chunk to a launch configured with stdin=pipe."""

    normalized_id, invalid = _normalize_launch_id(launch_id)
    if invalid:
        return invalid
    decoded, decode_error = _decode_canonical_base64(data_base64, "data_base64")
    if decode_error:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": decode_error,
        }
    assert decoded is not None
    if not decoded:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "data_base64 must decode to at least one byte",
        }
    if len(decoded) > _MAX_LAUNCH_IO_CHUNK_BYTES:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "data_base64 exceeds the 1048576-byte decoded limit",
        }
    wait_value, wait_error = _strict_int(wait_ms, "wait_ms")
    if wait_error:
        return {"ok": False, "errorCode": "INVALID_ARGUMENT", "error": wait_error}
    assert wait_value is not None
    if not 0 <= wait_value <= _MAX_LAUNCH_WAIT_MS:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "wait_ms must be between 0 and 60000",
        }
    if not isinstance(close_after_write, bool):
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "close_after_write must be a boolean",
        }
    canonical = base64.b64encode(decoded).decode("ascii")
    started = time.monotonic()
    deadline = started + (wait_value / 1000.0)
    slices = 0
    envelope: Optional[BridgeEnvelope] = None
    while True:
        slices += 1
        if wait_value:
            if slices == 1:
                slice_wait = min(_MAX_LAUNCH_NATIVE_WAIT_SLICE_MS, wait_value)
            else:
                remaining_ms = max(0, int(math.ceil((deadline - time.monotonic()) * 1000)))
                slice_wait = min(_MAX_LAUNCH_NATIVE_WAIT_SLICE_MS, remaining_ms)
        else:
            slice_wait = 0
        envelope = _bridge_request(
            "POST",
            "Debug/Launch/Stdin/Write",
            form_data={
                "launchId": normalized_id,
                "dataBase64": canonical,
                "waitMs": str(slice_wait),
                "closeAfterWrite": "true" if close_after_write else "false",
            },
            log=True,
            timeout_sec=max(5.0, slice_wait / 1000.0 + 2.0),
            guard="session",
            idempotent=False,
        )
        if envelope.ok:
            data = envelope.data if isinstance(envelope.data, dict) else {}
            accepted = data.get("acceptedBytes")
            if isinstance(accepted, int) and accepted != len(decoded):
                return {
                    "ok": False,
                    "errorCode": "LAUNCH_STDIN_PARTIAL_ACCEPT",
                    "error": "The bridge accepted a partial stdin chunk; refusing to retry it.",
                    "acceptedBytes": accepted,
                    "requestedBytes": len(decoded),
                    "clientWaitMs": wait_value,
                    "clientWaitSlices": slices,
                }
            break
        error_code = (
            envelope.error.code.casefold()
            if envelope.error and envelope.error.code
            else ""
        )
        if (
            error_code != "stdin_backpressure"
            or not wait_value
            or time.monotonic() >= deadline
        ):
            break
        # stdin_backpressure guarantees acceptedBytes==0, so repeating the
        # exact chunk is safe.  Transport/unknown errors are never retried to
        # avoid duplicating a write whose response may have been lost.
        if slice_wait <= 0:
            break
    payload = _launch_bridge_tool_result(
        envelope,
        "LAUNCH_STDIN_WRITE_FAILED",
        "Failed to write launch stdin.",
    )
    payload["clientWaitMs"] = wait_value
    payload["clientWaitedMs"] = min(
        wait_value, max(0, int((time.monotonic() - started) * 1000))
    )
    payload["clientWaitSlices"] = slices
    payload["clientWaitAggregated"] = slices > 1
    return payload


@mcp.tool()
def CloseLaunchStdin(launch_id: str) -> dict:
    """Close a launch pipe's write end, delivering deterministic EOF to the target."""

    normalized_id, invalid = _normalize_launch_id(launch_id)
    if invalid:
        return invalid
    envelope = _bridge_request(
        "POST",
        "Debug/Launch/Stdin/Close",
        form_data={"launchId": normalized_id},
        log=True,
        timeout_sec=5.0,
        guard="session",
        idempotent=False,
    )
    return _launch_bridge_tool_result(
        envelope, "LAUNCH_STDIN_CLOSE_FAILED", "Failed to close launch stdin."
    )


@mcp.tool()
def CloseLaunchResources(launch_id: str, timeout_ms: int = 5000) -> dict:
    """Bounded, retryable close of all retained launch workers and handles."""

    normalized_id, invalid = _normalize_launch_id(launch_id)
    if invalid:
        return invalid
    timeout_value, timeout_error = _strict_int(timeout_ms, "timeout_ms")
    if timeout_error:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": timeout_error,
        }
    assert timeout_value is not None
    if not 0 <= timeout_value <= 30000:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "timeout_ms must be between 0 and 30000",
        }
    envelope = _bridge_request(
        "POST",
        "Debug/Launch/Resources/Close",
        form_data={
            "launchId": normalized_id,
            "timeoutMs": str(timeout_value),
        },
        log=True,
        timeout_sec=max(10.0, timeout_value / 1000.0 + 5.0),
        guard="bridge",
        idempotent=False,
    )
    return _launch_bridge_tool_result(
        envelope,
        "LAUNCH_RESOURCES_CLOSE_FAILED",
        "Failed to close launch resources.",
    )


@mcp.tool()
def AttachToProcess(
    pid: int = 0,
    exe_filter: str = "",
    arch: str = "auto",
    restart_debugger: bool = False,
    stop_first: bool = True,
    timeout_ms: int = 20000,
    use_hidemain: str = "off",
    hidemain_root: str = "",
    hidemain_allow_system_changes: bool = False,
    hidemain_allow_unsigned_driver: bool = False,
    hidemain_acknowledge_kernel_risk: bool = False,
) -> dict:
    """
    Attach x64dbg/x32dbg to an already-running process.

    Args:
        pid: Exact target PID. Preferred when known.
        exe_filter: Process name or image-path substring when pid is not provided.
        arch: Desired debugger architecture. Auto prefers the target process architecture.
        restart_debugger: When true, restart the debugger before attach.
        stop_first: When true, stop the current debug session before attaching.
        timeout_ms: Maximum time to wait for the attach to complete.
        use_hidemain: off, auto, or force (default off).
        hidemain_root: Optional HideMain distribution root.
        hidemain_allow_system_changes: Allow starting an installed driver service.
        hidemain_allow_unsigned_driver: Explicit unsigned-driver acknowledgement.
        hidemain_acknowledge_kernel_risk: Explicit general kernel-driver/BSOD acknowledgement.
    """
    target = _resolve_attach_target(pid=pid, exe_filter=exe_filter)
    if not target.get("ok"):
        payload = dict(target)
        payload["logPath"] = LOG_PATH
        return payload
    requested_hidemain = str(use_hidemain or "off").strip().lower()
    if requested_hidemain not in ("off", "auto", "force"):
        return {
            "ok": False,
            "target": target,
            "error": f"Unknown HideMain mode: {use_hidemain}",
            "hideMain": {"ok": False, "mode": requested_hidemain},
            "logPath": LOG_PATH,
        }
    target_pid = int(target.get("pid") or 0)
    target_path = _repair_text_mojibake(str(target.get("imagePath") or "").strip())
    target_arch = str(target.get("arch") or "").strip().lower()
    desired_arch = _normalize_debugger_arch(arch, exe_path=target_path)
    if target_arch in ("x86", "x64") and desired_arch != target_arch:
        return {
            "ok": False,
            "error": f"Requested debugger arch {desired_arch} does not match target process arch {target_arch}.",
            "target": target,
            "requestedArch": desired_arch,
            "logPath": LOG_PATH,
        }
    ensure_result = EnsureDebugger(
        arch=target_arch or desired_arch,
        timeout_ms=min(max(timeout_ms, 0), 15000) or 15000,
        restart=restart_debugger,
    )
    recovery_result = None
    if (not isinstance(ensure_result, dict) or not ensure_result.get("ok")) and (
        not restart_debugger
    ):
        if _should_auto_restart_debugger(ensure_result):
            recovery_result = RestartDebugger(
                arch=target_arch or desired_arch,
                timeout_ms=min(max(timeout_ms, 0), 20000) or 20000,
                reload_target=False,
            )
            if isinstance(recovery_result, dict) and recovery_result.get("ok"):
                ensure_result = recovery_result
    if not isinstance(ensure_result, dict) or not ensure_result.get("ok"):
        return {
            "ok": False,
            "target": target,
            "requestedArch": target_arch or desired_arch,
            "ensureDebugger": ensure_result,
            "recoveryDebugger": recovery_result,
            "logPath": LOG_PATH,
        }
    hidemain_prepare = _prepare_hidemain_workflow(
        mode=use_hidemain,
        target_arch=target_arch or desired_arch,
        root=hidemain_root,
        allow_system_changes=hidemain_allow_system_changes,
        allow_unsigned=hidemain_allow_unsigned_driver,
        acknowledge_kernel_risk=hidemain_acknowledge_kernel_risk,
    )
    if str(use_hidemain or "off").strip().lower() == "force" and not hidemain_prepare.get("ok"):
        return {
            "ok": False,
            "target": target,
            "requestedArch": target_arch or desired_arch,
            "ensureDebugger": ensure_result,
            "recoveryDebugger": recovery_result,
            "hideMain": hidemain_prepare,
            "error": hidemain_prepare.get("error") or "HideMain force-mode preparation failed.",
            "logPath": LOG_PATH,
        }
    current_state = _build_debug_state(
        include_console=False, include_callstack=False, max_console_chars=0
    )
    current_pid = int(current_state.get("debuggeePid") or 0)
    if current_state.get("debugging") and current_pid == target_pid:
        binding = _bind_debuggee_session(
            pid=target_pid,
            image_path=target_path or _get_process_image_path(target_pid),
            strict=True,
            source="AttachToProcess",
        )
        _remember_runtime(
            lastDebuggeePid=target_pid,
            lastDebuggeeImage=_process_basename(target_path)
            or str(target.get("exe") or ""),
            lastDebuggeePath=target_path or _get_process_image_path(target_pid),
        )
        hidemain_result = _apply_hidemain_workflow(
            pid=target_pid,
            mode=use_hidemain,
            root=hidemain_root,
            allow_system_changes=hidemain_allow_system_changes,
            allow_unsigned=hidemain_allow_unsigned_driver,
            acknowledge_kernel_risk=hidemain_acknowledge_kernel_risk,
        )
        hidemain_required = str(use_hidemain or "off").strip().lower() == "force"
        return {
            "ok": bool(not hidemain_required or hidemain_result.get("ok")),
            "alreadyAttached": True,
            "target": target,
            "requestedArch": target_arch or desired_arch,
            "state": current_state,
            "binding": binding,
            "ensureDebugger": ensure_result,
            "recoveryDebugger": recovery_result,
            "hideMain": hidemain_result,
            "error": (
                hidemain_result.get("error") or "HideMain force-mode application failed."
                if hidemain_required and not hidemain_result.get("ok")
                else None
            ),
            "logPath": LOG_PATH,
        }
    if current_pid != target_pid:
        _clear_bound_session()
    if current_state.get("debugging") and not stop_first:
        return {
            "ok": False,
            "error": "Debugger is already attached to another process. Use stop_first=true to replace it.",
            "target": target,
            "requestedArch": target_arch or desired_arch,
            "state": current_state,
            "ensureDebugger": ensure_result,
            "recoveryDebugger": recovery_result,
            "logPath": LOG_PATH,
        }
    if stop_first:
        session_info = (
            current_state.get("session", {})
            if isinstance(current_state.get("session"), dict)
            else {}
        )
        if current_state.get("debugging") or current_state.get("state") == "exited":
            try:
                DebugStop()
            except Exception:
                pass
            _wait_for_debugger_idle(
                timeout_ms=min(max(timeout_ms, 0), 2500) or 2500, poll_ms=125
            )
        elif bool(session_info.get("stopping")):
            _wait_for_debugger_idle(
                timeout_ms=min(max(timeout_ms, 0), 2500) or 2500, poll_ms=125
            )
    _restore_pending_scyllahide_profile(force=True)
    attach_context = _capture_launch_context(
        target_path or str(target.get("exe") or "")
    )
    _remember_runtime(lastLaunchContext=attach_context, lastUiRetarget=None)
    attach_commands = [
        f"attach 0x{target_pid:X}",
        f"attach {target_pid:X}",
        f"attach 0x{target_pid:X}, 0, 0",
    ]
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    last_result: Any = None
    state = _build_debug_state(
        include_console=False, include_callstack=False, max_console_chars=0
    )
    for command in attach_commands:
        last_result = ExecCommand(command)
        state = _wait_for_attached_debuggee(
            target_pid=target_pid, deadline=deadline, poll_ms=125
        )
        if state.get("debugging") and int(state.get("debuggeePid") or 0) == target_pid:
            if not state.get("paused"):
                remaining_ms = max(250, int((deadline - time.time()) * 1000))
                pause_state = WaitForPause(
                    timeout_ms=min(remaining_ms, 3000), poll_ms=100
                )
                if isinstance(pause_state, dict) and pause_state.get("debugging"):
                    inferred_pause_pid = int(pause_state.get("debuggeePid") or 0)
                    if inferred_pause_pid in (0, target_pid):
                        pause_state = dict(pause_state)
                        pause_state["debuggeePid"] = target_pid
                        state = pause_state
            _update_launch_context_source_pid(target_pid)
            binding = _bind_debuggee_session(
                pid=target_pid,
                image_path=target_path or _get_process_image_path(target_pid),
                strict=True,
                source="AttachToProcess",
            )
            _remember_runtime(
                lastDebuggeePid=target_pid,
                lastDebuggeeImage=_process_basename(target_path)
                or str(target.get("exe") or ""),
                lastDebuggeePath=target_path or _get_process_image_path(target_pid),
            )
            _log_event(
                "attach_process_success",
                pid=target_pid,
                exePath=target_path,
                arch=target_arch or desired_arch,
                command=command,
            )
            hidemain_result = _apply_hidemain_workflow(
                pid=target_pid,
                mode=use_hidemain,
                root=hidemain_root,
                allow_system_changes=hidemain_allow_system_changes,
                allow_unsigned=hidemain_allow_unsigned_driver,
                acknowledge_kernel_risk=hidemain_acknowledge_kernel_risk,
            )
            hidemain_required = str(use_hidemain or "off").strip().lower() == "force"
            return {
                "ok": bool(not hidemain_required or hidemain_result.get("ok")),
                "target": target,
                "requestedArch": target_arch or desired_arch,
                "attachResult": last_result,
                "state": state,
                "binding": binding,
                "ensureDebugger": ensure_result,
                "recoveryDebugger": recovery_result,
                "hideMain": hidemain_result,
                "error": (
                    (hidemain_result.get("error") or "HideMain force-mode application failed.")
                    if hidemain_required and not hidemain_result.get("ok")
                    else None
                ),
                "logPath": LOG_PATH,
            }
        if time.time() >= deadline:
            break
    _log_event(
        "attach_process_failed",
        pid=target_pid,
        exePath=target_path,
        arch=target_arch or desired_arch,
        result=last_result,
        state=state,
    )
    diagnostics = _build_attach_failure_diagnostics(target_pid)
    error = f"Timed out attaching to pid {target_pid}."
    if diagnostics.get("hint"):
        error = f"{error} {diagnostics.get('hint')}"
    return {
        "ok": False,
        "target": target,
        "requestedArch": target_arch or desired_arch,
        "attachResult": last_result,
        "state": state,
        "diagnostics": diagnostics,
        "ensureDebugger": ensure_result,
        "recoveryDebugger": recovery_result,
        "error": error,
        "logPath": LOG_PATH,
    }


@mcp.tool()
def GetProcessDebugStatus(pid: int = 0) -> dict:
    """
    Query ProcessDebugPort / ProcessDebugObjectHandle / ProcessDebugFlags for a PID.

    Args:
        pid: Target PID. Defaults to the current debuggee when omitted.
    """
    payload = _query_process_debug_status(pid=pid)
    payload["logPath"] = LOG_PATH
    return payload


@mcp.tool()
def RemoveProcessDebug(pid: int = 0) -> dict:
    """
    Attempt to detach an inherited/foreign debug object from a process.

    Args:
        pid: Target PID. Defaults to the current debuggee when omitted.
    """
    payload = _remove_process_debug_object(pid=pid)
    payload["logPath"] = LOG_PATH
    if payload.get("ok"):
        _log_event(
            "remove_process_debug",
            pid=payload.get("pid"),
            removed=payload.get("removed"),
            ntstatus=payload.get("ntstatus"),
        )
    return payload


@mcp.tool()
def GetInteractionHistory(limit: int = 80, kinds_json: str = "") -> dict:
    """
    Return parsed interaction history across run/pause/input/gui/capture actions.
    """
    kinds = {
        str(item).strip()
        for item in _normalize_name_items(kinds_json)
        if str(item).strip()
    }
    history = list(_get_runtime_value("interactionHistory", []) or [])
    if kinds:
        history = [
            entry
            for entry in history
            if str((entry or {}).get("kind", "")).strip() in kinds
        ]
    safe_limit = max(1, min(int(limit), 256))
    return {
        "count": len(history[-safe_limit:]),
        "entries": history[-safe_limit:],
        "availableKinds": sorted(
            {
                str((entry or {}).get("kind", ""))
                for entry in history
                if isinstance(entry, dict)
            }
        ),
        "logPath": LOG_PATH,
    }


@mcp.tool()
def GetInputHistory(limit: int = 40) -> dict:
    """
    Return recent keyboard/text input actions emitted by the bridge.
    """
    history = list(_get_runtime_value("inputHistory", []) or [])
    safe_limit = max(1, min(int(limit), 128))
    return {
        "count": len(history[-safe_limit:]),
        "entries": history[-safe_limit:],
        "logPath": LOG_PATH,
    }


@mcp.tool()
def GetWindowCapture(capture_id: str) -> dict:
    """
    Return metadata for a previously stored window capture.
    """
    capture = _get_window_capture(capture_id)
    if not capture:
        return {
            "ok": False,
            "captureId": capture_id,
            "error": "Window capture not found",
        }
    return {"ok": True, **_window_capture_public(capture)}


@mcp.tool()
def GetWindowCaptureHistory(limit: int = 24) -> dict:
    """
    Return metadata for recent captured windows/screens.
    """
    with _RUNTIME_LOCK:
        order = list(_RUNTIME_STATE.get("windowCaptureOrder", []))
        captures = dict(_RUNTIME_STATE.get("windowCaptures", {}))
    safe_limit = max(1, min(int(limit), 64))
    items = [
        _window_capture_public(captures[item])
        for item in order[-safe_limit:]
        if item in captures
    ]
    return {"count": len(items), "captures": items, "logPath": LOG_PATH}


@mcp.tool()
def GetDebuggeeWindows(
    pid: int = 0,
    include_children: bool = True,
    visible_only: bool = False,
    max_depth: int = 4,
) -> dict:
    """
    Enumerate top-level windows and child controls for the debuggee.
    """
    try:
        snapshot = _collect_gui_snapshot(
            pid=pid,
            include_children=include_children,
            visible_only=visible_only,
            max_depth=max_depth,
        )
        snapshot["analysis"] = _analyze_gui_snapshot(snapshot)
        _log_event(
            "get_debuggee_windows",
            pid=snapshot.get("pid"),
            topWindowCount=snapshot.get("summary", {}).get("topWindowCount"),
        )
        return snapshot
    except Exception as e:
        if not pid:
            try:
                snapshot = _collect_retarget_gui_snapshot(
                    visible_only=visible_only,
                    include_children=include_children,
                    max_depth=max_depth,
                )
            except Exception:
                snapshot = None
            if snapshot:
                snapshot["analysis"] = _analyze_gui_snapshot(snapshot)
                _log_event(
                    "get_debuggee_windows_retarget",
                    pid=snapshot.get("pid"),
                    hwnd=(
                        (snapshot.get("retarget") or {})
                        if isinstance(snapshot.get("retarget"), dict)
                        else {}
                    ).get("hwnd"),
                    exe=(
                        (snapshot.get("retarget") or {})
                        if isinstance(snapshot.get("retarget"), dict)
                        else {}
                    ).get("exe"),
                    topWindowCount=snapshot.get("summary", {}).get("topWindowCount"),
                )
                return snapshot
        _log_event("get_debuggee_windows_error", pid=pid, error=str(e))
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def AnalyzeDebuggeeGui(
    pid: int = 0, visible_only: bool = True, max_depth: int = 4
) -> dict:
    """
    Summarize the current GUI state of the debuggee and suggest likely Edit/Button controls.
    """
    snapshot = GetDebuggeeWindows(
        pid=pid, include_children=True, visible_only=visible_only, max_depth=max_depth
    )
    if snapshot.get("ok") is False:
        return snapshot
    analysis = _analyze_gui_snapshot(snapshot)
    return {
        "pid": snapshot.get("pid"),
        "summary": snapshot.get("summary", {}),
        "analysis": analysis,
        "windows": snapshot.get("windows", []),
        "logPath": LOG_PATH,
    }


@mcp.tool()
def GetDebuggeeUiAutomation(
    pid: int = 0, visible_only: bool = True, max_depth: int = 4, timeout_ms: int = 12000
) -> dict:
    """
    Collect a UI Automation tree snapshot for the current debuggee.
    """
    target_pid = 0
    try:
        try:
            target_pid = _infer_debuggee_pid(pid)
        except Exception:
            retarget = _discover_launch_retarget_candidate(visible_only=visible_only)
            if not retarget:
                raise
            target_pid = int(retarget.get("pid") or 0)
        snapshot = _run_with_uia_pump(
            target_pid,
            lambda: _collect_uia_snapshot(
                pid=target_pid,
                visible_only=visible_only,
                max_depth=max_depth,
                timeout_ms=timeout_ms,
            ),
        )
        snapshot["analysis"] = _analyze_uia_snapshot(snapshot)
        _log_event(
            "get_debuggee_uia",
            pid=snapshot.get("pid"),
            elementCount=snapshot.get("summary", {}).get("elementCount"),
        )
        return snapshot
    except Exception as e:
        if target_pid:
            try:
                gui_snapshot = GetDebuggeeWindows(
                    pid=target_pid,
                    include_children=True,
                    visible_only=visible_only,
                    max_depth=max_depth,
                )
                if gui_snapshot.get("ok") is not False and (
                    gui_snapshot.get("analysis") or {}
                ).get("hasVisibleWindow"):
                    snapshot = _synthesize_uia_snapshot_from_gui(gui_snapshot)
                    _log_event(
                        "get_debuggee_uia_fallback",
                        pid=snapshot.get("pid"),
                        elementCount=snapshot.get("summary", {}).get("elementCount"),
                        reason=str(e),
                    )
                    return snapshot
            except Exception:
                pass
        _log_event("get_debuggee_uia_error", pid=pid, error=str(e))
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def AnalyzeDebuggeeUiAutomation(
    pid: int = 0, visible_only: bool = True, max_depth: int = 4, timeout_ms: int = 12000
) -> dict:
    """
    Summarize UI Automation value/invoke targets for the current debuggee.
    """
    snapshot = GetDebuggeeUiAutomation(
        pid=pid, visible_only=visible_only, max_depth=max_depth, timeout_ms=timeout_ms
    )
    if snapshot.get("ok") is False:
        return snapshot
    return {
        "pid": snapshot.get("pid"),
        "summary": snapshot.get("summary", {}),
        "analysis": snapshot.get("analysis", {}),
        "windows": snapshot.get("windows", []),
        "logPath": LOG_PATH,
    }


@mcp.tool()
def SetUiAutomationValue(
    value: str, pid: int = 0, hwnd: str = "", automation_id: str = "", name: str = ""
) -> dict:
    """
    Set a UI Automation ValuePattern target.
    """
    target_pid = _infer_debuggee_pid(pid)
    snapshot = GetDebuggeeUiAutomation(pid=target_pid, visible_only=True, max_depth=6)
    if snapshot.get("ok"):
        target = _resolve_uia_target(
            snapshot, hwnd=hwnd, automation_id=automation_id, name=name, pattern="Value"
        )
        if target and (
            snapshot.get("fallback") == "win32_gui_snapshot"
            or str(target.get("frameworkId") or "").strip().lower() == "win32"
            or "Value" not in set(_normalize_uia_patterns(target.get("patterns")))
        ):
            hwnd_fallback = str(target.get("hwnd") or "")
            if hwnd_fallback:
                result = SetControlText(hwnd_fallback, value)
                result["uiaFallback"] = "win32_set_control_text"
                result["uiaTarget"] = {
                    "hwnd": hwnd_fallback,
                    "automationId": target.get("automationId"),
                    "name": target.get("name"),
                    "className": target.get("className"),
                }
                _log_event(
                    "set_uia_value_fallback",
                    pid=target_pid,
                    hwnd=hwnd_fallback,
                    automationId=target.get("automationId"),
                    name=target.get("name"),
                )
                return result
    script = (
        _uia_selector_script(
            target_pid,
            hwnd=hwnd,
            automation_id=automation_id,
            name=name,
            pattern="Value",
        )
        + f"""
$patternObj = $null
if (-not $picked.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$patternObj)) {{
  throw 'Target does not support ValuePattern'
}}
$patternObj.SetValue({json.dumps(str(value))})
@{{
  ok = $true
  pid = $targetPid
  hwnd = try {{ if ($picked.Current.NativeWindowHandle) {{ ('0x{{0:X}}' -f [int]$picked.Current.NativeWindowHandle) }} else {{ $null }} }} catch {{ $null }}
  name = try {{ [string]$picked.Current.Name }} catch {{ '' }}
  automationId = try {{ [string]$picked.Current.AutomationId }} catch {{ '' }}
  value = {json.dumps(str(value))}
}} | ConvertTo-Json -Depth 6 -Compress
"""
    )
    try:
        result = _run_with_uia_pump(
            target_pid, lambda: _run_powershell_json(script, timeout_ms=6000)
        )
        _log_event(
            "set_uia_value",
            pid=target_pid,
            hwnd=result.get("hwnd"),
            automationId=result.get("automationId"),
            name=result.get("name"),
        )
        return result
    except Exception as e:
        _log_event(
            "set_uia_value_error",
            pid=target_pid,
            hwnd=hwnd,
            automationId=automation_id,
            name=name,
            error=str(e),
        )
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def InvokeUiAutomationElement(
    pid: int = 0, hwnd: str = "", automation_id: str = "", name: str = ""
) -> dict:
    """
    Invoke a UI Automation element with InvokePattern.
    """
    target_pid = _infer_debuggee_pid(pid)
    snapshot = GetDebuggeeUiAutomation(pid=target_pid, visible_only=True, max_depth=6)
    if snapshot.get("ok"):
        target = _resolve_uia_target(
            snapshot,
            hwnd=hwnd,
            automation_id=automation_id,
            name=name,
            pattern="Invoke",
        )
        if target and (
            snapshot.get("fallback") == "win32_gui_snapshot"
            or str(target.get("frameworkId") or "").strip().lower() == "win32"
            or "Invoke" not in set(_normalize_uia_patterns(target.get("patterns")))
        ):
            hwnd_fallback = str(target.get("hwnd") or "")
            if hwnd_fallback:
                result = ClickControl(hwnd_fallback)
                result["uiaFallback"] = "win32_click_control"
                result["uiaTarget"] = {
                    "hwnd": hwnd_fallback,
                    "automationId": target.get("automationId"),
                    "name": target.get("name"),
                    "className": target.get("className"),
                }
                _log_event(
                    "invoke_uia_element_fallback",
                    pid=target_pid,
                    hwnd=hwnd_fallback,
                    automationId=target.get("automationId"),
                    name=target.get("name"),
                )
                return result
    script = (
        _uia_selector_script(
            target_pid,
            hwnd=hwnd,
            automation_id=automation_id,
            name=name,
            pattern="Invoke",
        )
        + """
$patternObj = $null
if (-not $picked.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$patternObj)) {
  throw 'Target does not support InvokePattern'
}
$patternObj.Invoke()
@{
  ok = $true
  pid = $targetPid
  hwnd = try { if ($picked.Current.NativeWindowHandle) { ('0x{0:X}' -f [int]$picked.Current.NativeWindowHandle) } else { $null } } catch { $null }
  name = try { [string]$picked.Current.Name } catch { '' }
  automationId = try { [string]$picked.Current.AutomationId } catch { '' }
} | ConvertTo-Json -Depth 6 -Compress
"""
    )
    try:
        result = _run_with_uia_pump(
            target_pid, lambda: _run_powershell_json(script, timeout_ms=6000)
        )
        _log_event(
            "invoke_uia_element",
            pid=target_pid,
            hwnd=result.get("hwnd"),
            automationId=result.get("automationId"),
            name=result.get("name"),
        )
        return result
    except Exception as e:
        _log_event(
            "invoke_uia_element_error",
            pid=target_pid,
            hwnd=hwnd,
            automationId=automation_id,
            name=name,
            error=str(e),
        )
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def SubmitDebuggeeUiAutomation(
    text: str = "", texts_json: str = "", pid: int = 0, button_text: str = ""
) -> dict:
    """
    Fill UI Automation value targets and invoke a likely submit element.
    """
    snapshot = GetDebuggeeUiAutomation(pid=pid, visible_only=True, max_depth=6)
    if snapshot.get("ok") is False:
        return snapshot
    analysis = snapshot.get("analysis", {})
    actions: List[Dict[str, Any]] = []
    payload = _parse_text_payload(texts_json)
    text_values = payload.get("list", [])
    text_map = payload.get("map", {})
    elements = list(
        snapshot.get("elements", []) or _flatten_uia_tree(snapshot.get("windows", []))
    )
    value_elements = [
        item
        for item in elements
        if isinstance(item, dict)
        and "Value" in list(item.get("patterns", []) or [])
        and bool(item.get("enabled", True))
    ]
    value_elements.sort(
        key=lambda item: (
            item.get("depth", 0),
            0 if item.get("name") else 1,
            (item.get("rect", {}) or {}).get("top", 0),
            (item.get("rect", {}) or {}).get("left", 0),
        )
    )
    if text_map:
        for key, value in text_map.items():
            target = _select_uia_element(
                elements, name=key, pattern="Value"
            ) or _select_uia_element(elements, automation_id=key, pattern="Value")
            if target:
                actions.append(
                    SetUiAutomationValue(
                        value=value,
                        pid=snapshot.get("pid") or pid,
                        hwnd=str(target.get("hwnd") or ""),
                        automation_id=str(target.get("automationId") or ""),
                        name=str(target.get("name") or ""),
                    )
                )
    elif text_values:
        for index, value in enumerate(text_values):
            if index >= len(value_elements):
                break
            target = value_elements[index]
            actions.append(
                SetUiAutomationValue(
                    value=value,
                    pid=snapshot.get("pid") or pid,
                    hwnd=str(target.get("hwnd") or ""),
                    automation_id=str(target.get("automationId") or ""),
                    name=str(target.get("name") or ""),
                )
            )
    elif text and analysis.get("suggestedValueHwnd"):
        actions.append(
            SetUiAutomationValue(
                value=text,
                pid=snapshot.get("pid") or pid,
                hwnd=str(analysis.get("suggestedValueHwnd") or ""),
                automation_id=str(analysis.get("suggestedValueAutomationId") or ""),
                name=str(analysis.get("suggestedValueName") or ""),
            )
        )
    button_target = (
        _select_uia_element(elements, name=button_text, pattern="Invoke")
        if button_text
        else None
    )
    if not button_target and analysis.get("suggestedInvokeHwnd"):
        button_target = _select_uia_element(
            elements,
            hwnd=str(analysis.get("suggestedInvokeHwnd") or ""),
            pattern="Invoke",
        )
    if button_target:
        actions.append(
            InvokeUiAutomationElement(
                pid=snapshot.get("pid") or pid,
                hwnd=str(button_target.get("hwnd") or ""),
                automation_id=str(button_target.get("automationId") or ""),
                name=str(button_target.get("name") or ""),
            )
        )
    ok = bool(actions) and all(bool(item.get("ok")) for item in actions)
    _log_event(
        "submit_debuggee_uia", pid=snapshot.get("pid"), ok=ok, actionCount=len(actions)
    )
    return {
        "ok": ok,
        "snapshot": snapshot,
        "analysis": analysis,
        "actions": actions,
        "logPath": LOG_PATH,
    }


@mcp.tool()
def AnalyzeAntiDebugSurface(exe_path: str = "") -> dict:
    """
    Analyze a PE target for anti-debug and protector signals and recommend a ScyllaHide profile.
    """
    target_path = _resolve_target_exe_path(exe_path)
    if not target_path:
        return {
            "ok": False,
            "error": "No executable path was provided and no debuggee is active.",
        }
    try:
        result = _analyze_antidebug_surface(target_path)
        result["logPath"] = LOG_PATH
        return result
    except Exception as e:
        _log_event("analyze_antidebug_surface_error", path=target_path, error=str(e))
        return {"ok": False, "path": target_path, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def GetScyllaHideStatus(pid: int = 0, exe_path: str = "", arch: str = "auto") -> dict:
    """
    Inspect ScyllaHide installation, configured profile, and whether the hook is loaded in the current debuggee.
    """
    debugger_info = _get_active_debugger_info()
    desired_arch = str(arch or "auto").strip().lower()
    if desired_arch == "auto":
        desired_arch = str(debugger_info.get("arch") or "auto")
    paths = _scyllahide_paths_for_arch(desired_arch)
    plugin_path = str(paths.get("pluginPath") or "")
    hook_path = str(paths.get("hookPath") or "")
    config_path = str(paths.get("configPath") or "")
    injector_path = str(paths.get("injectorPath") or "")
    # The MCP hooks via InjectorCLI + HookLibrary + the profile INI. The x64dbg
    # GUI plugin (ScyllaHideX64DBGPlugin) is NOT shipped in the standalone
    # ScyllaHide release and is not needed for injection, so it is optional.
    plugin_present = bool(plugin_path and os.path.exists(plugin_path))
    installed = bool(
        hook_path
        and os.path.exists(hook_path)
        and config_path
        and os.path.exists(config_path)
        and injector_path
        and os.path.exists(injector_path)
    )
    profile_info = (
        _read_scyllahide_profile(config_path)
        if config_path and os.path.exists(config_path)
        else {
            "currentProfile": "",
            "profiles": [],
            "activeProfiles": [],
            "disabledProfiles": [],
            "currentProfileDisabled": False,
        }
    )
    state = _build_debug_state(
        include_console=False, include_callstack=False, max_console_chars=0
    )
    module_names = _collect_module_names() if state.get("debugging") else []
    hook_name = os.path.basename(hook_path).lower() if hook_path else ""
    runtime_record = _get_runtime_value("lastScyllaHide")
    runtime_match = (
        isinstance(runtime_record, dict)
        and int(runtime_record.get("pid") or 0)
        == int(pid or state.get("debuggeePid") or 0)
        and _process_exists(int(runtime_record.get("pid") or 0))
        and str(runtime_record.get("hookPath") or "").lower() == hook_path.lower()
        and bool(runtime_record.get("ok"))
    )
    scylla_log = _read_scyllahide_log_status(
        paths,
        since_mtime=float((runtime_record or {}).get("logMtime") or 0.0)
        if isinstance(runtime_record, dict)
        else 0.0,
        since_size=int((runtime_record or {}).get("logSize") or 0)
        if isinstance(runtime_record, dict)
        else 0,
    )
    log_runtime_match = (
        isinstance(runtime_record, dict)
        and int(runtime_record.get("pid") or 0)
        == int(pid or state.get("debuggeePid") or 0)
        and _process_exists(int(runtime_record.get("pid") or 0))
        and str(runtime_record.get("hookPath") or "").lower() == hook_path.lower()
        and bool(runtime_record.get("preArmed"))
        and bool(scylla_log.get("hasHookingLines"))
    )
    target_path = _resolve_target_exe_path(exe_path)
    analysis = None
    if target_path:
        try:
            analysis = _analyze_antidebug_surface(target_path)
        except Exception:
            analysis = None
    target_pid = int(pid or state.get("debuggeePid") or 0)
    hook_present = bool(hook_path and os.path.exists(hook_path))
    config_present = bool(config_path and os.path.exists(config_path))
    injector_present = bool(injector_path and os.path.exists(injector_path))
    return {
        "ok": installed,
        "activeDebugger": debugger_info,
        "arch": paths.get("arch"),
        "installDir": paths.get("installDir"),
        "integrationMode": "injector_cli",
        "integrationReady": installed,
        "injectionMethod": "InjectorCLI + HookLibrary + profile INI",
        "guiPluginRequired": False,
        "guiPluginPresent": plugin_present,
        "pluginPath": plugin_path,
        # Backward-compatible alias. This field describes only the optional
        # x64dbg GUI plugin, not whether the MCP injection backend is installed.
        "pluginPresent": plugin_present,
        "hookPath": hook_path,
        "configPath": config_path,
        "injectorPath": injector_path,
        "testExePath": paths.get("testExePath"),
        "installed": installed,
        "components": {
            "injector": injector_present,
            "hookLibrary": hook_present,
            "profileIni": config_present,
            "guiPlugin": plugin_present,
        },
        "currentProfile": profile_info.get("currentProfile"),
        "currentProfileDisabled": bool(profile_info.get("currentProfileDisabled")),
        "availableProfiles": profile_info.get(
            "activeProfiles", profile_info.get("profiles", [])
        ),
        "disabledProfiles": profile_info.get("disabledProfiles", []),
        "debuggeePid": target_pid,
        "hookInjected": bool(
            (hook_name and hook_name in module_names)
            or runtime_match
            or log_runtime_match
        ),
        "hookModuleName": hook_name,
        "hookSeenInModuleList": bool(hook_name and hook_name in module_names),
        "hookSeenInLog": bool(
            log_runtime_match
            or (
                bool(scylla_log.get("hasHookingLines"))
                and bool(scylla_log.get("fresh") or scylla_log.get("recent"))
            )
        ),
        "runtimeRecord": runtime_record if runtime_match else None,
        "moduleNames": module_names[:64],
        "scyllaLog": scylla_log,
        "analysis": analysis,
        "logPath": LOG_PATH,
    }


@mcp.tool()
def SetScyllaHideProfile(profile: str, arch: str = "auto") -> dict:
    """
    Update the configured ScyllaHide profile for the selected debugger installation.
    """
    if _is_disabled_scylla_profile(profile):
        return {
            "ok": False,
            "error": "The requested virtualization research profile is disabled in this build.",
            "code": "research_profile_disabled",
            "logPath": LOG_PATH,
        }
    desired_arch = str(arch or "auto").strip().lower()
    if desired_arch == "auto":
        desired_arch = str((_get_active_debugger_info() or {}).get("arch") or "auto")
    paths = _scyllahide_paths_for_arch(desired_arch)
    config_path = str(paths.get("configPath") or "")
    if not config_path or not os.path.exists(config_path):
        return {
            "ok": False,
            "error": "ScyllaHide config was not found for the requested architecture.",
            "paths": paths,
            "logPath": LOG_PATH,
        }
    try:
        result = _write_scyllahide_profile(config_path, profile)
        result["arch"] = paths.get("arch")
        result["paths"] = paths
        result["logPath"] = LOG_PATH
        _log_event(
            "set_scyllahide_profile",
            arch=paths.get("arch"),
            profile=profile,
            configPath=config_path,
        )
        return result
    except Exception as e:
        _log_event(
            "set_scyllahide_profile_error",
            arch=paths.get("arch"),
            profile=profile,
            error=str(e),
        )
        return {"ok": False, "error": str(e), "paths": paths, "logPath": LOG_PATH}


@mcp.tool()
def EnsureScyllaHideForDebuggee(
    pid: int = 0,
    exe_path: str = "",
    arch: str = "auto",
    profile: str = "auto",
    force: bool = False,
) -> dict:
    """
    Inject ScyllaHide into the current debuggee when analysis suggests anti-debug behavior or when forced.
    """
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
    target_pid = int(pid or state.get("debuggeePid") or 0)
    if not target_pid:
        try:
            target_pid = _infer_debuggee_pid(0)
        except Exception as e:
            return {"ok": False, "error": str(e), "state": state, "logPath": LOG_PATH}
    desired_arch = str(arch or "auto").strip().lower()
    target_path = _resolve_target_exe_path(exe_path)
    if desired_arch == "auto":
        desired_arch = str(
            (_get_active_debugger_info() or {}).get("arch")
            or (_detect_pe_arch(target_path) or "auto")
        )
    status = GetScyllaHideStatus(
        pid=target_pid, exe_path=target_path, arch=desired_arch
    )
    if not status.get("installed"):
        return {
            "ok": False,
            "error": "ScyllaHide is not installed for the active debugger architecture.",
            "status": status,
            "logPath": LOG_PATH,
        }
    chosen_profile = str(profile or "auto").strip()
    analysis = (
        status.get("analysis") if isinstance(status.get("analysis"), dict) else None
    )
    if chosen_profile.lower() == "auto":
        chosen_profile = str(
            (analysis or {}).get("suggestedScyllaHideProfile") or "Disabled"
        )
    if status.get("hookInjected") and not force:
        return {
            "ok": True,
            "alreadyInjected": True,
            "skipped": False,
            "profile": chosen_profile,
            "status": status,
            "analysis": analysis,
            "logPath": LOG_PATH,
        }
    if (not force) and (not chosen_profile or chosen_profile == "Disabled"):
        return {
            "ok": True,
            "skipped": True,
            "reason": "Analysis did not justify ScyllaHide for this target.",
            "profile": chosen_profile or "Disabled",
            "status": status,
            "analysis": analysis,
            "logPath": LOG_PATH,
        }
    preparation = _advance_past_startup_pause(timeout_ms=4000, max_runs=4, poll_ms=100)
    refreshed_status = GetScyllaHideStatus(
        pid=target_pid, exe_path=target_path, arch=desired_arch
    )
    if refreshed_status.get("hookInjected") and not force:
        payload = {
            "ok": True,
            "alreadyInjected": True,
            "skipped": False,
            "profile": chosen_profile,
            "status": refreshed_status,
            "analysis": analysis,
            "preparation": preparation,
            "logPath": LOG_PATH,
        }
        _log_event(
            "ensure_scyllahide",
            pid=target_pid,
            arch=refreshed_status.get("arch"),
            profile=chosen_profile,
            ok=True,
            skipped=False,
            alreadyInjected=True,
            advancedStartup=bool(preparation.get("advanced")),
        )
        return payload
    verification = _verify_scyllahide_prearmed(
        target_pid,
        target_path,
        desired_arch,
        timeout_ms=1200,
        poll_ms=100,
    )
    refreshed_status = (
        (verification.get("status") or refreshed_status)
        if isinstance(verification, dict)
        else refreshed_status
    )
    if refreshed_status.get("hookInjected") and not force:
        payload = {
            "ok": True,
            "alreadyInjected": True,
            "skipped": False,
            "profile": chosen_profile,
            "status": refreshed_status,
            "analysis": analysis,
            "preparation": preparation,
            "verification": verification,
            "logPath": LOG_PATH,
        }
        _log_event(
            "ensure_scyllahide",
            pid=target_pid,
            arch=refreshed_status.get("arch"),
            profile=chosen_profile,
            ok=True,
            skipped=False,
            alreadyInjected=True,
            verifiedAfterWait=True,
            advancedStartup=bool(preparation.get("advanced")),
        )
        return payload
    try:
        inject_result = _inject_scyllahide_for_pid(
            target_pid,
            str(refreshed_status.get("arch") or status.get("arch") or desired_arch),
            chosen_profile or "Basic",
        )
    except Exception as e:
        _log_event(
            "inject_scyllahide_error",
            pid=target_pid,
            arch=desired_arch,
            profile=chosen_profile,
            error=str(e),
        )
        return {
            "ok": False,
            "error": str(e),
            "status": status,
            "analysis": analysis,
            "logPath": LOG_PATH,
        }
    if not inject_result.get("ok"):
        refreshed_status = GetScyllaHideStatus(
            pid=target_pid, exe_path=target_path, arch=desired_arch
        )
        if refreshed_status.get("hookInjected"):
            inject_result = dict(inject_result)
            inject_result["ok"] = True
            inject_result["recoveredFromStatus"] = True
    payload = {
        "ok": bool(inject_result.get("ok")),
        "skipped": False,
        "profile": chosen_profile or "Basic",
        "status": refreshed_status,
        "analysis": analysis,
        "injectResult": inject_result,
        "preparation": preparation,
        "logPath": LOG_PATH,
    }
    _log_event(
        "ensure_scyllahide",
        pid=target_pid,
        arch=refreshed_status.get("arch") or status.get("arch"),
        profile=chosen_profile or "Basic",
        ok=payload["ok"],
        skipped=False,
        riskScore=(analysis or {}).get("riskScore"),
        advancedStartup=bool(preparation.get("advanced")),
        timedOut=bool(inject_result.get("timedOut")),
    )
    return payload


@mcp.tool()
def GetDebuggerPluginStatus(
    arch: str = "auto", pid: int = 0, exe_path: str = "", probe_commands: bool = False
) -> dict:
    """
    Return a consolidated view of debugger-side plugin installation and runtime status.
    """
    debugger_info = _get_active_debugger_info()
    target_path = _resolve_target_exe_path(exe_path)
    hidemain_status = None
    get_hidemain = globals().get("GetHideMainStatus")
    if callable(get_hidemain):
        try:
            hidemain_status = get_hidemain(pid=pid)
        except Exception as exc:
            hidemain_status = {"ok": False, "error": str(exc)}
    else:
        hidemain_status = {
            "ok": False,
            "loaded": False,
            "extension": dict(globals().get("_HIDEMAIN_TOOLS_STATUS") or {}),
        }
    return {
        "ok": True,
        "activeDebugger": debugger_info,
        "scyllaHide": GetScyllaHideStatus(pid=pid, exe_path=target_path, arch=arch),
        "hideMain": hidemain_status,
        "analysis": AnalyzeAntiDebugSurface(target_path) if target_path else None,
        "logPath": LOG_PATH,
    }


@mcp.tool()
def AnalyzeExecutablePacking(exe_path: str = "") -> dict:
    """
    Perform lightweight packer/obfuscation triage on a PE executable.
    """
    target_path = _resolve_target_exe_path(exe_path)
    if not target_path:
        return {
            "ok": False,
            "error": "No executable path was provided and no debuggee is active",
        }
    try:
        layout = _parse_pe_layout(target_path)
    except Exception as e:
        return {"ok": False, "path": target_path, "error": str(e)}
    anti_debug = None
    try:
        anti_debug = _analyze_antidebug_surface(target_path)
    except Exception:
        anti_debug = None
    imports = list(layout.get("imports", []))
    import_dll_count = len(imports)
    import_func_count = sum(len(item.get("functions", [])) for item in imports)
    entry_section = layout.get("entrySection") or {}
    entry_entropy = float(entry_section.get("entropy", 0.0) or 0.0)
    section_names = {
        str(item.get("name", "")).lower() for item in layout.get("sections", [])
    }
    import_names = {
        func.lower() for item in imports for func in item.get("functions", []) if func
    }
    signals: List[str] = []
    if any(name.startswith("upx") for name in section_names):
        signals.append("upx_section_names")
    if entry_section and entry_entropy >= 6.9:
        signals.append("high_entropy_entry_section")
    if (
        entry_section
        and bool(entry_section.get("executable"))
        and bool(entry_section.get("writable"))
    ):
        signals.append("writable_executable_entry_section")
    if import_dll_count <= 3:
        signals.append("few_imported_dlls")
    if import_func_count <= 20:
        signals.append("small_import_table")
    if {
        "loadlibrarya",
        "loadlibraryw",
        "getprocaddress",
    } & import_names and import_func_count <= 30:
        signals.append("dynamic_import_resolution_pattern")
    if layout.get("fileEntropy", 0.0) >= 6.8:
        signals.append("high_file_entropy")
    likely_packed = len(signals) >= 2
    return {
        "ok": True,
        "path": target_path,
        "arch": layout.get("arch"),
        "entryPointRva": layout.get("entryPointRva"),
        "entryPointVa": layout.get("entryPointVa"),
        "entrySection": entry_section,
        "fileEntropy": layout.get("fileEntropy"),
        "sectionCount": len(layout.get("sections", [])),
        "sections": layout.get("sections", []),
        "importSummary": {
            "dllCount": import_dll_count,
            "functionCount": import_func_count,
            "dlls": [item.get("dll") for item in imports[:20]],
        },
        "likelyPacked": likely_packed,
        "packerSignals": signals,
        "antiDebugSurface": anti_debug,
        "suggestedScyllaHideProfile": (anti_debug or {}).get(
            "suggestedScyllaHideProfile"
        ),
        "oepHints": {
            "entrySectionName": entry_section.get("name"),
            "entrySectionEntropy": entry_entropy,
            "entrySectionWritable": bool(entry_section.get("writable")),
            "entrySectionExecutable": bool(entry_section.get("executable")),
        },
        "importRebuildHints": [
            "Watch for runtime calls to LoadLibrary/GetProcAddress if the import table is very small.",
            "Break after suspicious unpacking stubs and compare module memory against on-disk sections.",
            "If the entry section is high-entropy, capture a later executable region and re-evaluate imports.",
        ],
    }


@mcp.tool()
def WaitForDebuggeeWindow(
    pid: int = 0,
    title_contains: str = "",
    class_name: str = "",
    timeout_ms: int = 5000,
    poll_ms: int = 100,
    visible_only: bool = True,
    include_children: bool = True,
    max_depth: int = 4,
) -> dict:
    """
    Wait until a debuggee window matching the requested title/class appears.
    """
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    last_snapshot: Dict[str, Any] = {}
    startup_advance: Dict[str, Any] = {}
    while time.time() <= deadline:
        last_snapshot = GetDebuggeeWindows(
            pid=pid,
            include_children=include_children,
            visible_only=visible_only,
            max_depth=max_depth,
        )
        if last_snapshot.get("ok") is False:
            time.sleep(max(poll_ms, 20) / 1000.0)
            continue
        match = _select_top_window(
            last_snapshot, title_contains=title_contains, class_name=class_name
        )
        if match:
            return {
                "ok": True,
                "timedOut": False,
                "window": match,
                "snapshot": last_snapshot,
                "startupAdvance": startup_advance,
            }
        remaining_ms = max(0, int((deadline - time.time()) * 1000))
        if remaining_ms > 0:
            state = _build_debug_state(
                include_console=False, include_callstack=True, max_console_chars=0
            )
            if _should_auto_advance_window_wait(state, gui_snapshot=last_snapshot):
                startup_advance = _advance_debuggee_toward_window(
                    timeout_ms=min(remaining_ms, max(3500, poll_ms * 20)),
                    poll_ms=poll_ms,
                    pid=pid,
                    visible_only=visible_only,
                    include_children=include_children,
                    max_depth=max_depth,
                )
                advanced_gui = (
                    startup_advance.get("gui", {})
                    if isinstance(startup_advance, dict)
                    else {}
                )
                advanced_match = _select_top_window(
                    advanced_gui, title_contains=title_contains, class_name=class_name
                )
                if advanced_match:
                    return {
                        "ok": True,
                        "timedOut": False,
                        "window": advanced_match,
                        "snapshot": advanced_gui,
                        "startupAdvance": startup_advance,
                    }
        time.sleep(max(poll_ms, 20) / 1000.0)
    final_snapshot = GetDebuggeeWindows(
        pid=pid,
        include_children=include_children,
        visible_only=visible_only,
        max_depth=max_depth,
    )
    if final_snapshot.get("ok") is not False:
        final_match = _select_top_window(
            final_snapshot, title_contains=title_contains, class_name=class_name
        )
        if final_match:
            return {
                "ok": True,
                "timedOut": False,
                "window": final_match,
                "snapshot": final_snapshot,
                "startupAdvance": startup_advance,
            }
    grace_state = _build_debug_state(
        include_console=False, include_callstack=True, max_console_chars=0
    )
    grace_snapshot = (
        final_snapshot if final_snapshot.get("ok") is not False else last_snapshot
    )
    if _should_auto_advance_window_wait(grace_state, gui_snapshot=grace_snapshot):
        grace_advance = _advance_debuggee_toward_window(
            timeout_ms=min(1500, max(600, poll_ms * 12)),
            poll_ms=poll_ms,
            pid=pid,
            visible_only=visible_only,
            include_children=include_children,
            max_depth=max_depth,
        )
        grace_gui = (
            grace_advance.get("gui", {}) if isinstance(grace_advance, dict) else {}
        )
        grace_match = _select_top_window(
            grace_gui, title_contains=title_contains, class_name=class_name
        )
        if grace_match:
            return {
                "ok": True,
                "timedOut": False,
                "window": grace_match,
                "snapshot": grace_gui,
                "startupAdvance": grace_advance,
            }
        if grace_advance and not startup_advance:
            startup_advance = grace_advance
    final_analysis = (
        (final_snapshot.get("analysis") or {})
        if isinstance(final_snapshot, dict)
        else {}
    )
    return {
        "ok": False,
        "timedOut": True,
        "snapshot": final_snapshot if final_snapshot else last_snapshot,
        "startupAdvance": startup_advance,
        "reason": "Only noise or placeholder windows became available."
        if not (title_contains or class_name)
        and final_analysis.get("hasAnyWindow")
        and not final_analysis.get("hasVisibleWindow")
        else "Timed out waiting for a matching debuggee window.",
        "logPath": LOG_PATH,
    }


@mcp.tool()
def WaitForDebuggeeInputIdle(pid: int = 0, timeout_ms: int = 1500) -> dict:
    """
    Wait until the debuggee's GUI thread reaches an input-idle state.
    """
    try:
        target_pid = _infer_debuggee_pid(pid)
        result = _wait_for_process_input_idle(target_pid, timeout_ms=timeout_ms)
        result["ok"] = bool(result.get("ok"))
        result["logPath"] = LOG_PATH
        _log_event(
            "wait_for_debuggee_input_idle",
            pid=target_pid,
            ready=result.get("ready"),
            timedOut=result.get("timedOut"),
            supported=result.get("supported"),
            reason=result.get("reason"),
        )
        return result
    except Exception as e:
        _log_event("wait_for_debuggee_input_idle_error", pid=pid, error=str(e))
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def WaitForDebuggeeWindowReady(
    pid: int = 0,
    hwnd: str = "",
    title_contains: str = "",
    class_name: str = "",
    timeout_ms: int = 5000,
    poll_ms: int = 100,
    visible_only: bool = True,
    stable_polls: int = 2,
    require_input_idle: bool = True,
    client_only: bool = False,
) -> dict:
    """
    Wait until a debuggee window both exists and becomes stable enough for automation.
    """
    try:
        if not str(hwnd or "").strip():
            started = time.time()
            window_wait = WaitForDebuggeeWindow(
                pid=pid,
                title_contains=title_contains,
                class_name=class_name,
                timeout_ms=timeout_ms,
                poll_ms=poll_ms,
                visible_only=visible_only,
                include_children=True,
                max_depth=4,
            )
            if not window_wait.get("ok"):
                payload = dict(window_wait)
                payload["logPath"] = LOG_PATH
                _log_event(
                    "wait_for_debuggee_window_ready",
                    pid=(window_wait.get("snapshot") or {}).get("pid"),
                    hwnd=None,
                    ready=False,
                    timedOut=window_wait.get("timedOut"),
                    requireInputIdle=require_input_idle,
                )
                return payload
            hwnd = str((window_wait.get("window") or {}).get("hwnd") or "")
            resolved_pid = int(
                ((window_wait.get("snapshot") or {}).get("pid") or pid or 0)
            )
            consumed_ms = int((time.time() - started) * 1000)
            timeout_ms = max(250, int(timeout_ms) - consumed_ms)
            pid = resolved_pid
        result = _wait_for_resolved_window_ready(
            pid=pid,
            hwnd=hwnd,
            title_contains=title_contains,
            class_name=class_name,
            visible_only=visible_only,
            timeout_ms=timeout_ms,
            poll_ms=poll_ms,
            stable_polls=stable_polls,
            require_input_idle=require_input_idle,
            client_only=client_only,
        )
        result["logPath"] = LOG_PATH
        _log_event(
            "wait_for_debuggee_window_ready",
            pid=result.get("pid"),
            hwnd=result.get("hwnd"),
            ready=result.get("ok"),
            timedOut=result.get("timedOut"),
            requireInputIdle=require_input_idle,
        )
        return result
    except Exception as e:
        _log_event(
            "wait_for_debuggee_window_ready_error", pid=pid, hwnd=hwnd, error=str(e)
        )
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def SetControlText(hwnd: str, text: str) -> dict:
    """
    Set text for a GUI control, typically an Edit control.
    """
    try:
        result = _set_control_text(_parse_hwnd_value(hwnd), text)
        _log_event(
            "set_control_text",
            hwnd=hwnd,
            text=text,
            refreshedText=result.get("refreshedText"),
        )
        return result
    except Exception as e:
        _log_event("set_control_text_error", hwnd=hwnd, text=text, error=str(e))
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def ClickControl(hwnd: str) -> dict:
    """
    Click a GUI control, typically a Button.
    """
    try:
        result = _click_control(_parse_hwnd_value(hwnd))
        _log_event("click_control", hwnd=hwnd)
        return result
    except Exception as e:
        _log_event("click_control_error", hwnd=hwnd, error=str(e))
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def ReadControlText(hwnd: str) -> dict:
    """
    Read text from a specific GUI control using Unicode and ANSI fallbacks.
    """
    try:
        parsed = _parse_hwnd_value(hwnd)
        return {
            "ok": True,
            "hwnd": f"0x{parsed:X}",
            "text": _get_control_text(parsed),
        }
    except Exception as e:
        _log_event("read_control_text_error", hwnd=hwnd, error=str(e))
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def WaitForGuiChange(
    pid: int = 0,
    previous_primary_hwnd: str = "",
    previous_titles_json: str = "",
    timeout_ms: int = 4000,
    poll_ms: int = 100,
    visible_only: bool = True,
) -> dict:
    """
    Wait until the GUI changes compared to a previous snapshot.
    """
    baseline_titles = _parse_json_string_list(previous_titles_json)
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    last_snapshot: Dict[str, Any] = {}
    while time.time() <= deadline:
        last_snapshot = GetDebuggeeWindows(
            pid=pid, include_children=True, visible_only=visible_only, max_depth=5
        )
        if last_snapshot.get("ok") is False:
            time.sleep(max(poll_ms, 20) / 1000.0)
            continue
        summary = last_snapshot.get("summary", {})
        current_primary = str(summary.get("primaryWindowHwnd") or "")
        current_titles = summary.get("titles", [])
        if previous_primary_hwnd and current_primary != previous_primary_hwnd:
            return {
                "ok": True,
                "timedOut": False,
                "reason": "primary_window_changed",
                "snapshot": last_snapshot,
            }
        if baseline_titles and current_titles != baseline_titles:
            return {
                "ok": True,
                "timedOut": False,
                "reason": "titles_changed",
                "snapshot": last_snapshot,
            }
        time.sleep(max(poll_ms, 20) / 1000.0)
    return {
        "ok": False,
        "timedOut": True,
        "reason": "Timed out waiting for a GUI change.",
        "snapshot": last_snapshot,
        "logPath": LOG_PATH,
    }


@mcp.tool()
def CaptureDebuggeeWindow(
    pid: int = 0,
    hwnd: str = "",
    title_contains: str = "",
    class_name: str = "",
    client_only: bool = True,
    visible_only: bool = True,
    focus_window: bool = True,
    timeout_ms: int = 2500,
    save_path: str = "",
) -> dict:
    """
    Capture the debuggee's current top window or a specific hwnd and store a visual snapshot.
    """
    try:
        result = _capture_window_snapshot(
            pid=pid,
            hwnd=hwnd,
            title_contains=title_contains,
            class_name=class_name,
            client_only=client_only,
            visible_only=visible_only,
            focus_window=focus_window,
            timeout_ms=timeout_ms,
            save_path=save_path,
        )
        _log_event(
            "capture_debuggee_window",
            pid=result.get("pid"),
            hwnd=result.get("hwnd"),
            clientOnly=result.get("clientOnly"),
            sha256=result.get("sha256"),
            captureId=result.get("captureId"),
        )
        return {"ok": True, **result, "logPath": LOG_PATH}
    except Exception as e:
        _log_event("capture_debuggee_window_error", pid=pid, hwnd=hwnd, error=str(e))
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def CompareWindowCaptures(
    before_capture_id: str, after_capture_id: str, max_changes: int = 16
) -> dict:
    """
    Compare two stored window captures and summarize visual differences.
    """
    before = _get_window_capture(before_capture_id)
    after = _get_window_capture(after_capture_id)
    if not before or not after:
        return {
            "ok": False,
            "beforeCaptureId": before_capture_id,
            "afterCaptureId": after_capture_id,
            "error": "One or both window captures were not found",
        }
    return _compare_window_capture_records(before, after, max_changes=max_changes)


@mcp.tool()
def WaitForWindowVisualChange(
    pid: int = 0,
    hwnd: str = "",
    title_contains: str = "",
    class_name: str = "",
    baseline_capture_id: str = "",
    client_only: bool = True,
    visible_only: bool = True,
    focus_window: bool = True,
    timeout_ms: int = 4000,
    poll_ms: int = 150,
    min_changed_pixels: int = 32,
) -> dict:
    """
    Wait until the target window's visual content changes by a meaningful amount.
    """
    baseline = _get_window_capture(baseline_capture_id) if baseline_capture_id else None
    if not baseline:
        baseline_result = CaptureDebuggeeWindow(
            pid=pid,
            hwnd=hwnd,
            title_contains=title_contains,
            class_name=class_name,
            client_only=client_only,
            visible_only=visible_only,
            focus_window=focus_window,
            timeout_ms=timeout_ms,
        )
        if not baseline_result.get("ok"):
            return baseline_result
        baseline = _get_window_capture(str(baseline_result.get("captureId") or ""))
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    last_after: Optional[Dict[str, Any]] = None
    last_comparison: Optional[Dict[str, Any]] = None
    while time.time() <= deadline:
        current_result = CaptureDebuggeeWindow(
            pid=pid or int((baseline or {}).get("pid") or 0),
            hwnd=hwnd or str((baseline or {}).get("hwnd") or ""),
            title_contains=title_contains,
            class_name=class_name,
            client_only=client_only,
            visible_only=visible_only,
            focus_window=focus_window,
            timeout_ms=max(500, min(2500, int(poll_ms) * 2)),
        )
        if current_result.get("ok"):
            last_after = _get_window_capture(str(current_result.get("captureId") or ""))
            if last_after:
                last_comparison = _compare_window_capture_records(
                    baseline, last_after, max_changes=16
                )
                if last_comparison.get("hashChanged") and int(
                    last_comparison.get("changedPixels") or 0
                ) >= int(min_changed_pixels):
                    _log_event(
                        "wait_for_window_visual_change_hit",
                        beforeCaptureId=baseline.get("captureId"),
                        afterCaptureId=last_after.get("captureId"),
                        changedPixels=last_comparison.get("changedPixels"),
                    )
                    return {
                        "ok": True,
                        "timedOut": False,
                        "beforeCapture": _window_capture_public(baseline),
                        "afterCapture": _window_capture_public(last_after),
                        "comparison": last_comparison,
                        "logPath": LOG_PATH,
                    }
        time.sleep(max(20, int(poll_ms)) / 1000.0)
    _log_event(
        "wait_for_window_visual_change_timeout",
        beforeCaptureId=(baseline or {}).get("captureId"),
        afterCaptureId=(last_after or {}).get("captureId") if last_after else None,
        changedPixels=(last_comparison or {}).get("changedPixels")
        if last_comparison
        else None,
    )
    return {
        "ok": False,
        "timedOut": True,
        "beforeCapture": _window_capture_public(baseline) if baseline else None,
        "afterCapture": _window_capture_public(last_after) if last_after else None,
        "comparison": last_comparison,
        "reason": "Timed out waiting for a meaningful window visual change.",
        "logPath": LOG_PATH,
    }


@mcp.tool()
def AnalyzeDebuggeeInteraction(
    pid: int = 0,
    visible_only: bool = True,
    max_depth: int = 4,
    max_console_chars: int = 4000,
) -> dict:
    """
    Combine debugger state, console state, and GUI state into one interaction snapshot.
    """
    state = _build_debug_state(
        include_console=True,
        include_callstack=True,
        max_console_chars=max_console_chars,
    )
    gui = GetDebuggeeWindows(
        pid=pid, include_children=True, visible_only=visible_only, max_depth=max_depth
    )
    gui_analysis = gui.get("analysis", {}) if isinstance(gui, dict) else {}
    uia = None
    uia_analysis: Dict[str, Any] = {}
    if not (
        gui_analysis.get("hasEdit")
        or gui_analysis.get("hasButton")
        or gui_analysis.get("safeAutoButtonHwnd")
    ):
        uia_pid = pid or int((gui or {}).get("pid") or 0)
        uia = GetDebuggeeUiAutomation(
            pid=uia_pid, visible_only=visible_only, max_depth=max_depth
        )
        uia_analysis = uia.get("analysis", {}) if isinstance(uia, dict) else {}
    anti_debug = _detect_common_antidebug_pause(
        state, gui_snapshot=gui if isinstance(gui, dict) else None
    )
    interaction_mode = "none"
    startup_paused = _is_startup_pause(
        state, gui_snapshot=gui if isinstance(gui, dict) else None
    )
    raw_window_ready = bool(gui_analysis.get("hasVisibleWindow")) and not any(
        (
            gui_analysis.get("hasEdit"),
            gui_analysis.get("hasButton"),
            gui_analysis.get("safeAutoButtonHwnd"),
            uia_analysis.get("hasValueElement"),
            uia_analysis.get("hasInvokeElement"),
        )
    )
    if state.get("waitingForInput"):
        interaction_mode = "console"
    elif anti_debug.get("handled"):
        interaction_mode = "startup_antidebug"
    elif startup_paused:
        interaction_mode = "startup"
    elif gui_analysis.get("hasEdit") and gui_analysis.get("hasButton"):
        interaction_mode = "gui_form"
    elif gui_analysis.get("safeAutoButtonHwnd"):
        interaction_mode = "gui_button"
    elif uia_analysis.get("hasValueElement") and uia_analysis.get("hasInvokeElement"):
        interaction_mode = "uia_form"
    elif uia_analysis.get("hasInvokeElement"):
        interaction_mode = "uia_button"
    elif raw_window_ready:
        interaction_mode = "raw_window"
    elif gui_analysis.get("hasVisibleWindow"):
        interaction_mode = "gui"
    recommended_action = "inspect"
    if anti_debug.get("handled"):
        recommended_action = "bypass_common_antidebug"
    elif startup_paused:
        recommended_action = "resume_startup"
    elif state.get("shouldAutoSubmit"):
        recommended_action = "submit_console_input"
    elif gui_analysis.get("hasEdit") and gui_analysis.get("hasButton"):
        recommended_action = "submit_gui_form"
    elif gui_analysis.get("safeAutoButtonHwnd"):
        recommended_action = "click_safe_button"
    elif uia_analysis.get("hasValueElement") and uia_analysis.get("hasInvokeElement"):
        recommended_action = "submit_uia_form"
    elif uia_analysis.get("hasInvokeElement"):
        recommended_action = "invoke_uia_button"
    elif raw_window_ready:
        recommended_action = "use_raw_window_input"
    return {
        "state": state,
        "gui": gui,
        "uia": uia,
        "interactionMode": interaction_mode,
        "startupPaused": startup_paused,
        "antiDebugPause": bool(anti_debug.get("handled")),
        "antiDebugApi": anti_debug.get("api") if anti_debug.get("handled") else None,
        "antiDebugObservedApi": anti_debug.get("api")
        if anti_debug.get("observed")
        else None,
        "recommendedAction": recommended_action,
        "shouldOfferConsoleInput": bool(state.get("shouldAutoSubmit")),
        "shouldOfferGuiInput": bool(
            gui_analysis.get("hasEdit") and gui_analysis.get("hasButton")
        ),
        "shouldOfferUiAutomation": bool(
            uia_analysis.get("hasValueElement") or uia_analysis.get("hasInvokeElement")
        ),
        "shouldOfferRawWindowInput": raw_window_ready,
        "rawWindowSuggestedHwnd": gui_analysis.get("primaryWindowHwnd"),
        "rawWindowSuggestedTitle": gui_analysis.get("primaryWindowTitle"),
        "safeAutoButtonHwnd": gui_analysis.get("safeAutoButtonHwnd"),
        "safeAutoButtonTitle": gui_analysis.get("safeAutoButtonTitle"),
        "logPath": LOG_PATH,
    }


@mcp.tool()
def AutoRespondToDebuggeeGui(
    text: str = "",
    texts_json: str = "",
    pid: int = 0,
    window_title: str = "",
    button_text: str = "",
    timeout_ms: int = 4000,
    poll_ms: int = 150,
    visible_only: bool = True,
) -> dict:
    """
    Wait for a GUI form or safe dialog action and only interact when the target is clearly ready.
    """
    effective_timeout_ms = max(timeout_ms, 20000 if (text or texts_json) else 12000)
    deadline = time.time() + (effective_timeout_ms / 1000.0)
    extra_budget_ms = 0
    max_extra_budget_ms = 12000 if (text or texts_json) else 6000
    clicked_buttons: List[Dict[str, Any]] = []
    total_auto_runs = 0
    total_removed: List[str] = []
    total_bypasses: List[Dict[str, Any]] = []
    last_state: Dict[str, Any] = {}
    last_gui: Dict[str, Any] = {}

    def extend_deadline(extra_ms: int) -> None:
        nonlocal deadline, extra_budget_ms
        allowed = min(
            max(0, int(extra_ms)), max(0, max_extra_budget_ms - extra_budget_ms)
        )
        if allowed <= 0:
            return
        extra_budget_ms += allowed
        deadline += allowed / 1000.0

    while time.time() <= deadline:
        remaining_ms = max(0, int((deadline - time.time()) * 1000))
        primed = _advance_debuggee_toward_interaction(
            mode="gui",
            timeout_ms=remaining_ms,
            poll_ms=poll_ms,
            pid=pid,
            visible_only=visible_only,
            max_depth=5,
        )
        last_state = primed.get("state", {}) if isinstance(primed, dict) else {}
        last_gui = primed.get("gui", {}) if isinstance(primed, dict) else {}
        total_auto_runs += int(primed.get("autoRuns", 0) or 0)
        for addr in primed.get("removedBreakpoints", []):
            if addr not in total_removed:
                total_removed.append(addr)
        for item in primed.get("autoBypasses", []):
            if item not in total_bypasses:
                total_bypasses.append(item)

        if last_state.get("state") in ("exited", "not_debugging"):
            return {
                "ok": False,
                "reason": "Target exited before a safe GUI interaction was detected.",
                "state": last_state,
                "gui": last_gui,
                "timedOut": False,
                "autoRuns": total_auto_runs,
                "autoBypasses": total_bypasses,
                "removedBreakpoints": total_removed,
                "intermediateActions": clicked_buttons,
            }
        if last_state.get("waitingForInput") or last_state.get("shouldAutoSubmit"):
            return {
                "ok": False,
                "timedOut": False,
                "reason": "A console input prompt was detected. Use AutoRespondToDebuggeeConsole for this target.",
                "redirectSuggested": "console",
                "analysis": {
                    "debuggeePid": last_state.get("debuggeePid"),
                    "promptText": last_state.get("promptText"),
                    "confidence": last_state.get("inputConfidence"),
                    "reason": last_state.get("inputReason"),
                    "consoleLines": last_state.get("console", {}).get("lines", [])[-8:],
                },
                "state": last_state,
                "gui": last_gui,
                "autoRuns": total_auto_runs,
                "autoBypasses": total_bypasses,
                "removedBreakpoints": total_removed,
                "intermediateActions": clicked_buttons,
            }
        if not primed.get("ready"):
            break

        analysis = last_gui.get("analysis", {}) if isinstance(last_gui, dict) else {}
        safe_button_hwnd = str(analysis.get("safeAutoButtonHwnd") or "")
        has_form = bool(analysis.get("hasEdit") and analysis.get("hasButton"))
        uia_snapshot = None
        uia_analysis: Dict[str, Any] = {}
        if not has_form and not safe_button_hwnd:
            uia_snapshot = GetDebuggeeUiAutomation(
                pid=pid or int(last_gui.get("pid") or 0),
                visible_only=visible_only,
                max_depth=6,
            )
            uia_analysis = (
                uia_snapshot.get("analysis", {})
                if isinstance(uia_snapshot, dict)
                else {}
            )
        if safe_button_hwnd and not has_form:
            previous_primary = str(analysis.get("primaryWindowHwnd") or "")
            previous_titles = json.dumps(
                list((last_gui.get("summary", {}) or {}).get("titles", []))
            )
            click_result = SubmitDebuggeeGuiForm(
                pid=pid or int(last_gui.get("pid") or 0),
                window_title=window_title
                or str(analysis.get("primaryWindowTitle") or ""),
                button_hwnd=safe_button_hwnd,
            )
            clicked_buttons.append(
                {
                    "kind": "safe_button",
                    "hwnd": safe_button_hwnd,
                    "title": analysis.get("safeAutoButtonTitle"),
                    "ok": bool(click_result.get("ok")),
                }
            )
            if not click_result.get("ok"):
                return {
                    "ok": False,
                    "timedOut": False,
                    "analysis": analysis,
                    "state": last_state,
                    "gui": last_gui,
                    "result": click_result,
                    "autoRuns": total_auto_runs,
                    "autoBypasses": total_bypasses,
                    "removedBreakpoints": total_removed,
                    "intermediateActions": clicked_buttons,
                }
            extend_deadline(3000)
            change_result = WaitForGuiChange(
                pid=pid or int(last_gui.get("pid") or 0),
                previous_primary_hwnd=previous_primary,
                previous_titles_json=previous_titles,
                timeout_ms=min(max(600, poll_ms * 8), 2000),
                poll_ms=max(50, min(poll_ms, 150)),
                visible_only=visible_only,
            )
            if not change_result.get("ok"):
                focus_result = FocusDebuggeeWindow(
                    pid=pid or int(last_gui.get("pid") or 0), timeout_ms=1500
                )
                key_result = (
                    SendForegroundKeys(json.dumps(["ENTER"]))
                    if focus_result.get("ok")
                    else {"ok": False, "reason": "focus_failed"}
                )
                clicked_buttons.append(
                    {
                        "kind": "safe_button_enter_fallback",
                        "hwnd": safe_button_hwnd,
                        "ok": bool(key_result.get("ok")),
                    }
                )
                change_result = WaitForGuiChange(
                    pid=pid or int(last_gui.get("pid") or 0),
                    previous_primary_hwnd=previous_primary,
                    previous_titles_json=previous_titles,
                    timeout_ms=min(max(600, poll_ms * 8), 2000),
                    poll_ms=max(50, min(poll_ms, 150)),
                    visible_only=visible_only,
                )
            post_snapshot = GetDebuggeeWindows(
                pid=pid or int(last_gui.get("pid") or 0),
                include_children=True,
                visible_only=visible_only,
                max_depth=5,
            )
            post_controls = (
                post_snapshot.get("controls", [])
                if isinstance(post_snapshot, dict)
                else []
            )
            button_still_present = bool(
                _select_gui_control(
                    post_controls,
                    hwnd=safe_button_hwnd,
                    visible_only=True,
                    enabled_only=True,
                )
            )
            if button_still_present:
                focus_result = FocusDebuggeeWindow(
                    pid=pid or int(last_gui.get("pid") or 0), timeout_ms=1500
                )
                if focus_result.get("ok"):
                    button_node = _select_gui_control(
                        post_controls,
                        hwnd=safe_button_hwnd,
                        visible_only=True,
                        enabled_only=True,
                    )
                    top_node = _select_top_window(
                        post_snapshot,
                        hwnd=str(
                            (post_snapshot.get("summary", {}) or {}).get(
                                "primaryWindowHwnd"
                            )
                            or ""
                        ),
                    )
                    if button_node and top_node:
                        button_rect = _control_rect(button_node)
                        top_rect = _control_rect(top_node)
                        if button_rect and top_rect:
                            rel_x = max(
                                5,
                                int(button_rect.get("left", 0))
                                - int(top_rect.get("left", 0))
                                + max(6, int(button_rect.get("width", 0)) // 2),
                            )
                            rel_y = max(
                                5,
                                int(button_rect.get("top", 0))
                                - int(top_rect.get("top", 0))
                                + max(6, int(button_rect.get("height", 0)) // 2),
                            )
                            raw_click_result = ClickActiveWindow(x=rel_x, y=rel_y)
                            clicked_buttons.append(
                                {
                                    "kind": "safe_button_raw_click",
                                    "hwnd": safe_button_hwnd,
                                    "ok": bool(raw_click_result.get("ok")),
                                }
                            )
                    key_result = SendForegroundKeys(json.dumps(["ENTER"]))
                    clicked_buttons.append(
                        {
                            "kind": "safe_button_enter_fallback",
                            "hwnd": safe_button_hwnd,
                            "ok": bool(key_result.get("ok")),
                        }
                    )
                    extend_deadline(3000)
                    change_result = WaitForGuiChange(
                        pid=pid or int(last_gui.get("pid") or 0),
                        previous_primary_hwnd=previous_primary,
                        previous_titles_json=previous_titles,
                        timeout_ms=min(max(600, poll_ms * 8), 2000),
                        poll_ms=max(50, min(poll_ms, 150)),
                        visible_only=visible_only,
                    )
            time.sleep(max(50, min(poll_ms, 150)) / 1000.0)
            continue

        if (
            uia_analysis.get("hasValueElement") or uia_analysis.get("hasInvokeElement")
        ) and (text or texts_json or uia_analysis.get("hasInvokeElement")):
            result = SubmitDebuggeeUiAutomation(
                text=text,
                texts_json=texts_json,
                pid=pid or int(last_gui.get("pid") or 0),
                button_text=button_text,
            )
            return {
                "ok": bool(result.get("ok")),
                "timedOut": False,
                "analysis": analysis,
                "uia": uia_snapshot,
                "state": last_state,
                "gui": last_gui,
                "result": result,
                "autoRuns": total_auto_runs,
                "autoBypasses": total_bypasses,
                "removedBreakpoints": total_removed,
                "intermediateActions": clicked_buttons,
            }

        if (text or texts_json) and has_form:
            result = SubmitDebuggeeGuiForm(
                text=text,
                texts_json=texts_json,
                pid=pid or int(last_gui.get("pid") or 0),
                window_title=window_title,
                button_text=button_text,
            )
            return {
                "ok": bool(result.get("ok")),
                "timedOut": False,
                "analysis": analysis,
                "state": last_state,
                "gui": last_gui,
                "result": result,
                "autoRuns": total_auto_runs,
                "autoBypasses": total_bypasses,
                "removedBreakpoints": total_removed,
                "intermediateActions": clicked_buttons,
            }

        if not text and not texts_json and safe_button_hwnd:
            result = SubmitDebuggeeGuiForm(
                pid=pid or int(last_gui.get("pid") or 0),
                window_title=window_title
                or str(analysis.get("primaryWindowTitle") or ""),
                button_hwnd=safe_button_hwnd,
            )
            return {
                "ok": bool(result.get("ok")),
                "timedOut": False,
                "analysis": analysis,
                "state": last_state,
                "gui": last_gui,
                "result": result,
                "autoRuns": total_auto_runs,
                "autoBypasses": total_bypasses,
                "removedBreakpoints": total_removed,
                "intermediateActions": clicked_buttons,
            }

        break

    _log_event(
        "auto_respond_gui_timeout",
        timeoutMs=effective_timeout_ms,
        lastState=last_state.get("state"),
        gui=last_gui.get("analysis") if isinstance(last_gui, dict) else {},
        autoRuns=total_auto_runs,
        autoBypasses=total_bypasses,
        removedBreakpoints=total_removed,
        intermediateActions=clicked_buttons,
    )
    return {
        "ok": False,
        "timedOut": time.time() > deadline,
        "reason": "Timed out waiting for a safe GUI interaction opportunity.",
        "state": last_state,
        "gui": last_gui,
        "timeoutMs": effective_timeout_ms,
        "autoRuns": total_auto_runs,
        "autoBypasses": total_bypasses,
        "removedBreakpoints": total_removed,
        "intermediateActions": clicked_buttons,
        "logPath": LOG_PATH,
    }


@mcp.tool()
def SubmitDebuggeeGuiForm(
    text: str = "",
    texts_json: str = "",
    pid: int = 0,
    window_title: str = "",
    button_text: str = "",
    edit_hwnd: str = "",
    button_hwnd: str = "",
    edit_index: int = 0,
    button_index: int = 0,
    verbose: bool = False,
) -> dict:
    """
    Populate an Edit control and click a Button in the debuggee GUI.

    Set verbose=True to include full pre/post GUI snapshots. Default False
    returns only the chosen controls, actions, and a compact summary.
    """
    snapshot = GetDebuggeeWindows(
        pid=pid, include_children=True, visible_only=True, max_depth=5
    )
    if snapshot.get("ok") is False:
        return snapshot
    state_before = _build_debug_state(
        include_console=False, include_callstack=False, max_console_chars=0
    )
    auto_resumed = False
    resume_result = None
    pause_result = None
    paused_state = None
    removed_breakpoints: List[str] = []
    window_node = (
        _select_top_window(snapshot, title_contains=window_title)
        if window_title
        else None
    )
    controls = (
        _controls_for_window(window_node)
        if window_node
        else snapshot.get("controls", [])
    )
    analysis = _analyze_gui_snapshot(
        {
            "pid": snapshot.get("pid"),
            "controls": controls,
            "summary": snapshot.get("summary", {}),
        }
    )
    if state_before.get("paused") and int(state_before.get("debuggeePid") or 0) == int(
        snapshot.get("pid") or 0
    ):
        current_state = state_before
        for _attempt in range(4):
            removed_breakpoints.extend(
                _remove_safe_startup_breakpoints(
                    current_state.get("debuggeeImage"),
                    allow_debuggee_entrypoint=True,
                    current_addr=str(current_state.get("rip") or ""),
                )
            )
            resume_result = DebugRun()
            auto_resumed = True
            time.sleep(0.25)
            current_state = _build_debug_state(
                include_console=False, include_callstack=False, max_console_chars=0
            )
            if current_state.get("running"):
                break
            if (
                current_state.get("paused")
                and not current_state.get("breakpointCount")
                and not removed_breakpoints
            ):
                break
        snapshot = GetDebuggeeWindows(
            pid=snapshot.get("pid") or pid,
            include_children=True,
            visible_only=True,
            max_depth=5,
        )
        if snapshot.get("ok") is False:
            return snapshot
        window_node = (
            _select_top_window(snapshot, title_contains=window_title)
            if window_title
            else None
        )
        controls = (
            _controls_for_window(window_node)
            if window_node
            else snapshot.get("controls", [])
        )
        analysis = _analyze_gui_snapshot(
            {
                "pid": snapshot.get("pid"),
                "controls": controls,
                "summary": snapshot.get("summary", {}),
            }
        )
        if current_state.get("paused"):
            return {
                "ok": False,
                "error": "GUI target is still paused inside the debugger and cannot process window messages yet.",
                "snapshot": snapshot,
                "analysis": analysis,
                "stateBefore": state_before,
                "stateAfterResumeAttempts": current_state,
                "autoResumed": auto_resumed,
                "resumeResult": resume_result,
                "removedBreakpoints": removed_breakpoints,
                "logPath": LOG_PATH,
            }
    chosen_edit = _select_gui_control(
        controls,
        role="edit",
        hwnd=edit_hwnd,
        index=edit_index,
        visible_only=True,
        enabled_only=True,
    )
    chosen_button = _select_gui_control(
        controls,
        role="button",
        hwnd=button_hwnd,
        text_contains=button_text,
        index=button_index,
        visible_only=True,
        enabled_only=True,
    )
    if not chosen_button and analysis.get("suggestedButtonHwnd"):
        chosen_button = _select_gui_control(
            controls,
            role="button",
            hwnd=str(analysis.get("suggestedButtonHwnd")),
            visible_only=True,
            enabled_only=True,
        )
    actions: List[Dict[str, Any]] = []
    payload = _parse_text_payload(texts_json)
    text_values = payload.get("list", [])
    text_map = payload.get("map", {})
    if text_values or text_map:
        editable_controls = [
            item
            for item in controls
            if isinstance(item, dict)
            and str(item.get("role", "")).lower() == "edit"
            and bool(item.get("visible"))
            and bool(item.get("enabled"))
        ]
        editable_controls = _sorted_controls_by_layout(editable_controls)
        if not editable_controls:
            return {
                "ok": False,
                "error": "No suitable Edit control found.",
                "snapshot": snapshot,
                "analysis": analysis,
                "logPath": LOG_PATH,
            }
        field_hints = {item.get("hwnd"): item for item in _infer_field_hints(controls)}
        remaining_controls = list(editable_controls)
        if text_map:
            for key, value in text_map.items():
                matched = None
                for control in list(remaining_controls):
                    hint = field_hints.get(control.get("hwnd"), {})
                    if _text_matches(
                        str(hint.get("labelText", "")), key
                    ) or _text_matches(str(control.get("title", "")), key):
                        matched = control
                        remaining_controls.remove(control)
                        break
                if matched:
                    actions.append(
                        _set_control_text(_parse_hwnd_value(matched["hwnd"]), value)
                    )
        for idx, value in enumerate(text_values):
            if idx >= len(remaining_controls):
                break
            actions.append(
                _set_control_text(
                    _parse_hwnd_value(remaining_controls[idx]["hwnd"]), value
                )
            )
    elif text:
        if not chosen_edit:
            return {
                "ok": False,
                "error": "No suitable Edit control found.",
                "snapshot": snapshot,
                "analysis": analysis,
                "logPath": LOG_PATH,
            }
        actions.append(_set_control_text(_parse_hwnd_value(chosen_edit["hwnd"]), text))
    if chosen_button:
        actions.append(_click_control(_parse_hwnd_value(chosen_button["hwnd"])))
    elif not actions:
        return {
            "ok": False,
            "error": "No suitable GUI action found.",
            "snapshot": snapshot,
            "analysis": analysis,
            "logPath": LOG_PATH,
        }
    time.sleep(0.15)
    post_snapshot = GetDebuggeeWindows(
        pid=snapshot.get("pid") or pid,
        include_children=True,
        visible_only=True,
        max_depth=5,
    )
    if auto_resumed:
        time.sleep(0.35)
        pause_result = DebugPause()
        paused_state = WaitForPause(2000, 100)
    result: Dict[str, Any] = {
        "ok": True,
        "chosenEdit": {
            "hwnd": chosen_edit.get("hwnd") if chosen_edit else None,
            "controlId": chosen_edit.get("controlId") if chosen_edit else None,
            "title": chosen_edit.get("title") if chosen_edit else None,
        } if chosen_edit else None,
        "chosenButton": {
            "hwnd": chosen_button.get("hwnd") if chosen_button else None,
            "controlId": chosen_button.get("controlId") if chosen_button else None,
            "title": chosen_button.get("title") if chosen_button else None,
        } if chosen_button else None,
        "actions": actions,
        "postSummary": post_snapshot.get("summary") if isinstance(post_snapshot, dict) else None,
        "autoResumed": auto_resumed,
        "removedBreakpoints": removed_breakpoints,
        "logPath": LOG_PATH,
    }
    if verbose:
        result.update({
            "window": window_node,
            "snapshot": snapshot,
            "postSnapshot": post_snapshot,
            "analysis": analysis,
            "stateBefore": state_before,
            "resumeResult": resume_result,
            "pauseResult": pause_result,
            "pausedState": paused_state,
        })
    _log_event(
        "submit_debuggee_gui_form",
        pid=snapshot.get("pid"),
        windowTitle=window_title,
        chosenEdit=chosen_edit.get("hwnd") if chosen_edit else None,
        chosenButton=chosen_button.get("hwnd") if chosen_button else None,
        text=text,
        texts=text_values,
        textMap=text_map,
    )
    return result


def _prepare_scyllahide_launch(
    exe_path: str, target_arch: str, use_scyllahide: str, scyllahide_profile: str
) -> Dict[str, Any]:
    dismiss_result = _dismiss_scyllahide_dialog(timeout_ms=300, poll_ms=75)
    scylla_mode = str(use_scyllahide or "auto").strip().lower()
    payload: Dict[str, Any] = {
        "ok": True,
        "skipped": True,
        "reason": "ScyllaHide policy disabled.",
        "profile": "Disabled",
        "preArmed": False,
        "force": False,
    }
    if dismiss_result.get("found"):
        payload["dismissedDialog"] = dismiss_result
    status = GetScyllaHideStatus(exe_path=exe_path, arch=target_arch or "auto")
    if not status.get("installed"):
        if scylla_mode in ("off", "disabled", "never"):
            return payload
        return {
            "ok": False,
            "skipped": False,
            "preArmed": False,
            "reason": "ScyllaHide is not installed for the active debugger architecture.",
            "status": status,
            "profile": "Disabled",
            "force": scylla_mode in ("force", "on", "always"),
            "logPath": LOG_PATH,
        }
    original_profile = str(status.get("currentProfile") or "Disabled")
    config_path = str(status.get("configPath") or "")
    analysis = (
        status.get("analysis") if isinstance(status.get("analysis"), dict) else None
    )
    if scylla_mode in ("off", "disabled", "never"):
        payload.update(
            {
                "status": status,
                "analysis": analysis,
                "profile": "Disabled",
                "force": False,
            }
        )
        if original_profile and original_profile != "Disabled" and config_path:
            try:
                set_result = _write_scyllahide_profile(
                    config_path, "Disabled", allow_disabled=True
                )
                log_bookmark = _read_scyllahide_log_status(
                    _scyllahide_paths_for_arch(target_arch or "auto")
                )
                payload.update(
                    {
                        "preArmed": True,
                        "reason": "ScyllaHide temporarily disabled for this launch.",
                        "originalProfile": original_profile,
                        "setProfile": set_result,
                        "logBookmark": log_bookmark,
                    }
                )
            except Exception as e:
                payload.update(
                    {
                        "ok": False,
                        "skipped": False,
                        "preArmed": False,
                        "reason": str(e),
                        "logPath": LOG_PATH,
                    }
                )
        return payload
    explicit_profile = str(scyllahide_profile or "").strip()
    chosen_profile = explicit_profile if explicit_profile else "auto"
    profile_was_auto = chosen_profile.lower() == "auto"
    if profile_was_auto:
        chosen_profile = str(
            (analysis or {}).get("suggestedScyllaHideProfile") or "Disabled"
        )
    force_enabled = scylla_mode in ("force", "on", "always")
    if force_enabled and _is_disabled_scylla_profile(chosen_profile):
        if explicit_profile and not profile_was_auto:
            return {
                "ok": False,
                "skipped": False,
                "preArmed": False,
                "reason": (
                    "ScyllaHide force mode cannot use a disabled profile. "
                    "Choose an active profile such as Basic."
                ),
                "status": status,
                "analysis": analysis,
                "profile": chosen_profile,
                "force": True,
                "logPath": LOG_PATH,
            }
        chosen_profile = "Basic"
    payload.update(
        {
            "status": status,
            "analysis": analysis,
            "profile": chosen_profile or "Disabled",
            "force": force_enabled,
        }
    )
    if (not payload["force"]) and (not chosen_profile or chosen_profile == "Disabled"):
        if original_profile and original_profile != "Disabled" and config_path:
            try:
                set_result = _write_scyllahide_profile(
                    config_path, "Disabled", allow_disabled=True
                )
                log_bookmark = _read_scyllahide_log_status(
                    _scyllahide_paths_for_arch(target_arch or "auto")
                )
                payload.update(
                    {
                        "preArmed": True,
                        "reason": "Analysis did not justify ScyllaHide for this target, so it was temporarily disabled.",
                        "originalProfile": original_profile,
                        "setProfile": set_result,
                        "logBookmark": log_bookmark,
                    }
                )
            except Exception as e:
                payload.update(
                    {
                        "ok": False,
                        "skipped": False,
                        "preArmed": False,
                        "reason": str(e),
                        "logPath": LOG_PATH,
                    }
                )
        else:
            payload["reason"] = "Analysis did not justify ScyllaHide for this target."
        return payload
    try:
        set_result = _write_scyllahide_profile(config_path, chosen_profile or "Basic")
    except Exception as e:
        return {
            "ok": False,
            "skipped": False,
            "preArmed": False,
            "reason": str(e),
            "status": status,
            "analysis": analysis,
            "profile": chosen_profile or "Basic",
            "force": payload["force"],
            "logPath": LOG_PATH,
        }
    log_bookmark = _read_scyllahide_log_status(
        _scyllahide_paths_for_arch(target_arch or "auto")
    )
    _remember_runtime(
        lastScyllaHide={
            "pid": 0,
            "arch": status.get("arch"),
            "profile": chosen_profile or "Basic",
            "hookPath": status.get("hookPath"),
            "ok": False,
            "preArmed": True,
            "logMtime": log_bookmark.get("mtime"),
            "logSize": log_bookmark.get("size"),
            "timestamp": _now_iso(),
        }
    )
    payload.update(
        {
            "ok": True,
            "skipped": False,
            "preArmed": True,
            "reason": "ScyllaHide profile armed before init.",
            "originalProfile": original_profile,
            "setProfile": set_result,
            "logBookmark": log_bookmark,
        }
    )
    return payload


def _verify_scyllahide_prearmed(
    target_pid: int,
    exe_path: str,
    arch: str,
    timeout_ms: int = 2500,
    poll_ms: int = 125,
) -> Dict[str, Any]:
    started = time.time()
    deadline = started + (max(timeout_ms, 0) / 1000.0)
    last_status: Dict[str, Any] = {}
    while True:
        status = GetScyllaHideStatus(
            pid=target_pid, exe_path=exe_path, arch=arch or "auto"
        )
        last_status = status if isinstance(status, dict) else {}
        if last_status.get("hookInjected"):
            return {
                "ok": True,
                "hookInjected": True,
                "status": last_status,
                "elapsedMs": round((time.time() - started) * 1000, 2),
                "verification": "status",
            }
        dismiss_result = _dismiss_scyllahide_dialog(
            expected_substrings=["already hooked", "ntopenfile is already hooked"],
            timeout_ms=800,
            poll_ms=100,
        )
        dialog_message = str(dismiss_result.get("message") or "")
        if dismiss_result.get("found") and (
            dismiss_result.get("dismissed") or dismiss_result.get("matched")
        ):
            return {
                "ok": True,
                "hookInjected": True,
                "status": last_status,
                "elapsedMs": round((time.time() - started) * 1000, 2),
                "verification": "already_hooked_dialog",
                "dialogDetected": True,
                "dialogMessage": dialog_message,
                "dismissedDialog": dismiss_result,
            }
        if time.time() >= deadline:
            return {
                "ok": False,
                "hookInjected": False,
                "status": last_status,
                "elapsedMs": round((time.time() - started) * 1000, 2),
                "verification": "timeout",
            }
        time.sleep(max(0.05, poll_ms / 1000.0))


def _restore_scyllahide_launch_profile(prepared: Dict[str, Any]) -> None:
    if not isinstance(prepared, dict):
        return
    if not prepared.get("preArmed"):
        return
    original_profile = str(prepared.get("originalProfile") or "").strip()
    config_path = str(
        (
            (prepared.get("status") or {})
            if isinstance(prepared.get("status"), dict)
            else {}
        ).get("configPath")
        or ""
    )
    if not original_profile or not config_path or not os.path.exists(config_path):
        return
    try:
        _write_scyllahide_profile(
            config_path, original_profile, allow_disabled=True
        )
    except Exception:
        pass


def _queue_scyllahide_profile_restore(prepared: Dict[str, Any]) -> None:
    if not isinstance(prepared, dict) or not prepared.get("preArmed"):
        return
    original_profile = str(prepared.get("originalProfile") or "").strip()
    status = prepared.get("status") if isinstance(prepared.get("status"), dict) else {}
    config_path = str(status.get("configPath") or "").strip()
    if not original_profile or not config_path:
        return
    _remember_runtime(
        pendingScyllaHideRestore={
            "originalProfile": original_profile,
            "configPath": config_path,
            "queuedAt": _now_iso(),
        }
    )


def _restore_pending_scyllahide_profile(force: bool = False) -> Dict[str, Any]:
    pending = _get_runtime_value("pendingScyllaHideRestore")
    if not isinstance(pending, dict):
        return {"ok": True, "restored": False, "pending": False}
    config_path = str(pending.get("configPath") or "").strip()
    original_profile = str(pending.get("originalProfile") or "").strip()
    if not config_path or not original_profile:
        _remember_runtime(pendingScyllaHideRestore=None)
        return {"ok": True, "restored": False, "pending": False}
    if not force:
        state = _build_debug_state(
            include_console=False, include_callstack=False, max_console_chars=0
        )
        session = (
            state.get("session", {}) if isinstance(state.get("session"), dict) else {}
        )
        if state.get("debugging") or bool(session.get("stopping")):
            return {
                "ok": True,
                "restored": False,
                "pending": True,
                "deferred": True,
                "state": state,
            }
    try:
        result = _write_scyllahide_profile(
            config_path, original_profile, allow_disabled=True
        )
        _remember_runtime(pendingScyllaHideRestore=None)
        return {
            "ok": True,
            "restored": True,
            "pending": False,
            "result": result,
        }
    except Exception as e:
        return {
            "ok": False,
            "restored": False,
            "pending": True,
            "error": str(e),
            "configPath": config_path,
            "originalProfile": original_profile,
        }


def _wait_for_debugger_idle(
    timeout_ms: int = 2500, poll_ms: int = 125
) -> Dict[str, Any]:
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    last_state = _build_debug_state(
        include_console=False, include_callstack=False, max_console_chars=0
    )
    while time.time() < deadline:
        session = (
            last_state.get("session", {})
            if isinstance(last_state.get("session"), dict)
            else {}
        )
        if not last_state.get("debugging") and not bool(session.get("stopping")):
            return last_state
        time.sleep(max(0.05, poll_ms / 1000.0))
        last_state = _build_debug_state(
            include_console=False, include_callstack=False, max_console_chars=0
        )
    return last_state


def _wait_for_init_debug_state(
    deadline: float, settle_ms: int = 2000, poll_ms: int = 25
) -> Dict[str, Any]:
    settle_deadline = min(deadline, time.time() + (max(settle_ms, 0) / 1000.0))
    last_state = _build_debug_state(
        include_console=False, include_callstack=False, max_console_chars=0
    )
    while time.time() < settle_deadline:
        if last_state.get("debugging"):
            return last_state
        time.sleep(max(0.05, poll_ms / 1000.0))
        last_state = _build_debug_state(
            include_console=False, include_callstack=False, max_console_chars=0
        )
    return last_state


def _wait_for_attached_debuggee(
    target_pid: int, deadline: float, poll_ms: int = 125
) -> Dict[str, Any]:
    last_state = _build_debug_state(
        include_console=False, include_callstack=False, max_console_chars=0
    )
    while time.time() < deadline:
        inferred_pid = int(last_state.get("debuggeePid") or 0)
        if not inferred_pid:
            try:
                inferred_pid = _infer_debuggee_pid()
            except Exception:
                inferred_pid = 0
        if last_state.get("debugging") and inferred_pid == int(target_pid):
            payload = dict(last_state)
            payload["debuggeePid"] = int(target_pid)
            return payload
        time.sleep(max(0.05, poll_ms / 1000.0))
        last_state = _build_debug_state(
            include_console=False, include_callstack=False, max_console_chars=0
        )
    return last_state


@mcp.tool()
def InitDebuggee(
    exe_path: str,
    timeout_ms: int = 5000,
    retries: int = 5,
    stop_first: bool = False,
    use_scyllahide: str = "auto",
    scyllahide_profile: str = "",
    use_hidemain: str = "off",
    hidemain_root: str = "",
    hidemain_allow_system_changes: bool = False,
    hidemain_allow_unsigned_driver: bool = False,
    hidemain_acknowledge_kernel_risk: bool = False,
    arguments: Optional[List[str]] = None,
    command_line: str = "",
    working_directory: str = "",
    environment: Optional[Dict[str, Optional[str]]] = None,
    inherit_environment: bool = True,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
    child_policy: str = "none",
    capture_limit_bytes: int = _DEFAULT_CAPTURE_LIMIT_BYTES,
) -> dict:
    """
    Preferred first call when the target executable path is known.

    Reliably start a new debuggee with retries and state verification. This
    tool detects the target architecture, resolves X64DBG_ROOT, starts the
    matching x32dbg/x64dbg instance, waits for its authenticated bridge, and
    opens the target. Do not preflight BridgeHello, probe port 8888, or search
    debugger installation paths manually before calling InitDebuggee.

    Args:
        exe_path: Absolute path to the executable.
        timeout_ms: Maximum total time to spend retrying.
        retries: Maximum number of init attempts.
        stop_first: When true, stop the current debug session before init.
        use_scyllahide: "auto", "off", or "force". Auto only injects when analysis suggests anti-debug.
        scyllahide_profile: Optional explicit ScyllaHide profile override.
        use_hidemain: "off", "auto", or "force". Default off; auto never starts
            the kernel driver, while force requires explicit safety acknowledgements.
        hidemain_root: Optional HideMain distribution root.
        hidemain_allow_system_changes: Allow starting an already-installed service.
        hidemain_allow_unsigned_driver: Explicitly allow an unsigned driver start.
        hidemain_acknowledge_kernel_risk: Acknowledge general kernel-driver/BSOD risk.
        arguments: Argument vector excluding argv[0]. Mutually exclusive with command_line.
        command_line: Explicit Windows command-line tail.
        working_directory: Current directory for the new process.
        environment: Per-launch environment overrides. The current bridge reports
            this unsupported and the call fails explicitly instead of ignoring it.
        inherit_environment: Whether the target should inherit the debugger environment.
        stdin: Typed stdin object (inherit/null/file/bytes/pipe).
        stdout: Typed stdout object (inherit/null/file/pipe).
        stderr: Typed stderr object (inherit/null/file/pipe). All streams must be
            explicit together, or all omitted for console inheritance.
        child_policy: none, attach-first, attach-all, or break-on-create.
        capture_limit_bytes: Bounded pipe retention/queue capacity in bytes.
    """
    exe_path = _repair_text_mojibake(str(exe_path or "").strip())
    requested_hidemain = str(use_hidemain or "off").strip().lower()
    if requested_hidemain not in ("off", "auto", "force"):
        return {
            "ok": False,
            "attempts": 0,
            "exePath": exe_path,
            "error": f"Unknown HideMain mode: {use_hidemain}",
            "hideMain": {"ok": False, "mode": requested_hidemain},
            "timedOut": False,
        }
    launch_spec = _build_launch_spec(
        exe_path,
        arguments=arguments,
        command_line=command_line,
        working_directory=working_directory,
        environment=environment,
        inherit_environment=inherit_environment,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        child_policy=child_policy,
        capture_limit_bytes=capture_limit_bytes,
    )
    if not launch_spec.get("ok"):
        return {
            "ok": False,
            "attempts": 0,
            "exePath": exe_path,
            "error": launch_spec.get("error"),
            "errorCode": "INVALID_ARGUMENT",
            "timedOut": False,
        }
    bridge_ready = _ensure_init_debugger_bridge(exe_path, timeout_ms)
    if not bridge_ready.get("ok"):
        return {
            **bridge_ready,
            "attempts": 0,
            "exePath": exe_path,
            "timedOut": False,
        }
    target_arch = bridge_ready.get("targetArch")
    bridge_recovery = bridge_ready.get("recoveryDebugger")
    launch_caps = _launch_capabilities()
    capability_error = _validate_launch_v2_capabilities(launch_spec, launch_caps)
    if capability_error and _is_stale_launch_contract_error(capability_error):
        # A debugger instance started before the current plugin was installed can
        # still answer Bridge/Hello while advertising launch.version=0.  Typed
        # InitDebuggee calls must recover that exact stale instance once instead
        # of returning a misleading capability error to every caller.
        recovery_arch = _normalize_debugger_arch("auto", exe_path=exe_path)
        bridge_recovery = RestartDebugger(
            arch=recovery_arch,
            timeout_ms=min(max(timeout_ms, 0), 20000) or 20000,
            reload_target=False,
        )
        if isinstance(bridge_recovery, dict) and bridge_recovery.get("ok"):
            hello = _bridge_request(
                "GET",
                "Bridge/Hello",
                log=False,
                timeout_sec=1.0,
                guard="none",
                idempotent=True,
            )
            if hello.ok:
                _cache_bridge_identity(hello.data)
            launch_caps = _launch_capabilities()
            capability_error = _validate_launch_v2_capabilities(
                launch_spec, launch_caps
            )
    if capability_error:
        return {
            **capability_error,
            "attempts": 0,
            "exePath": exe_path,
            "timedOut": False,
            "capabilities": launch_caps,
            "recoveryDebugger": bridge_recovery,
        }
    is_v2_launch = int(_parse_int(launch_spec.get("contractVersion"), 0) or 0) >= 2
    if not is_v2_launch and (
        launch_spec.get("arguments") or launch_spec.get("rawCommandLine")
    ) and not bool(launch_caps.get("args")):
        return {
            "ok": False,
            "attempts": 0,
            "exePath": exe_path,
            "error": "Bridge/Hello does not advertise launch argument support.",
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "capability": "launch.args",
            "timedOut": False,
        }
    if (
        not is_v2_launch
        and launch_spec.get("workingDirectory")
        and not bool(launch_caps.get("cwd"))
    ):
        return {
            "ok": False,
            "attempts": 0,
            "exePath": exe_path,
            "error": "Bridge/Hello does not advertise launch working-directory support.",
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "capability": "launch.cwd",
            "timedOut": False,
        }
    custom_environment = bool(launch_spec.get("environment")) or not bool(
        launch_spec.get("inheritEnvironment", True)
    )
    if (
        not is_v2_launch
        and custom_environment
        and not bool(launch_caps.get("environment"))
    ):
        return {
            "ok": False,
            "attempts": 0,
            "exePath": exe_path,
            "error": "This x64dbg bridge cannot supply a per-launch environment block.",
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "capability": "launch.environment",
            "timedOut": False,
        }
    debugger_info = _get_active_debugger_info()
    active_arch = debugger_info.get("arch")
    if (
        target_arch in ("x86", "x64")
        and active_arch in ("x86", "x64")
        and target_arch != active_arch
    ):
        reason = (
            f"Target {os.path.basename(exe_path)} is {target_arch}, but the active debugger bridge is {debugger_info.get('exe')} "
            f"({active_arch}). Launch the matching debugger first."
        )
        _log_event(
            "init_debuggee_arch_mismatch",
            exePath=exe_path,
            targetArch=target_arch,
            debuggerArch=active_arch,
            debuggerExe=debugger_info.get("exe"),
            debuggerPid=debugger_info.get("pid"),
        )
        return {
            "ok": False,
            "reason": reason,
            "exePath": exe_path,
            "targetArch": target_arch,
            "activeDebugger": debugger_info,
            "state": _build_debug_state(
                include_console=False, include_callstack=False, max_console_chars=0
            ),
            "timedOut": False,
        }

    launch_succeeded = False
    if stop_first:
        pre_stop_state = _build_debug_state(
            include_console=False, include_callstack=False, max_console_chars=0
        )
        _clear_bound_session()
        session_info = (
            pre_stop_state.get("session", {})
            if isinstance(pre_stop_state.get("session"), dict)
            else {}
        )
        if pre_stop_state.get("debugging") or pre_stop_state.get("state") == "exited":
            try:
                DebugStop()
            except Exception:
                pass
            _wait_for_debugger_idle(
                timeout_ms=min(max(timeout_ms, 0), 2500) or 2500, poll_ms=125
            )
        elif bool(session_info.get("stopping")):
            _wait_for_debugger_idle(
                timeout_ms=min(max(timeout_ms, 0), 2500) or 2500, poll_ms=125
            )
    _restore_pending_scyllahide_profile(force=True)

    hidemain_prepare = _prepare_hidemain_workflow(
        mode=use_hidemain,
        target_arch=target_arch or "auto",
        root=hidemain_root,
        allow_system_changes=hidemain_allow_system_changes,
        allow_unsigned=hidemain_allow_unsigned_driver,
        acknowledge_kernel_risk=hidemain_acknowledge_kernel_risk,
    )
    if str(use_hidemain or "off").strip().lower() == "force" and not hidemain_prepare.get("ok"):
        return {
            "ok": False,
            "attempts": 0,
            "exePath": exe_path,
            "targetArch": target_arch,
            "state": _build_debug_state(
                include_console=False, include_callstack=False, max_console_chars=0
            ),
            "hideMain": hidemain_prepare,
            "error": hidemain_prepare.get("error") or "HideMain force-mode preparation failed.",
            "timedOut": False,
        }

    _clear_bound_session()
    launch_context = _capture_launch_context(exe_path, launch_spec=launch_spec)
    _remember_runtime(
        lastLaunchContext=launch_context,
        lastLaunchSpec=dict(launch_spec),
        lastUiRetarget=None,
    )
    scylla_prepare = _prepare_scyllahide_launch(
        exe_path, target_arch or "auto", use_scyllahide, scyllahide_profile
    )

    launch_paths = (
        [exe_path]
        if is_v2_launch
        or (
            launch_caps
            and (
                launch_caps.get("args")
                or launch_caps.get("cwd")
                or launch_caps.get("environment")
            )
        )
        else _build_init_launch_paths(exe_path)
    )

    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    last_result: Any = None
    attempts = max(1, retries)
    dependency_diagnostics = _find_missing_runtime_dependencies(exe_path)
    try:
        for attempt in range(1, attempts + 1):
            last_result = None
            state = _build_debug_state(
                include_console=False, include_callstack=False, max_console_chars=0
            )
            for launch_path in launch_paths:
                attempt_spec = dict(launch_spec)
                attempt_spec["exePath"] = launch_path
                last_result = _launch_via_bridge(
                    attempt_spec,
                    timeout_sec=max(0.25, min(3.0, deadline - time.time())),
                )
                if isinstance(last_result, dict) and last_result.get("success"):
                    state = _wait_for_init_debug_state(
                        deadline=deadline, settle_ms=2000, poll_ms=25
                    )
                else:
                    state = _build_debug_state(
                        include_console=False,
                        include_callstack=False,
                        max_console_chars=0,
                    )
                if state.get("debugging"):
                    break
            if (
                isinstance(last_result, dict)
                and last_result.get("success")
                and state.get("debugging")
            ):
                _update_launch_context_source_pid(int(state.get("debuggeePid") or 0))
                scylla_payload: Dict[str, Any] = dict(scylla_prepare)
                # When ScyllaHide is skipped/disabled, drop the full status+analysis
                # blobs (~15 KB) — callers who need them can call GetScyllaHideStatus.
                if scylla_payload.get("skipped"):
                    scylla_payload = {
                        "ok": True,
                        "skipped": True,
                        "reason": scylla_payload.get("reason"),
                        "profile": scylla_payload.get("profile"),
                    }
                target_pid = int(state.get("debuggeePid") or 0)
                hidemain_payload = _apply_hidemain_workflow(
                    pid=target_pid,
                    mode=use_hidemain,
                    root=hidemain_root,
                    allow_system_changes=hidemain_allow_system_changes,
                    allow_unsigned=hidemain_allow_unsigned_driver,
                    acknowledge_kernel_risk=hidemain_acknowledge_kernel_risk,
                )
                hidemain_required = (
                    str(use_hidemain or "off").strip().lower() == "force"
                )
                if hidemain_required and not hidemain_payload.get("ok"):
                    binding = _bind_debuggee_session(
                        pid=target_pid,
                        image_path=exe_path,
                        strict=True,
                        source="InitDebuggee:HideMainFailed",
                    )
                    state = _refresh_state_after_session_binding(state)
                    _log_event(
                        "init_debuggee_hidemain_failed",
                        exePath=exe_path,
                        pid=target_pid,
                        result=hidemain_payload,
                    )
                    return {
                        "ok": False,
                        "launched": True,
                        "protectionFailed": True,
                        "attempts": attempt,
                        "initResult": last_result,
                        "state": state,
                        "binding": binding,
                        "scyllaHide": scylla_payload,
                        "hideMain": hidemain_payload,
                        "error": (
                            hidemain_payload.get("error")
                            or "Target launched paused, but HideMain force-mode protection failed."
                        ),
                        "timedOut": False,
                    }
                if scylla_prepare.get("preArmed") and not scylla_prepare.get("skipped"):
                    _remember_runtime(
                        lastScyllaHide={
                            "pid": target_pid,
                            "arch": (scylla_prepare.get("status") or {}).get("arch")
                            if isinstance(scylla_prepare.get("status"), dict)
                            else target_arch,
                            "profile": scylla_prepare.get("profile"),
                            "hookPath": (
                                (scylla_prepare.get("status") or {})
                                if isinstance(scylla_prepare.get("status"), dict)
                                else {}
                            ).get("hookPath"),
                            "ok": False,
                            "preArmed": True,
                            "logMtime": (
                                (scylla_prepare.get("logBookmark") or {})
                                if isinstance(scylla_prepare.get("logBookmark"), dict)
                                else {}
                            ).get("mtime"),
                            "logSize": (
                                (scylla_prepare.get("logBookmark") or {})
                                if isinstance(scylla_prepare.get("logBookmark"), dict)
                                else {}
                            ).get("size"),
                            "timestamp": _now_iso(),
                        }
                    )
                    prepared_status = (
                        scylla_prepare.get("status")
                        if isinstance(scylla_prepare.get("status"), dict)
                        else {}
                    )
                    gui_prearm_available = bool(
                        prepared_status.get("guiPluginPresent")
                    )
                    if gui_prearm_available:
                        preparation = _advance_past_startup_pause(
                            timeout_ms=4000, max_runs=4, poll_ms=100
                        )
                        verification = _verify_scyllahide_prearmed(
                            target_pid,
                            exe_path,
                            target_arch or "auto",
                            timeout_ms=3000,
                            poll_ms=125,
                        )
                        scylla_status = (
                            (verification.get("status") or {})
                            if isinstance(verification, dict)
                            else {}
                        )
                    else:
                        # InjectorCLI is the supported MCP backend.  Waiting for
                        # a GUI plugin that is not installed resumes short-lived
                        # targets far enough for them to exit before injection.
                        preparation = {
                            "ok": True,
                            "skipped": True,
                            "reason": (
                                "Optional GUI plugin is absent; injecting through "
                                "InjectorCLI while the target is paused."
                            ),
                        }
                        verification = {
                            "ok": False,
                            "skipped": True,
                            "hookInjected": False,
                            "reason": "Direct InjectorCLI backend selected.",
                        }
                        scylla_status = prepared_status
                    scylla_payload.update(
                        {
                            "status": scylla_status,
                            "preparation": preparation,
                            "verification": verification,
                            "ok": bool(
                                (verification or {}).get("hookInjected")
                                or scylla_status.get("hookInjected")
                            ),
                        }
                    )
                    if not scylla_payload.get("ok"):
                        inject_result = _inject_scyllahide_for_pid(
                            target_pid,
                            str(
                                (scylla_status or {}).get("arch")
                                or target_arch
                                or "auto"
                            ),
                            str(scylla_prepare.get("profile") or "Basic"),
                        )
                        refreshed_status = GetScyllaHideStatus(
                            pid=target_pid,
                            exe_path=exe_path,
                            arch=target_arch or "auto",
                        )
                        get_lean_state = globals().get("GetDebugStateLean")
                        post_injection_state = (
                            get_lean_state()
                            if callable(get_lean_state)
                            else _build_debug_state(
                                include_console=False,
                                include_callstack=False,
                                max_console_chars=0,
                            )
                        )
                        post_injection_deadline = time.time() + 1.5
                        while (
                            time.time() < post_injection_deadline
                            and not (
                                str(
                                    post_injection_state.get("exceptionCode") or "0"
                                )
                                .strip()
                                .casefold()
                                not in {"0", "0x0", "none"}
                                and bool(
                                    post_injection_state.get("exceptionFirstChance")
                                )
                            )
                        ):
                            time.sleep(0.1)
                            post_injection_state = (
                                get_lean_state()
                                if callable(get_lean_state)
                                else _build_debug_state(
                                    include_console=False,
                                    include_callstack=False,
                                    max_console_chars=0,
                                )
                            )
                        post_exception_code = str(
                            post_injection_state.get("exceptionCode") or "0"
                        ).strip().casefold()
                        post_exception_allowed = {
                            "0",
                            "0x0",
                            "none",
                            "0x80000003",
                            "0x4000001e",
                            "0x4000001f",
                        }
                        post_injection_fault = (
                            post_exception_code not in post_exception_allowed
                            and bool(post_injection_state.get("exceptionFirstChance"))
                            and str(post_injection_state.get("stopReason") or "")
                            .strip()
                            .casefold()
                            == "exception"
                        )
                        if post_injection_fault:
                            inject_result = dict(inject_result)
                            inject_result.update(
                                {
                                    "ok": False,
                                    "postInjectionException": post_injection_state,
                                    "error": (
                                        "The target raised a first-chance exception "
                                        f"{post_exception_code} immediately after "
                                        "ScyllaHide injection."
                                    ),
                                }
                            )
                        scylla_payload.update(
                            {
                                "injectResult": inject_result,
                                "status": refreshed_status,
                                "ok": bool(
                                    inject_result.get("ok")
                                    and not post_injection_fault
                                    or refreshed_status.get("hookInjected")
                                ),
                            }
                        )
                        if post_injection_fault:
                            scylla_payload["ok"] = False
                    scylla_required = (
                        str(use_scyllahide or "auto").strip().lower()
                        in ("force", "on", "always")
                    )
                    if scylla_required and not scylla_payload.get("ok"):
                        failed_state = (
                            get_lean_state()
                            if callable(get_lean_state)
                            else _build_debug_state(
                                include_console=False,
                                include_callstack=False,
                                max_console_chars=0,
                            )
                        )
                        binding = _bind_debuggee_session(
                            pid=target_pid,
                            image_path=exe_path,
                            strict=True,
                            source="InitDebuggee:ScyllaHideFailed",
                        )
                        failed_state = _refresh_state_after_session_binding(failed_state)
                        _log_event(
                            "init_debuggee_scyllahide_failed",
                            exePath=exe_path,
                            pid=target_pid,
                            result=scylla_payload,
                        )
                        return {
                            "ok": False,
                            "launched": True,
                            "protectionFailed": True,
                            "attempts": attempt,
                            "initResult": last_result,
                            "state": failed_state,
                            "binding": binding,
                            "scyllaHide": scylla_payload,
                            "hideMain": hidemain_payload,
                            "error": (
                                "Target launched, but ScyllaHide force-mode "
                                "injection could not be verified."
                            ),
                            "timedOut": False,
                        }
                _log_event(
                    "init_debuggee_success",
                    exePath=exe_path,
                    attempts=attempt,
                    pid=state.get("debuggeePid"),
                )
                if scylla_prepare.get("preArmed"):
                    _queue_scyllahide_profile_restore(scylla_prepare)
                launch_succeeded = True
                binding = _bind_debuggee_session(
                    pid=int(state.get("debuggeePid") or 0),
                    image_path=exe_path,
                    strict=True,
                    source="InitDebuggee",
                )
                state = _refresh_state_after_session_binding(state)
                return {
                    "ok": True,
                    "attempts": attempt,
                    "initResult": last_result,
                    "state": state,
                    "binding": binding,
                    "scyllaHide": scylla_payload,
                    "hideMain": hidemain_payload,
                    "timedOut": False,
                }
            if time.time() >= deadline:
                break
            time.sleep(min(0.25 * attempt, 0.75))

        _log_event(
            "init_debuggee_failed",
            exePath=exe_path,
            attempts=attempts,
            lastResult=last_result,
        )
        return {
            "ok": False,
            "attempts": attempts,
            "initResult": last_result,
            "state": _build_debug_state(
                include_console=False, include_callstack=False, max_console_chars=0
            ),
            "scyllaHide": scylla_prepare if scylla_prepare.get("preArmed") else None,
            "hideMain": hidemain_prepare,
            "dependencyDiagnostics": dependency_diagnostics,
            "hint": (
                dependency_diagnostics.get("hint")
                if isinstance(dependency_diagnostics, dict)
                and dependency_diagnostics.get("hint")
                else None
            ),
            "timedOut": time.time() >= deadline,
        }
    finally:
        if not launch_succeeded:
            _restore_scyllahide_launch_profile(scylla_prepare)


@mcp.tool()
def ReadDebuggeeConsole(
    pid: int = 0, max_chars: int = 4000, wait_ms: int = 1500, poll_ms: int = 150
) -> dict:
    """
    Read the visible text from the debuggee console window.

    Args:
        pid: Optional debuggee PID. When omitted, the current target is inferred.
        max_chars: Maximum visible console characters to read.
        wait_ms: If the console has not been painted yet, keep retrying up to this
            long for non-empty text. This removes the need for callers to sleep
            after resuming the target before reading a freshly printed prompt.
        poll_ms: Retry interval while waiting for console text to appear.
    """
    try:
        deadline = time.time() + (max(wait_ms, 0) / 1000.0)
        result = _read_console_text(pid=pid, max_chars=max_chars)
        while (
            isinstance(result, dict)
            and not str(result.get("text") or "").strip()
            and time.time() < deadline
        ):
            time.sleep(max(poll_ms, 20) / 1000.0)
            result = _read_console_text(pid=pid, max_chars=max_chars)
        _log_event(
            "read_console",
            pid=result.get("pid"),
            ok=result.get("ok"),
            prompt=result.get("lines", [])[-1:] if result.get("lines") else [],
        )
        return result
    except Exception as e:
        _log_event("read_console_error", pid=pid, error=str(e))
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def GetDebugState(
    include_console: bool = False,
    include_callstack: bool = False,
    include_registers: bool = False,
    include_breakpoints: bool = False,
    include_session: bool = False,
    max_console_chars: int = 1200,
) -> dict:
    """
    Get a normalized debugger state snapshot.

    Args:
        include_console: When true, read visible console text if available.
        include_callstack: When true, include the current call stack while paused.
        include_registers: When true, include the current register dump while paused.
        include_breakpoints: When true, include breakpoint lists and hit counts.
        include_session: When true, include the raw session payload from the bridge.
        max_console_chars: Maximum visible console characters to read.
    """
    try:
        return _build_debug_state(
            include_console=include_console,
            include_callstack=include_callstack,
            max_console_chars=max_console_chars,
            include_registers=include_registers,
            include_breakpoints=include_breakpoints,
            include_session=include_session,
        )
    except Exception as e:
        _log_event("get_debug_state_error", error=str(e))
        return {
            "state": "error",
            "error": str(e),
            "logPath": LOG_PATH,
        }


@mcp.tool()
def WaitForPause(timeout_ms: int = 10000, poll_ms: int = 100) -> dict:
    """
    Wait until the debuggee reaches a paused state or exits.
    """
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    since_seq = int(_get_runtime_value("lastResumeSeq", 0) or 0)
    skipped_filters: List[Dict[str, Any]] = []
    auto_continue_count = 0
    last_state: Dict[str, Any] = {}
    while time.time() <= deadline:
        remaining_ms = max(0, int((deadline - time.time()) * 1000))
        payload = _coerce_json_payload(
            safe_get(
                "Debug/WaitForPause",
                {"timeoutMs": min(max(remaining_ms, 100), 1500), "sinceSeq": since_seq},
                log=False,
            )
        )
        if isinstance(payload, dict):
            session = (
                payload.get("state", {}) if isinstance(payload.get("state"), dict) else {}
            )
            if session:
                since_seq = int(session.get("eventSeq") or since_seq)
                _remember_runtime(lastSessionEventSeq=since_seq)
            last_state = _build_debug_state(
                include_console=True, include_callstack=True, max_console_chars=4000
            )
            last_state["timedOut"] = bool(payload.get("timedOut"))
            last_state["timeoutMs"] = timeout_ms
            compact_payload = dict(payload)
            inner_state = compact_payload.get("state")
            if isinstance(inner_state, dict) and "history" in inner_state:
                compact_payload["state"] = {
                    k: v for k, v in inner_state.items() if k != "history"
                }
            last_state["waitInfo"] = compact_payload
        else:
            last_state = _build_debug_state(
                include_console=True, include_callstack=True, max_console_chars=4000
            )

        matched_filter = _match_exception_filter(last_state)
        if (
            _should_auto_continue_filtered_exception(last_state, matched_filter)
            and auto_continue_count < 64
            and time.time() < deadline
        ):
            auto_continue_count += 1
            skipped_filters.append(
                {
                    "code": matched_filter.get("matchedCode"),
                    "action": matched_filter.get("action"),
                    "firstChance": bool(matched_filter.get("exceptionFirstChance")),
                }
            )
            _log_event(
                "wait_for_pause_exception_filter_continue",
                code=matched_filter.get("matchedCode"),
                action=matched_filter.get("action"),
                firstChance=bool(matched_filter.get("exceptionFirstChance")),
                count=auto_continue_count,
            )
            requested_action = str(matched_filter.get("action") or "skip").lower()
            disposition = "pass" if requested_action == "pass" else "swallow"
            continuation = ContinueException(
                disposition=disposition,
                expected_event_seq=int(last_state.get("eventSeq") or since_seq or 0),
                resume=True,
            )
            skipped_filters[-1]["disposition"] = disposition
            skipped_filters[-1]["continuation"] = continuation
            if not continuation.get("ok"):
                last_state["exceptionContinuationError"] = continuation
                last_state["autoSkippedExceptions"] = skipped_filters
                return last_state
            continue

        if (
            last_state.get("state") in ("paused", "exited", "not_debugging")
            and not bool(last_state.get("timedOut"))
        ):
            last_state["timedOut"] = False
            if skipped_filters:
                last_state["autoSkippedExceptions"] = skipped_filters
            return last_state
        # A bridge wait is deliberately a short server-side slice so one client
        # cannot monopolize the single x64dbg command bridge. Keep polling until
        # the caller's overall deadline instead of treating one slice timeout as
        # the operation timeout.
        if isinstance(payload, dict) and last_state.get("timedOut"):
            if time.time() >= deadline:
                break
            time.sleep(max(poll_ms, 10) / 1000.0)
            continue
        time.sleep(max(poll_ms, 10) / 1000.0)
    last_state["timedOut"] = True
    last_state["timeoutMs"] = timeout_ms
    if skipped_filters:
        last_state["autoSkippedExceptions"] = skipped_filters
    _log_event(
        "wait_for_pause_timeout",
        timeoutMs=timeout_ms,
        lastState=last_state.get("state"),
    )
    return last_state


@mcp.tool()
def WaitForBreakpoint(
    addr: str = "", name: str = "", timeout_ms: int = 10000, poll_ms: int = 100
) -> dict:
    """
    Wait until a breakpoint is hit.

    Args:
        addr: Optional breakpoint address filter.
        name: Optional breakpoint name filter.
        timeout_ms: Maximum time to wait.
        poll_ms: Poll interval.
    """
    target_addr = _normalize_hex(addr) if addr else None
    since_seq = int(_get_runtime_value("lastResumeSeq", 0) or 0)
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    last_state: Dict[str, Any] = {}
    while time.time() <= deadline:
        remaining_ms = max(0, int((deadline - time.time()) * 1000))
        payload = _coerce_json_payload(
            safe_get(
                "Debug/WaitForBreakpointDetailed",
                {
                    "addr": addr,
                    "name": name,
                    "timeoutMs": min(max(remaining_ms, 50), 700),
                    "sinceSeq": since_seq,
                },
                log=False,
            )
        )
        last_state = _build_debug_state(
            include_console=True, include_callstack=True, max_console_chars=4000
        )
        if isinstance(payload, dict):
            session = (
                payload.get("state", {})
                if isinstance(payload.get("state"), dict)
                else {}
            )
            if session:
                observed_seq = int(session.get("eventSeq") or since_seq)
                since_seq = max(since_seq, observed_seq)
                _remember_runtime(lastSessionEventSeq=observed_seq)
            _remember_runtime(lastDetailedBreakpoint=payload)
            last_state.update(
                {
                    "timedOut": bool(payload.get("timedOut")),
                    "timeoutMs": timeout_ms,
                    "requestedAddr": target_addr,
                    "requestedName": name,
                    "waitInfo": payload,
                }
            )
            if not last_state["timedOut"]:
                return last_state
        elif last_state.get("state") in ("exited", "not_debugging"):
            last_state["timedOut"] = False
            return last_state
        time.sleep(max(poll_ms, 10) / 1000.0)
    last_state["timedOut"] = True
    last_state["timeoutMs"] = timeout_ms
    last_state["requestedAddr"] = target_addr
    last_state["requestedName"] = name
    _log_event(
        "wait_for_breakpoint_timeout",
        timeoutMs=timeout_ms,
        requestedAddr=target_addr,
        requestedName=name,
        lastState=last_state.get("state"),
    )
    return last_state


@mcp.tool()
def WaitForExit(timeout_ms: int = 10000, poll_ms: int = 100) -> dict:
    """
    Wait until the debuggee exits.
    """
    since_seq = int(_get_runtime_value("lastResumeSeq", 0) or 0)
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    last_state: Dict[str, Any] = {}
    tracked_pid = int(_get_runtime_value("lastDebuggeePid", 0) or 0)
    while time.time() <= deadline:
        remaining_ms = max(0, int((deadline - time.time()) * 1000))
        payload = _coerce_json_payload(
            safe_get(
                "Debug/WaitForExit",
                {
                    "timeoutMs": min(max(remaining_ms, 50), 700),
                    "sinceSeq": since_seq,
                },
                log=False,
            )
        )
        if isinstance(payload, dict):
            session = (
                payload.get("state", {})
                if isinstance(payload.get("state"), dict)
                else {}
            )
            if session:
                observed_seq = int(session.get("eventSeq") or since_seq)
                since_seq = max(since_seq, observed_seq)
                _remember_runtime(lastSessionEventSeq=observed_seq)
        last_state = _build_debug_state(
            include_console=False, include_callstack=False, max_console_chars=0
        )
        pid = int(last_state.get("debuggeePid") or tracked_pid or 0)
        if last_state.get("state") == "exited" or (pid and not _process_exists(pid)):
            last_state["timedOut"] = False
            last_state["state"] = "exited"
            last_state["exited"] = True
            return last_state
        if last_state.get("state") == "not_debugging" and not pid:
            last_state["timedOut"] = False
            last_state["exited"] = bool(last_state.get("exited"))
            return last_state
        if isinstance(payload, dict):
            compact_payload = dict(payload)
            inner_state = compact_payload.get("state")
            if isinstance(inner_state, dict) and "history" in inner_state:
                compact_payload["state"] = {
                    key: value
                    for key, value in inner_state.items()
                    if key != "history"
                }
            last_state["waitInfo"] = compact_payload
        time.sleep(max(poll_ms, 10) / 1000.0)
    last_state["timedOut"] = True
    last_state["timeoutMs"] = timeout_ms
    last_state["exited"] = bool(last_state.get("state") == "exited")
    _log_event(
        "wait_for_exit_timeout",
        timeoutMs=timeout_ms,
        trackedPid=tracked_pid,
        lastState=last_state.get("state"),
    )
    return last_state


@mcp.tool()
def AdvancePastStartupPause(
    timeout_ms: int = 4000, max_runs: int = 4, poll_ms: int = 100
) -> dict:
    """
    Resume through common loader/TLS/entry startup pauses until the target reaches a more useful stop.
    """
    try:
        result = _advance_past_startup_pause(
            timeout_ms=timeout_ms, max_runs=max_runs, poll_ms=poll_ms
        )
        _log_event(
            "advance_past_startup_pause",
            advanced=result.get("advanced"),
            runs=result.get("runs"),
            removedBreakpoints=result.get("removedBreakpoints"),
            endState=(
                (result.get("state") or {})
                if isinstance(result.get("state"), dict)
                else {}
            ).get("state"),
        )
        return {"ok": True, **result, "logPath": LOG_PATH}
    except Exception as e:
        _log_event("advance_past_startup_pause_error", error=str(e))
        return {"ok": False, "error": str(e), "logPath": LOG_PATH}


@mcp.tool()
def WaitForUserCode(
    module_name: str = "",
    timeout_ms: int = 10000,
    poll_ms: int = 100,
    max_runs: int = 12,
    skip_startup_exceptions: bool = True,
) -> dict:
    """
    Progress through startup noise until execution reaches a useful runtime state.

    By default the helper auto-skips common first-chance startup exceptions
    such as the initial loader breakpoint (`0x80000003`) and WOW64 startup
    notifications (`0x4000001F` / `0x4000001E`).
    """
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    iterations = 0
    auto_runs = 0
    removed_breakpoints: List[str] = []
    last_state = _build_debug_state(
        include_console=True, include_callstack=True, max_console_chars=4000
    )

    def _success_response(
        current_state: Dict[str, Any], current_readiness: Dict[str, Any]
    ) -> Dict[str, Any]:
        reached_user_code = current_readiness.get("reason") in (
            "paused_at_entrypoint",
            "paused_in_user_module",
        )
        interactive_ready = not reached_user_code
        hint = None
        if interactive_ready:
            hint = (
                "Execution appears interactive, but the debugger did not observe a "
                "stable pause inside user code."
            )
        return {
            "ok": True,
            "timedOut": False,
            "iterations": iterations,
            "autoRuns": auto_runs,
            "removedBreakpoints": removed_breakpoints,
            "state": current_state,
            "module": current_readiness.get("module"),
            "reason": current_readiness.get("reason"),
            "gui": current_readiness.get("gui"),
            "reachedUserCode": reached_user_code,
            "interactiveReady": interactive_ready,
            "hint": hint,
            "logPath": LOG_PATH,
        }

    while iterations < max(1, int(max_runs)) and time.time() <= deadline:
        iterations += 1
        readiness = _detect_useful_runtime_state(last_state, module_name=module_name)
        if readiness.get("ready"):
            if last_state.get("running") and readiness.get("reason") in (
                "waiting_for_input",
                "visible_window",
            ):
                try:
                    DebugPause()
                    remaining_ms = max(0, int((deadline - time.time()) * 1000))
                    if remaining_ms > 0:
                        stabilized = WaitForPause(
                            timeout_ms=min(remaining_ms, max(500, poll_ms * 6)),
                            poll_ms=max(50, min(poll_ms, 150)),
                        )
                        if isinstance(stabilized, dict):
                            last_state = stabilized
                            refreshed = _detect_useful_runtime_state(
                                last_state, module_name=module_name
                            )
                            if refreshed.get("ready"):
                                readiness = refreshed
                except Exception:
                    pass
            if last_state.get("running") and readiness.get("reason") not in (
                "paused_at_entrypoint",
                "paused_in_user_module",
            ):
                return {
                    "ok": False,
                    "timedOut": False,
                    "iterations": iterations,
                    "autoRuns": auto_runs,
                    "removedBreakpoints": removed_breakpoints,
                    "state": last_state,
                    "module": readiness.get("module"),
                    "reason": readiness.get("reason"),
                    "gui": readiness.get("gui"),
                    "reachedUserCode": False,
                    "interactiveReady": False,
                    "hint": (
                        "Detected an interactive runtime state, but execution is still "
                        "running. Call DebugPause, WaitForPause, or use RunToUserCode "
                        "for a strict paused stop."
                    ),
                    "logPath": LOG_PATH,
                }
            return _success_response(last_state, readiness)
        if last_state.get("state") in ("exited", "not_debugging"):
            break
        remaining_ms = max(0, int((deadline - time.time()) * 1000))
        if last_state.get("running") and remaining_ms <= max(1500, poll_ms * 8):
            stabilized_state, stabilized_readiness = _stabilize_user_code_wait_state(
                deadline=deadline,
                poll_ms=poll_ms,
                module_name=module_name,
                skip_startup_exceptions=skip_startup_exceptions,
            )
            if isinstance(stabilized_state, dict):
                last_state = stabilized_state
            if stabilized_readiness.get("ready"):
                return _success_response(last_state, stabilized_readiness)
        if last_state.get("paused"):
            bypass = _apply_common_antidebug_bypass(last_state)
            if bypass.get("handled"):
                removed_bp = _normalize_hex(bypass.get("removedBreakpoint"))
                if removed_bp and removed_bp not in removed_breakpoints:
                    removed_breakpoints.append(removed_bp)
                if time.time() >= deadline:
                    break
                DebugRun()
                auto_runs += 1
                remaining_ms = max(0, int((deadline - time.time()) * 1000))
                if remaining_ms <= 0:
                    break
                wait_state = WaitForPause(
                    timeout_ms=min(remaining_ms, max(300, poll_ms * 5)),
                    poll_ms=max(50, min(poll_ms, 150)),
                )
                last_state = (
                    wait_state
                    if isinstance(wait_state, dict)
                    else _build_debug_state(
                        include_console=True,
                        include_callstack=True,
                        max_console_chars=4000,
                    )
                )
                continue
            advanced = _advance_past_startup_pause(
                timeout_ms=max(250, min(int((deadline - time.time()) * 1000), 3000)),
                max_runs=2,
                poll_ms=max(50, min(poll_ms, 150)),
                skip_startup_exceptions=skip_startup_exceptions,
            )
            auto_runs += int(advanced.get("runs") or 0)
            for addr in list(advanced.get("removedBreakpoints") or []):
                if addr not in removed_breakpoints:
                    removed_breakpoints.append(addr)
            state_after = (
                advanced.get("state")
                if isinstance(advanced.get("state"), dict)
                else None
            )
            if isinstance(state_after, dict):
                last_state = state_after
                readiness = _detect_useful_runtime_state(
                    last_state, module_name=module_name
                )
                if readiness.get("ready"):
                    continue
                if last_state.get("paused") and not _is_startup_pause(last_state):
                    if (
                        skip_startup_exceptions
                        and _is_whitelisted_startup_exception(last_state)
                    ):
                        pass
                    else:
                        break
        if (
            last_state.get("paused")
            and skip_startup_exceptions
            and _is_whitelisted_startup_exception(last_state)
        ):
            if time.time() >= deadline:
                    break
        if time.time() >= deadline:
            break
        DebugRun()
        auto_runs += 1
        remaining_ms = max(0, int((deadline - time.time()) * 1000))
        if remaining_ms <= 0:
            break
        wait_state = WaitForPause(
            timeout_ms=min(remaining_ms, max(300, poll_ms * 5)),
            poll_ms=max(50, min(poll_ms, 150)),
        )
        if isinstance(wait_state, dict):
            last_state = wait_state
        else:
            last_state = _build_debug_state(
                include_console=True, include_callstack=True, max_console_chars=4000
            )
    if last_state.get("running"):
        stabilized_state, stabilized_readiness = _stabilize_user_code_wait_state(
            deadline=time.time() + max(0.6, min(1.2, poll_ms / 250.0)),
            poll_ms=poll_ms,
            module_name=module_name,
            skip_startup_exceptions=skip_startup_exceptions,
        )
        if isinstance(stabilized_state, dict):
            last_state = stabilized_state
        if stabilized_readiness.get("ready"):
            return _success_response(last_state, stabilized_readiness)
    final_hint = None
    session = last_state.get("session", {}) if isinstance(last_state.get("session"), dict) else {}
    if last_state.get("state") in ("exited", "not_debugging") or last_state.get("exited"):
        final_hint = "Debuggee exited before reaching user code."
    elif skip_startup_exceptions and _is_whitelisted_startup_exception(last_state):
        final_hint = (
            "Stopped on a whitelisted startup exception; try a longer timeout or "
            "inspect the current state manually."
        )
    elif (not skip_startup_exceptions) and _is_whitelisted_startup_exception(last_state):
        final_hint = (
            "Stopped on a common startup exception. Re-run with "
            "`skip_startup_exceptions=true` to auto-continue past it."
        )
    elif last_state.get("running"):
        final_hint = (
            "The debuggee is still running. Call DebugPause, WaitForPause, or use "
            "RunToUserCode for a strict user-code pause."
        )
    elif session.get("exceptionCode"):
        final_hint = f"Last exception: {session.get('exceptionCode')}"
    return {
        "ok": False,
        "timedOut": bool(time.time() > deadline),
        "iterations": iterations,
        "autoRuns": auto_runs,
        "removedBreakpoints": removed_breakpoints,
        "state": last_state,
        "module": _resolve_module_record_for_address(last_state.get("rip")),
        "reachedUserCode": False,
        "interactiveReady": False,
        "hint": final_hint,
        "logPath": LOG_PATH,
    }


@mcp.tool()
def ListChildProcesses(
    parent_pid: int = 0,
    include_descendants: bool = True,
    only_new: bool = False,
    exe_filter: str = "",
    visible_only: bool = True,
    include_console_hosts: bool = False,
) -> dict:
    """
    List child or descendant processes of the current debuggee/launch source and rank likely runtime candidates.
    """
    try:
        result = _list_child_process_candidates(
            parent_pid=parent_pid,
            include_descendants=include_descendants,
            only_new=only_new,
            exe_filter=exe_filter,
            visible_only=visible_only,
            include_console_hosts=include_console_hosts,
        )
        _log_event(
            "list_child_processes",
            parentPid=result.get("parentPid"),
            count=result.get("count"),
            includeDescendants=include_descendants,
            onlyNew=only_new,
            exeFilter=exe_filter,
            includeConsoleHosts=include_console_hosts,
        )
        result["logPath"] = LOG_PATH
        return result
    except Exception as e:
        _log_event("list_child_processes_error", parentPid=parent_pid, error=str(e))
        return {"ok": False, "error": str(e), "children": [], "logPath": LOG_PATH}


@mcp.tool()
def WaitForChildProcess(
    parent_pid: int = 0,
    exe_filter: str = "",
    timeout_ms: int = 10000,
    poll_ms: int = 100,
    include_descendants: bool = True,
    only_new: bool = True,
    require_window: bool = False,
    visible_only: bool = True,
    include_console_hosts: bool = False,
) -> dict:
    """
    Wait for a likely child/descendant runtime process to appear after launch or during debugging.
    """
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    last_result: Dict[str, Any] = {}
    while time.time() <= deadline:
        last_result = _list_child_process_candidates(
            parent_pid=parent_pid,
            include_descendants=include_descendants,
            only_new=only_new,
            exe_filter=exe_filter,
            visible_only=visible_only,
            include_console_hosts=include_console_hosts,
        )
        children = (
            list(last_result.get("children", []))
            if isinstance(last_result, dict)
            else []
        )
        if require_window:
            children = [item for item in children if item.get("hasWindow")]
        if children:
            chosen = children[0]
            _remember_runtime(lastChildProcessCandidate=chosen)
            _log_event(
                "wait_for_child_process_hit",
                parentPid=last_result.get("parentPid"),
                childPid=chosen.get("pid"),
                childExe=chosen.get("exe"),
                score=chosen.get("score"),
                requireWindow=require_window,
                includeConsoleHosts=include_console_hosts,
            )
            return {
                "ok": True,
                "timedOut": False,
                "parentPid": last_result.get("parentPid"),
                "candidate": chosen,
                "children": children,
                "count": len(children),
                "logPath": LOG_PATH,
            }
        time.sleep(max(20, int(poll_ms)) / 1000.0)
    _log_event(
        "wait_for_child_process_timeout",
        parentPid=(last_result or {}).get("parentPid"),
        exeFilter=exe_filter,
        requireWindow=require_window,
        onlyNew=only_new,
        includeConsoleHosts=include_console_hosts,
    )
    return {
        "ok": False,
        "timedOut": True,
        "parentPid": (last_result or {}).get("parentPid")
        if isinstance(last_result, dict)
        else 0,
        "children": list((last_result or {}).get("children", []))
        if isinstance(last_result, dict)
        else [],
        "count": int((last_result or {}).get("count", 0))
        if isinstance(last_result, dict)
        else 0,
        "logPath": LOG_PATH,
    }


@mcp.tool()
def ReadMemory(addr: str, size: int, ty: str = "bytes", max_chars: int = 1024) -> dict:
    """
    Read a memory range in a RE-friendly format.

    Args:
        addr: Address or expression such as `0x401000`, `module!func+0x10`, or `[rbp+0x20]`.
        size: Number of bytes to read.
        ty: One of `hex`, `bytes`, `ascii`, `utf8`, `utf16`, `u8`, `u16`, `u32`, `u64`.
        max_chars: Text decoding limit for ascii/utf8/utf16 views.
    """
    payload = _coerce_json_payload(
        safe_get(
            "Memory/ReadRange",
            {
                "addr": addr,
                "size": int(size),
                "format": ty,
                "maxChars": int(max_chars),
            },
            log=False,
        )
    )
    if isinstance(payload, dict):
        return payload
    return {
        "ok": False,
        "addr": addr,
        "sizeRequested": int(size),
        "format": ty,
        "error": str(payload),
    }


@mcp.tool()
def CaptureMemorySnapshot(ranges_json: str, label: str = "") -> dict:
    """
    Capture one or more memory ranges and store the snapshot in runtime history.
    """
    specs = _parse_capture_specs(ranges_json)
    if not specs:
        return {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "ranges_json must contain at least one valid range",
        }
    ranges: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    for index, spec in enumerate(specs):
        read = ReadMemory(
            addr=str(spec.get("expr") or ""),
            size=int(spec.get("size") or 0),
            ty=str(spec.get("format") or "hex"),
            max_chars=4096,
        )
        read["label"] = spec.get("label") or f"range{index}"
        read["expression"] = spec.get("expr")
        ranges.append(read)
        if not bool(read.get("ok")):
            failures.append(
                {
                    "index": index,
                    "label": read.get("label"),
                    "expression": read.get("expression"),
                    "error": read.get("error") or "Memory read failed",
                }
            )
    snapshot = _store_memory_snapshot(
        {
            "capturedAt": _now_iso(),
            "label": label,
            "ranges": ranges,
            "complete": not failures,
            "failures": failures,
        }
    )
    _log_event(
        "capture_memory_snapshot",
        snapshotId=snapshot.get("snapshotId"),
        label=label,
        rangeCount=len(ranges),
    )
    return {"ok": not failures, **snapshot}


@mcp.tool()
def GetMemorySnapshot(snapshot_id: str) -> dict:
    """
    Return a previously stored memory snapshot by id.
    """
    snapshot = _get_memory_snapshot(snapshot_id)
    if not snapshot:
        return {"ok": False, "snapshotId": snapshot_id, "error": "Snapshot not found"}
    return {"ok": True, **snapshot}


@mcp.tool()
def CompareMemorySnapshots(
    before_snapshot_id: str, after_snapshot_id: str, max_changes: int = 32
) -> dict:
    """
    Compare two stored memory snapshots and summarize changed bytes per range.
    """
    before = _get_memory_snapshot(before_snapshot_id)
    after = _get_memory_snapshot(after_snapshot_id)
    if not before or not after:
        return {
            "ok": False,
            "beforeSnapshotId": before_snapshot_id,
            "afterSnapshotId": after_snapshot_id,
            "error": "One or both snapshots were not found",
        }
    before_owner = before.get("owner") if isinstance(before.get("owner"), dict) else {}
    after_owner = after.get("owner") if isinstance(after.get("owner"), dict) else {}
    owner_keys = (
        "bridgeInstanceId",
        "sessionId",
        "sessionGeneration",
        "processId",
    )
    owner_mismatches = [
        key for key in owner_keys if before_owner.get(key) != after_owner.get(key)
    ]
    if owner_mismatches or not all(before_owner.get(key) for key in owner_keys):
        return {
            "ok": False,
            "beforeSnapshotId": before_snapshot_id,
            "afterSnapshotId": after_snapshot_id,
            "errorCode": "SNAPSHOT_OWNER_MISMATCH",
            "error": "Memory snapshots belong to different or unowned debug sessions.",
            "mismatches": owner_mismatches,
            "beforeOwner": before_owner,
            "afterOwner": after_owner,
        }
    if not before.get("complete", True) or not after.get("complete", True):
        return {
            "ok": False,
            "beforeSnapshotId": before_snapshot_id,
            "afterSnapshotId": after_snapshot_id,
            "errorCode": "INCOMPLETE_SNAPSHOT",
            "error": "One or both memory snapshots contain failed ranges.",
        }
    before_ranges = list(before.get("ranges", []))
    after_ranges = list(after.get("ranges", []))
    comparisons: List[Dict[str, Any]] = []
    for index, after_range in enumerate(after_ranges):
        before_range = before_ranges[index] if index < len(before_ranges) else {}
        comparison = _summarize_hex_changes(
            before_range.get("hex", ""),
            after_range.get("hex", ""),
            max_changes=max_changes,
        )
        comparison.update(
            {
                "label": after_range.get("label")
                or before_range.get("label")
                or f"range{index}",
                "expression": after_range.get("expression")
                or before_range.get("expression"),
                "beforeAddr": before_range.get("addr"),
                "afterAddr": after_range.get("addr"),
                "sizeRequested": after_range.get(
                    "sizeRequested", before_range.get("sizeRequested")
                ),
            }
        )
        comparisons.append(comparison)
    return {
        "ok": True,
        "beforeSnapshotId": before_snapshot_id,
        "afterSnapshotId": after_snapshot_id,
        "changedRanges": [item for item in comparisons if item.get("changed")],
        "rangeComparisons": comparisons,
    }


@mcp.tool()
def SaveState(
    label: str = "",
    ranges_json: str = "",
) -> dict:
    """
    Snapshot debuggee state: all GP registers + eflags + (optionally) memory ranges.

    Args:
        label: Optional human-readable label.
        ranges_json: Optional JSON array of `{label, expr, size}` memory ranges
            to capture. Typical use is `[{"label":"stack","expr":"esp","size":256}]`.
            Omit to snapshot only registers.

    Returns summary: {ok, snapshotId, label, registerCount, rangeCount, createdAt}.
    Use RestoreState(snapshotId) to revert, GetStateSnapshot(snapshotId) for full contents.
    """
    state = _build_debug_state(
        include_console=False, include_callstack=True, max_console_chars=0
    )
    if not state.get("debugging") or not state.get("paused"):
        return {
            "ok": False,
            "error": "SaveState requires a paused debuggee",
            "currentState": state.get("state"),
        }
    owner = _capture_snapshot_owner(require_thread=True)
    if not owner.get("strong"):
        return {
            "ok": False,
            "errorCode": "SESSION_IDENTITY_UNAVAILABLE",
            "error": "A strong Bridge/Hello session and thread identity is required to save restorable state.",
            "owner": owner,
        }
    regs = _read_snapshot_registers()
    ranges: List[Dict[str, Any]] = []
    range_failures: List[Dict[str, Any]] = []
    specs = _parse_capture_specs(ranges_json) if ranges_json else []
    for index, spec in enumerate(specs):
        read = ReadMemory(
            addr=str(spec.get("expr") or ""),
            size=int(spec.get("size") or 0),
            ty="hex",
            max_chars=4096,
        )
        if isinstance(read, dict) and read.get("ok"):
            ranges.append({
                "label": spec.get("label") or f"range{index}",
                "expr": spec.get("expr"),
                "addr": read.get("addr"),
                "size": read.get("sizeRead"),
                "hex": read.get("hex"),
            })
        else:
            range_failures.append(
                {
                    "index": index,
                    "label": spec.get("label") or f"range{index}",
                    "expr": spec.get("expr"),
                    "error": read.get("error") if isinstance(read, dict) else str(read),
                }
            )
    if range_failures:
        return {
            "ok": False,
            "errorCode": "SNAPSHOT_CAPTURE_FAILED",
            "error": "One or more requested state ranges could not be captured.",
            "failures": range_failures,
            "owner": owner,
        }
    record = _store_state_snapshot({
        "createdAt": _now_iso(),
        "label": str(label or ""),
        "registers": regs,
        "ranges": ranges,
        "owner": owner,
    })
    return {
        "ok": True,
        "snapshotId": record["snapshotId"],
        "label": record["label"],
        "registerCount": len(regs),
        "rangeCount": len(ranges),
        "createdAt": record["createdAt"],
        "owner": owner,
    }


def _mutation_lease_error(envelope: BridgeEnvelope, fallback: str) -> Dict[str, Any]:
    error = envelope.error
    return {
        "ok": False,
        "errorCode": error.code if error else "MUTATION_LEASE_FAILED",
        "error": error.message if error else fallback,
        "retryable": bool(error.retryable) if error else False,
        "details": dict(error.details) if error and error.details else {},
        "meta": dict(envelope.meta or {}),
    }


def _acquire_mutation_lease(ttl_ms: int = 60000) -> Dict[str, Any]:
    ttl = max(1000, min(int(ttl_ms), 120000))
    current_lease = _mutation_lease_snapshot()
    acquisition_nonce = str(current_lease.get("acquisitionNonce") or "")
    identity = _identity_for_guard()
    if (
        current_lease.get("sessionId")
        and str(current_lease.get("sessionId")) != str(identity.get("sessionId") or "")
    ):
        acquisition_nonce = ""
    if not acquisition_nonce:
        acquisition_nonce = secrets.token_hex(32)
    envelope = _bridge_request(
        "POST",
        "Debug/Mutation/Acquire",
        form_data={
            "ttlMs": str(ttl),
            "acquisitionNonce": acquisition_nonce,
        },
        guard="session",
        timeout_sec=5.0,
    )
    if not envelope.ok or not isinstance(envelope.data, dict):
        return _mutation_lease_error(envelope, "Mutation lease acquisition failed.")
    lease = envelope.data.get("lease")
    if not isinstance(lease, dict) or not str(lease.get("token") or ""):
        return {
            "ok": False,
            "errorCode": "INVALID_MUTATION_LEASE_RESPONSE",
            "error": "Bridge returned no mutation lease token.",
            "response": envelope.data,
            "meta": envelope.meta,
        }
    # The bridge intentionally never echoes the nonce.  Keep it only in this
    # process so a stolen lease token cannot be replayed without the binding
    # nonce, and use the same nonce across renew/release/guarded operations.
    lease = {**lease, "acquisitionNonce": acquisition_nonce}
    state = _set_mutation_lease_state(lease)
    return {"ok": True, "lease": {**lease, **state}, "meta": envelope.meta}


def _renew_mutation_lease(ttl_ms: int = 60000) -> Dict[str, Any]:
    ttl = max(1000, min(int(ttl_ms), 120000))
    if not _mutation_lease_snapshot().get("token"):
        return {
            "ok": False,
            "errorCode": "MUTATION_LEASE_NOT_HELD",
            "error": "This MCP client has no active mutation lease token.",
        }
    envelope = _bridge_request(
        "POST",
        "Debug/Mutation/Renew",
        form_data={
            "ttlMs": str(ttl),
            "acquisitionNonce": str(
                _mutation_lease_snapshot().get("acquisitionNonce") or ""
            ),
        },
        guard="session",
        timeout_sec=5.0,
    )
    if not envelope.ok or not isinstance(envelope.data, dict):
        return _mutation_lease_error(envelope, "Mutation lease renewal failed.")
    lease = envelope.data.get("lease")
    if not isinstance(lease, dict) or not str(lease.get("token") or ""):
        return {
            "ok": False,
            "errorCode": "INVALID_MUTATION_LEASE_RESPONSE",
            "error": "Bridge returned no renewed mutation lease token.",
            "response": envelope.data,
            "meta": envelope.meta,
        }
    lease = {
        **lease,
        "acquisitionNonce": str(
            _mutation_lease_snapshot().get("acquisitionNonce") or ""
        ),
    }
    state = _set_mutation_lease_state(lease)
    return {"ok": True, "lease": {**lease, **state}, "meta": envelope.meta}


def _release_mutation_lease() -> Dict[str, Any]:
    envelope = _bridge_request(
        "POST",
        "Debug/Mutation/Release",
        form_data={},
        guard="session",
        timeout_sec=5.0,
    )
    try:
        if not envelope.ok or not isinstance(envelope.data, dict):
            return _mutation_lease_error(envelope, "Mutation lease release failed.")
        lease = envelope.data.get("lease")
        return {
            "ok": True,
            "lease": dict(lease) if isinstance(lease, dict) else {},
            "meta": envelope.meta,
        }
    finally:
        # A failed release can only leave a server-side lease until its bounded
        # expiry. Never keep sending a locally stale token after that outcome.
        _clear_mutation_lease_state()


@mcp.tool()
def AcquireMutationLease(ttl_ms: int = 60000) -> Dict[str, Any]:
    """Acquire an exclusive, session-bound lease for a multi-request mutation.

    The lease is owned by this MCP client instance, expires automatically, and
    blocks other guarded mutations until release. ``ttl_ms`` is clamped to
    1,000..120,000 ms. Ordinary single mutations do not need a lease when none
    is active.
    """

    with _MUTATION_TRANSACTION_LOCK:
        return _acquire_mutation_lease(ttl_ms)


@mcp.tool()
def RenewMutationLease(ttl_ms: int = 60000) -> Dict[str, Any]:
    """Renew this MCP client's active session mutation lease."""

    with _MUTATION_TRANSACTION_LOCK:
        return _renew_mutation_lease(ttl_ms)


@mcp.tool()
def ReleaseMutationLease() -> Dict[str, Any]:
    """Release this MCP client's active session mutation lease idempotently."""

    with _MUTATION_TRANSACTION_LOCK:
        return _release_mutation_lease()


def _mutation_result_ok(result: Any) -> tuple[bool, str]:
    if isinstance(result, dict):
        if result.get("ok") is False or result.get("success") is False:
            error = result.get("error")
            if isinstance(error, dict):
                return False, str(error.get("message") or error)
            return False, str(error or result)
        return True, ""
    text = str(result or "").strip()
    lowered = text.casefold()
    if lowered.startswith(("error", "request failed")) or any(
        marker in lowered
        for marker in (
            "stale_session",
            "session identity",
            "guard required",
            "failed",
        )
    ):
        return False, text
    return True, ""


@mcp.tool()
def RestoreState(snapshot_id: str, restore_memory: bool = True) -> dict:
    """Lease-serialise and execute one complete state restore workflow."""
    with _MUTATION_TRANSACTION_LOCK:
        snapshot = _get_state_snapshot(snapshot_id)
        if not snapshot:
            return {"ok": False, "snapshotId": snapshot_id, "error": "Snapshot not found"}
        ownership = _snapshot_owner_match(
            snapshot.get("owner"), require_thread=True
        )
        if not ownership.get("matches"):
            return {
                "ok": False,
                "snapshotId": snapshot_id,
                "errorCode": "SNAPSHOT_OWNER_MISMATCH",
                "error": "Snapshot belongs to a different bridge, debug session, process, or thread.",
                "ownership": ownership,
            }
        owned_lease = False
        if not _mutation_lease_snapshot().get("token"):
            acquired = _acquire_mutation_lease(60000)
            if not acquired.get("ok"):
                return {
                    "ok": False,
                    "snapshotId": snapshot_id,
                    "errorCode": acquired.get("errorCode", "MUTATION_LEASE_FAILED"),
                    "error": acquired.get("error", "Could not acquire mutation lease."),
                    "lease": acquired,
                }
            owned_lease = True
        try:
            return _restore_state_impl(snapshot_id, restore_memory)
        finally:
            if owned_lease:
                _release_mutation_lease()


def _restore_state_impl(snapshot_id: str, restore_memory: bool = True) -> dict:
    """
    Revert debuggee registers (and optionally memory) to a saved state snapshot.

    Must be called while the debuggee is paused. Returns {ok, restored: {registers, ranges}}.
    """
    snapshot = _get_state_snapshot(snapshot_id)
    if not snapshot:
        return {"ok": False, "snapshotId": snapshot_id, "error": "Snapshot not found"}
    ownership = _snapshot_owner_match(snapshot.get("owner"), require_thread=True)
    if not ownership.get("matches"):
        return {
            "ok": False,
            "snapshotId": snapshot_id,
            "errorCode": "SNAPSHOT_OWNER_MISMATCH",
            "error": "Snapshot belongs to a different bridge, debug session, process, or thread.",
            "ownership": ownership,
        }
    state = _build_debug_state(include_console=False, include_callstack=False, max_console_chars=0)
    if not state.get("paused"):
        return {
            "ok": False,
            "snapshotId": snapshot_id,
            "error": "Debuggee must be paused to restore state",
            "currentState": state.get("state"),
        }
    restored_ranges: List[str] = []
    failed_ranges: List[Dict[str, Any]] = []
    prepared_ranges: List[Dict[str, Any]] = []
    transaction_steps: List[Dict[str, Any]] = []
    if restore_memory:
        for item in snapshot.get("ranges", []):
            addr = item.get("addr") or item.get("expr")
            data = re.sub(r"\s+", "", str(item.get("hex") or ""))
            if not addr or not data:
                failed_ranges.append(
                    {"label": item.get("label"), "error": "Range has no address/data"}
                )
                continue
            if len(data) % 2 or re.fullmatch(r"[0-9A-Fa-f]+", data) is None:
                failed_ranges.append(
                    {"label": item.get("label"), "error": "Range contains invalid hex"}
                )
                continue
            prepared_ranges.append({**item, "resolvedAddr": str(addr), "hex": data})
    if failed_ranges:
        return {
            "ok": False,
            "snapshotId": snapshot_id,
            "errorCode": "INVALID_SNAPSHOT",
            "error": "Snapshot memory ranges failed preflight validation.",
            "failed": {"registers": [], "ranges": failed_ranges},
        }

    # Capture the live state before the first write.  If a later range or
    # register fails, these values are used for a reverse-order compensation
    # pass while the same mutation lease is still held.
    compensation_ranges: List[Dict[str, Any]] = []
    for item in prepared_ranges:
        addr = item["resolvedAddr"]
        size = len(item["hex"]) // 2
        live = ReadMemory(addr=addr, size=size, ty="hex", max_chars=0)
        live_hex = re.sub(r"\s+", "", str((live or {}).get("hex") or ""))
        if (
            not isinstance(live, dict)
            or not live.get("ok")
            or len(live_hex) != size * 2
        ):
            return {
                "ok": False,
                "snapshotId": snapshot_id,
                "errorCode": "RESTORE_PREFLIGHT_FAILED",
                "error": "Could not capture current bytes before restore.",
                "failed": {"registers": [], "ranges": [{
                    "label": item.get("label") or addr,
                    "error": "Live pre-state read failed",
                }]},
            }
        compensation_ranges.append({"addr": addr, "hex": live_hex})

    registers = dict(snapshot.get("registers") or {})
    compensation_registers: Dict[str, Any] = {}
    for name in registers:
        live_register = RegisterGet(name)
        if isinstance(live_register, dict):
            live_value = live_register.get("value", live_register.get("result"))
            live_ok = live_register.get("ok", True) is not False
        else:
            live_value = live_register
            live_ok = not _is_register_error(live_register)
        live_text = str(live_value or "").strip()
        if (
            not live_ok
            or re.fullmatch(r"0[xX][0-9A-Fa-f]+", live_text) is None
        ):
            return {
                "ok": False,
                "snapshotId": snapshot_id,
                "errorCode": "RESTORE_PREFLIGHT_FAILED",
                "error": f"Could not capture current register {name}.",
                "failed": {"registers": [{"register": name}], "ranges": []},
            }
        compensation_registers[name] = live_text

    # Memory first, control registers last.  The target remains paused and every
    # individual mutation carries the same atomic session guard headers.
    for item in prepared_ranges:
        addr = item["resolvedAddr"]
        data = item["hex"]
        label = item.get("label") or addr
        try:
            write_result = MemoryWrite(addr, data)
            write_ok, write_error = _mutation_result_ok(write_result)
            if not write_ok:
                failed_ranges.append({"label": label, "error": write_error})
                transaction_steps.append({
                    "kind": "range",
                    "label": str(label),
                    "status": "failed",
                    "error": write_error,
                })
                break
            verify = ReadMemory(addr=addr, size=len(data) // 2, ty="hex", max_chars=0)
            observed = re.sub(r"\s+", "", str((verify or {}).get("hex") or ""))
            if not isinstance(verify, dict) or not verify.get("ok") or observed.casefold() != data.casefold():
                failed_ranges.append(
                    {
                        "label": label,
                        "error": "Memory read-back verification failed",
                        "expected": data,
                        "observed": observed,
                    }
                )
                transaction_steps.append({
                    "kind": "range",
                    "label": str(label),
                    "status": "failed",
                    "error": "readback_failed",
                })
                break
            restored_ranges.append(str(label))
            transaction_steps.append({
                "kind": "range",
                "label": str(label),
                "status": "verified",
            })
        except Exception as exc:
            failed_ranges.append({"label": label, "error": str(exc)})
            transaction_steps.append({
                "kind": "range",
                "label": str(label),
                "status": "failed",
                "error": str(exc),
            })
            break

    restored_regs: List[str] = []
    failed_regs: List[Dict[str, Any]] = []
    control_names = {"eip", "rip", "cip", "esp", "rsp", "csp", "eflags"}
    ordered_registers = sorted(
        registers.items(), key=lambda item: (item[0].casefold() in control_names, item[0])
    )
    if not failed_ranges:
        for name, value in ordered_registers:
            try:
                set_result = RegisterSet(name, value)
                set_ok, set_error = _mutation_result_ok(set_result)
                if not set_ok:
                    failed_regs.append({"register": name, "error": set_error})
                    transaction_steps.append({
                        "kind": "register",
                        "register": name,
                        "status": "failed",
                        "error": set_error,
                    })
                    break
                observed = RegisterGet(name)
                expected_int = _parse_int(value, None)
                observed_int = _parse_int(
                    observed.get("value", observed.get("result"))
                    if isinstance(observed, dict)
                    else observed,
                    None,
                )
                if expected_int is not None and observed_int != expected_int:
                    failed_regs.append(
                        {
                            "register": name,
                            "error": "Register read-back verification failed",
                            "expected": value,
                            "observed": observed,
                        }
                    )
                    transaction_steps.append({
                        "kind": "register",
                        "register": name,
                        "status": "failed",
                        "error": "readback_failed",
                    })
                    break
                restored_regs.append(name)
                transaction_steps.append({
                    "kind": "register",
                    "register": name,
                    "status": "verified",
                })
            except Exception as exc:
                failed_regs.append({"register": name, "error": str(exc)})
                transaction_steps.append({
                    "kind": "register",
                    "register": name,
                    "status": "failed",
                    "error": str(exc),
                })
                break
    compensation = {
        "attempted": bool(failed_ranges or failed_regs),
        "ranges": [],
        "registers": [],
    }
    if compensation["attempted"]:
        for item in reversed(compensation_ranges):
            try:
                outcome = MemoryWrite(item["addr"], item["hex"])
                ok, _ = _mutation_result_ok(outcome)
                compensation["ranges"].append({
                    "addr": item["addr"],
                    "ok": ok,
                })
                transaction_steps.append({
                    "kind": "compensation_range",
                    "addr": item["addr"],
                    "status": "rolled_back" if ok else "rollback_failed",
                })
            except Exception as exc:
                compensation["ranges"].append({
                    "addr": item["addr"],
                    "ok": False,
                    "error": str(exc),
                })
                transaction_steps.append({
                    "kind": "compensation_range",
                    "addr": item["addr"],
                    "status": "rollback_failed",
                    "error": str(exc),
                })
        for name, value in reversed(list(compensation_registers.items())):
            try:
                outcome = RegisterSet(name, value)
                ok, _ = _mutation_result_ok(outcome)
                compensation["registers"].append({
                    "register": name,
                    "ok": ok,
                })
                transaction_steps.append({
                    "kind": "compensation_register",
                    "register": name,
                    "status": "rolled_back" if ok else "rollback_failed",
                })
            except Exception as exc:
                compensation["registers"].append({
                    "register": name,
                    "ok": False,
                    "error": str(exc),
                })
                transaction_steps.append({
                    "kind": "compensation_register",
                    "register": name,
                    "status": "rollback_failed",
                    "error": str(exc),
                })
    compensation_ok = all(
        bool(item.get("ok"))
        for group in (compensation["ranges"], compensation["registers"])
        for item in group
    )
    if not failed_regs and not failed_ranges:
        transaction_state = "committed"
    elif compensation_ok:
        transaction_state = "rolled_back"
    else:
        transaction_state = "rollback_failed"
    _log_event(
        "restore_state",
        snapshotId=snapshot_id,
        registers=len(restored_regs),
        ranges=len(restored_ranges),
    )
    return {
        "ok": not failed_regs and not failed_ranges,
        "snapshotId": snapshot_id,
        "restored": {
            "registers": restored_regs,
            "ranges": restored_ranges,
        },
        "failed": {
            "registers": failed_regs,
            "ranges": failed_ranges,
        },
        "verified": not failed_regs and not failed_ranges,
        "transactionState": transaction_state,
        "steps": transaction_steps,
        "ownership": ownership,
        "compensation": compensation,
    }


@mcp.tool()
def GetStateSnapshot(snapshot_id: str) -> dict:
    """
    Return full contents of a state snapshot (registers + memory ranges).
    """
    snapshot = _get_state_snapshot(snapshot_id)
    if not snapshot:
        return {"ok": False, "snapshotId": snapshot_id, "error": "Snapshot not found"}
    return {"ok": True, **snapshot}


@mcp.tool()
def ListStateSnapshots(limit: int = 20) -> dict:
    """
    List saved state snapshots (most recent first).
    """
    with _RUNTIME_LOCK:
        order = list(_RUNTIME_STATE.get("stateSnapshotOrder", []))
        snapshots = dict(_RUNTIME_STATE.get("stateSnapshots", {}))
    items = []
    for sid in reversed(order[-max(1, int(limit)):]):
        snap = snapshots.get(sid, {})
        ownership = _snapshot_owner_match(snap.get("owner"), require_thread=True)
        items.append({
            "snapshotId": sid,
            "label": snap.get("label", ""),
            "createdAt": snap.get("createdAt"),
            "registerCount": len(snap.get("registers") or {}),
            "rangeCount": len(snap.get("ranges") or []),
            "owner": snap.get("owner"),
            "stale": not ownership.get("matches"),
            "ownerMismatches": ownership.get("mismatches"),
        })
    return {"ok": True, "count": len(items), "snapshots": items}


@mcp.tool()
def DeleteStateSnapshot(snapshot_id: str) -> dict:
    """
    Delete a saved state snapshot.
    """
    removed = _delete_state_snapshot(snapshot_id)
    return {"ok": removed, "snapshotId": snapshot_id, "deleted": removed}


@mcp.tool()
def SetConditionalBreakpoint(
    addr: str,
    condition: str = "",
    log_text: str = "",
    command: str = "",
    name: str = "",
    singleshot: bool = False,
) -> dict:
    """
    Set a breakpoint with a condition / log text / command hook.

    Args:
        addr: Breakpoint address.
        condition: Expression evaluated each hit. Example "rax==0xDEAD" — BP only
            fires when the condition is true. Leave empty for always-fire.
        log_text: Optional log template printed on hit (uses x64dbg {expr} syntax,
            e.g. "rax={rax}, [rsp+8]={[rsp+8]}"). Useful as tracepoint.
        command: Optional x64dbg command run on hit (e.g. "DebugRun" to auto-continue).
        name: Optional BP name.
        singleshot: If true, BP is removed after first hit.

    Returns {ok, addr, condition, logText, setResult}.
    """
    state = _build_debug_state(include_console=False, include_callstack=False, max_console_chars=0)
    if not state.get("debugging"):
        return {"ok": False, "error": "SetConditionalBreakpoint requires an active debug session"}
    addr_norm = _normalize_hex(addr) or str(addr)
    set_result = DebugSetBreakpoint(addr_norm)
    actions: List[Dict[str, Any]] = [{"step": "set", "result": set_result}]
    # Detect failure of the primary BP set. x64dbg returns str "Breakpoint set
    # successfully" on success; anything containing "Error" / "Fail" is a miss.
    set_result_str = (
        str(set_result.get("result") if isinstance(set_result, dict) else set_result) or ""
    )
    set_ok = "success" in set_result_str.lower() and "error" not in set_result_str.lower()
    if not set_ok:
        return {
            "ok": False,
            "addr": addr_norm,
            "error": f"Failed to set breakpoint: {set_result_str}",
            "hint": "Breakpoint may already exist at that address, or address is invalid. Use DebugDeleteBreakpoint first, or check GetBreakpointList.",
            "actions": actions,
        }
    config_failures: List[str] = []
    def _check(step_name: str, res: Any) -> None:
        if isinstance(res, dict) and res.get("success") is False:
            config_failures.append(step_name)
    if condition:
        r = ExecCommand(f"SetBreakpointCondition {addr_norm}, \"{condition}\"")
        actions.append({"step": "condition", "result": r})
        _check("condition", r)
    if log_text:
        r = ExecCommand(f"SetBreakpointLog {addr_norm}, \"{log_text}\"")
        actions.append({"step": "logText", "result": r})
        _check("logText", r)
    if command:
        r = ExecCommand(f"SetBreakpointCommand {addr_norm}, \"{command}\"")
        actions.append({"step": "command", "result": r})
        _check("command", r)
        r2 = ExecCommand(f"SetBreakpointCommandCondition {addr_norm}, \"1\"")
        actions.append({"step": "commandEnable", "result": r2})
        _check("commandEnable", r2)
    if name:
        r = ExecCommand(f"SetBreakpointName {addr_norm}, \"{name}\"")
        actions.append({"step": "name", "result": r})
        _check("name", r)
    if singleshot:
        r = ExecCommand(f"SetBreakpointSingleshoot {addr_norm}, 1")
        actions.append({"step": "singleshot", "result": r})
        _check("singleshot", r)
    return {
        "ok": not config_failures,
        "addr": addr_norm,
        "condition": condition,
        "logText": log_text,
        "command": command,
        "configFailures": config_failures if config_failures else None,
        "actions": actions,
    }


@mcp.tool()
def WatchMemoryChanges(
    ranges_json: str,
    step_kind: str = "over",
    steps: int = 1,
    max_changes: int = 32,
) -> dict:
    """
    Capture memory before and after one or more debugger steps and summarize byte-level changes.
    """
    before = CaptureMemorySnapshot(ranges_json=ranges_json, label="before")
    step_results: List[Dict[str, Any]] = []
    for _ in range(max(1, int(steps))):
        step_kind_lower = str(step_kind or "over").strip().lower()
        if step_kind_lower == "in":
            step_result = DebugStepIn()
        elif step_kind_lower == "out":
            step_result = DebugStepOut()
        else:
            step_kind_lower = "over"
            step_result = DebugStepOver()
        wait_state = WaitForPause(timeout_ms=3000, poll_ms=50)
        step_results.append(
            {
                "stepKind": step_kind_lower,
                "stepResult": step_result,
                "waitState": wait_state,
            }
        )
    after = CaptureMemorySnapshot(ranges_json=ranges_json, label="after")
    diff = CompareMemorySnapshots(
        str(before.get("snapshotId")),
        str(after.get("snapshotId")),
        max_changes=max_changes,
    )
    _log_event(
        "watch_memory_changes",
        beforeSnapshotId=before.get("snapshotId"),
        afterSnapshotId=after.get("snapshotId"),
        changedRangeCount=len(diff.get("changedRanges", [])),
        steps=len(step_results),
    )
    return {
        "ok": bool(before.get("ok")) and bool(after.get("ok")) and bool(diff.get("ok")),
        "before": before,
        "after": after,
        "diff": diff,
        "steps": step_results,
    }


@mcp.tool()
def EvalBatch(expressions_json: str) -> dict:
    """
    Evaluate a batch of expressions.

    Args:
        expressions_json: JSON array or newline/comma-separated expressions.
    """
    payload = _coerce_json_payload(
        safe_post(
            "Eval/Batch",
            {"expressions": _encode_expression_payload(expressions_json)},
            log=False,
        )
    )
    if isinstance(payload, dict):
        return payload
    return {"ok": False, "error": str(payload), "items": []}


@mcp.tool()
def CaptureContext(
    registers_json: str = "",
    expressions_json: str = "",
    ranges_json: str = "",
    stack_slots_json: str = "",
) -> dict:
    """
    Capture registers, expressions, memory ranges, and stack slots in one call.

    Args:
        registers_json: JSON array or comma/newline-separated register names.
        expressions_json: JSON array or newline-separated expressions.
        ranges_json: JSON array of `{label, expr, size, format}` specs.
        stack_slots_json: JSON array of `{label, expr, size, format}` specs.
    """
    payload = _coerce_json_payload(
        safe_post(
            "Context/Capture",
            {
                "registers": ",".join(_normalize_name_items(registers_json)),
                "expressions": _encode_expression_payload(expressions_json),
                "ranges": _encode_capture_specs(ranges_json),
                "stackSlots": _encode_capture_specs(stack_slots_json),
            },
            log=False,
        )
    )
    if isinstance(payload, dict):
        return payload
    return {"ok": False, "error": str(payload)}


@mcp.tool()
def ReadFrame(
    base_expr: str = "",
    slots_json: str = "",
    expressions_json: str = "",
    ranges_json: str = "",
    registers_json: str = "",
) -> dict:
    """
    Snapshot the current frame.

    Args:
        base_expr: Frame base expression, usually `rbp`/`ebp`.
        slots_json: JSON array of `{label, expr, size, format}` stack slot specs.
        expressions_json: Extra expressions to evaluate.
        ranges_json: Extra memory ranges to read.
        registers_json: Optional register names to include.
    """
    payload = _coerce_json_payload(
        safe_post(
            "Frame/Snapshot",
            {
                "baseExpr": base_expr,
                "slots": _encode_capture_specs(slots_json),
                "expressions": _encode_expression_payload(expressions_json),
                "ranges": _encode_capture_specs(ranges_json),
                "registers": ",".join(_normalize_name_items(registers_json)),
            },
            log=False,
        )
    )
    if isinstance(payload, dict):
        return payload
    return {"ok": False, "error": str(payload)}


@mcp.tool()
def WaitForBreakpointDetailed(
    addr: str = "", name: str = "", timeout_ms: int = 10000, poll_ms: int = 100
) -> dict:
    """
    Wait for a breakpoint and return the normalized event structure.
    """
    del poll_ms
    since_seq = int(_get_runtime_value("lastResumeSeq", 0) or 0)
    payload = _coerce_json_payload(
        safe_get(
            "Debug/WaitForBreakpointDetailed",
            {
                "addr": addr,
                "name": name,
                "timeoutMs": timeout_ms,
                "sinceSeq": since_seq,
            },
            log=False,
        )
    )
    if isinstance(payload, dict):
        session = (
            payload.get("state", {}) if isinstance(payload.get("state"), dict) else {}
        )
        if session:
            _remember_runtime(lastSessionEventSeq=int(session.get("eventSeq") or 0))
        _remember_runtime(lastDetailedBreakpoint=payload)
        return payload
    return {
        "hit": False,
        "timedOut": True,
        "timeoutMs": timeout_ms,
        "requestedAddr": addr,
        "requestedName": name,
        "error": str(payload),
    }


def _record_breakpoint_capture(
    event: Dict[str, Any],
    capture: Dict[str, Any],
    requested_addr: str = "",
    requested_name: str = "",
    capture_kind: str = "breakpoint",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    instruction = _current_instruction(event.get("rip"))
    entry = {
        "capturedAt": _now_iso(),
        "captureKind": capture_kind,
        "eventSeq": event.get("eventSeq"),
        "addr": event.get("addr"),
        "rip": event.get("rip"),
        "threadId": event.get("threadId"),
        "stopReason": event.get("stopReason"),
        "breakpointName": event.get("breakpointName"),
        "breakpointModule": event.get("breakpointModule"),
        "requestedAddr": requested_addr,
        "requestedName": requested_name,
        "capture": capture,
        "instruction": instruction,
    }
    if isinstance(extra, dict):
        entry.update(extra)
    _append_breakpoint_capture_history(entry)
    _log_event(
        "breakpoint_capture",
        eventSeq=entry.get("eventSeq"),
        addr=entry.get("addr"),
        rip=entry.get("rip"),
        captureKind=capture_kind,
        breakpointName=entry.get("breakpointName"),
        breakpointModule=entry.get("breakpointModule"),
        requestedAddr=requested_addr,
        requestedName=requested_name,
    )
    return entry


def _is_system_noise_breakpoint(event: Dict[str, Any]) -> bool:
    """Return True only for BPs we are confident are OS/loader noise, not user BPs.

    A foreign BP hit inside the debuggee module is almost always a user-set
    breakpoint (entry point, previously-set check) — resuming past it silently
    destroys the investigation. Only system DLL callbacks are safe to skip.
    """
    module = str(event.get("breakpointModule") or "").lower()
    name = str(event.get("breakpointName") or "").lower()
    debuggee = str(_get_current_debuggee_image_name() or "").lower()
    if "tls callback" in name:
        return True
    if module and debuggee and module == debuggee:
        return False
    if module in ("", debuggee):
        return False
    system_modules = (
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
        "gdi32.dll", "gdi32full.dll", "ucrtbase.dll", "win32u.dll",
        "msvcrt.dll", "vcruntime140.dll", "vcruntime140d.dll",
    )
    return any(module == m for m in system_modules)


def _is_delayed_pause_for_skipped_breakpoint(
    event: Dict[str, Any], skipped: Dict[str, Any]
) -> bool:
    """Recognize x86's delayed CB_PAUSEDEBUG after a skipped loader BP.

    Some x86 plugin callback sequences deliver the pause callback for a system
    breakpoint after the client has already submitted ``run``.  The target then
    remains paused with the same breakpoint metadata but stopReason ``pause``.
    Only this exact, causally-linked sequence is safe to resume automatically.
    """

    state = event.get("state") if isinstance(event.get("state"), dict) else {}
    return bool(
        skipped
        and event.get("timedOut")
        and state.get("paused")
        and str(event.get("lastEventType") or "").casefold() == "pause_debug"
        and str(event.get("stopReason") or "").casefold() == "pause"
        and str(event.get("breakpointName") or "").casefold()
        == str(skipped.get("name") or "").casefold()
        and str(event.get("breakpointModule") or "").casefold()
        == str(skipped.get("module") or "").casefold()
        and int(event.get("eventSeq") or 0) > int(skipped.get("eventSeq") or 0)
    )


def _is_safe_startup_breakpoint_exception(event: Dict[str, Any]) -> bool:
    """Identify only the first-chance OS loader breakpoint before user code.

    On x86, x64dbg can expose the initial ``INT3`` as an exception event
    instead of a named breakpoint. A waiter for a user breakpoint would then
    remain parked on that event until its deadline. Limit automatic
    continuation to first-chance 0x80000003 events in known system modules so
    an application's deliberate anti-debug breakpoint is never swallowed.
    """

    state = event.get("state") if isinstance(event.get("state"), dict) else {}
    stop_reason = str(
        event.get("stopReason") or state.get("stopReason") or ""
    ).casefold()
    code = str(
        state.get("exceptionCode") or event.get("exceptionCode") or ""
    ).casefold()
    first_chance = state.get(
        "exceptionFirstChance", event.get("exceptionFirstChance")
    )
    if (
        stop_reason != "exception"
        or code not in {"0x80000003", "80000003"}
        or first_chance is not True
    ):
        return False
    module = _resolve_module_record_for_address(
        event.get("rip") or state.get("ip") or state.get("address")
    ) or {}
    module_name = str(module.get("name") or "").casefold()
    debuggee = str(_get_current_debuggee_image_name() or "").casefold()
    return bool(
        module_name
        and module_name != debuggee
        and module_name in {"ntdll.dll", "kernel32.dll", "kernelbase.dll"}
    )


def _continue_safe_startup_breakpoint(event: Dict[str, Any]) -> Dict[str, Any]:
    state = event.get("state") if isinstance(event.get("state"), dict) else {}
    event_seq = int(
        event.get("eventSeq")
        or state.get("exceptionEventSeq")
        or state.get("eventSeq")
        or 0
    )
    return ContinueException(
        disposition="handled",
        expected_event_seq=event_seq,
        resume=True,
    )


@mcp.tool()
def WaitForBreakpointCapture(
    addr: str = "",
    name: str = "",
    registers_json: str = "",
    expressions_json: str = "",
    ranges_json: str = "",
    stack_slots_json: str = "",
    timeout_ms: int = 10000,
    poll_ms: int = 100,
    ignore_foreign_breakpoints: bool = True,
    max_skip_breakpoints: int = 8,
    detail: str = "",
) -> dict:
    """
    Wait for a breakpoint hit and capture structured context immediately after the stop.
    """
    detail_level, detail_error = _resolve_response_detail(detail)
    if detail_error:
        return detail_error
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    skips = 0
    event: Dict[str, Any] = {}
    result: Dict[str, Any] = {
        "ok": False,
        "event": event,
        "skippedBreakpoints": [],
        "skippedExceptions": [],
        "resumeRepairs": [],
    }
    while True:
        remaining_ms = max(0, int((deadline - time.time()) * 1000))
        event = WaitForBreakpointDetailed(
            addr=addr, name=name, timeout_ms=remaining_ms, poll_ms=poll_ms
        )
        matched_requested = bool(event.get("matchedRequested", event.get("hit")))
        observed_breakpoint = bool(event.get("observedBreakpoint")) or (
            str(event.get("stopReason") or "").lower() == "breakpoint"
            and event.get("addr")
        )
        if matched_requested and not bool(event.get("timedOut")):
            break
        if (
            ignore_foreign_breakpoints
            and _is_safe_startup_breakpoint_exception(event)
            and remaining_ms > 0
            and skips < max(0, int(max_skip_breakpoints))
        ):
            continuation = _continue_safe_startup_breakpoint(event)
            result["skippedExceptions"].append(
                {
                    "rip": event.get("rip"),
                    "exceptionCode": (
                        (event.get("state") or {}).get("exceptionCode")
                        if isinstance(event.get("state"), dict)
                        else None
                    ),
                    "eventSeq": event.get("eventSeq"),
                    "continuation": continuation,
                }
            )
            if not continuation.get("ok"):
                break
            skips += 1
            continue
        # The native bridge deliberately caps one blocking wait to a short
        # slice. A slice timeout is not the caller's overall timeout.
        if bool(event.get("timedOut")) and remaining_ms > 0:
            skipped = result["skippedBreakpoints"][-1] if result["skippedBreakpoints"] else {}
            if (
                len(result["resumeRepairs"]) < len(result["skippedBreakpoints"])
                and _is_delayed_pause_for_skipped_breakpoint(event, skipped)
            ):
                result["resumeRepairs"].append(
                    {
                        "eventSeq": event.get("eventSeq"),
                        "skippedEventSeq": skipped.get("eventSeq"),
                    }
                )
                DebugRun()
            continue
        if (
            ignore_foreign_breakpoints
            and observed_breakpoint
            and not matched_requested
            and _is_system_noise_breakpoint(event)
            and remaining_ms > 0
            and skips < max(0, int(max_skip_breakpoints))
        ):
            result["skippedBreakpoints"].append(
                {
                    "addr": event.get("addr"),
                    "rip": event.get("rip"),
                    "name": event.get("breakpointName"),
                    "module": event.get("breakpointModule"),
                    "eventSeq": event.get("eventSeq"),
                }
            )
            skips += 1
            DebugRun()
            continue
        break
    result["event"] = event
    hit = bool(event.get("matchedRequested", event.get("hit"))) and not bool(
        event.get("timedOut")
    )
    result["ok"] = hit
    if hit:
        capture = CaptureContext(
            registers_json=registers_json,
            expressions_json=expressions_json,
            ranges_json=ranges_json,
            stack_slots_json=stack_slots_json,
        )
        result["capture"] = capture
        result["historyEntry"] = _record_breakpoint_capture(
            event, capture, requested_addr=addr, requested_name=name
        )
    return (
        _compact_breakpoint_capture_result(result)
        if detail_level == "summary"
        else result
    )


@mcp.tool()
def SetBreakpointWithCapture(
    addr: str,
    registers_json: str = "",
    expressions_json: str = "",
    ranges_json: str = "",
    stack_slots_json: str = "",
    timeout_ms: int = 10000,
    delete_after_hit: bool = False,
    resume: bool = False,
    ignore_foreign_breakpoints: bool = True,
    max_skip_breakpoints: int = 8,
) -> dict:
    """
    Set a breakpoint, wait for it to hit, and capture structured context.
    """
    set_result = DebugSetBreakpoint(addr)
    result: Dict[str, Any] = {
        "setResult": set_result,
        "addr": addr,
        "skippedBreakpoints": [],
        "skippedExceptions": [],
        "resumeRepairs": [],
    }
    if resume:
        result["runResult"] = DebugRun()
    deadline = time.time() + (max(timeout_ms, 0) / 1000.0)
    event: Dict[str, Any] = {}
    skips = 0
    while True:
        remaining_ms = max(0, int((deadline - time.time()) * 1000))
        event = WaitForBreakpointDetailed(addr=addr, timeout_ms=remaining_ms)
        matched_requested = bool(event.get("matchedRequested", event.get("hit")))
        observed_breakpoint = bool(event.get("observedBreakpoint")) or (
            str(event.get("stopReason") or "").lower() == "breakpoint"
            and event.get("addr")
        )
        if matched_requested and not bool(event.get("timedOut")):
            break
        if (
            ignore_foreign_breakpoints
            and _is_safe_startup_breakpoint_exception(event)
            and remaining_ms > 0
            and skips < max(0, int(max_skip_breakpoints))
        ):
            continuation = _continue_safe_startup_breakpoint(event)
            result["skippedExceptions"].append(
                {
                    "rip": event.get("rip"),
                    "exceptionCode": (
                        (event.get("state") or {}).get("exceptionCode")
                        if isinstance(event.get("state"), dict)
                        else None
                    ),
                    "eventSeq": event.get("eventSeq"),
                    "continuation": continuation,
                }
            )
            if not continuation.get("ok"):
                break
            skips += 1
            continue
        if bool(event.get("timedOut")) and remaining_ms > 0:
            skipped = result["skippedBreakpoints"][-1] if result["skippedBreakpoints"] else {}
            if (
                len(result["resumeRepairs"]) < len(result["skippedBreakpoints"])
                and _is_delayed_pause_for_skipped_breakpoint(event, skipped)
            ):
                result["resumeRepairs"].append(
                    {
                        "eventSeq": event.get("eventSeq"),
                        "skippedEventSeq": skipped.get("eventSeq"),
                    }
                )
                DebugRun()
            continue
        if (
            ignore_foreign_breakpoints
            and observed_breakpoint
            and not matched_requested
            and _is_system_noise_breakpoint(event)
            and remaining_ms > 0
            and skips < max(0, int(max_skip_breakpoints))
        ):
            result["skippedBreakpoints"].append(
                {
                    "addr": event.get("addr"),
                    "rip": event.get("rip"),
                    "name": event.get("breakpointName"),
                    "module": event.get("breakpointModule"),
                    "eventSeq": event.get("eventSeq"),
                }
            )
            skips += 1
            DebugRun()
            continue
        break

    result["event"] = event
    hit = bool(event.get("matchedRequested", event.get("hit"))) and not bool(
        event.get("timedOut")
    )
    if hit:
        capture = CaptureContext(
            registers_json=registers_json,
            expressions_json=expressions_json,
            ranges_json=ranges_json,
            stack_slots_json=stack_slots_json,
        )
        result["capture"] = capture
        result["historyEntry"] = _record_breakpoint_capture(
            event, capture, requested_addr=addr
        )
    if delete_after_hit:
        result["deleteResult"] = DebugDeleteBreakpoint(addr)
    result["ok"] = hit
    return result


@mcp.tool()
def StepWithSnapshot(
    step_kind: str = "over",
    registers_json: str = "",
    expressions_json: str = "",
    ranges_json: str = "",
    stack_slots_json: str = "",
) -> dict:
    """
    Step once and capture before/after context snapshots.
    """
    before = CaptureContext(
        registers_json=registers_json,
        expressions_json=expressions_json,
        ranges_json=ranges_json,
        stack_slots_json=stack_slots_json,
    )
    before_instruction = _current_instruction(
        (before.get("state", {}) if isinstance(before, dict) else {}).get("ip")
    )
    step_kind_lower = str(step_kind or "over").strip().lower()
    if step_kind_lower == "in":
        step_result = DebugStepIn()
    elif step_kind_lower == "out":
        step_result = DebugStepOut()
    else:
        step_kind_lower = "over"
        step_result = DebugStepOver()
    wait_state = WaitForPause(timeout_ms=3000, poll_ms=50)
    after = CaptureContext(
        registers_json=registers_json,
        expressions_json=expressions_json,
        ranges_json=ranges_json,
        stack_slots_json=stack_slots_json,
    )
    after_instruction = _current_instruction(
        (after.get("state", {}) if isinstance(after, dict) else {}).get("ip")
    )
    snapshot = {
        "ok": True,
        "stepKind": step_kind_lower,
        "stepResult": step_result,
        "waitState": wait_state,
        "before": before,
        "beforeInstruction": before_instruction,
        "after": after,
        "afterInstruction": after_instruction,
    }
    _append_trace_history(snapshot)
    _log_event(
        "trace_snapshot",
        stepKind=step_kind_lower,
        waitState=wait_state.get("state"),
        rip=(after.get("state", {}) if isinstance(after, dict) else {}).get("ip"),
    )
    return snapshot


@mcp.tool()
def GetTraceHistory(limit: int = 20) -> dict:
    """
    Return recent StepWithSnapshot history.
    """
    history = list(_get_runtime_value("traceHistory", []) or [])
    safe_limit = max(1, min(int(limit), 64))
    return {"count": len(history[-safe_limit:]), "entries": history[-safe_limit:]}


@mcp.tool()
def GetBreakpointCaptureHistory(limit: int = 20) -> dict:
    """
    Return recent breakpoint-triggered structured captures.
    """
    history = list(_get_runtime_value("breakpointCaptureHistory", []) or [])
    safe_limit = max(1, min(int(limit), 64))
    return {"count": len(history[-safe_limit:]), "entries": history[-safe_limit:]}


@mcp.tool()
def ClearRuntimeHistory(
    clear_trace: bool = True, clear_breakpoints: bool = True
) -> dict:
    """
    Clear in-memory trace and breakpoint capture history.
    """
    with _RUNTIME_LOCK:
        if clear_trace:
            _RUNTIME_STATE["traceHistory"] = []
        if clear_breakpoints:
            _RUNTIME_STATE["breakpointCaptureHistory"] = []
        _RUNTIME_STATE["interactionHistory"] = []
        _RUNTIME_STATE["inputHistory"] = []
        _RUNTIME_STATE["memorySnapshots"] = {}
        _RUNTIME_STATE["memorySnapshotOrder"] = []
        _RUNTIME_STATE["memorySnapshotSeq"] = 0
        _RUNTIME_STATE["windowCaptures"] = {}
        _RUNTIME_STATE["windowCaptureOrder"] = []
        _RUNTIME_STATE["windowCaptureSeq"] = 0
        _RUNTIME_STATE["lastScyllaHide"] = None
    return {
        "ok": True,
        "clearedTrace": bool(clear_trace),
        "clearedBreakpointCaptures": bool(clear_breakpoints),
        "clearedInteractionHistory": True,
        "clearedInputHistory": True,
        "clearedMemorySnapshots": True,
        "clearedWindowCaptures": True,
    }


@mcp.tool()
def ReadLocalBuffer(
    ptr_expr: str = "",
    len_expr: str = "",
    ptr: str = "",
    length: int = 0,
    ty: str = "utf8",
    max_bytes: int = 4096,
    layout_json: str = "",
) -> dict:
    """
    Read a buffer/string from a ptr+len pair without manual address arithmetic.
    """
    if layout_json:
        layout_payload = _coerce_json_payload(layout_json)
        if isinstance(layout_payload, dict):
            if not ptr_expr:
                ptr_expr = str(
                    layout_payload.get(
                        "ptrExpr", layout_payload.get("ptr_expr", ptr_expr)
                    )
                    or ""
                )
            if not len_expr:
                len_expr = str(
                    layout_payload.get(
                        "lenExpr", layout_payload.get("len_expr", len_expr)
                    )
                    or ""
                )
            if not ptr:
                ptr = str(layout_payload.get("ptr", ptr) or "")
            if not length:
                length = int(
                    _parse_int(
                        str(
                            layout_payload.get(
                                "length", layout_payload.get("len", length)
                            )
                            or "0"
                        ),
                        0,
                    )
                    or 0
                )
            if ty == "utf8":
                ty = str(
                    layout_payload.get("ty", layout_payload.get("format", ty)) or ty
                )
            if max_bytes == 4096:
                max_bytes = int(
                    _parse_int(
                        str(
                            layout_payload.get(
                                "maxBytes", layout_payload.get("max_bytes", max_bytes)
                            )
                            or "0"
                        ),
                        max_bytes,
                    )
                    or max_bytes
                )
    resolved_ptr = ptr
    resolved_length = int(length or 0)
    eval_items: List[str] = []
    if ptr_expr:
        eval_items.append(ptr_expr)
    if len_expr:
        eval_items.append(len_expr)
    if eval_items:
        eval_payload = EvalBatch(json.dumps(eval_items))
        items = eval_payload.get("items", []) if isinstance(eval_payload, dict) else []
        if ptr_expr and len(items) >= 1 and items[0].get("success"):
            resolved_ptr = str(items[0].get("value") or "")
        if len_expr and len(items) >= 2 and items[1].get("success"):
            resolved_length = int(
                _parse_int(
                    str(items[1].get("valueDecimal") or items[1].get("value") or "0"), 0
                )
                or 0
            )
    if not resolved_ptr:
        return {"ok": False, "error": "Pointer expression did not resolve."}
    resolved_length = max(0, min(int(resolved_length), int(max_bytes)))
    payload = ReadMemory(resolved_ptr, resolved_length, ty=ty, max_chars=max_bytes)
    payload["ptr"] = resolved_ptr
    payload["length"] = resolved_length
    return payload


@mcp.tool()
def RunBridgeSelfCheck(source_root: str = "", include_hashes: bool = True) -> dict:
    """
    Check which bridge/binaries are live and whether source/live/cache/vendor/runtime copies drift.
    """
    paths = _resolve_bridge_artifact_paths(source_root)
    signatures = {
        name: _file_signature(str(path), include_hash=include_hashes)
        for name, path in paths.items()
        if path is not None
    }
    debugger_info = _get_active_debugger_info()
    active_arch = str(debugger_info.get("arch") or "").lower()
    active_runtime_key = (
        "runtimeDp64"
        if active_arch == "x64"
        else "runtimeDp32"
        if active_arch == "x86"
        else None
    )
    comparisons = {
        "sourceVsLive": _compare_signatures(
            signatures.get("sourceBridge", {}), signatures.get("liveBridge", {})
        ),
        "liveVsCache": _compare_signatures(
            signatures.get("liveBridge", {}), signatures.get("cacheBridge", {})
        ),
        "vendor32VsRuntime32": _compare_signatures(
            signatures.get("vendorDp32", {}), signatures.get("runtimeDp32", {})
        ),
        "vendor64VsRuntime64": _compare_signatures(
            signatures.get("vendorDp64", {}), signatures.get("runtimeDp64", {})
        ),
    }
    drifts: List[str] = []
    if signatures.get("sourceBridge", {}).get("exists") and not comparisons[
        "sourceVsLive"
    ].get("sameSha256"):
        drifts.append("source_live_python_mismatch")
    # A personal Codex configuration can execute the source launcher directly
    # and legitimately have no plugin-cache copy. A cache is a drift source
    # only when it actually exists and disagrees with the live bridge.
    if (
        signatures.get("liveBridge", {}).get("exists")
        and signatures.get("cacheBridge", {}).get("exists")
        and not comparisons["liveVsCache"].get("sameSha256")
    ):
        drifts.append("live_cache_python_mismatch")
    if signatures.get("vendorDp32", {}).get("exists") and not comparisons[
        "vendor32VsRuntime32"
    ].get("sameSha256"):
        drifts.append("vendor_runtime_dp32_mismatch")
    if signatures.get("vendorDp64", {}).get("exists") and not comparisons[
        "vendor64VsRuntime64"
    ].get("sameSha256"):
        drifts.append("vendor_runtime_dp64_mismatch")
    if not _EXT_TOOLS_STATUS.get("loaded"):
        drifts.append("ext_tools_not_loaded")
    state = _build_debug_state(
        include_console=False, include_callstack=False, max_console_chars=0
    )
    plugin_status = GetDebuggerPluginStatus(
        arch="auto",
        pid=int(state.get("debuggeePid") or 0),
        exe_path=str(state.get("debuggeePath") or ""),
        probe_commands=False,
    )
    active_runtime = (
        signatures.get(active_runtime_key, {}) if active_runtime_key else {}
    )
    hello = BridgeHello(refresh=True)
    hello_identity = (
        hello.get("identity")
        if isinstance(hello, dict) and isinstance(hello.get("identity"), dict)
        else {}
    )
    hello_payload = (
        hello.get("payload")
        if isinstance(hello, dict) and isinstance(hello.get("payload"), dict)
        else {}
    )
    auth_capability = (
        ((hello_payload.get("capabilities") or {}).get("authentication") or {})
        if isinstance(hello_payload, dict)
        else {}
    )
    with _BRIDGE_AUTH_LOCK:
        auth_cache = dict(_BRIDGE_AUTH_CACHE)
    auth_descriptor = {
        key: auth_cache.get(key)
        for key in (
            "source",
            "pid",
            "processStartTime100ns",
            "bridgeInstanceId",
            "port",
            "arch",
            "path",
        )
        if auth_cache.get(key) is not None
    }
    checks = {
        "sourceMatchesLive": bool(comparisons["sourceVsLive"].get("sameSha256")),
        "bridgeHello": bool(isinstance(hello, dict) and hello.get("ok")),
        "protocolV3": int(hello_identity.get("protocolVersion") or 0) >= 3,
        "routePolicy": bool(hello_identity.get("routePolicyCompatible")),
        "authenticatedTransport": bool(
            int(auth_capability.get("version") or 0) >= 1
            and str(auth_capability.get("header") or "") == BRIDGE_AUTH_HEADER
        ),
        "authDescriptorBound": bool(
            auth_cache.get("source") == "descriptor"
            and int(auth_cache.get("pid") or 0)
            == int(hello_identity.get("debuggerPid") or 0)
            and str(auth_cache.get("bridgeInstanceId") or "")
            == str(hello_identity.get("bridgeInstanceId") or "")
        ),
        "extTools": bool(_EXT_TOOLS_STATUS.get("loaded")),
        "toolProfiles": bool(_TOOL_PROFILE_STATUS.get("loaded")),
    }
    critical_drifts = {
        "source_live_python_mismatch",
        "live_cache_python_mismatch",
        "vendor_runtime_dp32_mismatch",
        "vendor_runtime_dp64_mismatch",
        "ext_tools_not_loaded",
    }
    overall_ok = all(checks.values()) and not bool(critical_drifts.intersection(drifts))
    return {
        "ok": overall_ok,
        "serverPid": os.getpid(),
        "serverUrl": x64dbg_server_url,
        "currentFile": str(Path(__file__).resolve()),
        "activeDebugger": debugger_info,
        "activeRuntimeBinary": active_runtime,
        "paths": {name: data.get("path") for name, data in signatures.items()},
        "signatures": signatures,
        "comparisons": comparisons,
        "drifts": drifts,
        "checks": checks,
        "bridge": {
            "protocolVersion": hello_identity.get("protocolVersion"),
            "bridgeInstanceId": hello_identity.get("bridgeInstanceId"),
            "debuggerPid": hello_identity.get("debuggerPid"),
            "debuggerArch": hello_identity.get("debuggerArch"),
            "sourceId": (hello_payload.get("build") or {}).get("sourceId"),
            "routePolicySourceId": hello_identity.get("routePolicySourceId"),
            "routePolicyExpectedId": _ROUTE_POLICY_ID,
        },
        "authentication": {
            "capability": auth_capability,
            "descriptor": auth_descriptor or None,
            "tokenExposed": False,
        },
        "toolProfile": dict(_TOOL_PROFILE_STATUS),
        "state": state,
        "pluginStatus": plugin_status,
        "extTools": dict(_EXT_TOOLS_STATUS),
        "logPath": LOG_PATH,
    }


@mcp.tool()
def SetMemoryRangeBreakpoint(
    addr: str,
    size: int,
    access_type: str = "write",
    singleshot: bool = False,
    name: str = "",
) -> dict:
    """
    Set a memory-range breakpoint using native x64dbg memory breakpoint commands.
    """
    resolved = _resolve_expression_value(addr)
    if resolved is None:
        return {
            "ok": False,
            "error": f"Could not resolve watch address: {addr}",
            "logPath": LOG_PATH,
        }
    addr_hex = _normalize_hex(resolved) or hex(resolved)
    safe_size = max(1, int(size))
    bp_type = _normalize_memory_breakpoint_type(access_type, singleshot=singleshot)
    result = ExecCommand(f"bpmrange {addr_hex},{safe_size},{bp_type}")
    watch_name = str(name or _memory_breakpoint_name(addr_hex, safe_size)).strip()
    named = ExecCommand(f"bpmname {addr_hex},{watch_name}") if watch_name else None
    payload = {
        "ok": bool(isinstance(result, dict) and result.get("success")),
        "addr": addr_hex,
        "size": safe_size,
        "type": bp_type,
        "name": watch_name,
        "setResult": result,
        "nameResult": named,
        "logPath": LOG_PATH,
    }
    _log_event(
        "set_memory_range_breakpoint",
        addr=addr_hex,
        size=safe_size,
        type=bp_type,
        name=watch_name,
        ok=payload["ok"],
    )
    return payload


@mcp.tool()
def DeleteMemoryBreakpoint(identifier: str = "") -> dict:
    """
    Delete a memory breakpoint by name or base address.
    """
    token = str(identifier or "").strip()
    result = ExecCommand(f"bpmc {token}" if token else "bpmc")
    ok = bool(isinstance(result, dict) and result.get("success"))
    _log_event("delete_memory_breakpoint", identifier=token or None, ok=ok)
    return {
        "ok": ok,
        "identifier": token or None,
        "result": result,
        "logPath": LOG_PATH,
    }


@mcp.tool()
def SetMemoryWatchpointWithCapture(
    addr: str,
    size: int,
    access_type: str = "write",
    name: str = "",
    registers_json: str = "",
    expressions_json: str = "",
    ranges_json: str = "",
    stack_slots_json: str = "",
    timeout_ms: int = 10000,
    resume: bool = True,
    delete_after_hit: bool = True,
    singleshot: bool = True,
    step_after_hit: bool = True,
    ignore_foreign_breakpoints: bool = True,
    max_skip_breakpoints: int = 8,
) -> dict:
    """
    Set a memory watchpoint, wait for it to hit, and capture the causing instruction plus runtime context.
    """
    resolved = _resolve_expression_value(addr)
    if resolved is None:
        return {
            "ok": False,
            "error": f"Could not resolve watch address: {addr}",
            "logPath": LOG_PATH,
        }
    addr_hex = _normalize_hex(resolved) or hex(resolved)
    watch_name = str(name or _memory_breakpoint_name(addr_hex, size)).strip()
    before_snapshot = CaptureMemorySnapshot(
        ranges_json=json.dumps(
            [
                {
                    "label": "watched_range",
                    "expr": addr_hex,
                    "size": int(size),
                    "format": "hex",
                }
            ]
        ),
        label=f"watch_before:{watch_name}",
    )
    set_result = SetMemoryRangeBreakpoint(
        addr=addr_hex,
        size=size,
        access_type=access_type,
        singleshot=singleshot,
        name=watch_name,
    )
    run_result = DebugRun() if resume else None
    capture_result = WaitForBreakpointCapture(
        name=watch_name,
        registers_json=registers_json,
        expressions_json=expressions_json,
        ranges_json=ranges_json,
        stack_slots_json=stack_slots_json,
        timeout_ms=timeout_ms,
        ignore_foreign_breakpoints=ignore_foreign_breakpoints,
        max_skip_breakpoints=max_skip_breakpoints,
        detail="full",
    )
    event = capture_result.get("event", {}) if isinstance(capture_result, dict) else {}
    cause_instruction = _current_instruction(event.get("rip"))
    post_step = None
    if (
        capture_result.get("ok")
        and step_after_hit
        and str(event.get("stopReason") or "").lower() != "exit"
    ):
        post_step = StepWithSnapshot(
            step_kind="over",
            registers_json=registers_json,
            expressions_json=expressions_json,
            ranges_json=ranges_json,
            stack_slots_json=stack_slots_json,
        )
    if not cause_instruction and isinstance(post_step, dict):
        fallback_instruction = post_step.get("beforeInstruction") or post_step.get(
            "afterInstruction"
        )
        if isinstance(fallback_instruction, dict):
            cause_instruction = fallback_instruction
    after_snapshot = CaptureMemorySnapshot(
        ranges_json=json.dumps(
            [
                {
                    "label": "watched_range",
                    "expr": addr_hex,
                    "size": int(size),
                    "format": "hex",
                }
            ]
        ),
        label=f"watch_after:{watch_name}",
    )
    diff = CompareMemorySnapshots(
        str(before_snapshot.get("snapshotId") or ""),
        str(after_snapshot.get("snapshotId") or ""),
    )
    delete_result = (
        DeleteMemoryBreakpoint(addr_hex)
        if (delete_after_hit or singleshot)
        else None
    )
    history_entry = capture_result.get("historyEntry")
    if isinstance(history_entry, dict):
        history_entry["captureKind"] = "memory_watchpoint"
        history_entry["watchpoint"] = {
            "addr": addr_hex,
            "size": int(size),
            "type": _normalize_memory_breakpoint_type(
                access_type, singleshot=singleshot
            ),
            "name": watch_name,
        }
        history_entry["beforeSnapshotId"] = before_snapshot.get("snapshotId")
        history_entry["afterSnapshotId"] = after_snapshot.get("snapshotId")
        history_entry["diff"] = diff
        history_entry["instruction"] = cause_instruction
        history_entry["postStep"] = post_step
    ok = bool(set_result.get("ok")) and bool(capture_result.get("ok"))
    _log_event(
        "memory_watchpoint_capture",
        ok=ok,
        addr=addr_hex,
        size=int(size),
        type=access_type,
        name=watch_name,
        rip=event.get("rip"),
        eventSeq=event.get("eventSeq"),
    )
    return {
        "ok": ok,
        "addr": addr_hex,
        "size": int(size),
        "name": watch_name,
        "accessType": access_type,
        "setResult": set_result,
        "runResult": run_result,
        "captureResult": capture_result,
        "causeInstruction": cause_instruction,
        "postStep": post_step,
        "beforeSnapshot": before_snapshot,
        "afterSnapshot": after_snapshot,
        "diff": diff,
        "deleteResult": delete_result,
        "logPath": LOG_PATH,
    }


def _execute_after_write_phase(
    address: int,
    size: int,
    label: str,
) -> Tuple[Dict[str, Any], bytes]:
    raw = _read_live_memory_exact(address, size)
    sample_size = min(len(raw), 256)
    try:
        protection: Any = MemoryGetProtect(f"0x{address:x}")
    except Exception as exc:
        protection = {"ok": False, "error": str(exc)}
    return (
        {
            "label": label,
            "capturedAt": _now_iso(),
            "address": f"0x{address:x}",
            "size": int(size),
            "sha256": hashlib.sha256(raw).hexdigest().upper(),
            "sampleHex": raw[:sample_size].hex(),
            "sampleSize": sample_size,
            "sampleTruncated": sample_size < len(raw),
            "protection": protection,
        },
        raw,
    )


def _execute_after_write_changed_ranges(
    before: bytes,
    after: bytes,
    address: int,
    max_ranges: int = 256,
) -> Dict[str, Any]:
    offsets = [
        index
        for index in range(max(len(before), len(after)))
        if (before[index] if index < len(before) else None)
        != (after[index] if index < len(after) else None)
    ]
    ranges: List[Dict[str, Any]] = []
    if offsets:
        start = offsets[0]
        end = start + 1
        for offset in offsets[1:]:
            if offset == end:
                end += 1
                continue
            ranges.append(
                {
                    "offset": start,
                    "address": f"0x{address + start:x}",
                    "size": end - start,
                    "beforeHex": before[start:end][:64].hex(),
                    "afterHex": after[start:end][:64].hex(),
                    "sampleTruncated": end - start > 64,
                }
            )
            start = offset
            end = offset + 1
        ranges.append(
            {
                "offset": start,
                "address": f"0x{address + start:x}",
                "size": end - start,
                "beforeHex": before[start:end][:64].hex(),
                "afterHex": after[start:end][:64].hex(),
                "sampleTruncated": end - start > 64,
            }
        )
    return {
        "changed": bool(offsets),
        "changedByteCount": len(offsets),
        "changedRangeCount": len(ranges),
        "rangesTruncated": len(ranges) > max(1, int(max_ranges)),
        "ranges": ranges[: max(1, int(max_ranges))],
        "_offsets": offsets,
    }


def _execute_after_write_address_identity(address: Any) -> Dict[str, Any]:
    value = _parse_int(address, 0) or 0
    try:
        payload = GetModuleList()
        modules = payload.get("modules", []) if isinstance(payload, dict) else []
    except Exception:
        modules = []
    module = next(
        (
            item
            for item in modules
            if isinstance(item, dict)
            and (_parse_int(item.get("base"), 0) or 0) <= value
            < (_parse_int(item.get("base"), 0) or 0)
            + (_parse_int(item.get("size"), 0) or 0)
        ),
        None,
    )
    if not module:
        return {"address": f"0x{value:x}", "module": None, "rva": None}
    base = _parse_int(module.get("base"), 0) or 0
    return {
        "address": f"0x{value:x}",
        "module": str(
            module.get("name")
            or os.path.basename(str(module.get("path") or ""))
        ),
        "modulePath": module.get("path"),
        "moduleBase": f"0x{base:x}",
        "rva": f"0x{value - base:x}",
    }


def _write_execute_after_write_evidence(
    payload: Dict[str, Any],
    output_path: str,
    overwrite: bool = False,
) -> Dict[str, Any]:
    target = Path(os.path.abspath(str(output_path or "")))
    if target.exists() and not overwrite:
        return {
            "ok": False,
            "schema": "execute-after-write-evidence-v1",
            "reason": "output_exists",
            "path": str(target),
        }
    body = {
        key: value
        for key, value in dict(payload or {}).items()
        if key != "evidenceSha256"
    }
    canonical = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest().upper()
    document = {**body, "evidenceSha256": digest}
    temporary = target.with_name(
        target.name + f".tmp-{os.getpid()}-{time.time_ns()}"
    )
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, target)
        return {
            "ok": True,
            "schema": "execute-after-write-evidence-v1",
            "path": str(target),
            "size": target.stat().st_size,
            "evidenceSha256": digest,
        }
    except Exception as exc:
        return {
            "ok": False,
            "schema": "execute-after-write-evidence-v1",
            "reason": "write_failed",
            "path": str(target),
            "error": str(exc),
        }
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


@mcp.tool()
def CaptureExecuteAfterWrite(
    addr: str,
    size: int,
    timeout_ms: int = 30000,
    resume: bool = True,
    evidence_path: str = "",
    overwrite: bool = False,
    max_execute_misses: int = 16,
    capture_callstacks: bool = True,
) -> dict:
    """Capture a proven write-then-execute transition for one memory range.

    The workflow records the range, catches and steps over its first write,
    then arms an execute memory breakpoint. It accepts execution only when
    RIP/EIP points at a byte changed since the initial snapshot. The target
    remains paused at that instruction so a dump can be captured without a
    race.
    """

    state = _build_debug_state(
        include_console=False,
        include_callstack=False,
        max_console_chars=0,
    )
    if not state.get("debugging") or not state.get("paused"):
        return {
            "ok": False,
            "schema": "execute-after-write-evidence-v1",
            "reason": "paused_debug_session_required",
            "state": state.get("state"),
        }
    hello = BridgeHello(refresh=True)
    if not isinstance(hello, dict) or not hello.get("ok"):
        return {
            "ok": False,
            "schema": "execute-after-write-evidence-v1",
            "reason": "authoritative_session_unavailable",
            "bridge": hello,
        }
    resolved = _resolve_expression_value(addr)
    if resolved is None:
        return {
            "ok": False,
            "schema": "execute-after-write-evidence-v1",
            "reason": "address_resolution_failed",
            "addressExpression": addr,
        }
    try:
        safe_size = int(size)
    except (TypeError, ValueError):
        safe_size = 0
    if not (1 <= safe_size <= 1_048_576):
        return {
            "ok": False,
            "schema": "execute-after-write-evidence-v1",
            "reason": "size_out_of_range",
            "minimum": 1,
            "maximum": 1_048_576,
        }
    if evidence_path:
        target = Path(os.path.abspath(str(evidence_path)))
        if target.exists() and not overwrite:
            return {
                "ok": False,
                "schema": "execute-after-write-evidence-v1",
                "reason": "output_exists",
                "path": str(target),
            }
    address = int(resolved)
    addr_hex = f"0x{address:x}"
    bitness = _detect_debuggee_bitness()
    ip_register = "rip" if bitness == 64 else "eip"
    sp_register = "rsp" if bitness == 64 else "esp"
    registers_json = json.dumps(
        [
            ip_register,
            sp_register,
            "rax" if bitness == 64 else "eax",
            "rcx" if bitness == 64 else "ecx",
            "rdx" if bitness == 64 else "edx",
        ]
    )
    range_json = json.dumps(
        [
            {
                "label": "execute_after_write_range",
                "expr": addr_hex,
                "size": min(safe_size, 2048),
                "format": "hex",
            }
        ]
    )
    workflow_id = f"eaw-{uuid.uuid4().hex[:16]}"
    identity = _breakpoint_lease_identity()
    started_at = _now_iso()
    try:
        before_phase, before_raw = _execute_after_write_phase(
            address, safe_size, "before-write"
        )
    except Exception as exc:
        return {
            "ok": False,
            "schema": "execute-after-write-evidence-v1",
            "reason": "initial_memory_read_failed",
            "error": str(exc),
            "address": addr_hex,
            "size": safe_size,
        }

    write_watch = SetMemoryWatchpointWithCapture(
        addr=addr_hex,
        size=safe_size,
        access_type="write",
        name=f"mcp_eaw_write_{workflow_id}",
        registers_json=registers_json,
        ranges_json=range_json,
        timeout_ms=max(100, int(timeout_ms)),
        resume=bool(resume),
        delete_after_hit=True,
        singleshot=True,
        step_after_hit=True,
        ignore_foreign_breakpoints=True,
        max_skip_breakpoints=16,
    )
    if not isinstance(write_watch, dict) or not write_watch.get("ok"):
        return {
            "ok": False,
            "schema": "execute-after-write-evidence-v1",
            "reason": "write_event_not_captured",
            "workflowId": workflow_id,
            "address": addr_hex,
            "size": safe_size,
            "writeWatch": write_watch,
        }
    try:
        after_write_phase, after_write_raw = _execute_after_write_phase(
            address, safe_size, "after-write"
        )
    except Exception as exc:
        return {
            "ok": False,
            "schema": "execute-after-write-evidence-v1",
            "reason": "post_write_memory_read_failed",
            "error": str(exc),
            "writeWatch": write_watch,
        }
    write_diff = _execute_after_write_changed_ranges(
        before_raw, after_write_raw, address
    )
    write_offsets = set(write_diff.pop("_offsets", []))
    if not write_offsets:
        return {
            "ok": False,
            "schema": "execute-after-write-evidence-v1",
            "reason": "write_event_changed_no_bytes",
            "workflowId": workflow_id,
            "address": addr_hex,
            "size": safe_size,
            "phases": [before_phase, after_write_phase],
            "writeWatch": write_watch,
        }
    write_callstack: Any = None
    if capture_callstacks:
        try:
            write_callstack = GetCallStack()
        except Exception as exc:
            write_callstack = {"ok": False, "error": str(exc)}

    execute_name = f"mcp_eaw_exec_{workflow_id}"
    execute_set = SetMemoryRangeBreakpoint(
        addr=addr_hex,
        size=safe_size,
        access_type="execute",
        singleshot=False,
        name=execute_name,
    )
    if not execute_set.get("ok"):
        return {
            "ok": False,
            "schema": "execute-after-write-evidence-v1",
            "reason": "execute_watchpoint_install_failed",
            "workflowId": workflow_id,
            "writeWatch": write_watch,
            "executeSet": execute_set,
        }
    deadline = time.monotonic() + max(100, int(timeout_ms)) / 1000.0
    execute_capture: Dict[str, Any] = {}
    execute_delete: Any = None
    misses: List[Dict[str, Any]] = []
    accepted_phase: Optional[Dict[str, Any]] = None
    accepted_raw = b""
    accepted_offsets: set[int] = set()
    try:
        run_result = DebugRun()
        run_ok, run_error = _mutation_result_ok(run_result)
        if not run_ok:
            return {
                "ok": False,
                "schema": "execute-after-write-evidence-v1",
                "reason": "execute_wait_resume_failed",
                "error": run_error,
                "run": run_result,
            }
        while time.monotonic() < deadline:
            remaining_ms = max(
                1, int((deadline - time.monotonic()) * 1000)
            )
            execute_capture = WaitForBreakpointCapture(
                name=execute_name,
                registers_json=registers_json,
                ranges_json=range_json,
                timeout_ms=remaining_ms,
                ignore_foreign_breakpoints=True,
                max_skip_breakpoints=16,
                detail="full",
            )
            if not execute_capture.get("ok"):
                break
            event = (
                execute_capture.get("event")
                if isinstance(execute_capture.get("event"), dict)
                else {}
            )
            execute_ip = _parse_int(
                event.get("rip") or event.get("addr"), 0
            ) or 0
            try:
                phase, current_raw = _execute_after_write_phase(
                    address, safe_size, "execute-hit"
                )
                current_diff = _execute_after_write_changed_ranges(
                    before_raw, current_raw, address
                )
                offsets = set(current_diff.get("_offsets") or [])
            except Exception as exc:
                phase = {"label": "execute-hit", "error": str(exc)}
                current_raw = b""
                offsets = set()
            execute_offset = execute_ip - address
            if (
                address <= execute_ip < address + safe_size
                and execute_offset in offsets
            ):
                accepted_phase = phase
                accepted_raw = current_raw
                accepted_offsets = offsets
                break
            misses.append(
                {
                    "eventSeq": event.get("eventSeq"),
                    "threadId": event.get("threadId"),
                    "rip": event.get("rip"),
                    "offset": execute_offset,
                    "insideRange": address
                    <= execute_ip
                    < address + safe_size,
                    "pointsAtChangedByte": execute_offset in offsets,
                }
            )
            if len(misses) >= max(0, int(max_execute_misses)):
                break
            resume_result = DebugRun()
            resume_ok, _ = _mutation_result_ok(resume_result)
            if not resume_ok:
                break
    finally:
        execute_delete = DeleteMemoryBreakpoint(addr_hex)
    if accepted_phase is None:
        return {
            "ok": False,
            "schema": "execute-after-write-evidence-v1",
            "reason": "changed_bytes_were_not_executed",
            "workflowId": workflow_id,
            "address": addr_hex,
            "size": safe_size,
            "writeWatch": write_watch,
            "writeDiff": write_diff,
            "executeSet": execute_set,
            "executeCapture": execute_capture,
            "executeMisses": misses,
            "executeDelete": execute_delete,
        }

    execute_event = (
        execute_capture.get("event")
        if isinstance(execute_capture.get("event"), dict)
        else {}
    )
    execute_ip = _parse_int(
        execute_event.get("rip") or execute_event.get("addr"), 0
    ) or 0
    final_diff = _execute_after_write_changed_ranges(
        before_raw, accepted_raw, address
    )
    final_diff.pop("_offsets", None)
    write_event = (
        (write_watch.get("captureResult") or {}).get("event")
        if isinstance(write_watch.get("captureResult"), dict)
        else {}
    ) or {}
    write_seq = int(write_event.get("eventSeq") or 0)
    execute_seq = int(execute_event.get("eventSeq") or 0)
    ordered = bool(write_seq and execute_seq and execute_seq > write_seq)
    execute_callstack: Any = None
    if capture_callstacks:
        try:
            execute_callstack = GetCallStack()
        except Exception as exc:
            execute_callstack = {"ok": False, "error": str(exc)}
    evidence = {
        "schema": "execute-after-write-evidence-v1",
        "workflowId": workflow_id,
        "startedAt": started_at,
        "completedAt": _now_iso(),
        "session": identity,
        "range": {
            "expression": str(addr),
            "address": addr_hex,
            "size": safe_size,
            "identity": _execute_after_write_address_identity(address),
        },
        "phases": [before_phase, after_write_phase, accepted_phase],
        "write": {
            "eventSeq": write_seq,
            "threadId": write_event.get("threadId"),
            "rip": write_event.get("rip"),
            "instruction": write_watch.get("causeInstruction"),
            "instructionIdentity": _execute_after_write_address_identity(
                write_event.get("rip")
            ),
            "postStep": write_watch.get("postStep"),
            "diff": write_diff,
            "callStack": write_callstack,
        },
        "execute": {
            "eventSeq": execute_seq,
            "threadId": execute_event.get("threadId"),
            "rip": f"0x{execute_ip:x}",
            "offset": execute_ip - address,
            "instruction": _current_instruction(f"0x{execute_ip:x}"),
            "instructionIdentity": _execute_after_write_address_identity(
                execute_ip
            ),
            "pointsAtChangedByte": (execute_ip - address)
            in accepted_offsets,
            "callStack": execute_callstack,
            "misses": misses,
        },
        "finalDiff": final_diff,
        "ordering": {
            "writeEventSeq": write_seq,
            "executeEventSeq": execute_seq,
            "strictlyOrdered": ordered,
        },
        "snapshotCount": 3,
    }
    ok = bool(
        ordered
        and final_diff.get("changed")
        and evidence["execute"]["pointsAtChangedByte"]
    )
    evidence_write: Optional[Dict[str, Any]] = None
    if ok and str(evidence_path or "").strip():
        evidence_write = _write_execute_after_write_evidence(
            evidence, evidence_path, overwrite=overwrite
        )
        ok = bool(evidence_write.get("ok"))
    _log_event(
        "capture_execute_after_write",
        ok=ok,
        workflowId=workflow_id,
        address=addr_hex,
        size=safe_size,
        writeEventSeq=write_seq,
        executeEventSeq=execute_seq,
        executeRip=f"0x{execute_ip:x}",
        changedByteCount=final_diff.get("changedByteCount"),
    )
    return {
        "ok": ok,
        "reason": (
            "captured"
            if ok
            else (
                "evidence_write_failed"
                if evidence_write and not evidence_write.get("ok")
                else "event_ordering_invalid"
            )
        ),
        **evidence,
        "writeWatch": write_watch,
        "executeSet": execute_set,
        "executeCapture": execute_capture,
        "executeDelete": execute_delete,
        "evidenceWrite": evidence_write,
    }


@mcp.tool()
def DecodeStructuredValue(
    layout: str,
    base_expr: str,
    ty: str = "utf8",
    max_bytes: int = 4096,
    arch: str = "auto",
    layout_json: str = "",
) -> dict:
    """
    Decode common structured layouts such as UNICODE_STRING, FILETIME, SOCKADDR, RECT, and simple Rust/C++ string/vector layouts.
    """
    layout_payload = _coerce_json_payload(layout_json) if layout_json else {}
    if layout_json and not isinstance(layout_payload, dict):
        return {
            "ok": False,
            "layout": layout,
            "error": "layout_json must decode to an object",
            "logPath": LOG_PATH,
        }
    desired_arch = str(arch or "auto").strip().lower()
    if desired_arch == "auto":
        desired_arch = _get_runtime_arch()
    result = _decode_common_layout(
        layout, base_expr, layout_payload or {}, desired_arch, ty, max_bytes
    )
    result["logPath"] = LOG_PATH
    return result


@mcp.tool()
def CaptureSymbolicBreakpoint(
    target: str,
    registers_json: str = "",
    expressions_json: str = "",
    ranges_json: str = "",
    stack_slots_json: str = "",
    timeout_ms: int = 10000,
    delete_after_hit: bool = False,
    resume: bool = True,
    source: str = "",
    symbol_name: str = "",
) -> dict:
    """
    Resolve a symbolic target such as `module!func+0x10`, set a breakpoint, and return structured runtime context on hit.
    """
    resolved = _resolve_expression_value(target)
    if resolved is None:
        return {
            "ok": False,
            "target": target,
            "source": source,
            "symbolName": symbol_name,
            "error": "Could not resolve symbolic target.",
            "logPath": LOG_PATH,
        }
    addr_hex = _normalize_hex(resolved) or hex(resolved)
    result = SetBreakpointWithCapture(
        addr=addr_hex,
        registers_json=registers_json,
        expressions_json=expressions_json,
        ranges_json=ranges_json,
        stack_slots_json=stack_slots_json,
        timeout_ms=timeout_ms,
        delete_after_hit=delete_after_hit,
        resume=resume,
    )
    result["resolvedAddr"] = addr_hex
    result["target"] = target
    result["source"] = source
    result["symbolName"] = symbol_name
    result["logPath"] = LOG_PATH
    return result


# ---------------------------------------------------------------------------
# API call tracer
#
# Records each hit on selected imported functions with arg values sampled from
# the calling convention's register/stack slots. Does NOT try to decode struct
# fields — callers use GetApiTraceLog + ReadMemory for deep inspection.
# ---------------------------------------------------------------------------

# Curated default filter: imports we almost always want to see in malware/CTF
# analysis. Patterns are case-insensitive substrings matched against
# `module!func`. Users can override via startApiTrace's `filter_patterns`.
