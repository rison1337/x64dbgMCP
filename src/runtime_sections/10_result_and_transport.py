MCP_SERVER_INSTRUCTIONS = """
Target-first startup rule: when an executable path is known, call InitDebuggee
directly. InitDebuggee detects x86/x64, resolves the configured X64DBG_ROOT,
starts the matching x32dbg/x64dbg instance, waits for its authenticated bridge,
and opens the target. Do not preflight BridgeHello, probe 127.0.0.1:8888, or
search common installation paths manually before InitDebuggee. BridgeHello is
for inspecting the identity of a debugger bridge that is already running.
""".strip()

mcp = FastMCP("x64dbg-mcp", instructions=MCP_SERVER_INSTRUCTIONS)

# These session-management functions are defined earlier because the legacy
# bridge helpers use them during module initialization. Register them only
# after FastMCP itself exists.
for _session_tool in (
    ListDebugSessions,
    GetChildBrokerState,
    SelectDebugSession,
    GetSelectedDebugSession,
):
    mcp.tool()(_session_tool)


# Public MCP calls use this result envelope.  The bridge transport has its own
# ``BridgeEnvelope`` above; keeping the two layers distinct lets internal
# helpers retain their historical scalar compatibility shim while every actual
# tool invocation has one predictable shape.
PUBLIC_RESULT_CONTRACT = "envelope-v1"
PUBLIC_RESULT_CONTRACT_SUNSET = "2026-12-31"
_LEGACY_RESULT_ENV = "X64DBG_MCP_LEGACY_RESULTS"
_RESPONSE_DETAIL_LEVELS = ("summary", "full")


def _resolve_response_detail(value: Any = "") -> Tuple[str, Optional[Dict[str, Any]]]:
    """Resolve per-call response detail without changing debugger semantics.

    Empty/``auto`` inherits the active tool profile: the model-facing compact
    profile uses bounded summaries, while every compatibility profile keeps the
    historical full payload.  Invalid values are returned as an ordinary tool
    validation error instead of escaping through FastMCP as a protocol error.
    """

    requested = str(value or "").strip().lower()
    if requested in ("", "auto"):
        profile = str(os.getenv("X64DBG_MCP_TOOL_PROFILE") or "full").strip().lower()
        return ("summary" if profile == "compact" else "full"), None
    if requested not in _RESPONSE_DETAIL_LEVELS:
        return "", {
            "ok": False,
            "errorCode": "INVALID_ARGUMENT",
            "error": "detail must be summary or full",
            "retryable": False,
        }
    return requested, None


def _compact_launch_result(payload: Any) -> Any:
    """Return the launch facts needed for the next debugger action.

    The original launch payload is deliberately left untouched and is returned
    by ``detail=full``.  This view only removes repeated capability, session,
    and state snapshots; it never performs a second debugger operation.
    """

    if not isinstance(payload, dict):
        return payload
    init = payload.get("init") if isinstance(payload.get("init"), dict) else {}
    state = init.get("state") if isinstance(init.get("state"), dict) else {}
    binding = init.get("binding") if isinstance(init.get("binding"), dict) else {}
    if not binding and isinstance(state.get("binding"), dict):
        binding = state.get("binding") or {}
    session = state.get("session") if isinstance(state.get("session"), dict) else {}
    advance = (
        payload.get("advanceToEntry")
        if isinstance(payload.get("advanceToEntry"), dict)
        else {}
    )
    advance_state = (
        advance.get("state") if isinstance(advance.get("state"), dict) else {}
    )
    advance_state_name = advance_state.get("state")
    if not advance_state_name and isinstance(advance.get("state"), str):
        advance_state_name = advance.get("state")
    pid = (
        state.get("debuggeePid")
        or binding.get("pid")
        or session.get("processId")
        or None
    )
    result: Dict[str, Any] = {
        "ok": bool(payload.get("ok")),
        "exePath": payload.get("exePath"),
        "pid": pid,
        "arch": (
            binding.get("debuggerArch")
            or payload.get("requestedArch")
            or init.get("targetArch")
        ),
        "moduleBase": binding.get("moduleBase") or None,
        "rip": advance_state.get("rip") or advance.get("rip") or state.get("rip"),
        "state": advance_state_name or state.get("state"),
        "stopReason": (
            advance_state.get("stopReason")
            or advance.get("stopReason")
            or state.get("stopReason")
        ),
        "sessionId": binding.get("sessionId") or session.get("sessionId") or None,
        "generation": (
            binding.get("sessionGeneration")
            or session.get("sessionGeneration")
            or session.get("generation")
            or None
        ),
        "eventSeq": (
            binding.get("eventSeq")
            or state.get("eventSeq")
            or session.get("eventSeq")
            or None
        ),
        "attempts": init.get("attempts"),
        "advancedToEntry": bool(advance.get("ok")) if advance else False,
        "timedOut": bool(init.get("timedOut")) if init else False,
        "availableDetails": [
            "ensureDebugger",
            "recoveryDebugger",
            "initialInit",
            "init",
            "advanceToEntry",
            "capabilities",
            "protection",
        ],
        "recoveredBridge": bool(payload.get("recoveryDebugger")),
    }
    for key in ("entrypointTool", "error", "errorCode", "hint", "reason"):
        if payload.get(key) not in (None, ""):
            result[key] = payload.get(key)
        elif init.get(key) not in (None, ""):
            result[key] = init.get(key)
    protection: Dict[str, Any] = {}
    for source, public_name in (("scyllaHide", "scyllaHide"),):
        item = init.get(source)
        if isinstance(item, dict):
            protection[public_name] = {
                "ok": bool(item.get("ok")),
                "skipped": bool(item.get("skipped")),
                "reason": item.get("reason") or item.get("error"),
            }
    if protection:
        result["protection"] = protection
    return result


def _compact_breakpoint_capture_result(payload: Any) -> Any:
    """Keep the matched stop and explicitly requested capture, omit history."""

    if not isinstance(payload, dict):
        return payload
    event = payload.get("event") if isinstance(payload.get("event"), dict) else {}
    state = event.get("state") if isinstance(event.get("state"), dict) else {}
    event_summary: Dict[str, Any] = {}
    for key in (
        "hit",
        "matchedRequested",
        "observedBreakpoint",
        "timedOut",
        "stopReason",
        "addr",
        "rip",
        "breakpointName",
        "breakpointModule",
        "eventSeq",
        "threadId",
    ):
        if key in event:
            event_summary[key] = event.get(key)
    for key in (
        "exceptionCode",
        "exceptionFirstChance",
        "exceptionAddress",
        "lastEventType",
    ):
        if key in state and key not in event_summary:
            event_summary[key] = state.get(key)
    result: Dict[str, Any] = {
        "ok": bool(payload.get("ok")),
        "event": event_summary,
        "skippedBreakpointCount": len(payload.get("skippedBreakpoints") or []),
        "skippedExceptionCount": len(payload.get("skippedExceptions") or []),
        "resumeRepairCount": len(payload.get("resumeRepairs") or []),
        "availableDetails": [
            "event.state",
            "skippedBreakpoints",
            "skippedExceptions",
            "resumeRepairs",
            "historyEntry",
        ],
    }
    if "capture" in payload:
        # CaptureContext contains only caller-requested registers, expressions,
        # memory ranges and stack slots.  Suppressing it would lose evidence.
        result["capture"] = payload.get("capture")
    for key in ("error", "errorCode", "hint"):
        if payload.get(key) not in (None, ""):
            result[key] = payload.get(key)
    return result


def _decorate_native_trace_page(
    payload: Any,
    *,
    requested_event_limit: int,
    requested_hit_limit: int,
) -> Any:
    """Add one stable, explicit pagination contract to bridge trace output."""

    if not isinstance(payload, dict):
        return payload
    result = dict(payload)
    event_returned = int(result.get("eventReturned") or len(result.get("events") or []))
    hit_returned = int(result.get("hitReturned") or len(result.get("hits") or []))
    event_has_more = bool(result.get("eventHasMore"))
    hit_has_more = bool(result.get("hitHasMore"))
    next_cursor: Dict[str, Any] = {}
    if event_has_more:
        next_cursor["eventAfterSeq"] = int(result.get("eventNextAfterSeq") or 0)
    if hit_has_more:
        next_cursor["hitOffset"] = int(result.get("hitOffset") or 0) + hit_returned
        next_cursor["hitAfterRevision"] = int(
            result.get("hitNextAfterRevision") or 0
        )
    result.update(
        {
            "pageSize": {
                "events": event_returned,
                "hits": hit_returned,
            },
            "requestedPageSize": {
                "events": max(0, int(requested_event_limit)),
                "hits": max(0, int(requested_hit_limit)),
            },
            "hasMore": event_has_more or hit_has_more,
            "nextCursor": next_cursor or None,
        }
    )
    return result


def _compact_native_trace_page(payload: Any) -> Any:
    """Keep trace progress and the explicitly requested page, drop config noise."""

    if not isinstance(payload, dict):
        return payload
    keep = (
        "ok",
        "traceId",
        "sessionId",
        "sessionGeneration",
        "processId",
        "mode",
        "active",
        "completed",
        "totalSteps",
        "matchedSteps",
        "uniqueAddresses",
        "eventCount",
        "droppedEvents",
        "droppedUnique",
        "stopReason",
        "eventOffset",
        "eventReturned",
        "eventHasMore",
        "eventAfterSeq",
        "eventNextAfterSeq",
        "eventCursorTruncated",
        "hitOffset",
        "hitReturned",
        "hitHasMore",
        "hitAfterRevision",
        "hitNextAfterRevision",
        "hitCursorTruncated",
        "events",
        "hits",
        "hitUpdates",
        "pageSize",
        "requestedPageSize",
        "hasMore",
        "nextCursor",
        "error",
        "errorCode",
        "hint",
    )
    result = {key: payload.get(key) for key in keep if key in payload}
    result["availableDetails"] = [
        "range",
        "limits",
        "captureConfiguration",
        "timestamps",
        "revisionBounds",
    ]
    return result


def _compact_native_trace_run(payload: Any) -> Any:
    """Summarize a completed trace without embedding its first evidence page."""

    if not isinstance(payload, dict):
        return payload
    evidence = (
        payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
    )
    wait = payload.get("wait") if isinstance(payload.get("wait"), dict) else {}
    result: Dict[str, Any] = {
        "ok": bool(payload.get("ok")),
        "traceId": payload.get("traceId"),
        "observed": bool(payload.get("observed")),
        "active": evidence.get("active", wait.get("active")),
        "completed": evidence.get("completed", wait.get("completed")),
        "totalSteps": evidence.get("totalSteps"),
        "matchedSteps": evidence.get("matchedSteps"),
        "eventCount": evidence.get("eventCount"),
        "uniqueAddresses": evidence.get("uniqueAddresses"),
        "stopReason": evidence.get("stopReason") or wait.get("stopReason"),
        "droppedEvents": evidence.get("droppedEvents"),
        "droppedUnique": evidence.get("droppedUnique"),
        "hasMore": bool(evidence.get("hasMore")),
        "nextCursor": evidence.get("nextCursor"),
        "availableDetails": ["command", "wait", "evidence"],
    }
    for key in ("error", "errorCode", "hint"):
        if payload.get(key) not in (None, ""):
            result[key] = payload.get(key)
    return result


def _canonical_error_code(value: Any, default: str = "TOOL_ERROR") -> str:
    """Normalize old error names into the stable public snake/upper taxonomy."""

    raw = str(value or "").strip()
    if not raw:
        return default
    match = re.match(r"^(?:error|http)[ _-]*(\d{3})$", raw, re.IGNORECASE)
    if match:
        return f"HTTP_{match.group(1)}"
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", raw).strip("_").upper()
    aliases = {
        "ERROR": default,
        "FAILED": "TOOL_ERROR",
        "FAILURE": "TOOL_ERROR",
        "REQUEST_FAILED": "BRIDGE_REQUEST_FAILED",
        "BRIDGE_ERROR": "BRIDGE_ERROR",
        "HTTP_ERROR": "HTTP_ERROR",
        "STALE_SESSION": "STALE_MUTATION_GUARD",
        "SESSION_GUARD_REQUIRED": "MISSING_SESSION_GUARD",
    }
    return aliases.get(normalized, normalized or default)


def _legacy_failure_text(value: str) -> Optional[Tuple[str, str, Optional[int]]]:
    """Recognize the legacy scalar error strings without classifying normal text."""

    text = str(value or "").strip()
    match = re.match(r"^Error\s+(\d{3})\s*:\s*(.*)$", text, re.IGNORECASE | re.DOTALL)
    if match:
        status = int(match.group(1))
        return f"HTTP_{status}", match.group(2).strip() or f"HTTP {status}", status
    match = re.match(r"^Request failed\s*:\s*(.*)$", text, re.IGNORECASE | re.DOTALL)
    if match:
        return "BRIDGE_REQUEST_FAILED", match.group(1).strip() or "Bridge request failed.", None
    match = re.match(
        r"^(?:unknown tool|tool error|failed(?:\b|:)|failure(?:\b|:)|cannot\b|could not\b|unable to\b)",
        text,
        re.IGNORECASE,
    )
    if match:
        return "TOOL_ERROR", text, None
    return None


def _public_identity_meta() -> Dict[str, Any]:
    """Return identity fields safely; offline tools must still get valid nulls."""

    try:
        identity = _identity_for_guard()
    except Exception:
        identity = {}
    def _positive_int(value: Any) -> Optional[int]:
        parsed = _parse_int(value, None)
        return int(parsed) if parsed is not None and int(parsed) > 0 else None

    return {
        "bridgeId": identity.get("bridgeInstanceId") or None,
        "sessionId": identity.get("sessionId") or None,
        "generation": _positive_int(identity.get("sessionGeneration")),
        "eventSeq": _positive_int(identity.get("eventSeq")),
        "debuggeePid": _positive_int(identity.get("debuggeePid")),
        "debuggerPid": _positive_int(identity.get("debuggerPid")),
    }


def _public_result_meta(
    tool_name: str,
    request_id: str,
    base_meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the canonical metadata block for one public tool invocation."""

    meta: Dict[str, Any] = dict(base_meta or {})
    # The public contract version is distinct from the HTTP transport version.
    transport_version = meta.pop("contractVersion", None)
    meta["contractVersion"] = 1
    meta["resultContract"] = PUBLIC_RESULT_CONTRACT
    meta["requestId"] = str(request_id or meta.get("requestId") or _new_request_id())
    meta["tool"] = str(tool_name or "")
    if transport_version is not None:
        meta.setdefault("transportContractVersion", transport_version)
    identity = _public_identity_meta()
    for key, value in identity.items():
        meta.setdefault(key, value)
    # Keep the canonical field names required by the published contract even
    # when an offline helper has no active bridge/session.
    meta.setdefault("endpoint", None)
    meta.setdefault("bridgeId", None)
    meta.setdefault("sessionId", None)
    meta.setdefault("generation", None)
    meta.setdefault("eventSeq", None)
    return _json_safe(meta)


def _public_error_from_value(
    value: Any,
    *,
    fallback_code: str = "TOOL_ERROR",
    fallback_message: str = "Tool operation failed.",
    http_status: Optional[int] = None,
    endpoint: str = "",
) -> BridgeError:
    """Convert a legacy dict/string/exception into one ``BridgeError``."""

    if isinstance(value, BridgeError):
        return value
    if isinstance(value, BaseException):
        return BridgeError(
            code=(fallback_code if fallback_code not in {"", "TOOL_ERROR"} else "TOOL_EXCEPTION"),
            message=str(value) or value.__class__.__name__,
            retryable=False,
            http_status=http_status,
            endpoint=endpoint,
        )
    if isinstance(value, dict):
        nested = value.get("error")
        if isinstance(nested, dict):
            raw_code = nested.get("code") or nested.get("errorCode") or value.get("errorCode")
            message = str(nested.get("message") or value.get("message") or fallback_message)
            details = dict(nested.get("details") or {})
            status = nested.get("httpStatus", http_status)
            retryable = nested.get("retryable")
        elif isinstance(nested, str) and nested.strip():
            parsed = _legacy_failure_text(nested)
            raw_code = value.get("errorCode") or value.get("code")
            if parsed:
                parsed_code, parsed_message, parsed_status = parsed
                raw_code = raw_code or parsed_code
                message = parsed_message
                status = value.get("httpStatus", parsed_status if http_status is None else http_status)
            else:
                message = nested
                status = value.get("httpStatus", http_status)
            details = dict(value.get("details") or {}) if isinstance(value.get("details"), dict) else {}
            retryable = value.get("retryable")
        else:
            raw_code = value.get("errorCode") or value.get("code")
            failure_items = value.get("errors")
            if isinstance(failure_items, (list, tuple)) and failure_items:
                derived_message = str(failure_items[0])
            else:
                derived_message = str(value.get("reason") or value.get("failure") or "")
            message = str(nested or value.get("message") or derived_message or fallback_message)
            if not raw_code and (failure_items or value.get("reason") or value.get("failure")):
                raw_code = "VALIDATION_FAILED"
            details = dict(value.get("details") or {}) if isinstance(value.get("details"), dict) else {}
            status = value.get("httpStatus", http_status)
            retryable = value.get("retryable")
        try:
            status_int = int(status) if status is not None else None
        except Exception:
            status_int = http_status
        if retryable is None:
            retryable = status_int in (408, 425, 429, 502, 503, 504)
        if endpoint and "endpoint" not in details:
            details["endpoint"] = endpoint
        return BridgeError(
            code=_canonical_error_code(raw_code, fallback_code),
            message=message,
            retryable=bool(retryable),
            http_status=status_int,
            endpoint=str(value.get("endpoint") or endpoint or ""),
            details=details,
        )
    if isinstance(value, str):
        parsed = _legacy_failure_text(value)
        if parsed:
            code, message, status = parsed
            return BridgeError(
                code=_canonical_error_code(code, fallback_code),
                message=message,
                retryable=status in (408, 425, 429, 502, 503, 504),
                http_status=status,
                endpoint=endpoint,
                details={"legacy": True} if status is not None else {},
            )
        return BridgeError(
            code=fallback_code,
            message=value or fallback_message,
            retryable=False,
            http_status=http_status,
            endpoint=endpoint,
        )
    return BridgeError(
        code=fallback_code,
        message=fallback_message,
        retryable=False,
        http_status=http_status,
        endpoint=endpoint,
    )


def _canonicalize_public_result(
    tool_name: str,
    result: Any,
    *,
    request_id: Optional[str] = None,
    exception: Optional[BaseException] = None,
) -> Dict[str, Any]:
    """Normalize any historical tool return into ``{ok,data,error,meta}``."""

    invocation_id = str(request_id or _new_request_id())
    if exception is not None:
        error = _public_error_from_value(exception, fallback_code="TOOL_EXCEPTION")
        return {
            "ok": False,
            "data": None,
            "error": error.as_dict(),
            "meta": _public_result_meta(tool_name, invocation_id),
        }

    if isinstance(result, BridgeEnvelope):
        base_meta = dict(result.meta or {})
        if result.ok:
            return {
                "ok": True,
                "data": _json_safe(result.data, limit=20000),
                "error": None,
                "meta": _public_result_meta(tool_name, invocation_id, base_meta),
            }
        error = result.error or _public_error_from_value(None)
        return {
            "ok": False,
            "data": _json_safe(result.data, limit=20000) if result.data is not None else None,
            "error": error.as_dict(),
            "meta": _public_result_meta(tool_name, invocation_id, base_meta),
        }

    # A few internal helpers already return the canonical shape.  Merge rather
    # than nest it, preserving their useful transport metadata.
    if isinstance(result, dict) and "ok" in result and "error" in result and "meta" in result:
        explicit_ok = bool(result.get("ok"))
        base_meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
        if explicit_ok:
            return {
                "ok": True,
                "data": _json_safe(result.get("data"), limit=20000),
                "error": None,
                "meta": _public_result_meta(tool_name, invocation_id, base_meta),
            }
        error = _public_error_from_value(result, fallback_code="TOOL_ERROR")
        return {
            "ok": False,
            "data": _json_safe(result.get("data"), limit=20000) if result.get("data") is not None else None,
            "error": error.as_dict(),
            "meta": _public_result_meta(tool_name, invocation_id, base_meta),
        }

    if isinstance(result, dict):
        has_ok = isinstance(result.get("ok"), bool)
        failed = (
            (has_ok and result.get("ok") is False)
            or (not has_ok and result.get("success") is False)
            or (not has_ok and result.get("error") not in (None, ""))
            or (not has_ok and result.get("errorCode") not in (None, ""))
            or (not has_ok and str(result.get("status") or "").casefold() in {"error", "failed"})
        )
        if failed:
            error = _public_error_from_value(result)
            residual = {
                key: value
                for key, value in result.items()
                if key not in {"ok", "success", "error", "errorCode", "code", "message", "retryable", "details", "httpStatus", "status"}
            }
            if residual and not error.details.get("legacyData"):
                details = dict(error.details)
                details["legacyData"] = _json_safe(residual, limit=12000)
                error = BridgeError(
                    code=error.code,
                    message=error.message,
                    retryable=error.retryable,
                    http_status=error.http_status,
                    endpoint=error.endpoint,
                    details=details,
                )
            return {
                "ok": False,
                "data": None,
                "error": error.as_dict(),
                "meta": _public_result_meta(tool_name, invocation_id),
            }
        return {
            "ok": True,
            "data": _json_safe(result, limit=20000),
            "error": None,
            "meta": _public_result_meta(tool_name, invocation_id),
        }

    if isinstance(result, str):
        # Some tools return JSON text; only decode an object/array when it is
        # unambiguously JSON, otherwise preserve ordinary debugger text.
        stripped = result.lstrip()
        if stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(result)
            except Exception:
                parsed = None
            if parsed is not None:
                return _canonicalize_public_result(tool_name, parsed, request_id=invocation_id)
        failure = _legacy_failure_text(result)
        if failure:
            error = _public_error_from_value(result)
            return {
                "ok": False,
                "data": None,
                "error": error.as_dict(),
                "meta": _public_result_meta(tool_name, invocation_id),
            }
        return {
            "ok": True,
            "data": result,
            "error": None,
            "meta": _public_result_meta(tool_name, invocation_id),
        }

    if result is False:
        error = _public_error_from_value(
            None,
            fallback_code="TOOL_FALSE_RESULT",
            fallback_message="Tool returned false without an error description.",
        )
        return {
            "ok": False,
            "data": None,
            "error": error.as_dict(),
            "meta": _public_result_meta(tool_name, invocation_id),
        }
    return {
        "ok": True,
        "data": _json_safe(result, limit=20000),
        "error": None,
        "meta": _public_result_meta(tool_name, invocation_id),
    }


def _legacy_results_requested() -> bool:
    return str(os.getenv(_LEGACY_RESULT_ENV) or "").strip().casefold() in {
        "1",
        "true",
        "yes",
        "on",
        "legacy",
    }


def _invoke_public_callable(
    tool_name: str,
    func: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Invoke a tool for MCP/CLI callers and apply the public result contract."""

    request_id = _new_request_id()
    try:
        result = func(*args, **kwargs)
    except Exception as exc:
        if _legacy_results_requested():
            return {"error": str(exc)}
        return _canonicalize_public_result(tool_name, None, request_id=request_id, exception=exc)
    if _legacy_results_requested():
        return result
    return _canonicalize_public_result(tool_name, result, request_id=request_id)


def _install_public_result_envelopes() -> None:
    """Wrap registered FastMCP tools without changing direct Python helpers."""

    manager = getattr(globals().get("mcp"), "_tool_manager", None)
    tools = getattr(manager, "_tools", None)
    if not isinstance(tools, dict):
        return

    # FastMCP validates arguments before calling ``Tool.fn``.  Install one
    # class-level boundary shim so malformed input and handler exceptions are
    # enveloped too; otherwise a missing required argument would escape as a
    # protocol-level ToolError while ordinary failures were JSON.
    try:
        from mcp.server.fastmcp.tools.base import Tool as _FastMCPTool
    except Exception:
        _FastMCPTool = None
    if _FastMCPTool is not None and not getattr(
        _FastMCPTool, "_x64dbg_contract_run_installed", False
    ):
        _original_tool_run = _FastMCPTool.run

        async def _contract_tool_run(
            self: Any,
            arguments: Dict[str, Any],
            context: Any = None,
            convert_result: bool = False,
        ) -> Any:
            marked = getattr(self, "_x64dbg_result_contract", None) == PUBLIC_RESULT_CONTRACT
            if not marked:
                return await _original_tool_run(
                    self, arguments, context=context, convert_result=convert_result
                )
            request_id = _new_request_id()
            try:
                # Ask the original runner for the raw function value.  We do
                # the content conversion exactly once below so both direct
                # ToolManager calls and FastMCP's low-level call_tool path have
                # the same canonical object underneath.
                raw = await _original_tool_run(
                    self, arguments, context=context, convert_result=False
                )
            except Exception as exc:
                if _legacy_results_requested():
                    result: Any = {"error": str(exc)}
                else:
                    fallback = "INVALID_ARGUMENT" if any(
                        marker in str(exc).casefold()
                        for marker in ("validation error", "field required", "missing")
                    ) else "TOOL_ERROR"
                    error = _public_error_from_value(exc, fallback_code=fallback)
                    result = {
                        "ok": False,
                        "data": None,
                        "error": error.as_dict(),
                        "meta": _public_result_meta(
                            getattr(self, "name", ""), request_id
                        ),
                    }
            else:
                if _legacy_results_requested():
                    result = raw
                elif (
                    isinstance(raw, dict)
                    and set(raw) >= {"ok", "data", "error", "meta"}
                    and raw.get("meta", {}).get("resultContract") == PUBLIC_RESULT_CONTRACT
                ):
                    result = raw
                else:
                    result = _canonicalize_public_result(
                        getattr(self, "name", ""), raw, request_id=request_id
                    )
            if convert_result:
                return self.fn_metadata.convert_result(result)
            return result

        _FastMCPTool.run = _contract_tool_run
        _FastMCPTool._x64dbg_contract_run_installed = True
        _FastMCPTool._x64dbg_original_run = _original_tool_run

    for name, tool in list(tools.items()):
        if getattr(tool, "_x64dbg_result_contract", None) == PUBLIC_RESULT_CONTRACT:
            continue
        original = getattr(tool, "fn", None)
        if not callable(original):
            continue
        if inspect.iscoroutinefunction(original):

            @wraps(original)
            async def wrapped_async(*args: Any, __original: Callable[..., Any] = original, __name: str = name, **kwargs: Any) -> Any:
                request_id = _new_request_id()
                try:
                    value = await __original(*args, **kwargs)
                except Exception as exc:
                    if _legacy_results_requested():
                        return {"error": str(exc)}
                    return _canonicalize_public_result(__name, None, request_id=request_id, exception=exc)
                if _legacy_results_requested():
                    return value
                return _canonicalize_public_result(__name, value, request_id=request_id)

            tool.fn = wrapped_async
            tool.is_async = True
        else:

            @wraps(original)
            def wrapped_sync(*args: Any, __original: Callable[..., Any] = original, __name: str = name, **kwargs: Any) -> Any:
                return _invoke_public_callable(__name, __original, *args, **kwargs)

            tool.fn = wrapped_sync
            tool.is_async = False
        # Existing output models describe legacy return types.  Clear only the
        # output side; the already-built argument model remains authoritative.
        metadata = getattr(tool, "fn_metadata", None)
        if metadata is not None:
            metadata.output_schema = None
            metadata.output_model = None
            metadata.wrap_output = False
        tool._x64dbg_result_contract = PUBLIC_RESULT_CONTRACT


_HTTP_LOCAL = local()
_CLIENT_INSTANCE_ID = str(uuid.uuid4())
_MUTATION_TRANSACTION_LOCK = RLock()
_MUTATION_LEASE_STATE_LOCK = Lock()
_MUTATION_LEASE_STATE: Dict[str, Any] = {
    "token": "",
    "acquisitionNonce": "",
    "sessionId": "",
    "generation": 0,
    "processId": 0,
    "expiresAtTickMs": 0,
    "revision": 0,
    "mutationSeq": 0,
    "emergencyEpoch": 0,
}
_SENSITIVE_FIELD_MARKERS = (
    "authorization",
    "cookie",
    "credential",
    "environment",
    "password",
    "secret",
    "stdin",
    "token",
)


def _redact_sensitive(value: Any, key: str = "") -> Any:
    key_lower = str(key or "").casefold()
    if key_lower and any(marker in key_lower for marker in _SENSITIVE_FIELD_MARKERS):
        if isinstance(value, dict):
            return {str(item_key): "<redacted>" for item_key in value}
        return "<redacted>"
    if isinstance(value, dict):
        return {
            str(item_key): _redact_sensitive(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_sensitive(item, key) for item in value]
    return _json_safe(value)


def _new_request_id() -> str:
    return str(uuid.uuid4())


def _bridge_url(endpoint: str) -> str:
    return f"{str(x64dbg_server_url or '').rstrip('/')}/{str(endpoint or '').lstrip('/')}"


def _get_http_session() -> requests.Session:
    """Return one requests.Session per calling thread.

    ``requests.Session`` mutates cookie/adapter state and is not documented as
    thread-safe.  Long bridge waits and regular MCP calls run concurrently, so
    sharing the old process-global Session could corrupt otherwise unrelated
    requests.  Retries are handled explicitly by ``_bridge_request`` instead of
    an adapter, because debugger mutations must never be replayed implicitly.
    """

    session = getattr(_HTTP_LOCAL, "session", None)
    if session is None:
        session = requests.Session()
        session.trust_env = False
        try:
            from requests.adapters import HTTPAdapter

            adapter = HTTPAdapter(pool_connections=4, pool_maxsize=8, max_retries=0)
            session.mount("http://", adapter)
        except Exception:
            pass
        _HTTP_LOCAL.session = session
    return session


def _normalize_bridge_identity(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    bridge = payload.get("bridge") if isinstance(payload.get("bridge"), dict) else {}
    debugger = payload.get("debugger") if isinstance(payload.get("debugger"), dict) else {}
    session = payload.get("session") if isinstance(payload.get("session"), dict) else {}
    capabilities = (
        payload.get("capabilities")
        if isinstance(payload.get("capabilities"), dict)
        else {}
    )
    bridge_id = str(
        payload.get("bridgeInstanceId")
        or payload.get("bridgeId")
        or bridge.get("instanceId")
        or ""
    ).strip()
    session_id = str(
        payload.get("sessionId") or session.get("sessionId") or session.get("id") or ""
    ).strip()
    generation = _parse_int(
        payload.get("sessionGeneration", session.get("generation")), 0
    ) or 0
    debugger_pid = _parse_int(
        payload.get("debuggerPid", debugger.get("pid")), 0
    ) or 0
    debuggee_pid = _parse_int(
        payload.get("debuggeePid", session.get("processId", payload.get("processId"))), 0
    ) or 0
    event_seq = _parse_int(
        payload.get("eventSeq", session.get("eventSeq")), 0
    ) or 0
    image_sha256 = str(
        session.get("imageSha256")
        or payload.get("imageSha256")
        or ""
    ).strip().upper()
    arch = str(
        payload.get("debuggerArch")
        or debugger.get("architecture")
        or debugger.get("arch")
        or ""
    ).strip().lower()
    protocol_version = _parse_int(payload.get("protocolVersion"), 0) or 0
    route_policy = (
        capabilities.get("routePolicy")
        if isinstance(capabilities.get("routePolicy"), dict)
        else {}
    )
    route_policy_id = str(route_policy.get("sourceId") or "").strip().casefold()
    if not any((bridge_id, session_id, generation, debugger_pid, protocol_version)):
        return {}
    return {
        "bridgeInstanceId": bridge_id,
        "sessionId": session_id,
        "sessionGeneration": int(generation),
        "eventSeq": int(event_seq),
        "debuggerPid": int(debugger_pid),
        "debuggerArch": arch,
        "debuggeePid": int(debuggee_pid),
        "debuggeeImagePath": _repair_text_mojibake(
            str(session.get("imagePath") or payload.get("imagePath") or "")
        ),
        "imageSha256": image_sha256 if TARGET_SHA256_RE.fullmatch(image_sha256) else "",
        "imageSize": int(
            _parse_int(session.get("imageSize", payload.get("imageSize")), 0) or 0
        ),
        "imageFileId": str(
            session.get("imageFileId") or payload.get("imageFileId") or ""
        ).strip(),
        "protocolVersion": int(protocol_version),
        "routePolicySourceId": route_policy_id,
        "routePolicyExpectedId": _ROUTE_POLICY_ID,
        "routePolicyCompatible": bool(route_policy_id == _ROUTE_POLICY_ID),
        "capabilities": dict(capabilities),
        "debugger": dict(debugger),
        "session": dict(session),
        "observedAt": _now_iso(),
    }


def _cache_bridge_identity(payload: Any) -> Dict[str, Any]:
    identity = _normalize_bridge_identity(payload)
    if identity:
        _remember_runtime(bridgeIdentity=identity, lastBridgeHelloAt=_now_iso())
    return identity


def _get_cached_bridge_identity() -> Dict[str, Any]:
    value = _get_runtime_value("bridgeIdentity")
    return dict(value) if isinstance(value, dict) else {}


def _update_bridge_identity_from_session(session_payload: Any) -> Dict[str, Any]:
    if not isinstance(session_payload, dict):
        return _get_cached_bridge_identity()
    current = _get_cached_bridge_identity()
    if not current.get("bridgeInstanceId"):
        return current
    session_id = str(
        session_payload.get("sessionId")
        or (session_payload.get("session") or {}).get("sessionId")
        if isinstance(session_payload.get("session"), dict)
        else session_payload.get("sessionId") or ""
    ).strip()
    nested = (
        session_payload.get("session")
        if isinstance(session_payload.get("session"), dict)
        else session_payload
    )
    updated = dict(current)
    if session_id:
        updated["sessionId"] = session_id
    generation = _parse_int(
        nested.get("generation", nested.get("sessionGeneration")), None
    )
    if generation is not None:
        updated["sessionGeneration"] = int(generation)
    event_seq = _parse_int(nested.get("eventSeq"), None)
    if event_seq is not None:
        updated["eventSeq"] = int(event_seq)
    pid = _parse_int(nested.get("processId", nested.get("debuggeePid")), None)
    if pid is not None:
        updated["debuggeePid"] = int(pid)
    image_path = str(nested.get("imagePath") or "")
    if image_path:
        updated["debuggeeImagePath"] = _repair_text_mojibake(image_path)
    image_sha256 = str(nested.get("imageSha256") or "").strip().upper()
    if image_sha256:
        updated["imageSha256"] = (
            image_sha256 if TARGET_SHA256_RE.fullmatch(image_sha256) else ""
        )
    image_size = _parse_int(nested.get("imageSize"), None)
    if image_size is not None:
        updated["imageSize"] = int(image_size)
    image_file_id = str(nested.get("imageFileId") or "").strip()
    if image_file_id:
        updated["imageFileId"] = image_file_id
    updated["session"] = dict(nested)
    updated["observedAt"] = _now_iso()
    _remember_runtime(bridgeIdentity=updated)
    return updated


def _normalize_bound_identity_for_headers(record: Any) -> Dict[str, Any]:
    value = dict(record) if isinstance(record, dict) else {}
    return {
        "bridgeInstanceId": str(value.get("bridgeInstanceId") or value.get("bridgeId") or ""),
        "sessionId": str(value.get("sessionId") or ""),
        "sessionGeneration": int(
            _parse_int(value.get("sessionGeneration", value.get("generation")), 0) or 0
        ),
        "debuggeePid": int(_parse_int(value.get("pid", value.get("debuggeePid")), 0) or 0),
        "eventSeq": int(_parse_int(value.get("eventSeq"), 0) or 0),
        "imageSha256": str(value.get("imageSha256") or "").strip().upper(),
        "imageSize": int(_parse_int(value.get("imageSize"), 0) or 0),
        "imageFileId": str(value.get("imageFileId") or "").strip(),
        "protocolVersion": int(_parse_int(value.get("protocolVersion"), 0) or 0),
        "routePolicySourceId": str(value.get("routePolicySourceId") or ""),
        "routePolicyCompatible": value.get("routePolicyCompatible"),
    }


def _identity_for_guard() -> Dict[str, Any]:
    binding: Dict[str, Any] = {}
    getter = globals().get("_get_bound_session")
    if callable(getter):
        try:
            binding = _normalize_bound_identity_for_headers(getter())
        except Exception:
            binding = {}
    current = _normalize_bound_identity_for_headers(_get_cached_bridge_identity())
    # An explicit binding owns a session.  Missing fields can be filled from the
    # live Hello only when both records identify the same bridge/session.
    if binding.get("bridgeInstanceId"):
        same_bridge = (
            not current.get("bridgeInstanceId")
            or binding.get("bridgeInstanceId") == current.get("bridgeInstanceId")
        )
        same_session = (
            not binding.get("sessionId")
            or not current.get("sessionId")
            or binding.get("sessionId") == current.get("sessionId")
        )
        if same_bridge and same_session:
            merged = {
                key: binding.get(key) or current.get(key)
                for key in (
                    "bridgeInstanceId",
                    "sessionId",
                    "sessionGeneration",
                    "debuggeePid",
                    "imageSha256",
                    "protocolVersion",
                    "routePolicySourceId",
                    "routePolicyCompatible",
                )
            }
            # eventSeq and auxiliary file identity are observations, not
            # immutable ownership fields.  A bound-session record intentionally
            # keeps its creation-time sequence, while mutations must use the
            # freshly observed bridge sequence for CAS.
            for key in ("eventSeq", "imageSize", "imageFileId"):
                merged[key] = current.get(key) or binding.get(key)
            merged["capabilities"] = current.get("capabilities") or binding.get(
                "capabilities"
            )
            return merged
        return binding
    return current


def _target_identity_hash_required(identity: Optional[Dict[str, Any]] = None) -> bool:
    """Whether the connected bridge has the v4 target-hash guard contract."""

    value = identity if isinstance(identity, dict) else _identity_for_guard()
    protocol = int(_parse_int(value.get("protocolVersion"), 0) or 0)
    capabilities = value.get("capabilities")
    if isinstance(capabilities, dict):
        guards = capabilities.get("strictSessionGuards")
        if isinstance(guards, dict) and bool(guards.get("targetSha256")):
            return True
        if bool(capabilities.get("targetIdentitySha256")):
            return True
    return protocol >= 4


def _local_bound_target_hash(identity: Dict[str, Any]) -> tuple[str, Optional[str]]:
    """Return the local target digest and a deterministic mismatch reason.

    The native bridge remains the final authority.  This inexpensive cached
    check catches a same-path replacement before a mutation leaves Python and
    gives callers a stable non-retryable error instead of relying on a later
    HTTP 409.
    """

    expected = str(identity.get("imageSha256") or "").strip().upper()
    if not expected or not TARGET_SHA256_RE.fullmatch(expected):
        return "", "target_hash_missing"
    binding = _get_bound_session()
    path = str(binding.get("imagePath") or "").strip()
    if not path:
        return expected, None
    observed = _image_sha256_cached(path)
    if not observed:
        # The native session snapshot is authoritative when the image has
        # become inaccessible (for example, a protected or deleted backing
        # file).  Only a readable replacement is evidence of turnover here;
        # the native hash guard still fails closed if its own identity is not
        # available.
        return expected, None
    if observed.upper() != expected:
        return observed.upper(), "target_hash_mismatch"
    return observed.upper(), None


def _parse_bridge_auth_file(path: Path) -> Dict[str, Any]:
    try:
        stat = path.stat()
        if not path.is_file() or stat.st_size <= 0 or stat.st_size > 4096:
            return {}
        fields: Dict[str, str] = {}
        for raw_line in path.read_text(encoding="ascii", errors="strict").splitlines():
            if "=" not in raw_line:
                return {}
            key, value = raw_line.split("=", 1)
            key = key.strip()
            if not key or key in fields:
                return {}
            fields[key] = value.strip()
        token = fields.get("token", "")
        pid = _parse_int(fields.get("pid"), 0) or 0
        start_time = _parse_int(fields.get("processStartTime100ns"), 0) or 0
        port = _parse_int(fields.get("port"), 0) or 0
        bridge_id = str(fields.get("bridgeInstanceId") or "").strip()
        arch = str(fields.get("arch") or "").strip().casefold()
        if (
            fields.get("version") != "1"
            or not BRIDGE_AUTH_TOKEN_RE.fullmatch(token)
            or pid <= 0
            or start_time <= 0
            or not bridge_id
            or len(bridge_id) > 128
            or any(ord(char) < 0x20 for char in bridge_id)
            or not (1 <= port <= 65535)
            or arch not in {"x86", "x64"}
        ):
            return {}
        return {
            "token": token.lower(),
            "pid": int(pid),
            "processStartTime100ns": int(start_time),
            "bridgeInstanceId": bridge_id,
            "port": int(port),
            "arch": arch,
            "path": str(path),
            "mtimeNs": int(stat.st_mtime_ns),
            "size": int(stat.st_size),
        }
    except (OSError, UnicodeError):
        return {}


def _request_bridge_descriptor(
    descriptor: Dict[str, Any],
    endpoint: str,
    *,
    bridge_id: str = "",
    timeout_sec: float = 1.0,
) -> Dict[str, Any]:
    """Read one explicitly identified bridge without changing global selection."""

    token = str(descriptor.get("token") or "")
    port = int(_parse_int(descriptor.get("port"), 0) or 0)
    if not BRIDGE_AUTH_TOKEN_RE.fullmatch(token) or not (1 <= port <= 65535):
        return {"ok": False, "errorCode": "invalid_bridge_descriptor"}
    headers = {
        "Accept": "application/json",
        BRIDGE_AUTH_HEADER: token,
        "X-MCP-Request-Id": _new_request_id(),
        "X-MCP-Client-Id": _CLIENT_INSTANCE_ID,
    }
    if bridge_id:
        headers["X-MCP-Bridge-Id"] = str(bridge_id)
    try:
        response = _get_http_session().get(
            f"http://127.0.0.1:{port}/{str(endpoint or '').lstrip('/')}",
            headers=headers,
            timeout=max(0.05, float(timeout_sec)),
            allow_redirects=False,
        )
        try:
            payload = response.json()
        except Exception:
            payload = None
        if response.status_code != 200 or not isinstance(payload, dict):
            return {
                "ok": False,
                "errorCode": "bridge_instance_request_failed",
                "httpStatus": int(response.status_code),
            }
        return {"ok": True, "data": payload}
    except requests.RequestException as exc:
        return {
            "ok": False,
            "errorCode": "bridge_instance_unreachable",
            "error": str(exc),
        }


def _validate_descriptor_hello(
    descriptor: Dict[str, Any], payload: Any
) -> tuple[bool, List[str]]:
    if not isinstance(payload, dict):
        return False, ["payload"]
    debugger = payload.get("debugger") if isinstance(payload.get("debugger"), dict) else {}
    http = payload.get("http") if isinstance(payload.get("http"), dict) else {}
    observed = {
        "pid": int(_parse_int(debugger.get("pid"), 0) or 0),
        "processStartTime100ns": int(
            _parse_int(debugger.get("processStartTime100ns"), 0) or 0
        ),
        "bridgeInstanceId": str(payload.get("bridgeInstanceId") or ""),
        "port": int(_parse_int(http.get("boundPort"), 0) or 0),
        "arch": str(debugger.get("architecture") or "").casefold(),
    }
    mismatched = [
        key
        for key in ("pid", "processStartTime100ns", "bridgeInstanceId", "port", "arch")
        if observed.get(key) != descriptor.get(key)
    ]
    return not mismatched, mismatched


def _enumerate_bridge_instances(
    *,
    root_launch_id: str = "",
    broker_id: str = "",
    include_state: bool = True,
) -> Dict[str, Any]:
    local_app_data = str(os.getenv("LOCALAPPDATA") or "").strip()
    if not local_app_data:
        return {
            "ok": False,
            "errorCode": "local_app_data_unavailable",
            "sessions": [],
        }
    try:
        debugger_pids = {
            int(item.get("pid") or 0)
            for item in _list_processes()
            if str(item.get("exe") or "").casefold() in ("x64dbg.exe", "x32dbg.exe")
        }
    except Exception as exc:
        return {
            "ok": False,
            "errorCode": "debugger_process_enumeration_failed",
            "error": str(exc),
            "sessions": [],
        }
    token_dir = Path(local_app_data) / "x64dbgMCP"
    selected_id = str(_get_runtime_value("selectedBridgeInstanceId") or "")
    sessions: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    for pid in sorted(debugger_pids):
        descriptor = _parse_bridge_auth_file(token_dir / f"bridge-{pid}.token")
        if not descriptor or int(descriptor.get("pid") or 0) != pid:
            errors.append({"debuggerPid": pid, "errorCode": "descriptor_unavailable"})
            continue
        hello_result = _request_bridge_descriptor(
            descriptor, "Bridge/Hello", timeout_sec=1.25
        )
        hello = hello_result.get("data") if hello_result.get("ok") else None
        valid, mismatched = _validate_descriptor_hello(descriptor, hello)
        if not valid:
            errors.append(
                {
                    "debuggerPid": pid,
                    "errorCode": "descriptor_identity_mismatch",
                    "fields": mismatched,
                }
            )
            continue
        child_broker = (
            dict(hello.get("childBroker"))
            if isinstance(hello.get("childBroker"), dict)
            else {}
        )
        if root_launch_id and str(child_broker.get("rootLaunchId") or "") != str(
            root_launch_id
        ):
            continue
        if broker_id and str(child_broker.get("brokerId") or "") != str(broker_id):
            continue
        session = dict(hello.get("session") or {})
        child_state: Optional[Dict[str, Any]] = None
        if include_state:
            bridge_instance_id = str(hello.get("bridgeInstanceId") or "")
            state_result = _request_bridge_descriptor(
                descriptor,
                "Debug/SessionState?includeHistory=false&historyLimit=0",
                bridge_id=bridge_instance_id,
                timeout_sec=1.25,
            )
            if state_result.get("ok"):
                session = dict(state_result.get("data") or {})
            broker_state_result = _request_bridge_descriptor(
                descriptor,
                "Debug/ChildBroker/State",
                bridge_id=bridge_instance_id,
                timeout_sec=1.25,
            )
            if broker_state_result.get("ok"):
                child_state = dict(broker_state_result.get("data") or {})
        bridge_instance_id = str(hello.get("bridgeInstanceId") or "")
        session_ref = (
            f"{bridge_instance_id}:{pid}:"
            f"{int(descriptor.get('processStartTime100ns') or 0)}"
        )
        sessions.append(
            {
                "sessionRef": session_ref,
                "selected": bool(selected_id and selected_id == bridge_instance_id),
                "isRoot": bool(
                    child_broker.get("rootLaunchId")
                    and int(child_broker.get("parentPid") or 0) == 0
                ),
                "debugger": dict(hello.get("debugger") or {}),
                "http": {
                    "boundPort": int(descriptor.get("port") or 0),
                    "state": str((hello.get("http") or {}).get("state") or ""),
                },
                "bridgeInstanceId": bridge_instance_id,
                "childBroker": child_broker,
                "session": session,
                "childBrokerState": child_state,
            }
        )
    sessions.sort(
        key=lambda item: (
            0 if item.get("isRoot") else 1,
            int((item.get("debugger") or {}).get("processStartTime100ns") or 0),
            int((item.get("debugger") or {}).get("pid") or 0),
        )
    )
    return {
        "ok": True,
        "rootLaunchId": str(root_launch_id or ""),
        "brokerId": str(broker_id or ""),
        "count": len(sessions),
        "sessions": sessions,
        "errors": errors,
    }


def _invalidate_bridge_auth_cache() -> None:
    with _BRIDGE_AUTH_LOCK:
        _BRIDGE_AUTH_CACHE.clear()


def _cleanup_stale_bridge_auth_files(
    token_dir: Path, debugger_pids: set[int]
) -> int:
    """Remove descriptors not owned by a visible x32dbg/x64dbg process.

    Forced debugger termination cannot run ``plugstop``. The tokens are already
    unusable, but their protected descriptors should not accumulate forever.
    Filename parsing is strict and unlink removes a symlink itself, never a
    target outside the token directory.
    """

    removed = 0
    try:
        candidates = list(token_dir.iterdir())
    except OSError:
        return 0
    for path in candidates:
        match = re.fullmatch(r"bridge-([1-9][0-9]*)\.token", path.name)
        if not match or int(match.group(1)) in debugger_pids:
            continue
        try:
            path.unlink()
            removed += 1
        except OSError:
            continue
    return removed


def _discover_bridge_auth_token() -> str:
    """Find the protected per-launch token without exposing it to MCP output."""
    try:
        configured_port = int(urlsplit(x64dbg_server_url).port or 0)
    except (TypeError, ValueError):
        return ""
    if not configured_port:
        return ""
    # Fast path: validate the cached descriptor by metadata only.  Trace and
    # polling calls must not enumerate every process on every HTTP request.
    with _BRIDGE_AUTH_LOCK:
        cached = dict(_BRIDGE_AUTH_CACHE)
    if (
        cached.get("source") == "descriptor"
        and int(cached.get("port") or 0) == configured_port
        and BRIDGE_AUTH_TOKEN_RE.fullmatch(str(cached.get("token") or ""))
    ):
        try:
            cached_stat = Path(str(cached.get("path") or "")).stat()
            if (
                int(cached_stat.st_mtime_ns) == int(cached.get("mtimeNs") or -1)
                and int(cached_stat.st_size) == int(cached.get("size") or -1)
            ):
                return str(cached["token"])
        except OSError:
            pass
        _invalidate_bridge_auth_cache()
    local_app_data = str(os.getenv("LOCALAPPDATA") or "").strip()
    if not local_app_data:
        return ""
    token_dir = Path(local_app_data) / "x64dbgMCP"
    process_discovery_succeeded = False
    try:
        debugger_pids = {
            int(item.get("pid") or 0)
            for item in _list_processes()
            if str(item.get("exe") or "").casefold() in ("x64dbg.exe", "x32dbg.exe")
        }
        process_discovery_succeeded = True
    except Exception:
        debugger_pids = set()
    debugger_pids.discard(0)
    if process_discovery_succeeded:
        _cleanup_stale_bridge_auth_files(token_dir, debugger_pids)
    if not debugger_pids:
        return ""
    identity = _get_cached_bridge_identity()
    preferred_pid = int(_parse_int(identity.get("debuggerPid"), 0) or 0)
    candidates: List[Dict[str, Any]] = []
    for pid in debugger_pids:
        parsed = _parse_bridge_auth_file(token_dir / f"bridge-{pid}.token")
        if (
            parsed
            and int(parsed.get("pid") or 0) == pid
            and int(parsed.get("port") or 0) == configured_port
        ):
            candidates.append(parsed)
    if not candidates:
        return ""
    candidates.sort(
        key=lambda item: (
            1 if int(item.get("pid") or 0) == preferred_pid else 0,
            int(item.get("mtimeNs") or 0),
        ),
        reverse=True,
    )
    chosen = candidates[0]
    cache_key = f"{chosen.get('path')}:{chosen.get('mtimeNs')}"
    with _BRIDGE_AUTH_LOCK:
        if _BRIDGE_AUTH_CACHE.get("key") != cache_key:
            _BRIDGE_AUTH_CACHE.clear()
            _BRIDGE_AUTH_CACHE.update(
                {
                    "key": cache_key,
                    "source": "descriptor",
                    "token": chosen["token"],
                    "pid": chosen["pid"],
                    "processStartTime100ns": chosen.get("processStartTime100ns"),
                    "bridgeInstanceId": chosen.get("bridgeInstanceId"),
                    "port": chosen.get("port"),
                    "arch": chosen.get("arch"),
                    "path": chosen.get("path"),
                    "mtimeNs": chosen.get("mtimeNs"),
                    "size": chosen.get("size"),
                }
            )
        return str(_BRIDGE_AUTH_CACHE.get("token") or "")


def _validate_hello_auth_binding(payload: Any) -> Optional[BridgeError]:
    """Bind a successful Hello response to the descriptor that supplied auth."""

    with _BRIDGE_AUTH_LOCK:
        descriptor = dict(_BRIDGE_AUTH_CACHE)
    if descriptor.get("source") != "descriptor":
        return BridgeError(
            code="AUTH_BINDING_MISSING",
            message="Bridge authentication did not originate from a protected descriptor.",
            endpoint="Bridge/Hello",
        )
    if not isinstance(payload, dict):
        return BridgeError(
            code="AUTH_BINDING_MISMATCH",
            message="Bridge/Hello did not return a verifiable authentication identity.",
            endpoint="Bridge/Hello",
        )
    debugger = payload.get("debugger") if isinstance(payload.get("debugger"), dict) else {}
    http = payload.get("http") if isinstance(payload.get("http"), dict) else {}
    observed = {
        "pid": int(_parse_int(debugger.get("pid"), 0) or 0),
        "processStartTime100ns": int(
            _parse_int(debugger.get("processStartTime100ns"), 0) or 0
        ),
        "bridgeInstanceId": str(payload.get("bridgeInstanceId") or ""),
        "port": int(_parse_int(http.get("boundPort"), 0) or 0),
        "arch": str(debugger.get("architecture") or "").casefold(),
    }
    mismatched = [
        key
        for key in ("pid", "processStartTime100ns", "bridgeInstanceId", "port", "arch")
        if observed.get(key) != descriptor.get(key)
    ]
    if mismatched:
        _invalidate_bridge_auth_cache()
        return BridgeError(
            code="AUTH_BINDING_MISMATCH",
            message="Bridge/Hello identity does not match the protected token descriptor.",
            endpoint="Bridge/Hello",
            details={"fields": mismatched},
        )
    return None


def _mutation_lease_snapshot() -> Dict[str, Any]:
    with _MUTATION_LEASE_STATE_LOCK:
        return dict(_MUTATION_LEASE_STATE)


def _set_mutation_lease_state(lease: Any) -> Dict[str, Any]:
    normalized = dict(lease) if isinstance(lease, dict) else {}
    token = str(normalized.get("token") or "").strip()
    with _MUTATION_LEASE_STATE_LOCK:
        _MUTATION_LEASE_STATE.clear()
        _MUTATION_LEASE_STATE.update(
            {
                "token": token,
                "acquisitionNonce": str(
                    normalized.get("acquisitionNonce")
                    or _MUTATION_LEASE_STATE.get("acquisitionNonce")
                    or ""
                ),
                "sessionId": str(normalized.get("sessionId") or ""),
                "generation": int(_parse_int(normalized.get("generation"), 0) or 0),
                "processId": int(_parse_int(normalized.get("processId"), 0) or 0),
                "expiresAtTickMs": int(
                    _parse_int(normalized.get("expiresAtTickMs"), 0) or 0
                ),
                "revision": int(_parse_int(normalized.get("revision"), 0) or 0),
                "mutationSeq": int(
                    _parse_int(normalized.get("mutationSeq"), 0) or 0
                ),
                "emergencyEpoch": int(
                    _parse_int(normalized.get("emergencyEpoch"), 0) or 0
                ),
            }
        )
        return dict(_MUTATION_LEASE_STATE)


def _clear_mutation_lease_state() -> None:
    _set_mutation_lease_state({})


def _guard_headers(
    guard: str,
    *,
    request_id: str,
    expected_event_seq: Optional[int] = None,
) -> tuple[Dict[str, str], Optional[BridgeError]]:
    normalized_guard = str(guard or "none").strip().lower()
    headers = {
        "Accept": "application/json",
        "X-MCP-Request-Id": request_id,
        "X-MCP-Client-Id": _CLIENT_INSTANCE_ID,
    }
    auth_token = _discover_bridge_auth_token()
    if auth_token:
        headers[BRIDGE_AUTH_HEADER] = auth_token
    if normalized_guard == "none":
        return headers, None
    lease_token = str(_mutation_lease_snapshot().get("token") or "")
    if lease_token:
        headers["X-MCP-Mutation-Lease"] = lease_token
        acquisition_nonce = str(
            _mutation_lease_snapshot().get("acquisitionNonce") or ""
        )
        if acquisition_nonce:
            headers["X-MCP-Mutation-Acquisition-Nonce"] = acquisition_nonce
    identity = _identity_for_guard()
    protocol_version = int(_parse_int(identity.get("protocolVersion"), 0) or 0)
    if protocol_version >= 3 and not bool(identity.get("routePolicyCompatible")):
        return headers, BridgeError(
            code="ROUTE_POLICY_MISMATCH",
            message="Python and native bridge mutation policies do not match.",
            details={
                "expected": _ROUTE_POLICY_ID,
                "observed": identity.get("routePolicySourceId"),
            },
        )
    bridge_id = str(identity.get("bridgeInstanceId") or "")
    if not bridge_id:
        return headers, BridgeError(
            code="BRIDGE_IDENTITY_UNAVAILABLE",
            message="Bridge/Hello identity is required before a guarded debugger operation.",
            endpoint="",
        )
    headers["X-MCP-Bridge-Id"] = bridge_id
    if normalized_guard == "bridge":
        return headers, None
    session_id = str(identity.get("sessionId") or "")
    generation = int(identity.get("sessionGeneration") or 0)
    debuggee_pid = int(identity.get("debuggeePid") or 0)
    missing = [
        name
        for name, value in (
            ("sessionId", session_id),
            ("sessionGeneration", generation),
            ("debuggeePid", debuggee_pid),
        )
        if not value
    ]
    if missing:
        return headers, BridgeError(
            code="SESSION_IDENTITY_UNAVAILABLE",
            message="Exact debug-session identity is unavailable for a state-changing operation.",
            details={"missing": missing},
        )
    headers["X-MCP-Session-Id"] = session_id
    headers["X-MCP-Session-Generation"] = str(generation)
    headers["X-MCP-Debuggee-Pid"] = str(debuggee_pid)
    strict_identity = _target_identity_hash_required(identity)
    target_sha256 = str(identity.get("imageSha256") or "").strip().upper()
    if strict_identity:
        binding_record = _get_bound_session()
        cached_record = _normalize_bound_identity_for_headers(
            _get_cached_bridge_identity()
        )
        binding_hash = str(binding_record.get("imageSha256") or "").strip().upper()
        cached_hash = str(cached_record.get("imageSha256") or "").strip().upper()
        if binding_hash and cached_hash and binding_hash != cached_hash:
            return headers, BridgeError(
                code="STALE_TARGET_IDENTITY",
                message="The bound target hash disagrees with the active bridge session.",
                endpoint="",
                details={"reason": "binding_session_hash_conflict"},
            )
        if not TARGET_SHA256_RE.fullmatch(target_sha256):
            return headers, BridgeError(
                code="TARGET_IDENTITY_UNAVAILABLE",
                message="The active debug session has no verified target SHA-256 identity.",
                endpoint="",
                details={"requiredHeader": "X-MCP-Debuggee-SHA256"},
            )
        headers["X-MCP-Debuggee-SHA256"] = target_sha256
        _observed_hash, local_hash_error = _local_bound_target_hash(identity)
        if local_hash_error:
            return headers, BridgeError(
                code="STALE_TARGET_IDENTITY",
                message="The bound target file identity changed or is unavailable.",
                endpoint="",
                details={"reason": local_hash_error},
            )

    # Event sequence is a mandatory CAS token for the v4 session contract.
    # Older bridges still receive it whenever a cached sequence exists, which
    # lets mixed-version deployments fail safely without breaking read-only
    # compatibility shims.
    event_value = expected_event_seq
    if event_value is None:
        event_value = _parse_int(identity.get("eventSeq"), 0) or 0
    if strict_identity and int(event_value or 0) <= 0:
        return headers, BridgeError(
            code="EVENT_IDENTITY_UNAVAILABLE",
            message="The active debug session has no event sequence for mutation CAS.",
            endpoint="",
            details={"requiredHeader": "X-MCP-Event-Seq"},
        )
    if event_value is not None and int(event_value or 0) >= 0:
        headers["X-MCP-Event-Seq"] = str(max(0, int(event_value)))
    return headers, None


def _default_request_guard(endpoint: str, params: Optional[Dict[str, Any]] = None) -> str:
    normalized = str(endpoint or "").strip().strip("/")
    manifest_guard = _ROUTE_POLICY.get("/" + normalized, "none")
    if normalized == "Debug/Attach":
        return "bridge"
    if manifest_guard == "exec_dynamic":
        command = str((params or {}).get("cmd") or "").strip().lower()
        first = command.split(None, 1)[0] if command else ""
        if first in {"init", "initdbg", "attach"}:
            return "bridge"
        return "session"
    return manifest_guard if manifest_guard in {"bridge", "session"} else "none"


def _normalize_bridge_error_code(value: Any, default: str = "BRIDGE_ERROR") -> str:
    text = str(value or default).strip()
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").upper()
    return normalized or default


def _bridge_error_from_http(
    endpoint: str,
    status: int,
    parsed: Any,
    text: str,
) -> BridgeError:
    error_payload = parsed.get("error") if isinstance(parsed, dict) else None
    if isinstance(error_payload, dict):
        code = _normalize_bridge_error_code(error_payload.get("code"), "HTTP_ERROR")
        message = str(error_payload.get("message") or text or f"HTTP {status}")
        details = error_payload.get("details")
    else:
        code = _normalize_bridge_error_code(
            (parsed or {}).get("code") if isinstance(parsed, dict) else None,
            "HTTP_ERROR",
        )
        message = str(
            ((parsed or {}).get("message") if isinstance(parsed, dict) else None)
            or text
            or f"HTTP {status}"
        )
        details = parsed if isinstance(parsed, dict) else {}
    if status == 409 and code == "HTTP_ERROR":
        code = "STALE_SESSION"
    elif status == 428 and code == "HTTP_ERROR":
        code = "SESSION_GUARD_REQUIRED"
    return BridgeError(
        code=code,
        message=message,
        retryable=status in (502, 503, 504),
        http_status=status,
        endpoint=endpoint,
        details=dict(details) if isinstance(details, dict) else {},
    )


def _bridge_request(
    method: str,
    endpoint: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    form_data: Optional[Dict[str, Any] | str] = None,
    json_body: Any = None,
    log: bool = True,
    timeout_sec: float = 15.0,
    guard: Optional[str] = None,
    expected_event_seq: Optional[int] = None,
    idempotent: bool = False,
) -> BridgeEnvelope:
    """Dispatch one bridge request with process-local mutation isolation.

    A native mutation lease isolates this MCP client from other clients.  The
    re-entrant lock below supplies the other half of the contract: while a
    multi-request transaction holds it, another worker in this Python server
    cannot reuse the same client id and lease token to interleave a mutation.
    Pause and Stop remain emergency operations and intentionally bypass the
    local lock, matching the native lease policy.
    """

    endpoint_clean = str(endpoint or "").strip().strip("/")
    request_guard = guard or _default_request_guard(endpoint_clean, params)
    emergency = endpoint_clean.casefold() in {"debug/pause", "debug/stop"}
    kwargs = {
        "params": params,
        "form_data": form_data,
        "json_body": json_body,
        "log": log,
        "timeout_sec": timeout_sec,
        "guard": guard,
        "expected_event_seq": expected_event_seq,
        "idempotent": idempotent,
    }
    if request_guard == "session" and not emergency:
        with _MUTATION_TRANSACTION_LOCK:
            return _bridge_request_impl(method, endpoint, **kwargs)
    return _bridge_request_impl(method, endpoint, **kwargs)


def _bridge_request_impl(
    method: str,
    endpoint: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    form_data: Optional[Dict[str, Any] | str] = None,
    json_body: Any = None,
    log: bool = True,
    timeout_sec: float = 15.0,
    guard: Optional[str] = None,
    expected_event_seq: Optional[int] = None,
    idempotent: bool = False,
) -> BridgeEnvelope:
    method_upper = str(method or "GET").strip().upper()
    endpoint_clean = str(endpoint or "").strip().strip("/")
    request_id = _new_request_id()
    started = time.time()
    meta: Dict[str, Any] = {
        "contractVersion": 3,
        "requestId": request_id,
        "method": method_upper,
        "endpoint": endpoint_clean,
        "clientInstanceId": _CLIENT_INSTANCE_ID,
    }
    if method_upper not in ("GET", "POST") or not endpoint_clean:
        error = BridgeError(
            code="INVALID_ARGUMENT",
            message="Bridge method must be GET/POST and endpoint must be non-empty.",
            endpoint=endpoint_clean,
        )
        return BridgeEnvelope(False, error=error, meta=meta)
    request_guard = guard or _default_request_guard(endpoint_clean, params)
    # For an implicit session mutation, refresh the authoritative event/hash
    # immediately before constructing headers.  Explicit expected_event_seq is
    # an intentional CAS pin and must never be silently replaced.  A small
    # thread-local recursion flag keeps the refresh itself unguarded and
    # prevents nested refreshes if a test/custom transport routes it back.
    refresh_state = request_guard == "session" and expected_event_seq is None
    refresh_state = refresh_state and _target_identity_hash_required(
        _identity_for_guard()
    )
    refresh_state = refresh_state and endpoint_clean.casefold() not in {
        "debug/sessionstate",
        "bridge/hello",
    }
    refresh_state = refresh_state and not bool(
        getattr(_HTTP_LOCAL, "refreshing_guard_identity", False)
    )
    if refresh_state:
        _HTTP_LOCAL.refreshing_guard_identity = True
        try:
            refresh = _bridge_request(
                "GET",
                "Debug/SessionState",
                params={"includeHistory": "false", "historyLimit": 0},
                log=False,
                timeout_sec=min(max(timeout_sec, 0.25), 2.0),
                guard="none",
                idempotent=True,
            )
            if refresh.ok and isinstance(refresh.data, dict):
                _update_bridge_identity_from_session(refresh.data)
        finally:
            _HTTP_LOCAL.refreshing_guard_identity = False
    headers, guard_error = _guard_headers(
        request_guard,
        request_id=request_id,
        expected_event_seq=expected_event_seq,
    )
    if guard_error:
        guard_error = BridgeError(
            code=guard_error.code,
            message=guard_error.message,
            retryable=False,
            endpoint=endpoint_clean,
            details=guard_error.details,
        )
        meta["elapsedMs"] = round((time.time() - started) * 1000, 2)
        if log:
            _log_event(
                "bridge_guard_rejected",
                endpoint=endpoint_clean,
                requestId=request_id,
                guard=request_guard,
                error=guard_error.as_dict(),
            )
        return BridgeEnvelope(False, error=guard_error, meta=meta)

    url = _bridge_url(endpoint_clean)
    encoded_params: Dict[str, Any] = dict(params or {})
    try:
        # Validate encoding up front. requests would otherwise fail after we had
        # already logged an apparently valid mutation attempt.
        if encoded_params:
            urlencode(
                encoded_params,
                doseq=True,
                quote_via=quote,
                safe="[]",
                encoding="utf-8",
                errors="strict",
            )
    except Exception as exc:
        error = BridgeError(
            code="INVALID_ARGUMENT",
            message=f"Failed to encode bridge parameters: {exc}",
            endpoint=endpoint_clean,
        )
        meta["elapsedMs"] = round((time.time() - started) * 1000, 2)
        return BridgeEnvelope(False, error=error, meta=meta)

    attempts = 2 if bool(idempotent and method_upper == "GET") else 1
    last_error: Optional[BridgeError] = None
    for attempt in range(1, attempts + 1):
        try:
            session = _get_http_session()
            timeout_value = max(0.05, float(timeout_sec))
            if method_upper == "GET":
                response = session.get(
                    url,
                    params=encoded_params or None,
                    headers=headers,
                    timeout=timeout_value,
                    allow_redirects=False,
                )
            else:
                post_kwargs: Dict[str, Any] = {
                    "params": encoded_params or None,
                    "headers": headers,
                    "timeout": timeout_value,
                    "allow_redirects": False,
                }
                if json_body is not None:
                    post_kwargs["json"] = json_body
                elif isinstance(form_data, dict):
                    post_kwargs["data"] = form_data
                elif isinstance(form_data, str):
                    post_kwargs["data"] = form_data.encode("utf-8")
                response = session.post(url, **post_kwargs)
            parsed, response_text = _decode_http_json_or_text(response)
            elapsed_ms = round((time.time() - started) * 1000, 2)
            meta.update(
                {
                    "attempt": attempt,
                    "elapsedMs": elapsed_ms,
                    "httpStatus": int(response.status_code),
                }
            )
            if not (200 <= int(response.status_code) < 300):
                if int(response.status_code) == 401:
                    _invalidate_bridge_auth_cache()
                    # A debugger restart or an x64/x86 switch rotates the
                    # descriptor token. Re-discover it once for an explicitly
                    # idempotent, unguarded read. Guarded requests and every
                    # mutation still fail closed and are never replayed.
                    if (
                        attempt < attempts
                        and method_upper == "GET"
                        and bool(idempotent)
                        and request_guard == "none"
                    ):
                        headers, retry_guard_error = _guard_headers(
                            request_guard,
                            request_id=request_id,
                            expected_event_seq=expected_event_seq,
                        )
                        if retry_guard_error is None:
                            url = _bridge_url(endpoint_clean)
                            continue
                last_error = _bridge_error_from_http(
                    endpoint_clean,
                    int(response.status_code),
                    parsed,
                    response_text,
                )
                if attempt < attempts and last_error.retryable:
                    continue
                if log:
                    _log_event(
                        "bridge_request_error",
                        requestId=request_id,
                        method=method_upper,
                        endpoint=endpoint_clean,
                        params=_redact_sensitive(encoded_params),
                        body=_redact_sensitive(
                            json_body if json_body is not None else form_data
                        ),
                        status=response.status_code,
                        elapsedMs=elapsed_ms,
                        error=last_error.as_dict(),
                    )
                return BridgeEnvelope(
                    False,
                    data=parsed if parsed is not None else None,
                    error=last_error,
                    meta=meta,
                )
            content_type = str(
                (getattr(response, "headers", {}) or {}).get("Content-Type", "")
            ).casefold()
            if "json" in content_type and parsed is None:
                last_error = BridgeError(
                    code="INVALID_RESPONSE",
                    message="Bridge returned malformed or empty JSON.",
                    retryable=False,
                    http_status=int(response.status_code),
                    endpoint=endpoint_clean,
                    details={"bodyPreview": response_text[:512]},
                )
                return BridgeEnvelope(False, error=last_error, meta=meta)
            data = parsed if parsed is not None else response_text
            if endpoint_clean.casefold() == "bridge/hello":
                auth_binding_error = _validate_hello_auth_binding(data)
                if auth_binding_error is not None:
                    meta["elapsedMs"] = elapsed_ms
                    return BridgeEnvelope(
                        False, data=data, error=auth_binding_error, meta=meta
                    )
                identity = _cache_bridge_identity(data)
                meta.update(
                    {
                        "bridgeInstanceId": identity.get("bridgeInstanceId"),
                        "sessionGeneration": identity.get("sessionGeneration"),
                        "eventSeq": identity.get("eventSeq"),
                    }
                )
            else:
                identity = _get_cached_bridge_identity()
                if identity:
                    meta.update(
                        {
                            "bridgeInstanceId": identity.get("bridgeInstanceId"),
                            "sessionGeneration": identity.get("sessionGeneration"),
                            "eventSeq": identity.get("eventSeq"),
                        }
                    )
            # A v2+ bridge can return an application-level failure with HTTP 2xx.
            if isinstance(data, dict) and data.get("ok") is False:
                raw_error = data.get("error")
                if isinstance(raw_error, dict):
                    last_error = BridgeError(
                        code=_normalize_bridge_error_code(
                            raw_error.get("code"), "BRIDGE_ERROR"
                        ),
                        message=str(raw_error.get("message") or "Bridge operation failed."),
                        retryable=bool(raw_error.get("retryable", False)),
                        http_status=int(response.status_code),
                        endpoint=endpoint_clean,
                        details=dict(raw_error.get("details") or {}),
                    )
                else:
                    last_error = BridgeError(
                        code=_normalize_bridge_error_code(
                            data.get("errorCode") or data.get("code"),
                            "BRIDGE_ERROR",
                        ),
                        message=str(raw_error or data.get("message") or "Bridge operation failed."),
                        retryable=False,
                        http_status=int(response.status_code),
                        endpoint=endpoint_clean,
                        details={
                            key: value
                            for key, value in data.items()
                            if key not in {"ok", "error", "message"}
                        },
                    )
                return BridgeEnvelope(False, data=data, error=last_error, meta=meta)
            if log:
                _log_event(
                    "bridge_request",
                    requestId=request_id,
                    method=method_upper,
                    endpoint=endpoint_clean,
                    params=_redact_sensitive(encoded_params),
                    body=_redact_sensitive(
                        json_body if json_body is not None else form_data
                    ),
                    status=response.status_code,
                    elapsedMs=elapsed_ms,
                    response=_redact_sensitive(data),
                )
            return BridgeEnvelope(True, data=data, meta=meta)
        except requests.exceptions.Timeout as exc:
            last_error = BridgeError(
                code="BRIDGE_TIMEOUT",
                message=str(exc) or "Bridge request timed out.",
                retryable=method_upper == "GET" and bool(idempotent),
                endpoint=endpoint_clean,
            )
        except requests.exceptions.ConnectionError as exc:
            last_error = BridgeError(
                code="BRIDGE_UNAVAILABLE",
                message=str(exc) or "Bridge is unavailable.",
                retryable=method_upper == "GET" and bool(idempotent),
                endpoint=endpoint_clean,
            )
        except requests.exceptions.RequestException as exc:
            last_error = BridgeError(
                code="BRIDGE_REQUEST_FAILED",
                message=str(exc),
                retryable=False,
                endpoint=endpoint_clean,
            )
        except Exception as exc:
            last_error = BridgeError(
                code="INTERNAL_ERROR",
                message=str(exc),
                retryable=False,
                endpoint=endpoint_clean,
            )
        if attempt < attempts and last_error.retryable:
            continue
        break
    meta["elapsedMs"] = round((time.time() - started) * 1000, 2)
    if log and last_error:
        _log_event(
            "bridge_request_exception",
            requestId=request_id,
            method=method_upper,
            endpoint=endpoint_clean,
            params=_redact_sensitive(encoded_params),
            elapsedMs=meta["elapsedMs"],
            error=last_error.as_dict(),
        )
    return BridgeEnvelope(
        False,
        error=last_error
        or BridgeError("BRIDGE_REQUEST_FAILED", "Unknown bridge request failure."),
        meta=meta,
    )


def _legacy_bridge_result(envelope: BridgeEnvelope) -> Any:
    if envelope.ok:
        return envelope.data
    # Preserve structured native failure payloads.  In particular, atomic
    # MemoryWrite/RegisterSet failures carry verified rollback state that must
    # not be collapsed into an "Error 500" string.
    if isinstance(envelope.data, dict):
        result = dict(envelope.data)
        result.setdefault("ok", False)
        if envelope.error is not None and not isinstance(result.get("error"), dict):
            result["error"] = envelope.error.as_dict()
        result.setdefault("meta", dict(envelope.meta or {}))
        return result
    error = envelope.error or BridgeError(
        "BRIDGE_REQUEST_FAILED", "Unknown bridge request failure."
    )
    if error.http_status is not None:
        return f"Error {error.http_status}: {error.message}"
    return f"Request failed: {error.message}"


def safe_get(
    endpoint: str,
    params: Optional[dict] = None,
    log: bool = True,
    timeout_sec: float = 15.0,
    guard: Optional[str] = None,
    expected_event_seq: Optional[int] = None,
):
    """
    Perform a GET request with optional query parameters.
    Returns parsed JSON if possible, otherwise text content
    """
    return _legacy_bridge_result(
        _bridge_request(
            "GET",
            endpoint,
            params=dict(params or {}),
            log=log,
            timeout_sec=timeout_sec,
            guard=guard,
            expected_event_seq=expected_event_seq,
            idempotent=(guard or _default_request_guard(endpoint, params)) == "none",
        )
    )


def safe_post(
    endpoint: str,
    data: dict | str,
    log: bool = True,
    timeout_sec: float = 15.0,
    guard: Optional[str] = None,
    expected_event_seq: Optional[int] = None,
    json_body: bool = False,
):
    """
    Perform a POST request with data.
    Returns parsed JSON if possible, otherwise text content
    """
    envelope = _bridge_request(
        "POST",
        endpoint,
        form_data=None if json_body else data,
        json_body=data if json_body else None,
        log=log,
        timeout_sec=timeout_sec,
        guard=guard,
        expected_event_seq=expected_event_seq,
        idempotent=False,
    )
    return _legacy_bridge_result(envelope)


@mcp.tool()
def BridgeHello(refresh: bool = True) -> dict:
    """Return the authoritative debugger bridge and debug-session identity.

    Diagnostic only for a debugger that is already running. When a target EXE
    path is known, call InitDebuggee directly instead of using BridgeHello as a
    preflight check; InitDebuggee selects and starts x32dbg/x64dbg from the
    configured X64DBG_ROOT and waits for this bridge automatically.

    This is the identity used by every state-changing operation.  ``ok`` is
    false for a legacy bridge because it cannot provide atomic stale-session
    protection.
    """

    cached = _get_cached_bridge_identity()
    if cached and not refresh:
        return {"ok": True, "identity": cached, "cached": True}
    envelope = _bridge_request(
        "GET",
        "Bridge/Hello",
        log=False,
        timeout_sec=2.0,
        guard="none",
        idempotent=True,
    )
    if not envelope.ok:
        return {
            "ok": False,
            "error": envelope.error.as_dict() if envelope.error else None,
            "meta": envelope.meta,
            "cachedIdentity": cached or None,
            "hint": (
                "If the target executable path is known, call InitDebuggee "
                "directly. It selects and starts x32dbg/x64dbg from "
                "X64DBG_ROOT and waits for the bridge; do not search common "
                "installation paths manually."
            ),
            "nextAction": {
                "tool": "InitDebuggee",
                "when": "target_executable_path_is_known",
                "arguments": {"exe_path": "<absolute-target-exe-path>"},
            },
        }
    identity = _cache_bridge_identity(envelope.data)
    if not identity.get("bridgeInstanceId"):
        return {
            "ok": False,
            "error": {
                "code": "INVALID_RESPONSE",
                "message": "Bridge/Hello did not contain bridgeInstanceId.",
                "retryable": False,
            },
            "payload": envelope.data,
            "meta": envelope.meta,
        }
    return {
        "ok": True,
        "identity": identity,
        "payload": envelope.data,
        "cached": False,
        "meta": envelope.meta,
    }


def _dispatch_async_exec_command(
    cmd: str,
    *,
    offset: int = 0,
    limit: int = 100,
    read_timeout_sec: float = 0.25,
) -> Dict[str, Any]:
    """
    Dispatch an ExecCommand request with an exact guarded transport result.

    A timeout is reported as acceptance-unknown; it is never treated as proof
    that a state-changing command ran.
    """
    params = {
        "cmd": str(cmd or ""),
        "offset": max(0, int(offset)),
        "limit": max(1, int(limit)),
    }
    envelope = _bridge_request(
        "GET",
        "ExecCommand",
        params=params,
        log=True,
        timeout_sec=max(0.05, float(read_timeout_sec)),
        guard=_default_request_guard("ExecCommand", params),
        idempotent=False,
    )
    if envelope.ok:
        result = envelope.data
        payload = dict(result) if isinstance(result, dict) else {"raw": result}
        payload.setdefault("ok", True)
        payload["accepted"] = True
        payload["acceptedKnown"] = True
        payload["detached"] = False
        payload["command"] = str(cmd or "")
        payload["elapsedMs"] = envelope.meta.get("elapsedMs")
        payload["requestId"] = envelope.meta.get("requestId")
        return payload
    error = envelope.error or BridgeError(
        "BRIDGE_REQUEST_FAILED", "Unknown command-dispatch failure."
    )
    timed_out = error.code == "BRIDGE_TIMEOUT"
    # A read timeout does not prove whether the bridge accepted a command.  The
    # old implementation claimed success and could make a caller issue a second
    # mutation.  Surface the uncertainty explicitly and let state polling decide.
    return {
        "ok": False,
        "accepted": False,
        "acceptedKnown": not timed_out,
        "acceptedUnknown": timed_out,
        "detached": False,
        "command": str(cmd or ""),
        "elapsedMs": envelope.meta.get("elapsedMs"),
        "requestId": envelope.meta.get("requestId"),
        "error": error.message,
        "errorCode": error.code,
    }


def _debug_step_via_exec_command(script_cmd: str, log_event_name: str) -> Dict[str, Any]:
    session_before = _get_debug_session_state(include_history=False, history_limit=0)
    before_seq = int(session_before.get("eventSeq") or 0) if session_before else 0
    result = _dispatch_async_exec_command(script_cmd, read_timeout_sec=0.25)
    session = _get_debug_session_state(include_history=False, history_limit=0)
    if session:
        _remember_runtime(
            lastResumeSeq=before_seq,
            lastSessionEventSeq=int(session.get("eventSeq") or 0),
        )
    else:
        _remember_runtime(lastResumeSeq=before_seq)
    _log_event(log_event_name, result=result)
    return result


def _get_mcp_tools_registry() -> Dict[str, Callable[..., Any]]:
    """
    Build a registry of available MCP-exposed tool callables in this module.
    Only include plain functions defined in this module whose names are exported-style.
    """
    registry: Dict[str, Callable[..., Any]] = {}
    for name, obj in globals().items():
        if not name or not name[0].isupper():
            continue
        if inspect.isfunction(obj) and getattr(obj, "__module__", None) == __name__:
            try:
                inspect.signature(obj)
                registry[name] = obj
            except (TypeError, ValueError):
                pass
    return registry


def _annotation_includes_type(annotation: Any, expected: Any) -> bool:
    if annotation is expected:
        return True
    origin = get_origin(annotation)
    if origin is None:
        return False
    return any(
        _annotation_includes_type(arg, expected)
        for arg in get_args(annotation)
        if arg is not type(None)
    )


def _resolve_callable_type_hints(func: Callable[..., Any]) -> Dict[str, Any]:
    try:
        return get_type_hints(func)
    except Exception:
        return {}


def _coerce_value_for_annotation(value: Any, annotation: Any) -> Any:
    if isinstance(value, str) and _annotation_includes_type(annotation, bool):
        return value.lower() in ("1", "true", "yes", "on")
    if isinstance(value, str) and _annotation_includes_type(annotation, int):
        try:
            return int(value, 0)
        except Exception:
            try:
                return int(value)
            except Exception:
                return value
    return value


def _describe_tool(name: str, func: Callable[..., Any]) -> Dict[str, Any]:
    sig = inspect.signature(func)
    type_hints = _resolve_callable_type_hints(func)
    params = []
    for p in sig.parameters.values():
        if p.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            # Skip non-JSON friendly params in schema
            continue
        annotation = type_hints.get(p.name, p.annotation)
        params.append(
            {
                "name": p.name,
                "required": p.default is inspect._empty,
                "type": "string"
                if annotation in (str, inspect._empty)
                else (
                    "boolean"
                    if _annotation_includes_type(annotation, bool)
                    else (
                        "integer"
                        if _annotation_includes_type(annotation, int)
                        else "string"
                    )
                ),
            }
        )
    return {
        "name": name,
        "description": (func.__doc__ or "").strip(),
        "params": params,
        "resultContract": PUBLIC_RESULT_CONTRACT,
    }


def _list_tools_description() -> List[Dict[str, Any]]:
    reg = _get_mcp_tools_registry()
    catalog = globals().get("_TOOL_CATALOG")
    if isinstance(catalog, dict) and isinstance(catalog.get("visibleTools"), list):
        visible = {str(name) for name in catalog["visibleTools"]}
        reg = {name: func for name, func in reg.items() if name in visible}
    return [
        _describe_tool(n, f) for n, f in sorted(reg.items(), key=lambda x: x[0].lower())
    ]


def _invoke_tool_by_name(name: str, args: Dict[str, Any]) -> Any:
    reg = _get_mcp_tools_registry()
    if name not in reg:
        if _legacy_results_requested():
            return {"error": f"Unknown tool: {name}"}
        return _canonicalize_public_result(
            str(name or ""),
            None,
            exception=ValueError(f"Unknown tool: {name}"),
        )
    func = reg[name]
    try:
        # Prefer keyword invocation; convert all values to strings unless bool/int expected
        sig = inspect.signature(func)
        type_hints = _resolve_callable_type_hints(func)
        bound_kwargs: Dict[str, Any] = {}
        for p in sig.parameters.values():
            if p.kind in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
                inspect.Parameter.POSITIONAL_ONLY,
            ):
                continue
            if p.name in args:
                value = args[p.name]
                annotation = type_hints.get(p.name, p.annotation)
                value = _coerce_value_for_annotation(value, annotation)
                bound_kwargs[p.name] = value
        return _invoke_public_callable(name, func, **bound_kwargs)
    except Exception as e:
        if _legacy_results_requested():
            return {"error": str(e)}
        return _canonicalize_public_result(name, None, exception=e)


def _block_to_dict(block: Any) -> Dict[str, Any]:
    try:
        # Newer anthropic SDK objects are Pydantic models
        if hasattr(block, "model_dump") and callable(getattr(block, "model_dump")):
            return block.model_dump()
    except Exception:
        pass
    if isinstance(block, dict):
        return block
    btype = getattr(block, "type", None)
    if btype == "text":
        return {"type": "text", "text": getattr(block, "text", "")}
    if btype == "tool_use":
        return {
            "type": "tool_use",
            "id": getattr(block, "id", None),
            "name": getattr(block, "name", None),
            "input": getattr(block, "input", {}) or {},
        }
    # Fallback generic representation
    return {"type": str(btype or "unknown"), "raw": str(block)}
