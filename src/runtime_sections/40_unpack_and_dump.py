def _build_find_oep_section_plan(
    module: Dict[str, Any], image_path: str, packer_section: str = ""
) -> Dict[str, Any]:
    base_hex = _normalize_hex((module or {}).get("base")) or "0x0"
    entry_hex = _normalize_hex((module or {}).get("entry")) or base_hex
    base_int = int(base_hex, 16)
    plan: Dict[str, Any] = {
        "layout": {},
        "imagePath": str(image_path or ""),
        "base": base_hex,
        "entry": entry_hex,
        "baseInt": base_int,
        "entryInt": int(entry_hex, 16),
        "execSections": [],
        "watchPhases": [],
        "entrySection": "",
        "tlsCallbacks": [],
        "exceptionDirectory": {},
    }
    try:
        layout = _parse_pe_layout(image_path)
    except Exception:
        return plan
    sections: List[Dict[str, Any]] = []
    entry_section_name = str((layout.get("entrySection") or {}).get("name") or "").strip()
    for section in list(layout.get("sections", [])) if isinstance(layout, dict) else []:
        if not isinstance(section, dict) or not bool(section.get("executable")):
            continue
        start = base_int + int(section.get("virtualAddress") or 0)
        size = max(
            int(section.get("virtualSize") or 0),
            int(section.get("rawSize") or 0),
            1,
        )
        sections.append(
            {
                "name": str(section.get("name") or ""),
                "nameLower": str(section.get("name") or "").strip().lower(),
                "start": start,
                "end": start + size,
                "startHex": f"0x{start:x}",
                "size": size,
                "sizeHex": f"0x{size:x}",
                "virtualAddress": int(section.get("virtualAddress") or 0),
                "virtualSize": int(section.get("virtualSize") or 0),
                "rawPointer": int(section.get("rawPointer") or 0),
                "rawSize": int(section.get("rawSize") or 0),
                "writable": bool(section.get("writable")),
                "entropy": float(section.get("entropy") or 0.0),
            }
        )

    def _phase_key(items: List[Dict[str, Any]]) -> tuple:
        return tuple(
            (int(item.get("start") or 0), int(item.get("size") or 0))
            for item in items
        )

    phases: List[List[Dict[str, Any]]] = []
    packer_lower = str(packer_section or "").strip().lower()
    primary = list(sections)
    if packer_lower and len(primary) > 1:
        filtered = [item for item in primary if item.get("nameLower") != packer_lower]
        if filtered:
            primary = filtered
    if entry_section_name and len(primary) > 1:
        filtered = [
            item for item in primary if item.get("nameLower") != entry_section_name.lower()
        ]
        if filtered:
            phases.append(filtered)
    if primary:
        phases.append(primary)
    if sections:
        phases.append(sections)
    deduped: List[List[Dict[str, Any]]] = []
    seen_keys = set()
    for phase in phases:
        if not phase:
            continue
        key = _phase_key(phase)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(phase)
    plan.update(
        {
            "layout": layout,
            "execSections": sections,
            "watchPhases": deduped,
            "entrySection": entry_section_name,
            "tlsCallbacks": [
                {
                    **dict(callback),
                    "runtimeVa": f"0x{base_int + int(str(callback.get('rva') or '0x0'), 16):x}",
                }
                for callback in list(
                    (layout.get("tlsDirectory") or {}).get("callbacks") or []
                )
                if isinstance(callback, dict) and callback.get("rva")
            ],
            "exceptionDirectory": dict(layout.get("exceptionDirectory") or {}),
        }
    )
    return plan


def _section_for_runtime_address(
    addr_int: int, sections: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    for section in sections:
        start = int(section.get("start") or 0)
        end = int(section.get("end") or 0)
        if start <= addr_int < end:
            return section
    return None


def _find_oep_candidate_from_state(
    state: Dict[str, Any],
    module_base_int: int,
    module_size: int,
    entry_int: int,
    exec_sections: List[Dict[str, Any]],
    entry_section_name: str = "",
) -> Optional[Dict[str, Any]]:
    rip_hex = _normalize_hex(state.get("rip"))
    if not rip_hex:
        return None
    rip_int = int(rip_hex, 16)
    module_limit = module_base_int + max(int(module_size or 0), 1)
    if not (module_base_int <= rip_int < module_limit):
        return None
    section = _section_for_runtime_address(rip_int, exec_sections)
    if not section:
        return None
    distance = abs(rip_int - entry_int)
    if distance <= 0x40:
        return None
    entry_section_lower = str(entry_section_name or "").strip().lower()
    section_name = str(section.get("name") or "")
    section_lower = str(section.get("nameLower") or "")
    callstack = state.get("callStack", {}) if isinstance(state.get("callStack"), dict) else {}
    return_from_non_module = False
    for item in list(callstack.get("entries", [])):
        if not isinstance(item, dict):
            continue
        to_hex = _normalize_hex(item.get("to"))
        if to_hex != rip_hex:
            continue
        from_hex = _normalize_hex(item.get("from"))
        if not from_hex:
            continue
        from_int = int(from_hex, 16)
        if not (module_base_int <= from_int < module_limit):
            return_from_non_module = True
            break
    if section_lower != entry_section_lower and distance >= 0x40:
        reason = f"entered executable section {section_name or '<unnamed>'} at {rip_hex}"
        confidence = "high" if return_from_non_module or distance >= 0x400 else "medium"
    elif return_from_non_module and distance >= 0x80:
        reason = f"returned into module code at {rip_hex} from non-module frame"
        confidence = "medium"
    elif distance >= 0x800:
        reason = f"reached module code far from entry stub at {rip_hex}"
        confidence = "medium"
    else:
        return None
    return {
        "rip": rip_hex,
        "ripInt": rip_int,
        "section": section_name,
        "sectionStart": str(section.get("startHex") or ""),
        "distanceFromEntry": f"0x{distance:x}",
        "returnFromNonModule": return_from_non_module,
        "reason": reason,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Generic dynamic OEP engine (packer-agnostic).
#
# Empirically-validated technique for the "unpack-in-memory then jump to a real
# OEP" class (UPX, ASPack, FSG, MPRESS, PECompact, Petite, simple crypters):
#   1. ESP-anchor fast-forward: at the stub entry, single-step the first push
#      (context save) and set a HARDWARE access breakpoint on the saved stack
#      slot. Running fires it near the stub tail, PAST the heavy decompression
#      writes, and is immune to page writes / protection changes (unlike x64dbg
#      memory/guard-page breakpoints, which the decompression destroys).
#   2. Section-hop conditional trace: `ticnd` until cip enters a non-stub
#      executable section — lands exactly at the OEP, fast, guard-immune.
# Virtualizing protectors are outside the generic OEP engine's recoverable
# contract.  They are reported as an honest failure (isLikelyVirtualized),
# never faked as a successful unpack.
# ---------------------------------------------------------------------------

def _oep_read_state() -> tuple:
    st = _build_debug_state(
        include_console=False,
        include_callstack=True,
        max_console_chars=0,
        include_registers=True,
    )
    return (st.get("registers") or {}), st


def _oep_norm_rip(regs: Dict[str, Any], state: Dict[str, Any]) -> Optional[str]:
    for key in ("rip", "cip", "eip"):
        value = regs.get(key)
        if value:
            return _normalize_hex(value)
    return _normalize_hex(state.get("rip"))


def _oep_reg_int(regs: Dict[str, Any], *names: str) -> Optional[int]:
    for name in names:
        value = regs.get(name)
        if value in (None, ""):
            continue
        try:
            return int(str(value), 16)
        except Exception:
            continue
    return None


def _oep_section_condition(sections: List[Dict[str, Any]]) -> str:
    parts = []
    for section in sections:
        start = int(section.get("start") or 0)
        end = int(section.get("end") or 0)
        if end > start:
            parts.append(f"(cip>=0x{start:x} && cip<0x{end:x})")
    return " || ".join(parts)


def _oep_wait_settle(deadline: float, poll_s: float = 0.35) -> Dict[str, Any]:
    """Wait for the (async) trace to leave the running state, or force-pause at the deadline."""
    while time.time() < deadline:
        _, st = _oep_read_state()
        if st.get("state") != "running":
            return st
        time.sleep(poll_s)
    try:
        DebugPause()
        time.sleep(0.3)
    except Exception:
        pass
    _, st = _oep_read_state()
    return st


def _oep_trace_to_sections(
    section_cond: str, deadline: float, max_steps: int = 6000000
) -> Optional[Dict[str, Any]]:
    """Conditional-trace until cip enters one of the section ranges (guard-immune)."""
    if not section_cond or time.time() >= deadline:
        return None
    try:
        TraceIntoConditional(condition=section_cond, max_steps=max_steps)
    except Exception:
        return None
    return _oep_wait_settle(deadline)


def _oep_trace_over_to_condition(
    condition: str, deadline: float, max_steps: int = 2000000
) -> Optional[Dict[str, Any]]:
    """Trace-over until a condition is true, skipping imported-call churn."""

    if not condition or time.time() >= deadline:
        return None
    try:
        TraceOverConditional(condition=condition, max_steps=max_steps)
    except Exception:
        return None
    return _oep_wait_settle(deadline)


def _oep_step_out(deadline: float) -> Optional[Dict[str, Any]]:
    """Step out once and wait for the resulting authoritative pause."""

    if time.time() >= deadline:
        return None
    try:
        submitted = DebugStepOut()
        if isinstance(submitted, dict) and submitted.get("ok") is False:
            return None
        remaining = max(250, int((deadline - time.time()) * 1000))
        waited = WaitForPause(timeout_ms=min(remaining, 10000), poll_ms=50)
        if isinstance(waited, dict) and waited.get("timedOut"):
            return _oep_wait_settle(deadline, poll_s=0.1)
    except Exception:
        return None
    _, state = _oep_read_state()
    return state


def _oep_run_to_temporary_address(
    address: str, deadline: float, workflow_id: str
) -> Optional[Dict[str, Any]]:
    """Run to one leased return address without touching a user breakpoint."""

    normalized = _normalize_hex(address)
    if not normalized or time.time() >= deadline:
        return None
    lease = AcquireBreakpointLease(
        normalized,
        workflow_id=workflow_id,
        breakpoint_type="normal",
        lease_ms=max(
            5000,
            min(int(max(0.0, deadline - time.time()) * 1000) + 2000, 120000),
        ),
        name="mcp-oep-stage-return",
    )
    if not (
        isinstance(lease, dict) and lease.get("ok") and lease.get("leaseId")
    ):
        return None
    target = int(normalized, 16)
    try:
        for _ in range(16):
            if time.time() >= deadline:
                return None
            DebugRun()
            remaining = max(250, int((deadline - time.time()) * 1000))
            waited = WaitForPause(
                timeout_ms=min(remaining, 8000),
                poll_ms=50,
            )
            if not isinstance(waited, dict):
                return None
            if waited.get("timedOut"):
                continue
            _, state = _oep_read_state()
            if state.get("state") in {"exited", "not_debugging"}:
                return state
            current = _normalize_hex(
                state.get("rip")
                or (state.get("registers") or {}).get("cip")
            )
            if current and int(current, 16) == target:
                return state
        return None
    finally:
        try:
            ReleaseBreakpointLease(str(lease["leaseId"]))
        except Exception:
            pass


def _oep_looks_like_prologue(rip_hex: str, _depth: int = 0) -> bool:
    try:
        disasm = DisasmGetInstructionRange(rip_hex, 6)
    except Exception:
        return False
    instructions = disasm.get("instructions") if isinstance(disasm, dict) else None
    if not instructions:
        return False
    text = [
        str(item.get("instruction") or "").strip().lower()
        for item in instructions[:6]
        if isinstance(item, dict)
    ]
    first = text[0] if text else ""
    if not first:
        return False
    junk_markers = ("int3", "???", "add byte ptr", "byte ptr ds:[rax], al")
    if any(marker in first for marker in junk_markers):
        return False
    opcode, _, operands = first.partition(" ")
    operands = operands.strip()
    if opcode in {"endbr64", "endbr32"}:
        return bool(len(text) > 1 and any(
            text[1].startswith(prefix)
            for prefix in ("push ", "sub rsp", "sub esp", "mov ebp, esp", "mov rbp, rsp")
        ))
    if opcode == "push":
        return bool(operands and "ptr" not in operands)
    if opcode == "sub":
        return operands.startswith(("rsp,", "esp,"))
    if opcode == "mov":
        normalized = operands.replace(" ", "")
        return bool(
            normalized.startswith(("ebp,esp", "rbp,rsp", "edi,edi"))
            or (
                ("[rsp+" in normalized or "[esp+" in normalized)
                and "," in normalized
                and normalized.split(",", 1)[0].endswith("]")
            )
        )
    if opcode == "call":
        # MSVC's CRT entry thunk is `call __security_init_cookie; jmp mainCRTStartup`.
        return bool(len(text) > 1 and text[1].startswith("jmp "))
    if opcode == "jmp" and _depth == 0:
        match = re.search(r"0x[0-9a-f]+", operands)
        if match:
            return _oep_looks_like_prologue(match.group(0), _depth=1)
    return False


def _oep_accept(rip_hex: Optional[str], section_plan: Dict[str, Any]) -> Dict[str, Any]:
    result = {"accepted": False, "rip": rip_hex, "confidence": None, "reason": ""}
    if not rip_hex:
        result["reason"] = "no rip"
        return result
    rip_int = int(rip_hex, 16)
    base_int = int(section_plan.get("baseInt") or 0)
    entry_int = int(section_plan.get("entryInt") or 0)
    exec_sections = section_plan.get("execSections") or []
    entry_section = str(section_plan.get("entrySection") or "").strip().lower()
    layout = section_plan.get("layout") or {}
    size_of_image = int(layout.get("sizeOfImage") or 0)
    if base_int and size_of_image and not (base_int <= rip_int < base_int + size_of_image):
        result["reason"] = "rip outside the image"
        return result
    section = _section_for_runtime_address(rip_int, exec_sections)
    if not section:
        result["reason"] = "rip not in an executable section"
        return result
    if entry_section and str(section.get("nameLower") or "") == entry_section:
        result["reason"] = f"rip still in packer/entry section {section.get('name')}"
        return result
    distance = abs(rip_int - entry_int)
    prologue_ok = _oep_looks_like_prologue(rip_hex)
    result.update(
        {
            "accepted": True,
            "confidence": "high" if prologue_ok else "medium",
            "section": section.get("name"),
            "distanceFromEntry": f"0x{distance:x}",
            "prologueLooksReal": prologue_ok,
            "reason": f"section-hop into {section.get('name') or '<unnamed>'} at {rip_hex}",
        }
    )
    return result


def _oep_exception_history_cursor() -> int:
    """Return a stable exclusive cursor without mutating exception history."""

    try:
        payload = GetExceptionHistory(after_seq=0, limit=1)
    except Exception:
        return 0
    if not isinstance(payload, dict) or not payload.get("ok"):
        return 0
    try:
        return max(
            int(payload.get("latestSeq") or 0),
            int(payload.get("nextAfterSeq") or 0),
        )
    except (TypeError, ValueError):
        return 0


def _oep_collect_exception_history(after_seq: int) -> Dict[str, Any]:
    """Collect a bounded, causally ordered exception delta for this workflow."""

    cursor = max(0, int(after_seq or 0))
    records: List[Dict[str, Any]] = []
    truncated = False
    error: Optional[str] = None
    for _ in range(4):
        try:
            payload = GetExceptionHistory(after_seq=cursor, limit=256)
        except Exception as exc:
            error = str(exc)
            break
        if not isinstance(payload, dict) or not payload.get("ok"):
            error = str(
                (payload or {}).get("error")
                if isinstance(payload, dict)
                else payload
            )
            break
        page = payload.get("records")
        if not isinstance(page, list):
            page = payload.get("history")
        page = page if isinstance(page, list) else []
        for item in page:
            if not isinstance(item, dict):
                continue
            records.append(
                {
                    key: item.get(key)
                    for key in (
                        "historySeq",
                        "eventSeq",
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
                        "requestedDisposition",
                        "appliedDisposition",
                        "outcome",
                        "continuationSource",
                    )
                    if item.get(key) not in (None, "")
                }
            )
        next_cursor = int(payload.get("nextAfterSeq") or cursor)
        if next_cursor <= cursor:
            break
        cursor = next_cursor
        if not bool(payload.get("hasMore")):
            break
    else:
        truncated = True
    return {
        "afterSeq": max(0, int(after_seq or 0)),
        "nextAfterSeq": cursor,
        "records": records,
        "count": len(records),
        "firstChanceCount": sum(
            1
            for item in records
            if bool(item.get("firstChance"))
            or str(item.get("chance") or "").lower() == "first"
        ),
        "secondChanceCount": sum(
            1
            for item in records
            if item.get("firstChance") is False
            or str(item.get("chance") or "").lower() == "second"
        ),
        "truncated": truncated,
        "error": error,
    }


def _oep_append_transition(
    telem: Dict[str, Any],
    phase: str,
    state: Optional[Dict[str, Any]] = None,
    **evidence: Any,
) -> None:
    multi = telem.setdefault("multiStage", {})
    transitions = multi.setdefault("transitions", [])
    if len(transitions) >= 128:
        multi["transitionsTruncated"] = True
        return
    state = state if isinstance(state, dict) else {}
    session = state.get("session") if isinstance(state.get("session"), dict) else {}
    item = {
        "seq": len(transitions) + 1,
        "phase": str(phase),
        "observedAt": _now_iso(),
        "eventSeq": int(state.get("eventSeq") or session.get("eventSeq") or 0),
        "threadId": state.get("threadId") or session.get("threadId"),
        "rip": _normalize_hex(
            state.get("rip") or session.get("ip") or evidence.get("address")
        ),
    }
    item.update({key: value for key, value in evidence.items() if value is not None})
    transitions.append(item)


def _oep_run_to_entry(
    entry_hex: str,
    deadline: float,
    tls_callbacks: Optional[List[Dict[str, Any]]] = None,
    telem: Optional[Dict[str, Any]] = None,
) -> bool:
    """Reach the module entry while preserving TLS/SEH causal evidence.

    Entry and statically declared TLS callback breakpoints are held through the
    session-bound lease manager, so pre-existing/user-modified breakpoints are
    never removed by this workflow. First-chance exceptions are passed to the
    debuggee so its VEH/SEH machinery retains normal semantics; second chance is
    recorded and stops the OEP hunt rather than forcing a crash.
    """

    telemetry = telem if isinstance(telem, dict) else {"notes": []}
    multi = telemetry.setdefault("multiStage", {})
    callbacks = [
        dict(item)
        for item in list(tls_callbacks or [])
        if isinstance(item, dict) and _normalize_hex(item.get("runtimeVa"))
    ][:64]
    multi["tlsCallbacksConfigured"] = callbacks
    workflow_id = f"oep-entry-{uuid.uuid4().hex[:16]}"
    lease_ms = max(5000, min(int(max(0.0, deadline - time.time()) * 1000) + 5000, 120000))
    leases: List[str] = []

    def acquire(address: str, name: str, required: bool) -> bool:
        result = AcquireBreakpointLease(
            address,
            workflow_id=workflow_id,
            breakpoint_type="normal",
            lease_ms=lease_ms,
            name=name,
        )
        if isinstance(result, dict) and result.get("ok") and result.get("leaseId"):
            leases.append(str(result["leaseId"]))
            return True
        telemetry.setdefault("notes", []).append(
            f"{name}: breakpoint lease failed: "
            f"{(result or {}).get('error') if isinstance(result, dict) else result}"
        )
        return not required

    regs, st = _oep_read_state()
    rip = _oep_norm_rip(regs, st)
    try:
        if rip and int(rip, 16) == int(entry_hex, 16):
            _oep_append_transition(telemetry, "entry", st, address=rip)
            return True
    except Exception:
        pass
    entry_int = int(entry_hex, 16)
    if not acquire(entry_hex, "mcp-oep-entry", required=True):
        return False
    callback_by_va = {
        int(str(item["runtimeVa"]), 16): item
        for item in callbacks
        if item.get("runtimeVa")
    }
    for callback_va, callback in callback_by_va.items():
        acquire(
            f"0x{callback_va:x}",
            f"mcp-oep-tls-{int(callback.get('index') or 0)}",
            required=False,
        )
    try:
        # Loop past intermediate loader stops (DLL-load / TLS / system events)
        # until the entry breakpoint actually fires. A single DebugRun often
        # lands on a DLL-load event well before the exe entry.
        seen_events = set()
        for _ in range(128):
            if time.time() >= deadline:
                break
            # The workflow can be invoked while launch is already paused on a
            # TLS callback's first-chance exception. Claim its disposition
            # before issuing Run; otherwise a generic run may preserve the
            # debugger-side pause/swallow behavior and never reach the entry.
            _, pre_state = _oep_read_state()
            pre_session = (
                pre_state.get("session")
                if isinstance(pre_state.get("session"), dict)
                else {}
            )
            pre_code = (
                pre_state.get("exceptionCode")
                or pre_session.get("exceptionCode")
                or "0x0"
            )
            pre_pending = bool(
                pre_session.get("exceptionPending")
                or (
                    str(pre_code).lower() not in {"", "0", "0x0"}
                    and str(
                        pre_state.get("stopReason")
                        or pre_session.get("stopReason")
                        or ""
                    ).lower()
                    == "exception"
                )
            )
            if pre_pending and not pre_session.get(
                "exceptionContinuationClaimed"
            ):
                pre_first = bool(
                    pre_state.get("exceptionFirstChance")
                    if pre_state.get("exceptionFirstChance") is not None
                    else pre_session.get("exceptionFirstChance")
                )
                pre_event_seq = int(
                    pre_state.get("eventSeq")
                    or pre_session.get("eventSeq")
                    or 0
                )
                _oep_append_transition(
                    telemetry,
                    "exception",
                    pre_state,
                    address=(
                        pre_state.get("exceptionAddress")
                        or pre_session.get("address")
                        or _oep_norm_rip(
                            pre_state.get("registers") or {}, pre_state
                        )
                    ),
                    exceptionCode=str(pre_code),
                    chance="first" if pre_first else "second",
                    observedBeforeRun=True,
                )
                if not pre_first:
                    telemetry.setdefault("notes", []).append(
                        "pre-entry second-chance exception stopped OEP workflow"
                    )
                    return False
                continuation = ContinueException(
                    disposition="not_handled",
                    expected_event_seq=pre_event_seq,
                    resume=False,
                )
                if not (
                    isinstance(continuation, dict) and continuation.get("ok")
                ):
                    telemetry.setdefault("notes", []).append(
                        "pre-entry exception pass failed: "
                        + str(
                            (continuation or {}).get("error")
                            if isinstance(continuation, dict)
                            else continuation
                        )
                    )
                    return False
            DebugRun()
            remaining = max(500, int((deadline - time.time()) * 1000))
            state = WaitForPause(timeout_ms=min(remaining, 8000), poll_ms=100)
            if not isinstance(state, dict):
                break
            if state.get("state") in ("exited", "not_debugging"):
                _oep_append_transition(telemetry, "exit_before_entry", state)
                break
            if state.get("timedOut"):
                continue
            regs, st = _oep_read_state()
            rip = _oep_norm_rip(regs, st)
            session = st.get("session") if isinstance(st.get("session"), dict) else {}
            event_seq = int(st.get("eventSeq") or session.get("eventSeq") or 0)
            event_key = (
                event_seq,
                str(st.get("stopReason") or session.get("stopReason") or ""),
                rip,
            )
            is_new_event = event_key not in seen_events
            if not is_new_event:
                telemetry.setdefault("notes", []).append(
                    f"pre-entry duplicate stop suppressed eventSeq={event_seq}"
                )
            else:
                seen_events.add(event_key)
            if rip and int(rip, 16) == entry_int:
                _oep_append_transition(telemetry, "entry", st, address=rip)
                return True
            rip_int = int(rip, 16) if rip else 0
            callback = callback_by_va.get(rip_int)
            if callback:
                _oep_append_transition(
                    telemetry,
                    "tls_callback",
                    st,
                    address=rip,
                    callbackIndex=int(callback.get("index") or 0),
                    callbackRva=callback.get("rva"),
                    callbackSection=callback.get("section"),
                )
                continue
            exception_code = (
                st.get("exceptionCode")
                or session.get("exceptionCode")
                or "0x0"
            )
            exception_pending = bool(
                session.get("exceptionPending")
                or (
                    str(exception_code).lower() not in {"", "0", "0x0"}
                    and str(
                        st.get("stopReason") or session.get("stopReason") or ""
                    ).lower()
                    == "exception"
                )
            )
            if exception_pending:
                first_chance = bool(
                    st.get("exceptionFirstChance")
                    if st.get("exceptionFirstChance") is not None
                    else session.get("exceptionFirstChance")
                )
                _oep_append_transition(
                    telemetry,
                    "exception",
                    st,
                    address=(
                        st.get("exceptionAddress")
                        or session.get("address")
                        or rip
                    ),
                    exceptionCode=str(exception_code),
                    chance="first" if first_chance else "second",
                )
                if not first_chance:
                    telemetry.setdefault("notes", []).append(
                        "pre-entry second-chance exception stopped OEP workflow"
                    )
                    return False
                continuation = ContinueException(
                    disposition="not_handled",
                    expected_event_seq=event_seq,
                    resume=False,
                )
                if not (
                    isinstance(continuation, dict) and continuation.get("ok")
                ):
                    telemetry.setdefault("notes", []).append(
                        "pre-entry exception pass failed: "
                        + str(
                            (continuation or {}).get("error")
                            if isinstance(continuation, dict)
                            else continuation
                        )
                    )
                    return False
                continue
            if is_new_event:
                # Kept for defensive completeness; ordinary transitions are
                # deliberately bounded to avoid bloating workflow artifacts.
                _oep_append_transition(telemetry, "loader_stop", st, address=rip)
        return False
    finally:
        for lease_id in reversed(leases):
            try:
                released = ReleaseBreakpointLease(lease_id)
                if isinstance(released, dict) and not released.get("ok"):
                    telemetry.setdefault("notes", []).append(
                        f"breakpoint lease release failed: {released.get('error')}"
                    )
            except Exception as exc:
                telemetry.setdefault("notes", []).append(
                    f"breakpoint lease release exception: {exc}"
                )


def _oep_layer_esp(
    entry_hex: str,
    ptr: int,
    section_cond: str,
    section_plan: Dict[str, Any],
    deadline: float,
    telem: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Primary: context-save anchor (HW access BP) fast-forward + section-hop trace."""
    regs, _ = _oep_read_state()
    entry_rsp = _oep_reg_int(regs, "rsp", "csp", "esp")
    if not entry_rsp:
        telem["notes"].append("esp: no stack pointer")
        return None
    DebugStepIn()
    regs2, st2 = _oep_read_state()
    new_rsp = _oep_reg_int(regs2, "rsp", "csp", "esp")
    if not new_rsp or new_rsp >= entry_rsp:
        telem["notes"].append("esp: entry did not save a context on the stack; layer skipped")
        return None
    # Anchor on the OUTERMOST saved slot (entry_rsp - pointer): written by the
    # first push and read LAST by the final restore, right before the tail jump.
    # Works for push/pushad/pushfd (any stack growth), x86 and x64.
    anchor = entry_rsp - ptr
    anchor_hex = f"0x{anchor:x}"
    hw = SetHardwareBreakpoint(anchor_hex, "access")
    telem["notes"].append(
        f"esp anchor {anchor_hex} hw={hw.get('success') if isinstance(hw, dict) else hw}"
    )
    if not (isinstance(hw, dict) and hw.get("success")):
        return None
    try:
        DebugRun()
        remaining = max(1000, int((deadline - time.time()) * 1000))
        state = WaitForPause(timeout_ms=min(remaining, 15000), poll_ms=100)
        if not isinstance(state, dict) or state.get("state") in ("exited", "not_debugging"):
            telem["notes"].append("esp: target exited before the anchor was restored")
            return None
    finally:
        try:
            DeleteHardwareBreakpoint(anchor_hex)
        except Exception:
            pass
    telem["reArms"] += 1
    regs_anchor, state_anchor = _oep_read_state()
    anchor_rip = _oep_norm_rip(regs_anchor, state_anchor)
    anchor_section = (
        _section_for_runtime_address(
            int(anchor_rip, 16),
            list(section_plan.get("execSections") or []),
        )
        if anchor_rip
        else None
    )
    if anchor_rip and anchor_section:
        candidate_evidence = _oep_runtime_disk_evidence(
            int(anchor_rip, 16), anchor_section, section_plan, span=16
        )
        section_evidence = _oep_section_mutation_evidence(
            anchor_section, section_plan
        )
        decision = _oep_same_section_refinement_decision(
            known_loader_shape=False,
            candidate_evidence=candidate_evidence,
            section_evidence=section_evidence,
        )
        if decision.get("refine"):
            telem["sameSectionAnchorEvidence"] = decision
            refined = _oep_trace_same_section_transfer(
                anchor_rip,
                anchor_section,
                section_plan,
                deadline,
                telem,
            )
            refined["sameSectionEvidence"] = decision
            return refined
    _oep_trace_to_sections(section_cond, deadline)
    regs3, st3 = _oep_read_state()
    if st3.get("state") in ("exited", "not_debugging"):
        telem["notes"].append("esp: target exited during the section-hop trace")
        return None
    verdict = _oep_accept(_oep_norm_rip(regs3, st3), section_plan)
    return _oep_refine_loader_stage_candidate(
        verdict, section_plan, deadline, telem
    )


def _oep_entry_section_entropy(section_plan: Dict[str, Any]) -> float:
    layout = section_plan.get("layout") or {}
    entry_section = layout.get("entrySection") if isinstance(layout, dict) else None
    if isinstance(entry_section, dict):
        try:
            return float(entry_section.get("entropy") or 0.0)
        except Exception:
            return 0.0
    return 0.0


def _oep_engine(
    module: Dict[str, Any],
    image_path: str,
    section_plan: Dict[str, Any],
    timeout_ms: int = 30000,
) -> Dict[str, Any]:
    """Packer-agnostic OEP detection. Returns a candidate + confidence + telemetry.
    Does NOT dump. Cleans up its own breakpoints."""
    deadline = time.time() + max(int(timeout_ms), 1000) / 1000.0
    layout = section_plan.get("layout") or {}
    arch = str(layout.get("arch") or "x64")
    ptr = 8 if arch == "x64" else 4
    entry_int = int(section_plan.get("entryInt") or 0)
    entry_hex = section_plan.get("entry") or f"0x{entry_int:x}"
    exec_sections = section_plan.get("execSections") or []
    entry_section = str(section_plan.get("entrySection") or "").strip().lower()
    non_stub = [
        s for s in exec_sections if str(s.get("nameLower") or "") != entry_section
    ]
    if not non_stub:
        non_stub = list(exec_sections)
    section_cond = _oep_section_condition(non_stub)
    telem: Dict[str, Any] = {
        "layerReached": None,
        "reArms": 0,
        "arch": arch,
        "sectionCond": section_cond,
        "notes": [],
        "multiStage": {
            "schema": "oep-multistage-evidence-v1",
            "tlsCallbacksConfigured": list(section_plan.get("tlsCallbacks") or []),
            "transitions": [],
            "exceptionCursorStart": _oep_exception_history_cursor(),
        },
    }

    def _finalize_multistage() -> None:
        multi = telem.setdefault("multiStage", {})
        if isinstance(multi.get("exceptionHistory"), dict):
            return
        history = _oep_collect_exception_history(
            int(multi.get("exceptionCursorStart") or 0)
        )
        multi["exceptionHistory"] = history
        transitions = list(multi.get("transitions") or [])
        multi["tlsCallbackHitCount"] = sum(
            1 for item in transitions if item.get("phase") == "tls_callback"
        )
        multi["exceptionTransitionCount"] = sum(
            1 for item in transitions if item.get("phase") == "exception"
        )
        multi["reachedEntry"] = any(
            item.get("phase") == "entry" for item in transitions
        )

    def _success(rip_hex: str, layer: str, verdict: Dict[str, Any]) -> Dict[str, Any]:
        telem["layerReached"] = layer
        _finalize_multistage()
        return {
            "ok": True,
            "oepAddr": rip_hex,
            "confidence": verdict.get("confidence"),
            "candidateSection": verdict.get("section"),
            "distanceFromEntry": verdict.get("distanceFromEntry"),
            "detectedVia": f"{layer}: {verdict.get('reason')}",
            "isLikelyVirtualized": False,
            "telemetry": telem,
        }

    # Layer 0 — already sitting at a valid OEP?
    regs, st = _oep_read_state()
    initial_session = (
        st.get("session") if isinstance(st.get("session"), dict) else {}
    )
    if bool(initial_session.get("exceptionPending")):
        multi = telem.setdefault("multiStage", {})
        multi["exceptionCursorStart"] = max(
            0, int(multi.get("exceptionCursorStart") or 0) - 1
        )
    cur_rip = _oep_norm_rip(regs, st)
    verdict0 = _oep_accept(cur_rip, section_plan)
    if verdict0.get("accepted"):
        verdict0 = _oep_refine_loader_stage_candidate(
            verdict0, section_plan, deadline, telem
        )
        if verdict0.get("accepted"):
            return _success(str(verdict0.get("rip") or cur_rip), "current_state", verdict0)
    if cur_rip:
        current_section = _section_for_runtime_address(
            int(cur_rip, 16), list(exec_sections)
        )
        if current_section:
            current_evidence = _oep_runtime_disk_evidence(
                int(cur_rip, 16), current_section, section_plan, span=16
            )
            current_section_evidence = _oep_section_mutation_evidence(
                current_section, section_plan
            )
            current_decision = _oep_same_section_refinement_decision(
                known_loader_shape=False,
                candidate_evidence=current_evidence,
                section_evidence=current_section_evidence,
            )
            if current_decision.get("refine"):
                telem["sameSectionCurrentEvidence"] = current_decision
                current_refined = _oep_trace_same_section_transfer(
                    cur_rip,
                    current_section,
                    section_plan,
                    deadline,
                    telem,
                )
                current_refined["sameSectionEvidence"] = current_decision
                if current_refined.get("accepted"):
                    return _success(
                        str(current_refined.get("rip")),
                        "current_state+same_section",
                        current_refined,
                    )

    # Reach the module entry (fresh stub) for the ESP trick.
    at_entry = _oep_run_to_entry(
        entry_hex,
        deadline,
        tls_callbacks=list(section_plan.get("tlsCallbacks") or []),
        telem=telem,
    )
    telem["notes"].append(f"reachedEntry={at_entry}")

    # Single-executable-section / TLS-unpacker case (e.g. MPRESS): there is no
    # distinct section to hop into. Such packers unpack before/at the entry
    # (often via a TLS callback), so the reached entry IS the OEP. Propose it and
    # let dump verification confirm — a still-packed stub here fails verification
    # (unresolved/corrupt/trivial IAT), so this cannot fake success. Checked
    # BEFORE the ESP layer so we do not single-step past the entry.
    exec_lowers = {str(s.get("nameLower") or "") for s in exec_sections}
    single_exec = len(exec_sections) <= 1 or exec_lowers <= {entry_section}
    if at_entry and single_exec and time.time() < deadline:
        regs_e, st_e = _oep_read_state()
        rip_e = _oep_norm_rip(regs_e, st_e)
        if rip_e and int(rip_e, 16) == entry_int and _oep_looks_like_prologue(rip_e):
            sec_e = _section_for_runtime_address(int(rip_e, 16), exec_sections)
            entry_evidence = (
                _oep_runtime_disk_evidence(
                    int(rip_e, 16), sec_e, section_plan, span=16
                )
                if sec_e
                else {}
            )
            entry_section_evidence = (
                _oep_section_mutation_evidence(sec_e, section_plan)
                if sec_e
                else {}
            )
            entry_decision = _oep_same_section_refinement_decision(
                known_loader_shape=False,
                candidate_evidence=entry_evidence,
                section_evidence=entry_section_evidence,
            )
            if entry_decision.get("refine") and sec_e:
                telem["sameSectionEntryEvidence"] = entry_decision
                entry_refined = _oep_trace_same_section_transfer(
                    rip_e,
                    sec_e,
                    section_plan,
                    deadline,
                    telem,
                )
                entry_refined["sameSectionEvidence"] = entry_decision
                if entry_refined.get("accepted"):
                    return _success(
                        str(entry_refined.get("rip")),
                        "entry+same_section",
                        entry_refined,
                    )
            else:
                verdict_e = {
                    "accepted": True,
                    "confidence": "low",
                    "section": (sec_e or {}).get("name") if sec_e else None,
                    "distanceFromEntry": "0x0",
                    "reason": f"single-section entry accepted as OEP at {rip_e} (verification-gated)",
                }
                return _success(rip_e, "entry_as_oep", verdict_e)

    # Layer P-ESP (primary)
    if at_entry and time.time() < deadline:
        esp = _oep_layer_esp(entry_hex, ptr, section_cond, section_plan, deadline, telem)
        if isinstance(esp, dict) and esp.get("accepted"):
            return _success(esp["rip"], "esp+trace", esp)

    # Fallback — section-hop trace from the current state (short-tail stubs).
    if time.time() < deadline and section_cond:
        settled = _oep_trace_to_sections(section_cond, deadline)
        if isinstance(settled, dict) and settled.get("state") not in (
            "exited",
            "not_debugging",
        ):
            regs2, st2 = _oep_read_state()
            verdict2 = _oep_accept(_oep_norm_rip(regs2, st2), section_plan)
            if verdict2.get("accepted"):
                verdict2 = _oep_refine_loader_stage_candidate(
                    verdict2, section_plan, deadline, telem
                )
                if verdict2.get("accepted"):
                    return _success(verdict2["rip"], "trace_from_state", verdict2)

    # Honest failure. State the fact (no OEP reached); flag virtualization only as
    # a hypothesis when the target is still alive churning without a clean hop —
    # do NOT key it on entropy, since a legitimate packer stub is high-entropy too.
    _, st_final = _oep_read_state()
    exited = st_final.get("state") in ("exited", "not_debugging")
    is_virt = not exited
    telem["layerReached"] = telem["layerReached"] or "exhausted"
    _finalize_multistage()
    return {
        "ok": False,
        "oepAddr": None,
        "reason": "target_exited" if exited else "oep_not_found_timeout",
        "isLikelyVirtualized": is_virt,
        "hint": (
            "The target exited before an OEP was reached."
            if exited
            else (
                "No clean OEP was reached within the budget. The target may use a "
                "virtualizing protector or an unpacking scheme this engine does not "
                "handle; the optional virtualization research backend is disabled."
            )
        ),
        "entrySectionEntropy": round(_oep_entry_section_entropy(section_plan), 3),
        "detectedVia": "",
        "telemetry": telem,
    }


def _pe_import_evidence(layout: Dict[str, Any]) -> Dict[str, Any]:
    descriptors = list(layout.get("imports") or [])
    pairs: set = set()
    dll_names: List[str] = []
    bad_dlls: List[str] = []
    unresolved_functions: List[Dict[str, str]] = []
    function_count = 0
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            bad_dlls.append(str(descriptor))
            continue
        dll_name = str(descriptor.get("dll") or "").strip()
        dll_names.append(dll_name)
        dll_valid = bool(
            dll_name
            and dll_name not in ("?", ".", "..")
            and len(dll_name) <= 260
            and re.fullmatch(r"[A-Za-z0-9_.+\-]+", dll_name)
        )
        if not dll_valid:
            bad_dlls.append(dll_name)
        normalized_dll = os.path.basename(dll_name).casefold()
        for raw_function in list(descriptor.get("functions") or []):
            function = str(raw_function or "").strip()
            function_count += 1
            unresolved = (
                not function
                or function == "?"
                or function.lower().startswith("rva:")
                or any(ord(char) < 0x20 for char in function)
            )
            if unresolved:
                unresolved_functions.append({"dll": dll_name, "function": function})
            else:
                pairs.add((normalized_dll, function.casefold()))
    return {
        "descriptorCount": len(descriptors),
        "functionCount": function_count,
        "dllNames": dll_names,
        "badDllNames": bad_dlls,
        "unresolvedFunctions": unresolved_functions,
        "pairs": pairs,
    }


def _verify_pe_dump(
    path: str,
    source_path: str = "",
    expected_entrypoint: str = "",
    module_base: str = "",
    require_imports: bool = True,
    strict_source_imports: bool = True,
    check_dependencies: bool = True,
) -> Dict[str, Any]:
    resolved = os.path.abspath(str(path or ""))
    errors: List[str] = []
    warnings_list: List[str] = []
    checks: Dict[str, Any] = {}
    if not resolved or not os.path.isfile(resolved):
        return {
            "ok": False,
            "verified": False,
            "runnableCandidate": False,
            "path": resolved,
            "errors": ["PE dump file was not found"],
            "warnings": [],
            "checks": checks,
        }
    file_size = os.path.getsize(resolved)
    try:
        layout = _parse_pe_layout(resolved)
    except Exception as exc:
        return {
            "ok": False,
            "verified": False,
            "runnableCandidate": False,
            "path": resolved,
            "size": file_size,
            "errors": [f"PE parse failed: {exc}"],
            "warnings": [],
            "checks": checks,
        }

    size_of_image = int(layout.get("sizeOfImage") or 0)
    size_of_headers = int(layout.get("sizeOfHeaders") or 0)
    entry_rva = _parse_int(layout.get("entryPointRva"), 0) or 0
    sections = list(layout.get("sections") or [])
    checks.update(
        {
            "arch": layout.get("arch"),
            "imageBase": layout.get("imageBase"),
            "entryPointRva": layout.get("entryPointRva"),
            "sizeOfImage": size_of_image,
            "sizeOfHeaders": size_of_headers,
            "sectionCount": len(sections),
            "dynamicBase": bool(layout.get("dynamicBase")),
            "highEntropyVa": bool(layout.get("highEntropyVa")),
            "iatDirectory": layout.get("iatDirectory"),
        }
    )
    if size_of_headers <= 0 or size_of_headers > file_size:
        errors.append("SizeOfHeaders is outside the file")
    if size_of_image <= 0 or not sections:
        errors.append("PE image has no usable image/section layout")
    if entry_rva and entry_rva >= size_of_image:
        errors.append("Entry point is outside SizeOfImage")
    entry_section = layout.get("entrySection")
    is_dll = bool((_parse_int(layout.get("characteristics"), 0) or 0) & 0x2000)
    if entry_rva and (not isinstance(entry_section, dict) or not entry_section.get("executable")):
        errors.append("Entry point is not inside an executable section")
    if not entry_rva and not is_dll:
        warnings_list.append("Executable image has a zero entry point")

    raw_ranges: List[Tuple[int, int, str]] = []
    for section in sections:
        name = str(section.get("name") or "")
        raw_pointer = int(section.get("rawPointer") or 0)
        raw_size = int(section.get("rawSize") or 0)
        virtual_address = int(section.get("virtualAddress") or 0)
        virtual_size = max(int(section.get("virtualSize") or 0), raw_size)
        if raw_size:
            if not _minidump_range_valid(raw_pointer, raw_size, file_size):
                errors.append(f"Section {name!r} raw data is outside the file")
            else:
                raw_ranges.append((raw_pointer, raw_pointer + raw_size, name))
        if size_of_image and virtual_address + virtual_size > size_of_image:
            errors.append(f"Section {name!r} exceeds SizeOfImage")
    for index, left in enumerate(sorted(raw_ranges)):
        for right in sorted(raw_ranges)[index + 1 : index + 2]:
            if right[0] < left[1]:
                errors.append(f"Sections {left[2]!r} and {right[2]!r} overlap on disk")

    import_evidence = _pe_import_evidence(layout)
    checks["imports"] = {
        key: value
        for key, value in import_evidence.items()
        if key != "pairs"
    }
    if import_evidence["badDllNames"]:
        errors.append("Import table contains invalid DLL names")
    if import_evidence["unresolvedFunctions"]:
        errors.append("Import table contains unresolved function names")
    if require_imports and int(import_evidence["functionCount"]) == 0:
        errors.append("Import table is empty")
    iat_directory = layout.get("iatDirectory") or {}
    if int(import_evidence["functionCount"]) > 0 and int(iat_directory.get("size") or 0) <= 0:
        warnings_list.append("Imports exist but IMAGE_DIRECTORY_ENTRY_IAT is empty")

    source_result: Optional[Dict[str, Any]] = None
    source = os.path.abspath(str(source_path or "")) if source_path else ""
    if source:
        if not os.path.isfile(source):
            errors.append("Source PE for comparison was not found")
        else:
            try:
                source_layout = _parse_pe_layout(source)
                source_evidence = _pe_import_evidence(source_layout)
                source_pairs = set(source_evidence["pairs"])
                output_pairs = set(import_evidence["pairs"])
                missing_pairs = sorted(source_pairs - output_pairs)
                coverage = (
                    (len(source_pairs) - len(missing_pairs)) / len(source_pairs)
                    if source_pairs
                    else 1.0
                )
                source_result = {
                    "path": source,
                    "arch": source_layout.get("arch"),
                    "imageBase": source_layout.get("imageBase"),
                    "importFunctions": len(source_pairs),
                    "matchedImportFunctions": len(source_pairs) - len(missing_pairs),
                    "importCoverage": round(coverage, 6),
                    "missingImports": [
                        {"dll": dll_name, "function": function}
                        for dll_name, function in missing_pairs[:256]
                    ],
                }
                if source_layout.get("arch") != layout.get("arch"):
                    errors.append("Dump architecture differs from the source PE")
                source_image_base = _parse_int(source_layout.get("imageBase"), 0) or 0
                output_image_base = _parse_int(layout.get("imageBase"), 0) or 0
                source_result["imageBaseChanged"] = source_image_base != output_image_base
                if (
                    source_image_base
                    and output_image_base != source_image_base
                    and bool(layout.get("dynamicBase"))
                ):
                    errors.append(
                        "Relocated memory image still has ASLR enabled; loader relocations would be applied twice"
                    )
                if strict_source_imports and missing_pairs:
                    errors.append("Dump regressed imports present in the source PE")
            except Exception as exc:
                errors.append(f"Source PE comparison failed: {exc}")
    checks["sourceComparison"] = source_result

    expected = _parse_int(expected_entrypoint, None)
    if expected is not None:
        base_value = _parse_int(module_base, None)
        image_base_value = _parse_int(layout.get("imageBase"), 0) or 0
        if base_value is not None and expected >= base_value:
            expected_rva = expected - base_value
        elif image_base_value and expected >= image_base_value:
            expected_rva = expected - image_base_value
        else:
            expected_rva = expected
        checks["expectedEntryPointRva"] = f"0x{int(expected_rva):x}"
        if int(expected_rva) != int(entry_rva):
            errors.append("Dump entry point does not match the requested runtime entry point")

    dependency_result: Optional[Dict[str, Any]] = None
    if check_dependencies and not import_evidence["badDllNames"]:
        dependency_result = _find_missing_runtime_dependencies(resolved)
        if not dependency_result.get("ok"):
            warnings_list.append(str(dependency_result.get("error") or "Dependency scan failed"))
    missing_dependencies = list((dependency_result or {}).get("missing") or [])
    checks["dependencies"] = dependency_result
    verified = not errors
    runnable_candidate = bool(verified and not missing_dependencies)
    return {
        "ok": verified,
        "verified": verified,
        "runnableCandidate": runnable_candidate,
        "path": resolved,
        "size": file_size,
        "sha256": _sha256_file(resolved),
        "layout": {
            "arch": layout.get("arch"),
            "imageBase": layout.get("imageBase"),
            "entryPointRva": layout.get("entryPointRva"),
            "sizeOfImage": size_of_image,
            "sectionCount": len(sections),
            "dllCharacteristics": layout.get("dllCharacteristics"),
        },
        "errors": errors,
        "warnings": warnings_list,
        "checks": checks,
    }


@mcp.tool()
def VerifyPEDump(
    path: str,
    source_path: str = "",
    expected_entrypoint: str = "",
    module_base: str = "",
    require_imports: bool = True,
    strict_source_imports: bool = True,
    check_dependencies: bool = True,
) -> dict:
    """Validate a dumped PE structurally and reject corrupt/unresolved IAT output.

    When ``source_path`` is supplied, every source import must remain represented
    unless ``strict_source_imports`` is disabled. ``expected_entrypoint`` accepts
    an RVA or runtime VA (with ``module_base``) and is checked exactly.
    """
    return _verify_pe_dump(
        path=path,
        source_path=source_path,
        expected_entrypoint=expected_entrypoint,
        module_base=module_base,
        require_imports=require_imports,
        strict_source_imports=strict_source_imports,
        check_dependencies=check_dependencies,
    )


def _sanitize_trailing_import_descriptors(path: str) -> Dict[str, Any]:
    """Remove only a provably-invalid trailing Scylla import-descriptor tail.

    Scylla's ordinary IAT search can include a few adjacent non-IAT pointers.
    When that happens after one or more fully valid descriptors, its rebuilt PE
    contains synthetic ``*invalid*`` DLLs.  This helper is deliberately narrow:
    it refuses an invalid first descriptor and refuses any valid descriptor
    after the first invalid one.  It never guesses names or functions.
    """

    resolved = os.path.abspath(str(path or ""))
    if not resolved or not os.path.isfile(resolved):
        return {"ok": False, "changed": False, "error": "PE file not found"}
    try:
        data = bytearray(Path(resolved).read_bytes())
        if len(data) < 0x100 or data[:2] != b"MZ":
            raise ValueError("not a PE image")
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ValueError("invalid PE signature")
        section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
        optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        optional = pe_offset + 24
        magic = struct.unpack_from("<H", data, optional)[0]
        if magic not in (0x10B, 0x20B):
            raise ValueError("unsupported optional-header magic")
        is_64 = magic == 0x20B
        pointer_size = 8 if is_64 else 4
        pointer_fmt = "<Q" if is_64 else "<I"
        ordinal_mask = 0x8000000000000000 if is_64 else 0x80000000
        size_of_headers = struct.unpack_from("<I", data, optional + 60)[0]
        directory_offset = optional + (112 if is_64 else 96)
        import_directory_offset = directory_offset + 8
        iat_directory_offset = directory_offset + 12 * 8
        import_rva, import_size = struct.unpack_from(
            "<II", data, import_directory_offset
        )
        if not import_rva or import_size < 20:
            return {
                "ok": False,
                "changed": False,
                "reason": "import_directory_absent",
            }
        section_table = optional + optional_size
        sections: List[Tuple[int, int, int, int]] = []
        for index in range(section_count):
            header = section_table + index * 40
            if header + 40 > len(data):
                raise ValueError("truncated section table")
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
                "<IIII", data, header + 8
            )
            sections.append(
                (virtual_address, max(virtual_size, raw_size), raw_pointer, raw_size)
            )

        def rva_to_offset(rva: int) -> Optional[int]:
            if 0 <= rva < size_of_headers and rva < len(data):
                return rva
            for start, span, raw_pointer, raw_size in sections:
                if start <= rva < start + span:
                    delta = rva - start
                    if delta >= raw_size:
                        return None
                    offset = raw_pointer + delta
                    return offset if 0 <= offset < len(data) else None
            return None

        def read_ascii(rva: int, limit: int = 512) -> str:
            offset = rva_to_offset(rva)
            if offset is None:
                return ""
            end = data.find(b"\0", offset, min(len(data), offset + limit))
            if end < 0:
                return ""
            try:
                return bytes(data[offset:end]).decode("ascii", errors="strict")
            except UnicodeDecodeError:
                return ""

        def inspect_thunks(thunk_rva: int) -> Tuple[bool, int]:
            offset = rva_to_offset(thunk_rva)
            if offset is None:
                return False, 0
            count = 0
            for _ in range(65536):
                if offset + pointer_size > len(data):
                    return False, count
                value = struct.unpack_from(pointer_fmt, data, offset)[0]
                if value == 0:
                    return count > 0, count
                if not (value & ordinal_mask):
                    name_offset = rva_to_offset(int(value) + 2)
                    if name_offset is None:
                        return False, count
                    end = data.find(
                        b"\0", name_offset, min(len(data), name_offset + 1024)
                    )
                    if end < 0 or end == name_offset:
                        return False, count
                    raw_name = bytes(data[name_offset:end])
                    if any(byte < 0x20 or byte > 0x7E for byte in raw_name):
                        return False, count
                count += 1
                offset += pointer_size
            return False, count

        descriptor_offset = rva_to_offset(import_rva)
        if descriptor_offset is None:
            raise ValueError("import directory RVA is not file-backed")
        records: List[Dict[str, Any]] = []
        terminator_offset: Optional[int] = None
        max_descriptors = min(4096, max(1, import_size // 20 + 8))
        cursor = descriptor_offset
        for index in range(max_descriptors):
            if cursor + 20 > len(data):
                break
            oft, _, _, name_rva, first_thunk = struct.unpack_from(
                "<IIIII", data, cursor
            )
            if not any((oft, name_rva, first_thunk)):
                terminator_offset = cursor
                break
            dll_name = read_ascii(name_rva)
            dll_valid = bool(
                dll_name
                and len(dll_name) <= 260
                and re.fullmatch(r"[A-Za-z0-9_.+\-]+", dll_name)
                and dll_name not in {"?", ".", ".."}
            )
            thunk_valid, thunk_count = inspect_thunks(oft or first_thunk)
            records.append(
                {
                    "index": index,
                    "offset": cursor,
                    "dll": dll_name or None,
                    "valid": bool(dll_valid and thunk_valid and first_thunk),
                    "thunkCount": thunk_count,
                    "firstThunk": first_thunk,
                }
            )
            cursor += 20
        first_invalid = next(
            (index for index, item in enumerate(records) if not item["valid"]),
            None,
        )
        if first_invalid is None:
            return {
                "ok": True,
                "changed": False,
                "reason": "no_invalid_trailing_descriptors",
                "descriptors": records,
            }
        if first_invalid == 0:
            return {
                "ok": False,
                "changed": False,
                "reason": "first_descriptor_invalid",
                "descriptors": records,
            }
        if any(item["valid"] for item in records[first_invalid + 1 :]):
            return {
                "ok": False,
                "changed": False,
                "reason": "valid_descriptor_after_invalid_gap",
                "descriptors": records,
            }
        trim_offset = int(records[first_invalid]["offset"])
        zero_end = (terminator_offset + 20) if terminator_offset is not None else cursor
        data[trim_offset : min(zero_end, len(data))] = b"\0" * min(
            zero_end - trim_offset, len(data) - trim_offset
        )
        valid_records = records[:first_invalid]
        new_import_size = (len(valid_records) + 1) * 20
        struct.pack_into("<II", data, import_directory_offset, import_rva, new_import_size)
        iat_starts = [int(item["firstThunk"]) for item in valid_records]
        iat_ends = [
            int(item["firstThunk"])
            + (int(item["thunkCount"]) + 1) * pointer_size
            for item in valid_records
        ]
        new_iat_rva = min(iat_starts)
        new_iat_size = max(iat_ends) - new_iat_rva
        struct.pack_into("<II", data, iat_directory_offset, new_iat_rva, new_iat_size)
        struct.pack_into("<I", data, optional + 64, 0)
        before_sha = _sha256_file(resolved).upper()
        temporary = Path(resolved).with_name(
            Path(resolved).name + f".tmp-imports-{os.getpid()}-{time.time_ns()}"
        )
        try:
            temporary.write_bytes(data)
            os.replace(temporary, resolved)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        repaired_layout = _parse_pe_layout(resolved)
        repaired_evidence = _pe_import_evidence(repaired_layout)
        verified = bool(
            not repaired_evidence.get("badDllNames")
            and not repaired_evidence.get("unresolvedFunctions")
            and int(repaired_evidence.get("functionCount") or 0) > 0
        )
        return {
            "ok": verified,
            "changed": True,
            "reason": "trailing_invalid_descriptors_removed"
            if verified
            else "post_sanitize_verification_failed",
            "validDescriptorCount": len(valid_records),
            "trimmedDescriptorCount": len(records) - len(valid_records),
            "trimmedDescriptors": records[first_invalid:],
            "importDirectory": {"rva": f"0x{import_rva:X}", "size": new_import_size},
            "iatDirectory": {"rva": f"0x{new_iat_rva:X}", "size": new_iat_size},
            "sha256Before": before_sha,
            "sha256After": _sha256_file(resolved).upper(),
            "verification": {
                "functionCount": repaired_evidence.get("functionCount"),
                "badDllNames": repaired_evidence.get("badDllNames"),
                "unresolvedFunctions": repaired_evidence.get("unresolvedFunctions"),
            },
        }
    except Exception as exc:
        return {
            "ok": False,
            "changed": False,
            "reason": "sanitize_failed",
            "error": str(exc),
        }


def _oep_verify_dump(
    oep_hex: str,
    base_int: int,
    fixed_path: str,
    packed_layout: Dict[str, Any],
    dump_payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Gate ok:true on a real unpacked dump: valid PE, entry moved out of the
    packer stub to the discovered OEP, IAT resolved, imports richer than the
    packed baseline. Never trusts mere file existence."""
    checks: Dict[str, Any] = {}
    payload = dump_payload if isinstance(dump_payload, dict) else {}
    inner = payload.get("dumpResult") if isinstance(payload.get("dumpResult"), dict) else payload

    def _verdict(verified: bool, reason: str) -> Dict[str, Any]:
        iat_resolved: Optional[bool] = None
        if "iatSize" in checks:
            iat_resolved = bool(int(checks.get("iatSize") or 0) > 0)
            if checks.get("badImportDlls") or checks.get("unresolvedImports"):
                iat_resolved = False
        entry_matches: Optional[bool] = None
        if checks.get("dumpEntryRva") is not None and checks.get("oepRva") is not None:
            entry_matches = checks.get("dumpEntryRva") == checks.get("oepRva")
        return {
            "verified": bool(verified),
            "reason": reason,
            "iatResolved": iat_resolved,
            "entryMatches": entry_matches,
            "dumpImportCount": checks.get("dumpImportFuncs"),
            "packedImportCount": checks.get("packedImportFuncs"),
            "checks": checks,
        }

    if not (fixed_path and os.path.exists(fixed_path)):
        return _verdict(False, "dump_no_fixed_file")
    try:
        iat_size = int(str(inner.get("iatSize") or "0"), 16)
    except Exception:
        iat_size = 0
    checks["iatSize"] = iat_size
    checks["searchResult"] = inner.get("searchResultName") or inner.get("searchResult")
    if iat_size <= 0:
        return _verdict(False, "dump_iat_unresolved")

    try:
        dump_layout = _parse_pe_layout(fixed_path)
    except Exception as exc:
        checks["parseError"] = str(exc)
        return _verdict(False, "dump_unparseable")

    dump_entry_rva = int(str(dump_layout.get("entryPointRva") or "0x0"), 16)
    packed_entry_rva = int(str(packed_layout.get("entryPointRva") or "0x0"), 16)
    oep_rva = int(oep_hex, 16) - int(base_int or 0)
    checks["dumpEntryRva"] = f"0x{dump_entry_rva:x}"
    checks["packedEntryRva"] = f"0x{packed_entry_rva:x}"
    checks["oepRva"] = f"0x{oep_rva:x}"
    # The dump's entry must be the OEP the engine chose (Scylla honored it). We do
    # NOT require the OEP to differ from the PE entry: TLS-based unpackers (e.g.
    # MPRESS) legitimately have OEP == the original entry point. A dump that
    # merely stayed on a still-packed stub is caught by the IAT/imports gates.
    if dump_entry_rva != oep_rva:
        return _verdict(False, "dump_entry_mismatch")

    def _func_count(layout: Dict[str, Any]) -> int:
        total = 0
        for entry in layout.get("imports", []) or []:
            total += len(entry.get("functions") or [])
        return total

    # Reject a corrupt import table: over-aggressive IAT reconstruction (Scylla
    # advancedSearch) can invent bogus descriptors with garbage DLL names like
    # "?", which make the Windows loader fail with "?.DLL not found".
    import re as _re
    dump_import_evidence = _pe_import_evidence(dump_layout)
    dll_names = list(dump_import_evidence.get("dllNames") or [])
    bad_names = list(dump_import_evidence.get("badDllNames") or [])
    checks["importDlls"] = dll_names[:24]
    if bad_names:
        checks["badImportDlls"] = bad_names[:8]
        return _verdict(False, "dump_iat_corrupt")
    unresolved_functions = list(dump_import_evidence.get("unresolvedFunctions") or [])
    if unresolved_functions:
        checks["unresolvedImports"] = unresolved_functions[:16]
        return _verdict(False, "dump_iat_unresolved_names")

    packed_funcs = _func_count(packed_layout)
    dump_funcs = _func_count(dump_layout)
    checks["packedImportFuncs"] = packed_funcs
    checks["dumpImportFuncs"] = dump_funcs
    if dump_funcs < 3:
        return _verdict(False, "dump_imports_trivial")
    if packed_funcs and dump_funcs < packed_funcs:
        return _verdict(False, "dump_imports_regressed")

    return _verdict(True, "verified")


def _make_dump_runnable(path: str) -> Dict[str, Any]:
    """Clear the ASLR flags (DYNAMIC_BASE / HIGH_ENTROPY_VA) in a dumped PE so the
    loader honors its ImageBase. A memory dump's absolute addresses are bound to
    the runtime base and packers strip relocations, so without this the dump
    relocates elsewhere and faults."""
    try:
        with open(path, "rb") as handle:
            data = bytearray(handle.read())
        if data[:2] != b"MZ":
            return {"ok": False, "error": "not a PE"}
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe : pe + 4] != b"PE\x00\x00":
            return {"ok": False, "error": "bad PE header"}
        dll_char_off = pe + 24 + 0x46
        checksum_off = pe + 24 + 0x40
        before = struct.unpack_from("<H", data, dll_char_off)[0]
        checksum_before = struct.unpack_from("<I", data, checksum_off)[0]
        after = before & ~0x0040 & ~0x0020  # clear DYNAMIC_BASE + HIGH_ENTROPY_VA
        if after != before or checksum_before != 0:
            struct.pack_into("<H", data, dll_char_off, after)
            # Scylla rebuilt the checksum before this final header mutation.
            # Zero is the canonical "not supplied" value and avoids publishing
            # a stale checksum as if it were still authoritative.
            struct.pack_into("<I", data, checksum_off, 0)
            with open(path, "wb") as handle:
                handle.write(data)
        return {
            "ok": True,
            "dllCharacteristicsBefore": f"0x{before:04x}",
            "dllCharacteristicsAfter": f"0x{after:04x}",
            "aslrCleared": after != before,
            "checksumBefore": f"0x{checksum_before:08x}",
            "checksumAfter": "0x00000000",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _scylla_raw_dump_path(output_path: str) -> str:
    directory, filename = os.path.split(output_path)
    stem, ext = os.path.splitext(filename)
    ext = ext or ".bin"
    return os.path.join(directory or os.getcwd(), f"{stem}.raw{ext}")


def _align_up(value: int, alignment: int) -> int:
    alignment = max(1, int(alignment or 1))
    return (int(value) + alignment - 1) // alignment * alignment


def _oep_select_runtime_iat_candidate(
    module_base: int,
    module_size: int,
    pointer_size: int,
) -> Dict[str, Any]:
    """Choose a unique, external-only live IAT pointer run.

    The generic candidate scanner also finds vtables and arrays of pointers
    back into the main image.  An automatic unpack must never promote one of
    those to an IAT.  This selector therefore requires every pointer in the
    run to resolve into a loaded module other than the main image, requires a
    unique dominant run, and records whether the following pointer-sized slot
    is the expected zero terminator.
    """

    scanner = globals().get("FindIATCandidates")
    if not callable(scanner):
        return {
            "ok": False,
            "schema": "runtime-iat-selection-v1",
            "reason": "candidate_scanner_unavailable",
        }
    if int(module_base or 0) <= 0 or int(module_size or 0) <= 0:
        return {
            "ok": False,
            "schema": "runtime-iat-selection-v1",
            "reason": "invalid_module_range",
        }
    if pointer_size not in (4, 8):
        return {
            "ok": False,
            "schema": "runtime-iat-selection-v1",
            "reason": "invalid_pointer_size",
        }
    try:
        modules_payload = GetModuleList()
        modules = (
            list(modules_payload.get("modules") or [])
            if isinstance(modules_payload, dict)
            else []
        )
        main_names = {
            os.path.basename(str(item.get("name") or item.get("path") or "")).casefold()
            for item in modules
            if _parse_int(item.get("base"), 0) == int(module_base)
        }
        scanned = scanner(
            base=f"0x{int(module_base):x}",
            size=int(module_size),
            pointer_size=pointer_size,
            min_entries=3,
            max_candidates=128,
        )
    except Exception as exc:
        return {
            "ok": False,
            "schema": "runtime-iat-selection-v1",
            "reason": "candidate_scan_failed",
            "error": str(exc),
        }
    if not isinstance(scanned, dict) or not scanned.get("ok"):
        return {
            "ok": False,
            "schema": "runtime-iat-selection-v1",
            "reason": "candidate_scan_failed",
            "scanner": scanned,
        }

    eligible: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []
    image_end = int(module_base) + int(module_size)
    for raw in list(scanned.get("candidates") or [])[:128]:
        if not isinstance(raw, dict):
            continue
        start = _parse_int(raw.get("base"), 0) or 0
        count = max(0, int(raw.get("count") or 0))
        width = int(raw.get("pointerSize") or pointer_size)
        targets = [
            item
            for item in list(raw.get("targets") or [])
            if isinstance(item, dict)
        ]
        target_names = [
            os.path.basename(str(item.get("module") or "")).casefold()
            for item in targets
        ]
        reason = ""
        if width != pointer_size:
            reason = "pointer_width_mismatch"
        elif count < 3:
            reason = "too_short"
        elif start < int(module_base) or start + count * pointer_size > image_end:
            reason = "outside_main_image"
        elif len(targets) != count or any(not name for name in target_names):
            reason = "unresolved_target"
        elif any(name in main_names for name in target_names):
            reason = "points_into_main_image"
        if reason:
            rejected.append(
                {
                    "base": f"0x{start:x}" if start else None,
                    "count": count,
                    "reason": reason,
                }
            )
            continue
        terminated = False
        try:
            tail = _read_live_memory_exact(
                start + count * pointer_size, pointer_size
            )
            terminated = len(tail) == pointer_size and not any(tail)
        except Exception:
            terminated = False
        eligible.append(
            {
                "base": f"0x{start:x}",
                "start": start,
                "rva": f"0x{start - int(module_base):x}",
                "count": count,
                "pointerSize": pointer_size,
                "nullTerminated": terminated,
                "size": count * pointer_size
                + (pointer_size if terminated else 0),
                "targetModules": sorted(set(target_names)),
            }
        )

    eligible.sort(key=lambda item: (-int(item["count"]), int(item["start"])))
    if not eligible:
        return {
            "ok": False,
            "schema": "runtime-iat-selection-v1",
            "reason": "no_external_iat_run",
            "scannerCandidateCount": int(scanned.get("candidateCount") or 0),
            "rejected": rejected[:32],
        }
    selected = eligible[0]
    runner_up = eligible[1] if len(eligible) > 1 else None
    dominant = (
        runner_up is None
        or int(selected["count"]) >= max(8, int(runner_up["count"]) * 5 // 4)
    )
    if not dominant:
        return {
            "ok": False,
            "schema": "runtime-iat-selection-v1",
            "reason": "ambiguous_external_runs",
            "candidates": eligible[:8],
            "rejected": rejected[:32],
        }
    return {
        "ok": True,
        "schema": "runtime-iat-selection-v1",
        "selectionReason": "unique_dominant_external_pointer_run",
        "scannerCandidateCount": int(scanned.get("candidateCount") or 0),
        "eligibleCandidateCount": len(eligible),
        "start": selected["base"],
        "rva": selected["rva"],
        "size": int(selected["size"]),
        "count": int(selected["count"]),
        "pointerSize": pointer_size,
        "nullTerminated": bool(selected["nullTerminated"]),
        "targetModules": list(selected["targetModules"]),
        "runnerUpCount": int(runner_up["count"]) if runner_up else 0,
        "rejected": rejected[:32],
    }


def _oep_resolve_runtime_iat_exports(
    selection: Dict[str, Any],
    module_base: int,
) -> Dict[str, Any]:
    """Resolve every selected live IAT pointer to an exact loaded PE export."""

    if not isinstance(selection, dict) or not selection.get("ok"):
        return {
            "ok": False,
            "schema": "runtime-iat-export-resolution-v1",
            "reason": "iat_selection_unavailable",
        }
    try:
        import pefile  # type: ignore
    except Exception as exc:
        return {
            "ok": False,
            "schema": "runtime-iat-export-resolution-v1",
            "reason": "pefile_unavailable",
            "error": str(exc),
        }
    start = _parse_int(selection.get("start"), 0) or 0
    count = max(0, int(selection.get("count") or 0))
    pointer_size = int(selection.get("pointerSize") or 0)
    if not start or count < 1 or pointer_size not in (4, 8):
        return {
            "ok": False,
            "schema": "runtime-iat-export-resolution-v1",
            "reason": "invalid_selection",
        }
    try:
        raw = _read_live_memory_exact(start, count * pointer_size)
        modules_payload = GetModuleList()
        modules = (
            list(modules_payload.get("modules") or [])
            if isinstance(modules_payload, dict)
            else []
        )
    except Exception as exc:
        return {
            "ok": False,
            "schema": "runtime-iat-export-resolution-v1",
            "reason": "live_state_read_failed",
            "error": str(exc),
        }

    catalogs: List[Dict[str, Any]] = []
    catalog_errors: List[Dict[str, str]] = []
    for module in modules:
        loaded_base = _parse_int(module.get("base"), 0) or 0
        loaded_size = _parse_int(module.get("size"), 0) or 0
        path = str(module.get("path") or "")
        if (
            not loaded_base
            or not loaded_size
            or loaded_base == int(module_base)
            or not path
            or not os.path.isfile(path)
        ):
            continue
        by_rva: Dict[int, List[Dict[str, Any]]] = {}
        try:
            pe = pefile.PE(path, fast_load=False)
            export_directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
            for symbol in list(
                getattr(export_directory, "symbols", []) or []
            ):
                rva = int(getattr(symbol, "address", 0) or 0)
                if rva <= 0:
                    continue
                raw_name = getattr(symbol, "name", None)
                name = (
                    raw_name.decode("ascii", errors="strict")
                    if isinstance(raw_name, bytes)
                    else str(raw_name or "")
                )
                record = {
                    "name": name or None,
                    "ordinal": int(getattr(symbol, "ordinal", 0) or 0),
                }
                by_rva.setdefault(rva, []).append(record)
        except Exception as exc:
            catalog_errors.append(
                {
                    "module": str(module.get("name") or os.path.basename(path)),
                    "error": str(exc),
                }
            )
            continue
        if by_rva:
            catalogs.append(
                {
                    "name": os.path.basename(
                        str(module.get("name") or path)
                    ),
                    "path": path,
                    "base": loaded_base,
                    "end": loaded_base + loaded_size,
                    "exports": by_rva,
                }
            )

    entries: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, Any]] = []
    module_counts: Dict[str, int] = {}
    pointer_fmt = "<Q" if pointer_size == 8 else "<I"
    for index in range(count):
        value = struct.unpack_from(pointer_fmt, raw, index * pointer_size)[0]
        catalog = next(
            (
                item
                for item in catalogs
                if int(item["base"]) <= value < int(item["end"])
            ),
            None,
        )
        symbols = (
            list(catalog["exports"].get(value - int(catalog["base"])) or [])
            if catalog
            else []
        )
        named = [item for item in symbols if item.get("name")]
        symbol = named[0] if named else (symbols[0] if symbols else None)
        if not catalog or not symbol or (
            not symbol.get("name") and not int(symbol.get("ordinal") or 0)
        ):
            unresolved.append(
                {
                    "index": index,
                    "iatVa": f"0x{start + index * pointer_size:x}",
                    "target": f"0x{value:x}",
                    "module": catalog.get("name") if catalog else None,
                    "rva": (
                        f"0x{value - int(catalog['base']):x}"
                        if catalog
                        else None
                    ),
                }
            )
            continue
        module_name = str(catalog["name"])
        module_counts[module_name] = module_counts.get(module_name, 0) + 1
        entries.append(
            {
                "index": index,
                "iatVa": f"0x{start + index * pointer_size:x}",
                "target": f"0x{value:x}",
                "module": module_name,
                "function": symbol.get("name"),
                "ordinal": int(symbol.get("ordinal") or 0),
                "exportRva": f"0x{value - int(catalog['base']):x}",
            }
        )
    return {
        "ok": len(entries) == count and not unresolved,
        "schema": "runtime-iat-export-resolution-v1",
        "reason": "resolved" if len(entries) == count and not unresolved else "unresolved_exports",
        "start": f"0x{start:x}",
        "rva": f"0x{start - int(module_base):x}",
        "pointerSize": pointer_size,
        "count": count,
        "resolvedCount": len(entries),
        "moduleCounts": module_counts,
        "unresolved": unresolved[:64],
        "catalogErrors": catalog_errors[:16],
        "entries": entries,
    }


def _rebuild_dump_imports_from_runtime_iat(
    raw_path: str,
    output_path: str,
    module_base: int,
    selection: Dict[str, Any],
    resolution: Dict[str, Any],
    entrypoint: str = "",
    overwrite: bool = False,
) -> Dict[str, Any]:
    """Append a loader-valid import directory while preserving the live IAT.

    Consecutive pointers resolving to the same DLL form one descriptor.  Each
    descriptor gets its own terminated OriginalFirstThunk array in the new
    section, while FirstThunk points at the original restored IAT slots used by
    the program's code.  This also handles interleaved target DLLs without
    patching any code references.
    """

    source = Path(os.path.abspath(str(raw_path or "")))
    target = Path(os.path.abspath(str(output_path or "")))
    if not source.is_file():
        return {
            "ok": False,
            "schema": "runtime-iat-import-rebuild-v1",
            "reason": "raw_dump_not_found",
        }
    if target.exists() and not overwrite:
        return {
            "ok": False,
            "schema": "runtime-iat-import-rebuild-v1",
            "reason": "output_exists",
        }
    if not resolution.get("ok"):
        return {
            "ok": False,
            "schema": "runtime-iat-import-rebuild-v1",
            "reason": "export_resolution_incomplete",
            "resolution": {
                key: value
                for key, value in resolution.items()
                if key != "entries"
            },
        }
    entries = [
        dict(item)
        for item in list(resolution.get("entries") or [])
        if isinstance(item, dict)
    ]
    pointer_size = int(selection.get("pointerSize") or 0)
    iat_start = _parse_int(selection.get("start"), 0) or 0
    if (
        pointer_size not in (4, 8)
        or not iat_start
        or not entries
        or len(entries) != int(selection.get("count") or 0)
    ):
        return {
            "ok": False,
            "schema": "runtime-iat-import-rebuild-v1",
            "reason": "invalid_runtime_iat_evidence",
        }

    groups: List[Dict[str, Any]] = []
    for entry in entries:
        index = int(entry.get("index") or 0)
        module_name = os.path.basename(str(entry.get("module") or ""))
        if (
            not groups
            or str(groups[-1]["module"]).casefold() != module_name.casefold()
            or index != int(groups[-1]["entries"][-1]["index"]) + 1
        ):
            groups.append(
                {
                    "module": module_name,
                    "startIndex": index,
                    "entries": [],
                }
            )
        groups[-1]["entries"].append(entry)

    try:
        data = bytearray(source.read_bytes())
        if len(data) < 0x100 or data[:2] != b"MZ":
            raise ValueError("raw dump is not a PE image")
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if (
            pe_offset + 24 > len(data)
            or data[pe_offset : pe_offset + 4] != b"PE\0\0"
        ):
            raise ValueError("raw dump has an invalid PE signature")
        section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
        optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        optional = pe_offset + 24
        magic = struct.unpack_from("<H", data, optional)[0]
        expected_magic = 0x20B if pointer_size == 8 else 0x10B
        if magic != expected_magic:
            raise ValueError("runtime IAT width does not match dump architecture")
        size_of_image_before = struct.unpack_from("<I", data, optional + 56)[0]
        requested_entry = _parse_int(entrypoint, None)
        if requested_entry is not None:
            requested_entry_rva = (
                int(requested_entry) - int(module_base)
                if int(requested_entry) >= int(module_base)
                else int(requested_entry)
            )
            if not (
                0 <= requested_entry_rva < max(size_of_image_before, 1)
            ):
                raise ValueError("requested entrypoint is outside the dump image")
            struct.pack_into(
                "<I", data, optional + 16, requested_entry_rva
            )
        else:
            requested_entry_rva = struct.unpack_from(
                "<I", data, optional + 16
            )[0]
        section_alignment = struct.unpack_from("<I", data, optional + 32)[0]
        file_alignment = struct.unpack_from("<I", data, optional + 36)[0]
        size_of_headers = struct.unpack_from("<I", data, optional + 60)[0]
        if not section_alignment or not file_alignment:
            raise ValueError("invalid PE alignment")
        section_table = optional + optional_size
        new_header = section_table + section_count * 40
        first_raw = len(data)
        max_virtual_end = 0
        for index in range(section_count):
            header = section_table + index * 40
            if header + 40 > len(data):
                raise ValueError("truncated PE section table")
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
                "<IIII", data, header + 8
            )
            # Packed images merge original code, IAT and writable CRT/data into
            # coarse packer sections.  The stale packed header often marks the
            # restored destination read/execute only even though the unpacked
            # program writes data inside it. Scylla applies the same writable
            # normalization to its raw dump; preserve that requirement for the
            # independent memory-reconstruction path.
            section_characteristics = struct.unpack_from(
                "<I", data, header + 36
            )[0]
            struct.pack_into(
                "<I",
                data,
                header + 36,
                section_characteristics | 0x80000000,
            )
            if raw_pointer:
                first_raw = min(first_raw, raw_pointer)
            max_virtual_end = max(
                max_virtual_end,
                virtual_address + max(virtual_size, raw_size),
            )
        if new_header + 40 > min(size_of_headers, first_raw):
            raise ValueError("PE headers have no room for an import section")

        descriptor_size = (len(groups) + 1) * 20
        blob = bytearray(descriptor_size)
        for group in groups:
            group["moduleOffset"] = len(blob)
            blob.extend(str(group["module"]).encode("ascii", errors="strict") + b"\0")
        if len(blob) & 1:
            blob.append(0)
        for group in groups:
            for entry in group["entries"]:
                function_name = str(entry.get("function") or "")
                if function_name:
                    entry["nameOffset"] = len(blob)
                    blob.extend(b"\0\0")
                    blob.extend(function_name.encode("ascii", errors="strict") + b"\0")
                    if len(blob) & 1:
                        blob.append(0)
                elif not int(entry.get("ordinal") or 0):
                    raise ValueError("resolved import has neither name nor ordinal")
        while len(blob) % pointer_size:
            blob.append(0)
        pointer_fmt = "<Q" if pointer_size == 8 else "<I"
        ordinal_mask = (
            0x8000000000000000 if pointer_size == 8 else 0x80000000
        )
        new_section_rva = _align_up(max_virtual_end, section_alignment)
        for group in groups:
            group["thunkOffset"] = len(blob)
            for entry in group["entries"]:
                if entry.get("function"):
                    thunk = new_section_rva + int(entry["nameOffset"])
                else:
                    thunk = ordinal_mask | int(entry.get("ordinal") or 0)
                blob.extend(struct.pack(pointer_fmt, thunk))
            blob.extend(b"\0" * pointer_size)

        iat_rva = iat_start - int(module_base)
        for index, group in enumerate(groups):
            struct.pack_into(
                "<IIIII",
                blob,
                index * 20,
                new_section_rva + int(group["thunkOffset"]),
                0,
                0,
                new_section_rva + int(group["moduleOffset"]),
                iat_rva + int(group["startIndex"]) * pointer_size,
            )

        new_raw = _align_up(len(data), file_alignment)
        raw_size = _align_up(len(blob), file_alignment)
        if len(data) < new_raw:
            data.extend(b"\0" * (new_raw - len(data)))
        data.extend(blob)
        if len(data) < new_raw + raw_size:
            data.extend(b"\0" * (new_raw + raw_size - len(data)))

        data[new_header : new_header + 8] = b".mcpimp\0"
        struct.pack_into(
            "<IIIIIIHHI",
            data,
            new_header + 8,
            len(blob),
            new_section_rva,
            raw_size,
            new_raw,
            0,
            0,
            0,
            0,
            0xC0000040,
        )
        struct.pack_into("<H", data, pe_offset + 6, section_count + 1)
        initialized_size = struct.unpack_from("<I", data, optional + 8)[0]
        struct.pack_into(
            "<I", data, optional + 8, initialized_size + raw_size
        )
        struct.pack_into(
            "<I",
            data,
            optional + 56,
            _align_up(new_section_rva + len(blob), section_alignment),
        )
        directory_offset = optional + (112 if pointer_size == 8 else 96)
        if directory_offset + 13 * 8 > optional + optional_size:
            raise ValueError("optional header has no import/IAT directories")
        struct.pack_into(
            "<II",
            data,
            directory_offset + 1 * 8,
            new_section_rva,
            descriptor_size,
        )
        # A stale bound-import directory is invalid after reconstruction.
        struct.pack_into("<II", data, directory_offset + 11 * 8, 0, 0)
        struct.pack_into(
            "<II",
            data,
            directory_offset + 12 * 8,
            iat_rva,
            int(selection.get("size") or len(entries) * pointer_size),
        )
        struct.pack_into("<I", data, optional + 64, 0)

        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(
            target.name + f".tmp-{os.getpid()}-{time.time_ns()}"
        )
        try:
            temporary.write_bytes(data)
            os.replace(temporary, target)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        runnable = _make_dump_runnable(str(target))
        parsed = _parse_pe_layout(str(target))
        evidence = _pe_import_evidence(parsed)
        expected_count = len(entries)
        rebuilt_count = int(evidence.get("functionCount") or 0)
        ok = (
            rebuilt_count == expected_count
            and not evidence.get("badDllNames")
            and not evidence.get("unresolvedFunctions")
        )
        return {
            "ok": ok,
            "schema": "runtime-iat-import-rebuild-v1",
            "reason": "rebuilt" if ok else "rebuilt_import_verification_failed",
            "path": str(target),
            "rawDumpPath": str(source),
            "section": {
                "name": ".mcpimp",
                "rva": f"0x{new_section_rva:x}",
                "virtualSize": len(blob),
                "rawOffset": f"0x{new_raw:x}",
                "rawSize": raw_size,
            },
            "iatStart": f"0x{iat_start:x}",
            "iatRva": f"0x{iat_rva:x}",
            "iatSize": f"0x{int(selection.get('size') or 0):x}",
            "entryRva": f"0x{requested_entry_rva:x}",
            "descriptorCount": len(groups),
            "importCount": rebuilt_count,
            "expectedImportCount": expected_count,
            "moduleCounts": dict(resolution.get("moduleCounts") or {}),
            "makeRunnable": runnable,
            "sha256": _sha256_file(str(target)).upper(),
            "verification": {
                "badDllNames": list(evidence.get("badDllNames") or []),
                "unresolvedFunctions": list(
                    evidence.get("unresolvedFunctions") or []
                )[:16],
            },
        }
    except Exception as exc:
        return {
            "ok": False,
            "schema": "runtime-iat-import-rebuild-v1",
            "reason": "rebuild_failed",
            "error": str(exc),
            "path": str(target),
            "rawDumpPath": str(source),
        }


def _validate_custom_resolver_trace(
    trace_id: str,
    resolution: Dict[str, Any],
) -> Dict[str, Any]:
    """Prove that every reconstructed IAT pointer was observed at a resolver."""

    record = _get_api_trace(trace_id)
    if not record:
        return {
            "ok": False,
            "schema": "runtime-import-trace-validation-v1",
            "reason": "trace_not_found",
            "traceId": trace_id,
        }
    calls = [
        item
        for item in list(record.get("calls") or [])
        if isinstance(item, dict)
        and str(item.get("targetKind") or "").casefold()
        == "import-resolver"
    ]
    observations: List[Dict[str, Any]] = []
    invalid_calls: List[Dict[str, Any]] = []
    for call in calls:
        subscription = (
            dict(call.get("dynamicTargetSubscription") or {})
            if isinstance(call.get("dynamicTargetSubscription"), dict)
            else {}
        )
        evidence = (
            dict(subscription.get("resolverEvidence") or {})
            if isinstance(subscription.get("resolverEvidence"), dict)
            else {}
        )
        identity = (
            dict(evidence.get("identity") or {})
            if isinstance(evidence.get("identity"), dict)
            else {}
        )
        valid = bool(
            call.get("returned")
            and not call.get("returnTrackingError")
            and evidence.get("exactExport")
            and identity.get("ok")
        )
        item = {
            "seq": int(call.get("seq") or 0),
            "returned": bool(call.get("returned")),
            "returnTrackingError": call.get("returnTrackingError"),
            "resolverModule": call.get("module"),
            "resolverFunction": call.get("func"),
            "requestKey": evidence.get("requestKey"),
            "requestKeyInt": evidence.get("requestKeyInt"),
            "keyEncoding": evidence.get("keyEncoding"),
            "requestedModuleHandle": evidence.get(
                "requestedModuleHandle"
            ),
            "returnedTarget": evidence.get("returnedTarget"),
            "identity": identity,
            "valid": valid,
        }
        observations.append(item)
        if not valid:
            invalid_calls.append(item)

    missing: List[Dict[str, Any]] = []
    matches: List[Dict[str, Any]] = []
    for entry in list(resolution.get("entries") or []):
        if not isinstance(entry, dict):
            continue
        target = str(_normalize_hex(entry.get("target")) or "").casefold()
        expected_module = os.path.basename(
            str(entry.get("module") or "")
        ).casefold()
        expected_function = str(entry.get("function") or "").casefold()
        expected_ordinal = int(entry.get("ordinal") or 0)
        observed = next(
            (
                item
                for item in observations
                if item.get("valid")
                and str(
                    _normalize_hex(item.get("returnedTarget")) or ""
                ).casefold()
                == target
                and os.path.basename(
                    str((item.get("identity") or {}).get("module") or "")
                ).casefold()
                == expected_module
                and (
                    (
                        expected_function
                        and str(
                            (item.get("identity") or {}).get("function")
                            or ""
                        ).casefold()
                        == expected_function
                    )
                    or (
                        not expected_function
                        and int(
                            (item.get("identity") or {}).get("ordinal") or 0
                        )
                        == expected_ordinal
                    )
                )
            ),
            None,
        )
        if observed:
            matches.append(
                {
                    "iatIndex": int(entry.get("index") or 0),
                    "target": entry.get("target"),
                    "resolverCallSeq": int(observed.get("seq") or 0),
                    "requestKey": observed.get("requestKey"),
                    "requestKeyInt": observed.get("requestKeyInt"),
                    "keyEncoding": observed.get("keyEncoding"),
                }
            )
        else:
            missing.append(
                {
                    "iatIndex": int(entry.get("index") or 0),
                    "target": entry.get("target"),
                    "module": entry.get("module"),
                    "function": entry.get("function"),
                    "ordinal": int(entry.get("ordinal") or 0),
                }
            )
    dropped = int(record.get("droppedCalls") or 0)
    ok = bool(observations) and not invalid_calls and not missing and dropped == 0
    return {
        "ok": ok,
        "schema": "runtime-import-trace-validation-v1",
        "reason": "complete" if ok else "incomplete_resolver_evidence",
        "traceId": trace_id,
        "traceLabel": record.get("label"),
        "customTargetCount": int(record.get("customTargetCount") or 0),
        "resolverCallCount": len(calls),
        "validObservationCount": len(observations) - len(invalid_calls),
        "matchedIatCount": len(matches),
        "expectedIatCount": len(list(resolution.get("entries") or [])),
        "droppedCalls": dropped,
        "invalidCalls": invalid_calls[:32],
        "missingIatEntries": missing[:64],
        "matches": matches,
        "observations": observations,
    }


def _write_runtime_import_recovery_evidence(
    payload: Dict[str, Any],
    output_path: str,
    overwrite: bool = False,
) -> Dict[str, Any]:
    target = Path(os.path.abspath(str(output_path or "")))
    if target.exists() and not overwrite:
        return {
            "ok": False,
            "schema": "runtime-import-recovery-v1",
            "reason": "evidence_output_exists",
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
            "schema": "runtime-import-recovery-v1",
            "path": str(target),
            "size": target.stat().st_size,
            "evidenceSha256": digest,
        }
    except Exception as exc:
        return {
            "ok": False,
            "schema": "runtime-import-recovery-v1",
            "reason": "evidence_write_failed",
            "path": str(target),
            "error": str(exc),
        }
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


@mcp.tool()
def RecoverRuntimeImports(
    module: str = "",
    table_base: str = "",
    table_symbol: str = "",
    table_count: int = 0,
    trace_id: str = "",
    raw_dump_path: str = "",
    output_path: str = "",
    evidence_path: str = "",
    entrypoint: str = "",
    overwrite: bool = False,
) -> dict:
    """Recover a custom/runtime IAT from exact live export evidence.

    The target must be paused after its resolver populated a contiguous pointer
    table. Select that table by absolute ``table_base`` or exported
    ``table_symbol`` and provide the exact non-null slot count. Every pointer
    is matched to an exact, non-forwarded export. When ``trace_id`` is supplied,
    each reconstructed slot must also be backed by a complete custom-resolver
    return observation with no dropped calls.

    Set ``output_path`` to rebuild a loader-valid PE import directory. Supply
    an existing ``raw_dump_path`` or let the tool create a raw memory PE next
    to the output. ``evidence_path`` writes canonical, hashed JSON evidence.
    """

    state = _build_debug_state(
        include_console=False,
        include_callstack=False,
        max_console_chars=0,
    )
    if not state.get("debugging") or not state.get("paused"):
        return {
            "ok": False,
            "schema": "runtime-import-recovery-v1",
            "reason": "paused_debug_session_required",
            "state": state.get("state"),
        }
    hello = BridgeHello(refresh=True)
    if not isinstance(hello, dict) or not hello.get("ok"):
        return {
            "ok": False,
            "schema": "runtime-import-recovery-v1",
            "reason": "authoritative_session_unavailable",
            "bridge": hello,
        }
    selectors = int(bool(str(table_base or "").strip())) + int(
        bool(str(table_symbol or "").strip())
    )
    if selectors != 1:
        return {
            "ok": False,
            "schema": "runtime-import-recovery-v1",
            "reason": "exactly_one_table_selector_required",
        }
    try:
        count = int(table_count)
    except (TypeError, ValueError):
        count = 0
    if not (1 <= count <= 4096):
        return {
            "ok": False,
            "schema": "runtime-import-recovery-v1",
            "reason": "table_count_out_of_range",
            "minimum": 1,
            "maximum": 4096,
        }
    if evidence_path:
        evidence_target = Path(os.path.abspath(str(evidence_path)))
        if evidence_target.exists() and not overwrite:
            return {
                "ok": False,
                "schema": "runtime-import-recovery-v1",
                "reason": "evidence_output_exists",
                "path": str(evidence_target),
            }
    module_record = _resolve_loaded_module_for_dump(module)
    if not module_record:
        return {
            "ok": False,
            "schema": "runtime-import-recovery-v1",
            "reason": "loaded_module_not_found",
            "module": module or None,
        }
    module_base = _parse_int(module_record.get("base"), 0) or 0
    module_size = _parse_int(module_record.get("size"), 0) or 0
    module_path = os.path.abspath(str(module_record.get("path") or ""))
    if not module_base or not module_size or not os.path.isfile(module_path):
        return {
            "ok": False,
            "schema": "runtime-import-recovery-v1",
            "reason": "loaded_module_identity_incomplete",
            "module": module_record,
        }
    try:
        layout = _parse_pe_layout(module_path)
    except Exception as exc:
        return {
            "ok": False,
            "schema": "runtime-import-recovery-v1",
            "reason": "module_pe_parse_failed",
            "error": str(exc),
        }
    pointer_size = 8 if str(layout.get("arch") or "") == "x64" else 4
    if table_symbol:
        table_address_text = _resolve_loaded_module_symbol(
            module_record,
            str(table_symbol),
        )
        table_address = _parse_int(table_address_text, 0) or 0
    else:
        table_address = _parse_int(table_base, 0) or 0
    table_bytes = count * pointer_size
    if (
        not table_address
        or table_address < module_base
        or table_address + table_bytes > module_base + module_size
    ):
        return {
            "ok": False,
            "schema": "runtime-import-recovery-v1",
            "reason": "runtime_iat_outside_module",
            "tableAddress": (
                f"0x{table_address:x}" if table_address else None
            ),
            "tableBytes": table_bytes,
            "moduleBase": f"0x{module_base:x}",
            "moduleSize": f"0x{module_size:x}",
        }
    null_terminated = False
    if (
        table_address + table_bytes + pointer_size
        <= module_base + module_size
    ):
        try:
            terminator = _read_live_memory_exact(
                table_address + table_bytes,
                pointer_size,
            )
            null_terminated = not any(terminator)
        except Exception:
            null_terminated = False
    selection = {
        "ok": True,
        "schema": "runtime-iat-selection-v1",
        "selectionReason": (
            "explicit_exported_symbol"
            if table_symbol
            else "explicit_absolute_address"
        ),
        "start": f"0x{table_address:x}",
        "rva": f"0x{table_address - module_base:x}",
        "size": table_bytes + (pointer_size if null_terminated else 0),
        "count": count,
        "pointerSize": pointer_size,
        "nullTerminated": null_terminated,
        "tableSymbol": str(table_symbol or "") or None,
    }
    resolution = _oep_resolve_runtime_iat_exports(
        selection,
        module_base,
    )
    if not resolution.get("ok"):
        return {
            "ok": False,
            "schema": "runtime-import-recovery-v1",
            "reason": "runtime_export_resolution_incomplete",
            "target": {
                "module": module_record.get("name"),
                "path": module_path,
                "base": f"0x{module_base:x}",
            },
            "table": selection,
            "resolution": resolution,
        }
    trace_validation: Dict[str, Any] = {
        "ok": True,
        "schema": "runtime-import-trace-validation-v1",
        "reason": "not_requested",
        "traceId": None,
    }
    if str(trace_id or "").strip():
        trace_validation = _validate_custom_resolver_trace(
            str(trace_id).strip(),
            resolution,
        )
        if not trace_validation.get("ok"):
            return {
                "ok": False,
                "schema": "runtime-import-recovery-v1",
                "reason": "custom_resolver_trace_incomplete",
                "target": {
                    "module": module_record.get("name"),
                    "path": module_path,
                    "base": f"0x{module_base:x}",
                },
                "table": selection,
                "resolution": resolution,
                "traceValidation": trace_validation,
            }

    raw_result: Optional[Dict[str, Any]] = None
    rebuild: Optional[Dict[str, Any]] = None
    structural_verification: Optional[Dict[str, Any]] = None
    if str(output_path or "").strip():
        final_output = os.path.abspath(str(output_path))
        raw_path = (
            os.path.abspath(str(raw_dump_path))
            if str(raw_dump_path or "").strip()
            else final_output + ".raw"
        )
        if os.path.normcase(raw_path) == os.path.normcase(final_output):
            return {
                "ok": False,
                "schema": "runtime-import-recovery-v1",
                "reason": "raw_and_rebuilt_paths_must_differ",
            }
        if os.path.isfile(raw_path):
            raw_result = {
                "ok": True,
                "source": "existing_raw_dump",
                "path": raw_path,
                "size": os.path.getsize(raw_path),
                "sha256": (_sha256_file(raw_path) or "").upper(),
            }
        else:
            memory_dumper = globals().get("DumpPeFromMemory")
            if not callable(memory_dumper):
                return {
                    "ok": False,
                    "schema": "runtime-import-recovery-v1",
                    "reason": "memory_pe_dumper_unavailable",
                }
            raw_result = memory_dumper(
                base=f"0x{module_base:x}",
                output_path=raw_path,
                image_size=module_size,
                header_template_path="",
                reverse_relocations=False,
                verify=True,
                overwrite=overwrite,
            )
        if not isinstance(raw_result, dict) or not raw_result.get("ok"):
            return {
                "ok": False,
                "schema": "runtime-import-recovery-v1",
                "reason": "raw_memory_dump_failed",
                "rawDump": raw_result,
            }
        rebuild = _rebuild_dump_imports_from_runtime_iat(
            raw_path,
            final_output,
            module_base,
            selection,
            resolution,
            entrypoint=entrypoint,
            overwrite=overwrite,
        )
        if not rebuild.get("ok"):
            return {
                "ok": False,
                "schema": "runtime-import-recovery-v1",
                "reason": "import_rebuild_failed",
                "rawDump": raw_result,
                "rebuild": rebuild,
                "table": selection,
                "resolution": resolution,
                "traceValidation": trace_validation,
            }
        try:
            rebuilt_layout = _parse_pe_layout(final_output)
            imports = [
                {
                    "module": os.path.basename(
                        str(descriptor.get("dll") or "")
                    ).casefold(),
                    "function": str(function or "").casefold(),
                }
                for descriptor in list(rebuilt_layout.get("imports") or [])
                if isinstance(descriptor, dict)
                for function in list(descriptor.get("functions") or [])
            ]
            expected = [
                {
                    "module": os.path.basename(
                        str(entry.get("module") or "")
                    ).casefold(),
                    "function": (
                        str(entry.get("function") or "").casefold()
                        or f"ordinal:{int(entry.get('ordinal') or 0)}"
                    ),
                }
                for entry in list(resolution.get("entries") or [])
            ]
            actual_iat_rva = _parse_int(
                rebuilt_layout.get("iatDirectory", {}).get("rva"),
                -1,
            )
            expected_iat_rva = table_address - module_base
            structural_ok = (
                imports == expected
                and actual_iat_rva == expected_iat_rva
                and int(
                    rebuilt_layout.get("iatDirectory", {}).get("size")
                    or 0
                )
                == int(selection.get("size") or 0)
            )
            structural_verification = {
                "ok": structural_ok,
                "schema": "runtime-import-structural-verification-v1",
                "expectedImports": expected,
                "actualImports": imports,
                "expectedIatRva": f"0x{expected_iat_rva:x}",
                "actualIatRva": (
                    f"0x{actual_iat_rva:x}"
                    if actual_iat_rva is not None
                    and actual_iat_rva >= 0
                    else None
                ),
                "expectedIatSize": int(selection.get("size") or 0),
                "actualIatSize": int(
                    rebuilt_layout.get("iatDirectory", {}).get("size")
                    or 0
                ),
            }
        except Exception as exc:
            structural_verification = {
                "ok": False,
                "schema": "runtime-import-structural-verification-v1",
                "error": str(exc),
            }
        if not structural_verification.get("ok"):
            return {
                "ok": False,
                "schema": "runtime-import-recovery-v1",
                "reason": "rebuilt_import_verification_failed",
                "rawDump": raw_result,
                "rebuild": rebuild,
                "structuralVerification": structural_verification,
            }
    elif str(raw_dump_path or "").strip():
        return {
            "ok": False,
            "schema": "runtime-import-recovery-v1",
            "reason": "raw_dump_path_requires_output_path",
        }

    module_digest = (_sha256_file(module_path) or "").upper()
    evidence = {
        "schema": "runtime-import-recovery-v1",
        "createdAt": _now_iso(),
        "target": {
            "module": module_record.get("name"),
            "path": module_path,
            "sha256": module_digest,
            "arch": layout.get("arch"),
            "base": f"0x{module_base:x}",
            "size": f"0x{module_size:x}",
            "entryPointRva": layout.get("entryPointRva"),
        },
        "table": selection,
        "resolution": resolution,
        "traceValidation": trace_validation,
        "rawDump": raw_result,
        "rebuild": rebuild,
        "structuralVerification": structural_verification,
    }
    evidence_write: Optional[Dict[str, Any]] = None
    if str(evidence_path or "").strip():
        evidence_write = _write_runtime_import_recovery_evidence(
            evidence,
            evidence_path,
            overwrite=overwrite,
        )
        if not evidence_write.get("ok"):
            return {
                "ok": False,
                "schema": "runtime-import-recovery-v1",
                "reason": "evidence_write_failed",
                **evidence,
                "evidenceWrite": evidence_write,
            }
    return {
        "ok": True,
        "schema": "runtime-import-recovery-v1",
        "reason": "recovered",
        **evidence,
        "evidenceWrite": evidence_write,
    }


def _dump_with_runtime_iat_rebuild(
    module: Dict[str, Any],
    entrypoint: str,
    output_path: str,
    source_path: str,
    selection: Dict[str, Any],
    resolution: Dict[str, Any],
) -> Dict[str, Any]:
    """Dump with Scylla's stable raw path, then rebuild imports in Python."""

    final_path = os.path.abspath(str(output_path or ""))
    raw_path = _scylla_raw_dump_path(final_path)
    memory_dumper = globals().get("DumpPeFromMemory")
    if callable(memory_dumper):
        raw_result = memory_dumper(
            base=str((module or {}).get("base") or ""),
            output_path=raw_path,
            image_size=_parse_int((module or {}).get("size"), 0) or 0,
            header_template_path="",
            reverse_relocations=False,
            verify=True,
            overwrite=False,
        )
        raw_source = "memory_pe_reconstruction"
    else:
        raw_result = {
            "ok": False,
            "error": "DumpPeFromMemory is unavailable",
        }
        raw_source = "unavailable"
    if not isinstance(raw_result, dict) or not raw_result.get("ok"):
        raw_result = _scylla_dump_module(
            module,
            entrypoint=entrypoint,
            output_path=raw_path,
            search_start=entrypoint,
            source_path=source_path,
            keep_raw_dump=True,
            fix_imports=False,
            rebuild=False,
            overwrite=False,
            make_runnable=False,
        )
        raw_source = "scylla_raw_fallback"
    if not isinstance(raw_result, dict) or not raw_result.get("ok"):
        result = dict(raw_result) if isinstance(raw_result, dict) else {}
        result.update(
            {
                "ok": False,
                "stage": "raw_dump",
                "path": final_path,
                "rawDumpPath": raw_path,
                "rawDumpSource": raw_source,
                "runtimeIatSelection": selection,
                "runtimeIatResolution": {
                    key: value
                    for key, value in resolution.items()
                    if key != "entries"
                },
            }
        )
        return result
    rebuilt = _rebuild_dump_imports_from_runtime_iat(
        raw_path,
        final_path,
        _parse_int((module or {}).get("base"), 0) or 0,
        selection,
        resolution,
        entrypoint=entrypoint,
        overwrite=False,
    )
    return {
        "ok": bool(rebuilt.get("ok")),
        "stage": "runtime_iat_rebuild",
        "path": final_path,
        "rawDumpPath": raw_path,
        "rawDumpSource": raw_source,
        "dumpSucceeded": True,
        "fixedExists": os.path.isfile(final_path),
        "fixedSize": os.path.getsize(final_path)
        if os.path.isfile(final_path)
        else 0,
        "iatStart": selection.get("start"),
        "iatSize": f"0x{int(selection.get('size') or 0):x}",
        "iatSource": "runtime_export_rebuild",
        "searchResult": 0,
        "searchResultName": "RUNTIME_EXPORT_RESOLUTION",
        "runtimeIatSelection": selection,
        "runtimeIatResolution": {
            key: value
            for key, value in resolution.items()
            if key != "entries"
        },
        "runtimeImportRebuild": rebuilt,
        "rawDumpResult": raw_result,
        "error": rebuilt.get("error") if not rebuilt.get("ok") else None,
    }


def _scylla_dump_module(
    module: Dict[str, Any],
    entrypoint: str,
    output_path: str,
    search_start: str = "",
    source_path: str = "",
    keep_raw_dump: bool = False,
    fix_imports: bool = True,
    rebuild: bool = True,
    advanced_search: bool = False,
    create_new_iat: bool = False,
    iat_start: str = "",
    iat_size: int = 0,
    overwrite: bool = False,
    make_runnable: bool = True,
) -> Dict[str, Any]:
    requested_output = str(output_path or "").strip()
    if not requested_output:
        return {"ok": False, "error": "Output path is required"}
    final_path = os.path.abspath(requested_output)
    entrypoint_hex = _normalize_hex(entrypoint)
    image_base = _normalize_hex(
        (module or {}).get("base") or _get_current_debuggee_module_base()
    )
    if not image_base:
        return {"ok": False, "error": "Could not resolve the module image base"}
    if not entrypoint_hex:
        return {"ok": False, "error": "Could not resolve the module entrypoint"}
    pid = 0
    try:
        pid = _infer_debuggee_pid(0)
    except Exception:
        pid = int(_get_runtime_value("lastDebuggeePid", 0) or 0)
    if not pid:
        return {"ok": False, "error": "No active debuggee PID is available"}
    hello = BridgeHello(refresh=True)
    if not isinstance(hello, dict) or not hello.get("ok"):
        return {"ok": False, "error": "Authoritative bridge identity is unavailable", "bridge": hello}
    os.makedirs(os.path.dirname(final_path), exist_ok=True)
    raw_path = _scylla_raw_dump_path(final_path) if fix_imports else final_path
    if os.path.normcase(raw_path) == os.path.normcase(final_path):
        raw_path = final_path + ".raw.bin" if fix_imports else final_path
    existing = [
        path
        for path in ({raw_path, final_path} if fix_imports else {final_path})
        if os.path.exists(path)
    ]
    if existing and not overwrite:
        return {
            "ok": False,
            "error": "Dump output already exists; set overwrite=true to replace it",
            "existingPaths": sorted(existing),
            "path": final_path,
            "rawDumpPath": raw_path,
        }
    iat_start_hex = _normalize_hex(iat_start)
    try:
        iat_size_value = max(0, int(iat_size or 0))
    except (TypeError, ValueError):
        return {"ok": False, "error": "iat_size must be an integer"}
    if bool(iat_start_hex) != bool(iat_size_value):
        return {"ok": False, "error": "iat_start and iat_size must be supplied together"}
    params = {
        "pid": str(int(pid)),
        "imageBase": image_base,
        "entrypoint": entrypoint_hex,
        "searchStart": _normalize_hex(search_start) or entrypoint_hex,
        "dumpPath": raw_path,
        "sourcePath": source_path or str((module or {}).get("path") or ""),
        "dumpProcess": "true",
        "overwrite": str(bool(overwrite)).lower(),
        "advancedSearch": str(bool(advanced_search)).lower(),
        "createNewIat": str(bool(create_new_iat)).lower(),
        "fixImports": str(bool(fix_imports)).lower(),
        "rebuild": str(bool(rebuild and fix_imports)).lower(),
        "updatePeHeaderChecksum": "true",
        "createBackup": "false",
    }
    if fix_imports:
        params["fixedPath"] = final_path
    if iat_start_hex and iat_size_value:
        params["iatStart"] = iat_start_hex
        params["iatSize"] = f"0x{iat_size_value:x}"
    payload = _coerce_json_payload(
        safe_post("Scylla/DumpFix", params, log=False, timeout_sec=120.0)
    )
    if not isinstance(payload, dict):
        return {
            "ok": False,
            "error": str(payload),
            "path": final_path,
            "rawDumpPath": raw_path,
        }
    result = dict(payload)
    result["path"] = final_path
    result["rawDumpPath"] = raw_path
    result["requestedIat"] = {
        "start": iat_start_hex or None,
        "size": iat_size_value,
        "source": "explicit" if iat_start_hex else "search",
    }
    # Only unpacking workflows should normally clear ASLR. Generic module dumps
    # may retain valid relocations and are safer left unchanged.
    if make_runnable and result.get("ok") and os.path.exists(final_path):
        result["makeRunnable"] = _make_dump_runnable(final_path)
    if (
        fix_imports
        and result.get("ok")
        and not keep_raw_dump
        and os.path.exists(raw_path)
    ):
        try:
            os.remove(raw_path)
            result["rawDumpCleaned"] = not os.path.exists(raw_path)
        except Exception as e:
            result["rawDumpCleaned"] = False
            result["rawDumpCleanError"] = str(e)
    return result


def _oep_callstack_stage_evidence(
    state: Dict[str, Any], section_plan: Dict[str, Any]
) -> Dict[str, Any]:
    callstack = (
        state.get("callStack")
        if isinstance(state.get("callStack"), dict)
        else {}
    )
    entries = [
        item
        for item in list(callstack.get("entries") or [])[:64]
        if isinstance(item, dict)
    ]
    base = int(section_plan.get("baseInt") or 0)
    image_size = int((section_plan.get("layout") or {}).get("sizeOfImage") or 0)
    limit = base + max(image_size, 1)
    module_frames = set()
    external_return_targets = set()
    comments: List[str] = []
    markers = (
        "raiseexception",
        "kiuserexceptiondispatcher",
        "rtlunwind",
        "rtldispatchexception",
        "c_specific_handler",
        "executehandler",
        "except_handler",
        "tls callback",
        "ldrpcalltlsinitializers",
        "ldrpinitializetls",
    )
    matched_markers = set()
    for item in entries:
        comment = str(item.get("comment") or "")
        comments.append(comment[:240])
        lowered = comment.casefold()
        matched_markers.update(marker for marker in markers if marker in lowered)
        for key in ("from", "to"):
            address = _normalize_hex(item.get(key))
            if not address:
                continue
            value = int(address, 16)
            if base <= value < limit:
                module_frames.add(value)
        from_hex = _normalize_hex(item.get("from"))
        to_hex = _normalize_hex(item.get("to"))
        if from_hex and to_hex:
            from_value = int(from_hex, 16)
            to_value = int(to_hex, 16)
            if base <= from_value < limit and not (base <= to_value < limit):
                if to_value:
                    external_return_targets.add(to_value)
    return {
        "exceptionRelated": bool(matched_markers),
        "matchedMarkers": sorted(matched_markers),
        "moduleFrames": [f"0x{value:x}" for value in sorted(module_frames)[:32]],
        "externalReturnTargets": [
            f"0x{value:x}" for value in sorted(external_return_targets)[:16]
        ],
        "comments": comments[:16],
        "entryCount": len(entries),
    }


def _oep_live_runtime_functions(
    section_plan: Dict[str, Any],
) -> Dict[str, Any]:
    """Read the restored x64 `.pdata` table directly from debuggee memory."""

    directory = section_plan.get("exceptionDirectory")
    directory = directory if isinstance(directory, dict) else {}
    try:
        directory_rva = int(str(directory.get("rva") or "0x0"), 16)
        directory_size = int(directory.get("size") or 0)
        base = int(section_plan.get("baseInt") or 0)
        image_size = int((section_plan.get("layout") or {}).get("sizeOfImage") or 0)
    except (TypeError, ValueError):
        return {"ok": False, "reason": "invalid_exception_directory"}
    if not base or not directory_rva or directory_size < 12:
        return {"ok": False, "reason": "exception_directory_unavailable"}
    bounded_size = min(directory_size - (directory_size % 12), 12 * 16384)
    try:
        data = _read_live_memory_exact(base + directory_rva, bounded_size)
    except Exception as exc:
        return {
            "ok": False,
            "reason": "exception_directory_read_failed",
            "error": str(exc),
        }
    functions: List[Dict[str, Any]] = []
    invalid = 0
    for index in range(len(data) // 12):
        begin_rva, end_rva, unwind_rva = struct.unpack_from(
            "<III", data, index * 12
        )
        if not any((begin_rva, end_rva, unwind_rva)):
            continue
        if (
            begin_rva >= end_rva
            or end_rva > max(image_size, 1)
            or unwind_rva >= max(image_size, 1)
        ):
            invalid += 1
            continue
        functions.append(
            {
                "index": index,
                "beginRva": begin_rva,
                "endRva": end_rva,
                "unwindInfoRva": unwind_rva,
                "begin": f"0x{base + begin_rva:x}",
                "endExclusive": f"0x{base + end_rva:x}",
            }
        )
    return {
        "ok": bool(functions),
        "directoryRva": f"0x{directory_rva:x}",
        "directorySize": directory_size,
        "readSize": bounded_size,
        "functionCount": len(functions),
        "invalidCount": invalid,
        "functions": functions,
    }


def _oep_resume_after_exception_callback(
    section_plan: Dict[str, Any],
    stack_evidence: Dict[str, Any],
    candidate_hex: str,
    deadline: float,
    telem: Dict[str, Any],
    workflow_id: str,
) -> Optional[Dict[str, Any]]:
    """Run to the restored TLS callback's real `ret`, then execute the return."""

    runtime = _oep_live_runtime_functions(section_plan)
    telem.setdefault("multiStage", {})["liveExceptionDirectory"] = {
        key: value
        for key, value in runtime.items()
        if key != "functions"
    }
    if not runtime.get("ok"):
        return None
    base = int(section_plan.get("baseInt") or 0)
    candidate = int(candidate_hex, 16)
    frame_rvas = sorted(
        {
            int(value, 16) - base
            for value in list(stack_evidence.get("moduleFrames") or [])
            if _normalize_hex(value)
            and base <= int(value, 16)
            and int(value, 16) != candidate
        }
    )
    function = next(
        (
            item
            for frame_rva in frame_rvas
            for item in list(runtime.get("functions") or [])
            if int(item["beginRva"]) <= frame_rva < int(item["endRva"])
        ),
        None,
    )
    if not isinstance(function, dict):
        return None
    begin = base + int(function["beginRva"])
    end = base + int(function["endRva"])
    instruction_count = max(8, min(512, (end - begin) + 8))
    try:
        disasm = DisasmGetInstructionRange(f"0x{begin:x}", instruction_count)
    except Exception:
        return None
    instructions = (
        disasm.get("instructions") if isinstance(disasm, dict) else None
    )
    returns = []
    for item in list(instructions or []):
        if not isinstance(item, dict):
            continue
        address = int(str(item.get("address") or "0x0"), 16)
        if not (begin <= address < end):
            continue
        opcode = str(item.get("instruction") or "").strip().casefold()
        if opcode == "ret" or opcode.startswith(("ret ", "retn", "retf")):
            returns.append(address)
    if not returns:
        return None
    # Prefer the last return in the bounded function. It covers the common
    # early-branch + shared epilogue layout generated for TLS callbacks.
    return_address = max(returns)
    _oep_append_transition(
        telem,
        "tls_callback_return_armed",
        None,
        address=f"0x{return_address:x}",
        functionBegin=f"0x{begin:x}",
        functionEndExclusive=f"0x{end:x}",
        frameRvas=[f"0x{value:x}" for value in frame_rvas],
    )
    at_return = _oep_run_to_temporary_address(
        f"0x{return_address:x}", deadline, workflow_id
    )
    if not isinstance(at_return, dict) or at_return.get("state") in {
        "exited",
        "not_debugging",
    }:
        return at_return
    _oep_append_transition(
        telem,
        "tls_callback_return_hit",
        at_return,
        address=f"0x{return_address:x}",
    )
    stepped = DebugStepIn()
    if isinstance(stepped, dict) and stepped.get("ok") is False:
        return None
    remaining = max(250, int((deadline - time.time()) * 1000))
    waited = WaitForPause(timeout_ms=min(remaining, 8000), poll_ms=50)
    if not isinstance(waited, dict):
        return None
    _, after_return = _oep_read_state()
    _oep_append_transition(
        telem,
        "tls_callback_returned",
        after_return,
        address=_normalize_hex(after_return.get("rip")),
    )
    return after_return


def _oep_refine_tls_seh_candidate(
    verdict: Dict[str, Any],
    section_plan: Dict[str, Any],
    deadline: float,
    telem: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Skip callback/exception stages and accept the next clean module entry.

    TLS unpackers may transfer into restored callback code before the actual
    program OEP. If that code raises a first-chance exception, a plain
    section-hop sees an exception helper/prologue and produces a false OEP.
    This refinement follows bounded module-exit/re-entry cycles, excludes the
    callback frames observed on the exception stack, and accepts only a clean
    executable re-entry with a plausible prologue.
    """

    if not verdict.get("accepted") or not list(
        section_plan.get("tlsCallbacks") or []
    ):
        return None
    multi = telem.get("multiStage") if isinstance(telem.get("multiStage"), dict) else {}
    history = _oep_collect_exception_history(
        int(multi.get("exceptionCursorStart") or 0)
    )
    first_chance_records = [
        item
        for item in list(history.get("records") or [])
        if bool(item.get("firstChance"))
        or str(item.get("chance") or "").casefold() == "first"
    ]
    if not first_chance_records:
        return None
    regs, state = _oep_read_state()
    current_hex = _oep_norm_rip(regs, state) or _normalize_hex(verdict.get("rip"))
    stack_evidence = _oep_callstack_stage_evidence(state, section_plan)
    callback_hit_count = sum(
        1
        for item in list(multi.get("transitions") or [])
        if item.get("phase") == "tls_callback"
    )
    if not stack_evidence.get("exceptionRelated") and not callback_hit_count:
        return None
    excluded_centers = {
        int(value, 16)
        for value in list(stack_evidence.get("moduleFrames") or [])
        if _normalize_hex(value)
    }
    if current_hex:
        excluded_centers.add(int(current_hex, 16))
    _oep_append_transition(
        telem,
        "tls_seh_candidate",
        state,
        address=current_hex,
        exceptionCodes=sorted(
            {
                str(item.get("exceptionCode") or "")
                for item in first_chance_records
                if item.get("exceptionCode")
            }
        ),
        stackEvidence=stack_evidence,
    )
    base = int(section_plan.get("baseInt") or 0)
    image_size = int((section_plan.get("layout") or {}).get("sizeOfImage") or 0)
    limit = base + max(image_size, 1)
    outside_condition = f"(cip<0x{base:x} || cip>=0x{limit:x})"
    inside_condition = _oep_section_condition(
        list(section_plan.get("execSections") or [])
    )
    entry_section_name = str(
        section_plan.get("entrySection") or ""
    ).strip().casefold()
    post_callback_sections = [
        item
        for item in list(section_plan.get("execSections") or [])
        if str(item.get("nameLower") or "").strip().casefold()
        != entry_section_name
    ]
    post_callback_condition = _oep_section_condition(post_callback_sections)
    if not base or not image_size or not inside_condition:
        return {
            **verdict,
            "accepted": False,
            "reason": "TLS/SEH refinement lacks a bounded executable image map",
        }
    return_workflow_id = f"oep-stage-return-{uuid.uuid4().hex[:16]}"
    current_stack_evidence = stack_evidence
    for cycle in range(1, 17):
        if time.time() >= deadline:
            break
        return_targets = list(
            current_stack_evidence.get("externalReturnTargets") or []
        )
        outside = None
        if cycle == 1 and current_hex:
            outside = _oep_resume_after_exception_callback(
                section_plan,
                current_stack_evidence,
                current_hex,
                deadline,
                telem,
                return_workflow_id,
            )
        if outside is None:
            outside = (
                _oep_run_to_temporary_address(
                    str(return_targets[0]), deadline, return_workflow_id
                )
                if bool(current_stack_evidence.get("exceptionRelated"))
                and return_targets
                else _oep_trace_over_to_condition(
                    outside_condition, deadline, max_steps=2_000_000
                )
            )
        if not isinstance(outside, dict) or outside.get("state") in {
            "exited",
            "not_debugging",
        }:
            return {
                **verdict,
                "accepted": False,
                "reason": "target exited during TLS/SEH module-exit refinement",
            }
        regs_out, state_out = _oep_read_state()
        outside_hex = _oep_norm_rip(regs_out, state_out)
        outside_int = int(outside_hex, 16) if outside_hex else 0
        still_in_module = bool(base <= outside_int < limit)
        outside_section = _section_for_runtime_address(
            outside_int, list(section_plan.get("execSections") or [])
        )
        _oep_append_transition(
            telem,
            (
                "tls_seh_module_return"
                if still_in_module
                else "tls_seh_module_exit"
            ),
            state_out,
            address=outside_hex,
            cycle=cycle,
        )
        if (
            still_in_module
            and outside_section
            and str(outside_section.get("nameLower") or "").strip().casefold()
            == entry_section_name
            and post_callback_condition
        ):
            hopped = _oep_trace_to_sections(
                post_callback_condition, deadline, max_steps=6_000_000
            )
            if not isinstance(hopped, dict) or hopped.get("state") in {
                "exited",
                "not_debugging",
            }:
                return {
                    **verdict,
                    "accepted": False,
                    "reason": "target exited before post-callback section transfer",
                }
            regs_in, state_in = _oep_read_state()
            reentry_hex = _oep_norm_rip(regs_in, state_in)
            _oep_append_transition(
                telem,
                "tls_seh_post_callback_hop",
                state_in,
                address=reentry_hex,
                cycle=cycle,
                fromSection=outside_section.get("name"),
            )
        elif still_in_module:
            state_in = state_out
            reentry_hex = outside_hex
        else:
            reentered = _oep_trace_to_sections(
                inside_condition, deadline, max_steps=2_000_000
            )
            if not isinstance(reentered, dict) or reentered.get("state") in {
                "exited",
                "not_debugging",
            }:
                return {
                    **verdict,
                    "accepted": False,
                    "reason": "target exited before TLS/SEH module re-entry",
                }
            regs_in, state_in = _oep_read_state()
            reentry_hex = _oep_norm_rip(regs_in, state_in)
        if not reentry_hex:
            continue
        reentry_int = int(reentry_hex, 16)
        reentry_stack = _oep_callstack_stage_evidence(state_in, section_plan)
        current_stack_evidence = reentry_stack
        callback_related = any(
            abs(reentry_int - center) <= 0x200 for center in excluded_centers
        )
        exception_related = bool(reentry_stack.get("exceptionRelated"))
        _oep_append_transition(
            telem,
            "tls_seh_module_reentry",
            state_in,
            address=reentry_hex,
            cycle=cycle,
            callbackRelated=callback_related,
            exceptionRelated=exception_related,
            stackEvidence=reentry_stack,
        )
        if callback_related or exception_related:
            excluded_centers.add(reentry_int)
            continue
        section = _section_for_runtime_address(
            reentry_int, list(section_plan.get("execSections") or [])
        )
        prologue_ok = _oep_looks_like_prologue(reentry_hex)
        if section and prologue_ok:
            candidate_int = int(
                _normalize_hex(verdict.get("rip")) or reentry_hex, 16
            )
            telem.setdefault("notes", []).append(
                f"TLS/SEH refinement accepted clean re-entry {reentry_hex} "
                f"after {cycle} cycle(s)"
            )
            return {
                "accepted": True,
                "rip": reentry_hex,
                "confidence": "high",
                "section": section.get("name"),
                "distanceFromEntry": (
                    f"0x{abs(reentry_int - int(section_plan.get('entryInt') or 0)):x}"
                ),
                "prologueLooksReal": True,
                "loaderStageCandidate": f"0x{candidate_int:x}",
                "tlsSehCycles": cycle,
                "reason": (
                    f"TLS/SEH clean module re-entry "
                    f"0x{candidate_int:x} -> {reentry_hex}"
                ),
            }
        excluded_centers.add(reentry_int)
    return {
        **verdict,
        "accepted": False,
        "reason": "TLS/SEH refinement exhausted without a clean program re-entry",
    }


def _oep_runtime_disk_evidence(
    address: int,
    section: Dict[str, Any],
    section_plan: Dict[str, Any],
    span: int = 96,
) -> Dict[str, Any]:
    """Compare a bounded live code window with its original mapped bytes."""

    start = int(section.get("start") or 0)
    end = int(section.get("end") or 0)
    offset = int(address) - start
    size = min(max(0, int(span)), max(0, end - int(address)))
    result: Dict[str, Any] = {
        "available": False,
        "address": f"0x{int(address):x}",
        "section": str(section.get("name") or ""),
        "comparedBytes": 0,
        "equalBytes": 0,
        "changedBytes": 0,
        "similarity": None,
        "diskBackedBytes": 0,
        "zeroFillBytes": 0,
    }
    if offset < 0 or size <= 0:
        result["reason"] = "address-outside-section"
        return result
    live = _read_memory_bytes(f"0x{int(address):x}", size)
    live_bytes = live.get("bytes") if isinstance(live, dict) and live.get("ok") else None
    if not isinstance(live_bytes, bytes) or len(live_bytes) != size:
        result["reason"] = "runtime-read-failed"
        return result
    raw_size = max(0, int(section.get("rawSize") or 0))
    raw_pointer = max(0, int(section.get("rawPointer") or 0))
    disk_backed = min(size, max(0, raw_size - offset))
    baseline = bytearray(size)
    image_path = str(section_plan.get("imagePath") or "")
    if disk_backed:
        if not image_path or not raw_pointer:
            result["reason"] = "disk-layout-unavailable"
            return result
        try:
            with open(image_path, "rb") as handle:
                handle.seek(raw_pointer + offset)
                source = handle.read(disk_backed)
        except OSError as exc:
            result["reason"] = f"disk-read-failed: {exc}"
            return result
        if len(source) != disk_backed:
            result["reason"] = "short-disk-read"
            return result
        baseline[:disk_backed] = source
    equal = sum(1 for left, right in zip(live_bytes, baseline) if left == right)
    changed = size - equal
    result.update(
        {
            "available": True,
            "comparedBytes": size,
            "equalBytes": equal,
            "changedBytes": changed,
            "similarity": round(equal / size, 6),
            "diskBackedBytes": disk_backed,
            "zeroFillBytes": size - disk_backed,
            "reason": "compared",
        }
    )
    return result


def _oep_section_mutation_evidence(
    section: Dict[str, Any],
    section_plan: Dict[str, Any],
    *,
    sample_size: int = 64,
    max_samples: int = 24,
) -> Dict[str, Any]:
    """Sample an executable section for unpacked code that differs from disk."""

    start = int(section.get("start") or 0)
    end = int(section.get("end") or 0)
    size = max(0, end - start)
    if size <= 0:
        return {
            "available": False,
            "section": str(section.get("name") or ""),
            "reason": "empty-section",
            "samples": [],
        }
    # Dense sampling is intentional: compact same-section stubs commonly
    # rewrite only 16-64 bytes, so one page-level sample can miss the payload
    # entirely.  Adjacent sample-sized windows cover compact sections without
    # gaps, while a strict cap keeps large executable sections bounded.
    count = min(
        max(1, int(max_samples)),
        max(3, (size + max(16, int(sample_size)) - 1) // max(16, int(sample_size))),
    )
    limit = max(start, end - max(1, int(sample_size)))
    addresses = sorted(
        {
            start + ((max(0, limit - start) * index) // max(1, count - 1))
            for index in range(count)
        }
    )
    samples = [
        _oep_runtime_disk_evidence(
            address, section, section_plan, span=max(16, int(sample_size))
        )
        for address in addresses
    ]
    available = [item for item in samples if item.get("available")]
    changed = [
        item
        for item in available
        if float(item.get("similarity") or 1.0) <= 0.90
        and int(item.get("changedBytes") or 0) >= 8
    ]
    return {
        "available": bool(available),
        "section": str(section.get("name") or ""),
        "sampleCount": len(samples),
        "availableSampleCount": len(available),
        "changedSampleCount": len(changed),
        "mutationRatio": round(len(changed) / max(1, len(available)), 6),
        "samples": samples,
    }


def _oep_same_section_refinement_decision(
    *,
    known_loader_shape: bool,
    candidate_evidence: Dict[str, Any],
    section_evidence: Dict[str, Any],
) -> Dict[str, Any]:
    """Pure fail-closed classifier for an unchanged loader in mutated code."""

    candidate_available = bool(candidate_evidence.get("available"))
    similarity = candidate_evidence.get("similarity")
    candidate_changed = int(candidate_evidence.get("changedBytes") or 0)
    candidate_unchanged = bool(
        candidate_available
        and similarity is not None
        and (
            float(similarity) >= 0.95
            # PE32 absolute operands can differ at one or two relocation bytes
            # even when the loader instruction stream itself is unchanged.
            or (candidate_changed <= 2 and float(similarity) >= 0.75)
        )
    )
    section_mutated = bool(
        section_evidence.get("available")
        and int(section_evidence.get("changedSampleCount") or 0) > 0
        and float(section_evidence.get("mutationRatio") or 0.0) > 0.0
    )
    generic = bool(candidate_unchanged and section_mutated)
    return {
        "refine": bool(known_loader_shape or generic),
        "knownLoaderShape": bool(known_loader_shape),
        "genericRuntimeMutation": generic,
        "candidateUnchanged": candidate_unchanged,
        "sectionMutated": section_mutated,
        "candidate": dict(candidate_evidence or {}),
        "section": dict(section_evidence or {}),
        "reason": (
            "known-loader-shape"
            if known_loader_shape
            else "unchanged-loader-inside-runtime-mutated-section"
            if generic
            else "no-loader-stage-evidence"
        ),
    }


def _oep_same_section_condition(
    section_start: int,
    section_end: int,
    excluded_centers: List[int],
    radius: int,
) -> str:
    ranges = [(int(section_start), int(section_end))]
    for center in excluded_centers:
        low = max(int(section_start), int(center) - int(radius))
        high = min(int(section_end), int(center) + int(radius))
        next_ranges: List[tuple[int, int]] = []
        for left, right in ranges:
            if high <= left or low >= right:
                next_ranges.append((left, right))
                continue
            if left < low:
                next_ranges.append((left, low))
            if high < right:
                next_ranges.append((high, right))
        ranges = next_ranges
    return " || ".join(
        f"(cip>=0x{left:x} && cip<0x{right:x})"
        for left, right in ranges
        if right > left
    )


def _oep_trace_same_section_transfer(
    seed_hex: str,
    section: Dict[str, Any],
    section_plan: Dict[str, Any],
    deadline: float,
    telem: Dict[str, Any],
    *,
    allow_unverified_fallback: bool = False,
    minimum_fallback_distance: int = 0x1000,
) -> Dict[str, Any]:
    """Find a far control transfer into runtime-mutated code in one section."""

    normalized_seed = _normalize_hex(seed_hex)
    if not normalized_seed:
        return {"accepted": False, "reason": "same-section seed has no RIP"}
    seed_int = int(normalized_seed, 16)
    section_start = int(section.get("start") or 0)
    section_end = int(section.get("end") or 0)
    if not (section_start <= seed_int < section_end):
        return {"accepted": False, "reason": "same-section seed is outside section"}
    excluded = [seed_int]
    transitions: List[Dict[str, Any]] = []
    radius = 0x20
    # A packer may deliberately stop on an inline INT3 after restoring code.
    # x64dbg keeps the exception pending until a disposition is selected; issuing
    # a trace command directly would re-deliver it as second chance instead of
    # advancing to the restored payload.  Swallow only a first-chance breakpoint,
    # guarded by its exact event sequence. Other exceptions remain untouched.
    _, initial_state = _oep_read_state()
    initial_session = (
        initial_state.get("session")
        if isinstance(initial_state.get("session"), dict)
        else {}
    )
    exception_code = str(
        initial_state.get("exceptionCode")
        or initial_session.get("exceptionCode")
        or ""
    ).strip().lower()
    exception_pending = bool(
        initial_state.get("exceptionPending")
        if initial_state.get("exceptionPending") is not None
        else initial_session.get("exceptionPending")
    )
    first_chance = bool(
        initial_state.get("exceptionFirstChance")
        if initial_state.get("exceptionFirstChance") is not None
        else initial_session.get("exceptionFirstChance")
    )
    if exception_pending and first_chance and exception_code in {
        "0x80000003",
        "80000003",
    }:
        event_seq = int(
            initial_state.get("eventSeq")
            or initial_session.get("eventSeq")
            or 0
        )
        continuation = ContinueException(
            disposition="handled",
            expected_event_seq=event_seq,
            resume=False,
        )
        telem["sameSectionExceptionContinuation"] = continuation
        if not (isinstance(continuation, dict) and continuation.get("ok")):
            return {
                "accepted": False,
                "reason": "failed to clear pending same-section breakpoint",
                "sameSectionTransitions": transitions,
                "continuation": continuation,
            }
    for cycle in range(1, 7):
        if time.time() >= deadline:
            break
        condition = _oep_same_section_condition(
            section_start, section_end, excluded, radius
        )
        if not condition:
            break
        telem.setdefault("notes", []).append(
            f"same-section cycle={cycle} seed={normalized_seed} condition={condition}"
        )
        settled = _oep_trace_to_sections(condition, deadline, max_steps=6000000)
        if not isinstance(settled, dict) or settled.get("state") in {
            "exited",
            "not_debugging",
        }:
            return {
                "accepted": False,
                "reason": "target exited during same-section refinement",
                "sameSectionTransitions": transitions,
            }
        regs, state = _oep_read_state()
        candidate_hex = _oep_norm_rip(regs, state)
        if not candidate_hex:
            break
        candidate_int = int(candidate_hex, 16)
        distance = abs(candidate_int - seed_int)
        evidence = _oep_runtime_disk_evidence(
            candidate_int, section, section_plan, span=96
        )
        prologue = _oep_looks_like_prologue(candidate_hex)
        runtime_mutated = bool(
            evidence.get("available")
            and evidence.get("similarity") is not None
            and float(evidence.get("similarity")) <= 0.90
            and int(evidence.get("changedBytes") or 0) >= 8
        )
        fallback = bool(
            allow_unverified_fallback
            and distance >= max(0x100, int(minimum_fallback_distance))
        )
        accepted = bool(
            section_start <= candidate_int < section_end
            and distance >= radius
            and prologue
            and (runtime_mutated or fallback)
        )
        transition = {
            "cycle": cycle,
            "from": normalized_seed,
            "to": candidate_hex,
            "distance": f"0x{distance:x}",
            "runtimeMutation": runtime_mutated,
            "fallback": fallback,
            "prologueLooksReal": prologue,
            "diskEvidence": evidence,
            "accepted": accepted,
        }
        transitions.append(transition)
        if accepted:
            return {
                "accepted": True,
                "rip": candidate_hex,
                "confidence": "high" if runtime_mutated else "medium",
                "section": str(section.get("name") or ""),
                "distanceFromEntry": (
                    f"0x{abs(candidate_int - int(section_plan.get('entryInt') or 0)):x}"
                ),
                "prologueLooksReal": True,
                "loaderStageCandidate": normalized_seed,
                "runtimeMutationEvidence": evidence,
                "sameSectionTransitions": transitions,
                "reason": (
                    f"runtime-mutated same-section transfer "
                    f"{normalized_seed} -> {candidate_hex}"
                    if runtime_mutated
                    else f"known-loader same-section transfer "
                    f"{normalized_seed} -> {candidate_hex}"
                ),
            }
        if candidate_int not in excluded:
            excluded.append(candidate_int)
        else:
            break
    return {
        "accepted": False,
        "reason": "same-section refinement exhausted without a mutated prologue",
        "sameSectionTransitions": transitions,
    }


def _oep_candidate_needs_refinement(
    verdict: Dict[str, Any], section_plan: Dict[str, Any]
) -> bool:
    """Return true when a section hop is a known loader-stage transition.

    MPRESS executes its decompressor inside ``.MPRESS1`` before making a long
    same-section transfer to the restored program entry. Treating the first
    ``.MPRESS2 -> .MPRESS1`` hop as OEP produces a syntactically valid but
    useless two-import dump.
    """

    candidate = str(verdict.get("section") or "").strip().lower()
    entry_section = str(section_plan.get("entrySection") or "").strip().lower()
    known = bool(
        candidate.startswith(".mpress") and entry_section.startswith(".mpress")
    )
    if not str(section_plan.get("imagePath") or ""):
        decision = _oep_same_section_refinement_decision(
            known_loader_shape=known,
            candidate_evidence={},
            section_evidence={},
        )
        verdict["sameSectionEvidence"] = decision
        return bool(decision.get("refine"))
    candidate_hex = _normalize_hex(verdict.get("rip"))
    section = (
        _section_for_runtime_address(
            int(candidate_hex, 16),
            list(section_plan.get("execSections") or []),
        )
        if candidate_hex
        else None
    )
    candidate_evidence = (
        _oep_runtime_disk_evidence(
            int(candidate_hex, 16), section, section_plan, span=16
        )
        if candidate_hex and section
        else {}
    )
    section_evidence = (
        _oep_section_mutation_evidence(section, section_plan) if section else {}
    )
    decision = _oep_same_section_refinement_decision(
        known_loader_shape=known,
        candidate_evidence=candidate_evidence,
        section_evidence=section_evidence,
    )
    verdict["sameSectionEvidence"] = decision
    return bool(decision.get("refine"))


def _oep_refine_loader_stage_candidate(
    verdict: Dict[str, Any],
    section_plan: Dict[str, Any],
    deadline: float,
    telem: Dict[str, Any],
) -> Dict[str, Any]:
    tls_seh_refined = _oep_refine_tls_seh_candidate(
        verdict, section_plan, deadline, telem
    )
    if isinstance(tls_seh_refined, dict):
        return tls_seh_refined
    if not verdict.get("accepted") or not _oep_candidate_needs_refinement(
        verdict, section_plan
    ):
        return verdict
    candidate_hex = _normalize_hex(verdict.get("rip"))
    if not candidate_hex:
        return {**verdict, "accepted": False, "reason": "loader-stage candidate has no RIP"}
    section = _section_for_runtime_address(
        int(candidate_hex, 16), list(section_plan.get("execSections") or [])
    )
    if not section:
        return {**verdict, "accepted": False, "reason": "loader-stage section is unavailable"}
    decision = (
        verdict.get("sameSectionEvidence")
        if isinstance(verdict.get("sameSectionEvidence"), dict)
        else {}
    )
    known = bool(decision.get("knownLoaderShape"))
    refined = _oep_trace_same_section_transfer(
        candidate_hex,
        section,
        section_plan,
        deadline,
        telem,
        allow_unverified_fallback=known,
        minimum_fallback_distance=0x1000,
    )
    refined["sameSectionEvidence"] = decision
    return refined


def _resolve_loaded_module_for_dump(module: str = "") -> Optional[Dict[str, Any]]:
    payload = GetModuleList()
    modules = payload.get("modules", []) if isinstance(payload, dict) else []
    requested = str(module or _get_current_debuggee_image_name() or "").strip().casefold()
    requested_base = os.path.basename(requested)
    requested_stem = os.path.splitext(requested_base)[0]
    for item in modules:
        if not isinstance(item, dict):
            continue
        candidates = {
            str(item.get("name") or "").strip().casefold(),
            os.path.basename(str(item.get("path") or "")).casefold(),
        }
        candidates |= {os.path.splitext(candidate)[0] for candidate in list(candidates)}
        if requested in candidates or requested_base in candidates or requested_stem in candidates:
            return dict(item)
    return None


def _read_live_memory_exact(address: int, size: int, chunk_size: int = 1_048_576) -> bytes:
    remaining = max(0, int(size))
    cursor = int(address)
    output = bytearray()
    while remaining:
        count = min(remaining, max(4096, min(int(chunk_size), 4 * 1024 * 1024)))
        payload = ReadMemory(f"0x{cursor:x}", count, ty="hex", max_chars=0)
        if not isinstance(payload, dict) or not payload.get("ok"):
            raise RuntimeError(
                f"Failed to read live module memory at 0x{cursor:x}: "
                f"{payload.get('error') if isinstance(payload, dict) else payload}"
            )
        raw_hex = str(payload.get("hex") or "")
        try:
            chunk = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise RuntimeError(f"Bridge returned invalid memory hex at 0x{cursor:x}: {exc}") from exc
        if len(chunk) != count:
            raise RuntimeError(
                f"Short live memory read at 0x{cursor:x}: expected {count}, got {len(chunk)}"
            )
        output.extend(chunk)
        cursor += count
        remaining -= count
    return bytes(output)


def _dump_loaded_module_overlay(
    module_record: Dict[str, Any],
    output_path: str,
    overwrite: bool = False,
    verify: bool = True,
) -> Dict[str, Any]:
    """Create a reloadable source-backed PE with live executable sections.

    Unlike a raw Scylla DLL image, this preserves pristine loader/CRT state,
    imports, TLS and writable data from the source file. Runtime relocation
    deltas in copied code are reversed so the output remains relocatable from
    its original preferred ImageBase.
    """
    try:
        import pefile  # type: ignore
    except Exception:
        return {"ok": False, "error": "pefile is required for source-backed module overlay dumps"}
    source_path = os.path.abspath(str((module_record or {}).get("path") or ""))
    requested_output = str(output_path or "").strip()
    if not source_path or not os.path.isfile(source_path):
        return {"ok": False, "error": "Loaded module has no readable source PE path"}
    if not requested_output:
        source_dir = os.path.dirname(source_path)
        stem, extension = os.path.splitext(os.path.basename(source_path))
        requested_output = os.path.join(source_dir, f"{stem}.live{extension or '.bin'}")
    final_path = os.path.abspath(requested_output)
    if os.path.normcase(final_path) == os.path.normcase(source_path):
        return {"ok": False, "error": "Output path must differ from the source module"}
    if os.path.exists(final_path) and not overwrite:
        return {
            "ok": False,
            "error": "Output file already exists; set overwrite=true to replace it",
            "path": final_path,
        }
    state = _build_debug_state(include_console=False, include_callstack=False, max_console_chars=0)
    if not state.get("debugging") or not state.get("paused"):
        return {
            "ok": False,
            "error": "Source-backed module dumping requires an active paused target",
            "state": state,
        }
    hello = BridgeHello(refresh=True)
    if not isinstance(hello, dict) or not hello.get("ok"):
        return {"ok": False, "error": "Authoritative bridge identity is unavailable", "bridge": hello}
    runtime_base = _parse_int((module_record or {}).get("base"), 0) or 0
    runtime_size = _parse_int((module_record or {}).get("size"), 0) or 0
    if runtime_base <= 0:
        return {"ok": False, "error": "Loaded module base is unavailable"}
    source_bytes = bytearray(Path(source_path).read_bytes())
    try:
        pe = pefile.PE(data=bytes(source_bytes), fast_load=False)
    except Exception as exc:
        return {"ok": False, "error": f"Source PE parse failed: {exc}"}
    preferred_base = int(pe.OPTIONAL_HEADER.ImageBase or 0)
    size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage or 0)
    if runtime_size and size_of_image > runtime_size:
        return {
            "ok": False,
            "error": "Loaded module is smaller than the source PE SizeOfImage",
            "runtimeSize": runtime_size,
            "sourceSizeOfImage": size_of_image,
        }
    selected: List[Dict[str, Any]] = []
    for section in pe.sections:
        characteristics = int(section.Characteristics or 0)
        if not (characteristics & 0x20000000):
            continue
        virtual_address = int(section.VirtualAddress or 0)
        virtual_size = int(section.Misc_VirtualSize or 0)
        raw_size = int(section.SizeOfRawData or 0)
        raw_pointer = int(section.PointerToRawData or 0)
        name = bytes(section.Name).split(b"\x00", 1)[0].decode("ascii", errors="replace")
        if raw_size <= 0:
            return {
                "ok": False,
                "unsupported": True,
                "error": f"Executable section {name!r} has no source raw storage; use the OEP/Scylla unpacking workflow",
                "section": name,
            }
        if raw_pointer < 0 or raw_pointer + raw_size > len(source_bytes):
            return {"ok": False, "error": f"Executable section {name!r} exceeds the source file"}
        selected.append(
            {
                "name": name,
                "rva": virtual_address,
                "virtualSize": virtual_size,
                "rawSize": raw_size,
                "rawPointer": raw_pointer,
                "runtimeStart": runtime_base + virtual_address,
                "runtimeEnd": runtime_base + virtual_address + raw_size,
            }
        )
    if not selected:
        return {"ok": False, "error": "Source PE has no executable sections to overlay"}

    active_breakpoints: List[Dict[str, Any]] = []
    try:
        breakpoint_payload = GetBreakpointList()
        for breakpoint in list((breakpoint_payload or {}).get("breakpoints") or []):
            if not isinstance(breakpoint, dict) or not breakpoint.get("active"):
                continue
            if str(breakpoint.get("type") or "").lower() not in ("normal", "software"):
                continue
            address = _parse_int(breakpoint.get("addr"), 0) or 0
            if any(item["runtimeStart"] <= address < item["runtimeEnd"] for item in selected):
                active_breakpoints.append(dict(breakpoint))
    except Exception:
        pass
    if active_breakpoints:
        return {
            "ok": False,
            "error": "Active software breakpoints overlap executable sections; disable them before dumping to avoid embedding INT3 bytes",
            "breakpoints": active_breakpoints,
        }

    copied_ranges: List[Tuple[int, int]] = []
    for item in selected:
        live = _read_live_memory_exact(int(item["runtimeStart"]), int(item["rawSize"]))
        raw_pointer = int(item["rawPointer"])
        source_bytes[raw_pointer : raw_pointer + len(live)] = live
        copied_ranges.append((int(item["rva"]), int(item["rva"]) + len(live)))

    delta = runtime_base - preferred_base
    relocations_adjusted = 0
    unsupported_relocations: set = set()
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]]
        )
        for block in list(getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []) or []):
            for relocation in list(block.entries or []):
                rva = int(relocation.rva or 0)
                if not any(start <= rva < end for start, end in copied_ranges):
                    continue
                file_offset = int(pe.get_offset_from_rva(rva))
                if int(relocation.type) == 10:
                    value = struct.unpack_from("<Q", source_bytes, file_offset)[0]
                    struct.pack_into("<Q", source_bytes, file_offset, (value - delta) & 0xFFFFFFFFFFFFFFFF)
                    relocations_adjusted += 1
                elif int(relocation.type) == 3:
                    value = struct.unpack_from("<I", source_bytes, file_offset)[0]
                    struct.pack_into("<I", source_bytes, file_offset, (value - delta) & 0xFFFFFFFF)
                    relocations_adjusted += 1
                elif int(relocation.type) != 0:
                    unsupported_relocations.add(int(relocation.type))
    except Exception as exc:
        return {"ok": False, "error": f"Failed to reverse runtime relocations: {exc}"}
    if unsupported_relocations:
        return {
            "ok": False,
            "unsupported": True,
            "error": "Executable sections contain unsupported relocation types",
            "relocationTypes": sorted(unsupported_relocations),
        }

    pe_offset = struct.unpack_from("<I", source_bytes, 0x3C)[0]
    struct.pack_into("<I", source_bytes, pe_offset + 24 + 64, 0)
    os.makedirs(os.path.dirname(final_path), exist_ok=True)
    temporary_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", delete=False, dir=os.path.dirname(final_path), prefix=".mcp-module-", suffix=".tmp"
        ) as handle:
            temporary_path = handle.name
            handle.write(source_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        if os.path.exists(final_path) and overwrite:
            os.remove(final_path)
        os.replace(temporary_path, final_path)
        temporary_path = ""
    finally:
        if temporary_path and os.path.exists(temporary_path):
            try:
                os.remove(temporary_path)
            except OSError:
                pass
    verification = (
        VerifyPEDump(
            final_path,
            source_path=source_path,
            expected_entrypoint=str(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            require_imports=True,
            strict_source_imports=True,
            check_dependencies=True,
        )
        if verify
        else None
    )
    verified = bool(not verify or (verification or {}).get("verified"))
    return {
        "ok": verified,
        "verified": verified if verify else None,
        "strategy": "source_backed_executable_overlay",
        "module": module_record.get("name"),
        "sourcePath": source_path,
        "path": final_path,
        "size": os.path.getsize(final_path),
        "sha256": _sha256_file(final_path),
        "preferredImageBase": f"0x{preferred_base:x}",
        "runtimeImageBase": f"0x{runtime_base:x}",
        "relocationDelta": f"0x{delta:x}",
        "relocationsAdjusted": relocations_adjusted,
        "sectionsCopied": selected,
        "writableStatePreservedFromSource": True,
        "importsPreservedFromSource": True,
        "verification": verification,
        "error": None if verified else "Overlay PE failed independent verification",
    }


@mcp.tool()
def DumpLoadedModule(
    module: str,
    output_path: str,
    overwrite: bool = False,
    verify: bool = True,
) -> dict:
    """Dump a loaded module as a reloadable source-backed PE.

    Live executable sections are overlaid onto the original PE after reversing
    runtime relocations. Loader-critical headers, imports, TLS and writable CRT
    state remain pristine. Active software breakpoints in copied code fail the
    operation rather than being embedded into the output.
    """
    record = _resolve_loaded_module_for_dump(module)
    if not record:
        return {"ok": False, "error": f"Loaded module could not be resolved: {module!r}"}
    return _dump_loaded_module_overlay(
        record,
        output_path=output_path,
        overwrite=overwrite,
        verify=verify,
    )


@mcp.tool()
def ReconstructImports(
    dump_path: str,
    output_path: str,
    module: str = "",
    search_start: str = "",
    iat_start: str = "",
    iat_size: int = 0,
    prefer_source_iat: bool = True,
    advanced_search: bool = False,
    create_new_iat: bool = False,
    rebuild: bool = True,
    overwrite: bool = False,
    verify: bool = True,
    make_runnable: bool = True,
) -> dict:
    """Repair an existing raw PE dump's imports using the paused live process.

    An explicit ``iat_start`` + ``iat_size`` is authoritative. Otherwise the
    exact source PE IAT directory is preferred when it is populated; Scylla
    search is the final fallback. The input dump is never modified in place.
    """
    raw_path = os.path.abspath(str(dump_path or "").strip())
    fixed_path = os.path.abspath(str(output_path or "").strip())
    if not str(dump_path or "").strip() or not os.path.isfile(raw_path):
        return {"ok": False, "error": "dump_path must name an existing raw PE dump"}
    if not str(output_path or "").strip():
        return {"ok": False, "error": "output_path is required"}
    if os.path.normcase(raw_path) == os.path.normcase(fixed_path):
        return {"ok": False, "error": "Input and output paths must be different"}
    if os.path.exists(fixed_path) and not overwrite:
        return {
            "ok": False,
            "error": "Output file already exists; set overwrite=true to replace it",
            "outputPath": fixed_path,
        }
    os.makedirs(os.path.dirname(fixed_path), exist_ok=True)
    state = _build_debug_state(include_console=False, include_callstack=False, max_console_chars=0)
    if not state.get("debugging") or not state.get("paused"):
        return {
            "ok": False,
            "error": "ReconstructImports requires an active paused debug session",
            "state": state,
        }
    hello = BridgeHello(refresh=True)
    if not isinstance(hello, dict) or not hello.get("ok"):
        return {"ok": False, "error": "Authoritative bridge identity is unavailable", "bridge": hello}
    module_record = _resolve_loaded_module_for_dump(module)
    if not module_record:
        return {"ok": False, "error": f"Loaded module could not be resolved: {module!r}"}
    image_base = _normalize_hex(module_record.get("base"))
    entrypoint = _normalize_hex(module_record.get("entry") or state.get("rip") or image_base)
    if not image_base or not entrypoint:
        return {"ok": False, "error": "Module image base/entrypoint is unavailable"}

    explicit_start = _normalize_hex(iat_start)
    try:
        explicit_size = max(0, int(iat_size or 0))
    except (TypeError, ValueError):
        return {"ok": False, "error": "iat_size must be an integer"}
    if bool(explicit_start) != bool(explicit_size):
        return {"ok": False, "error": "iat_start and iat_size must be supplied together"}
    iat_source = "explicit" if explicit_start else "search"
    source_path = str(module_record.get("path") or "")
    if not explicit_start and prefer_source_iat and source_path and os.path.isfile(source_path):
        try:
            source_layout = _parse_pe_layout(source_path)
            source_iat = source_layout.get("iatDirectory") or {}
            source_evidence = _pe_import_evidence(source_layout)
            source_iat_rva = _parse_int(source_iat.get("rva"), 0) or 0
            source_iat_size = int(source_iat.get("size") or 0)
            if (
                source_iat_rva > 0
                and source_iat_size > 0
                and int(source_evidence.get("functionCount") or 0) > 0
                and not source_evidence.get("badDllNames")
            ):
                explicit_start = f"0x{int(image_base, 16) + source_iat_rva:x}"
                explicit_size = source_iat_size
                iat_source = "source_pe_directory"
        except Exception:
            pass
    params: Dict[str, Any] = {
        "pid": str(int(_infer_debuggee_pid(0))),
        "imageBase": image_base,
        "entrypoint": entrypoint,
        "searchStart": _normalize_hex(search_start) or entrypoint,
        "dumpPath": raw_path,
        "fixedPath": fixed_path,
        "sourcePath": source_path,
        "dumpProcess": "false",
        "overwrite": str(bool(overwrite)).lower(),
        "advancedSearch": str(bool(advanced_search)).lower(),
        "createNewIat": str(bool(create_new_iat)).lower(),
        "fixImports": "true",
        "rebuild": str(bool(rebuild)).lower(),
        "updatePeHeaderChecksum": "true",
        "createBackup": "false",
    }
    if explicit_start and explicit_size:
        params["iatStart"] = explicit_start
        params["iatSize"] = f"0x{explicit_size:x}"
    native = _coerce_json_payload(
        safe_post("Scylla/DumpFix", params, log=False, timeout_sec=120.0)
    )
    if make_runnable and isinstance(native, dict) and native.get("ok") and os.path.isfile(fixed_path):
        native = dict(native)
        native["makeRunnable"] = _make_dump_runnable(fixed_path)
    verification = None
    if verify and os.path.isfile(fixed_path):
        verification = VerifyPEDump(
            fixed_path,
            source_path=source_path,
            expected_entrypoint=entrypoint,
            module_base=image_base,
            require_imports=True,
            strict_source_imports=True,
            check_dependencies=True,
        )
    native_ok = bool(isinstance(native, dict) and native.get("ok"))
    verified = bool(not verify or (verification or {}).get("verified"))
    return {
        "ok": native_ok and verified,
        "inputPath": raw_path,
        "outputPath": fixed_path,
        "module": module_record.get("name"),
        "imageBase": image_base,
        "entrypoint": entrypoint,
        "iatSource": iat_source,
        "iatStart": explicit_start or None,
        "iatSize": explicit_size,
        "native": native,
        "verification": verification,
        "error": None
        if native_ok and verified
        else (
            "Reconstructed PE failed independent verification"
            if native_ok
            else (native.get("error") if isinstance(native, dict) else str(native))
        ),
    }


_UNPACK_WORKFLOW_SCHEMA = "unpack-workflow-v1"


def _append_unpack_stage(
    stages: List[Dict[str, Any]],
    name: str,
    status: str,
    evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Append one bounded, JSON-safe unpack workflow event."""

    record = {
        "seq": len(stages) + 1,
        "stage": str(name or "unknown"),
        "status": str(status or "unknown"),
        "observedAt": _now_iso(),
        "evidence": dict(evidence or {}),
    }
    stages.append(record)
    return record


def _unpack_confidence_score(label: Any, verified: Optional[bool]) -> float:
    score = {
        "high": 0.85,
        "medium": 0.62,
        "low": 0.35,
    }.get(str(label or "").strip().lower(), 0.0)
    if verified is True:
        score = max(score, 0.95)
    elif verified is False:
        score = min(score, 0.25)
    return round(score, 3)


def _unpack_artifact_record(path: Any, kind: str) -> Optional[Dict[str, Any]]:
    resolved = os.path.abspath(str(path or "")) if path else ""
    if not resolved or not os.path.isfile(resolved):
        return None
    try:
        digest = _sha256_file(resolved)
    except Exception:
        digest = None
    return {
        "kind": str(kind or "artifact"),
        "path": resolved,
        "size": os.path.getsize(resolved),
        "sha256": str(digest or "").upper() or None,
    }


def _unpack_workflow_body(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema": _UNPACK_WORKFLOW_SCHEMA,
        "workflowId": result.get("workflowId"),
        "startedAt": result.get("startedAt"),
        "finishedAt": result.get("finishedAt"),
        "status": result.get("status"),
        "ok": bool(result.get("ok")),
        "verified": result.get("verified"),
        "confidence": result.get("confidence"),
        "confidenceScore": result.get("confidenceScore"),
        "target": dict(result.get("target") or {}),
        "candidate": {
            "address": result.get("oepAddr"),
            "section": result.get("candidateSection"),
            "detectedVia": result.get("detectedVia"),
            "distanceFromEntry": result.get("distanceFromEntry"),
        },
        "reason": result.get("reason"),
        "unsupported": result.get("unsupported"),
        "stages": list(result.get("stages") or []),
        "artifacts": list(result.get("artifacts") or []),
    }


def _write_unpack_workflow_artifact(
    result: Dict[str, Any], output_path: str
) -> Dict[str, Any]:
    target = Path(os.path.abspath(str(output_path or "")))
    body = _unpack_workflow_body(result)
    canonical = json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest().upper()
    payload = {**body, "workflowSha256": digest}
    temporary = target.with_name(
        target.name + f".tmp-{os.getpid()}-{time.time_ns()}"
    )
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, target)
        return {
            "ok": True,
            "schema": _UNPACK_WORKFLOW_SCHEMA,
            "path": str(target),
            "size": target.stat().st_size,
            "workflowSha256": digest,
        }
    except Exception as exc:
        return {
            "ok": False,
            "schema": _UNPACK_WORKFLOW_SCHEMA,
            "path": str(target),
            "error": str(exc),
        }
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


@mcp.tool()
def FindOEP(
    timeout_ms: int = 30000,
    packer_section: str = "",
    dump_to_path: str = "",
    timeline_to_path: str = "",
) -> dict:
    """
    Find the Original Entry Point (OEP) of a packed executable and, optionally,
    produce a VERIFIED unpacked dump.

    Engine: a packer-agnostic dynamic approach for the unpack-in-memory-then-jump
    class (UPX, ASPack, FSG, MPRESS, PECompact, Petite, simple crypters):
      1. ESP-anchor fast-forward -- a hardware breakpoint on the stub's saved
         register slot skips past the decompression loop and is immune to the
         page writes that defeat memory breakpoints.
      2. Section-hop conditional trace -- single-steps in the engine until
         execution enters a non-stub executable section (the OEP).
    Virtualizing protectors have no generic recoverable OEP contract here; they
    are reported honestly via isLikelyVirtualized rather than faked.  The optional
    virtualization research backend is disabled in this build.

    When dump_to_path is set, the dump is written via Scylla and VERIFIED before
    ok:true (entry moved out of the packer section to the OEP, IAT resolved,
    imports richer than the packed baseline). The raw memory dump is always kept,
    so a failed verification still leaves something for manual recovery.

    ``timeline_to_path`` optionally writes a canonical `unpack-workflow-v1`
    evidence artifact. Returns {ok, status, stages, artifacts, oepAddr,
    detectedVia, confidence, moduleBase, moduleSize, packerEntry, verified,
    reason, rawDumpPath, isLikelyVirtualized, ...}.
    """
    bridge_identity = BridgeHello(refresh=True)
    if not isinstance(bridge_identity, dict) or not bridge_identity.get("ok"):
        return {
            "ok": False,
            "error": "FindOEP requires authoritative bridge/session identity",
            "bridge": bridge_identity,
            "logPath": LOG_PATH,
        }
    state = _build_debug_state(include_console=False, include_callstack=False, max_console_chars=0)
    if not state.get("debugging"):
        return {"ok": False, "error": "FindOEP requires an active debug session", "logPath": LOG_PATH}
    module_base = _get_current_debuggee_module_base()
    if not module_base:
        return {"ok": False, "error": "No debuggee module loaded", "logPath": LOG_PATH}
    image = _get_current_debuggee_image_name() or ""
    try:
        mod_list = GetModuleList()
        modules = mod_list.get("modules", []) if isinstance(mod_list, dict) else []
        main = next((m for m in modules if str(m.get("name", "")).lower() == image.lower()), None)
        if not main:
            return {"ok": False, "error": f"Module {image} not in loaded list", "logPath": LOG_PATH}
    except Exception as e:
        return {"ok": False, "error": f"Module lookup failed: {e}", "logPath": LOG_PATH}
    image_path = str(main.get("path") or "")
    base_int = int(str(module_base or "0x0"), 16)
    module_size = int(str(main.get("size") or "0x0"), 16)
    entry = _normalize_hex(main.get("entry")) or module_base

    workflow_id = f"unpack-{uuid.uuid4().hex}"
    started_at = _now_iso()
    stages: List[Dict[str, Any]] = []
    try:
        image_sha256 = _sha256_file(image_path).upper() if image_path else None
    except Exception:
        image_sha256 = None
    target = {
        "path": image_path or None,
        "name": str(main.get("name") or image or ""),
        "sha256": image_sha256,
        "architecture": None,
        "moduleBase": module_base,
        "moduleSize": f"0x{module_size:x}" if module_size else None,
        "entry": entry,
    }
    _append_unpack_stage(
        stages,
        "session",
        "ready",
        {
            "debugging": True,
            "paused": bool(state.get("paused")),
            "moduleBase": module_base,
            "imageSha256": image_sha256,
            "bridgeInstanceId": (
                (bridge_identity.get("identity") or {}).get(
                    "bridgeInstanceId"
                )
                if isinstance(bridge_identity.get("identity"), dict)
                else None
            ),
            "sessionId": (
                (bridge_identity.get("identity") or {}).get("sessionId")
                if isinstance(bridge_identity.get("identity"), dict)
                else None
            ),
        },
    )

    section_plan = _build_find_oep_section_plan(main, image_path, packer_section=packer_section)
    layout = section_plan.get("layout") or {}
    target["architecture"] = layout.get("arch")
    _append_unpack_stage(
        stages,
        "layout",
        "ready" if layout else "degraded",
        {
            "architecture": layout.get("arch"),
            "entrySection": section_plan.get("entrySection"),
            "executableSectionCount": len(section_plan.get("execSections") or []),
            "watchPhaseCount": len(section_plan.get("watchPhases") or []),
            "tlsCallbackCount": len(section_plan.get("tlsCallbacks") or []),
            "exceptionDirectorySize": int(
                (section_plan.get("exceptionDirectory") or {}).get("size") or 0
            ),
            "packerSectionOverride": str(packer_section or "") or None,
        },
    )
    engine = _oep_engine(main, image_path, section_plan, timeout_ms=timeout_ms)
    _append_unpack_stage(
        stages,
        "oep_engine",
        "candidate" if engine.get("ok") else "failed",
        {
            "reason": engine.get("reason"),
            "detectedVia": engine.get("detectedVia") or None,
            "layerReached": (engine.get("telemetry") or {}).get("layerReached"),
            "candidate": engine.get("oepAddr"),
            "likelyVirtualized": bool(engine.get("isLikelyVirtualized")),
        },
    )
    multi_stage = (
        (engine.get("telemetry") or {}).get("multiStage")
        if isinstance(engine.get("telemetry"), dict)
        else {}
    )
    multi_stage = multi_stage if isinstance(multi_stage, dict) else {}
    multi_history = (
        multi_stage.get("exceptionHistory")
        if isinstance(multi_stage.get("exceptionHistory"), dict)
        else {}
    )
    _append_unpack_stage(
        stages,
        "tls_seh",
        (
            "observed"
            if (
                int(multi_stage.get("tlsCallbackHitCount") or 0)
                or int(multi_history.get("count") or 0)
            )
            else "not_observed"
        ),
        {
            "schema": multi_stage.get("schema"),
            "tlsCallbacks": list(multi_stage.get("tlsCallbacksConfigured") or []),
            "tlsCallbackHitCount": int(
                multi_stage.get("tlsCallbackHitCount") or 0
            ),
            "reachedEntry": bool(multi_stage.get("reachedEntry")),
            "transitions": list(multi_stage.get("transitions") or []),
            "exceptionHistory": multi_history,
            "exceptionDirectory": section_plan.get("exceptionDirectory"),
            "liveExceptionDirectory": multi_stage.get(
                "liveExceptionDirectory"
            ),
        },
    )

    result = {
        "schema": _UNPACK_WORKFLOW_SCHEMA,
        "workflowId": workflow_id,
        "startedAt": started_at,
        "ok": bool(engine.get("ok")),
        "status": "oep_detected" if engine.get("ok") else (
            "unsupported" if engine.get("isLikelyVirtualized") else "failed"
        ),
        "oepAddr": engine.get("oepAddr"),
        "detectedVia": engine.get("detectedVia") or "",
        "reason": engine.get("reason"),
        "confidence": engine.get("confidence"),
        "candidateSection": engine.get("candidateSection"),
        "distanceFromEntry": engine.get("distanceFromEntry"),
        "isLikelyVirtualized": bool(engine.get("isLikelyVirtualized")),
        "moduleBase": module_base,
        "moduleSize": f"0x{module_size:x}" if module_size else None,
        "packerEntry": entry,
        "watchPhases": [
            [str(item.get("name") or "") for item in phase]
            for phase in (section_plan.get("watchPhases") or [])
        ],
        "layerReached": (engine.get("telemetry") or {}).get("layerReached"),
        "telemetry": engine.get("telemetry"),
        "verified": None,
        "target": target,
        "stages": stages,
        "artifacts": [],
        "unsupported": (
            {
                "code": "VIRTUALIZED_OR_UNSUPPORTED_UNPACKER",
                "message": engine.get("hint")
                or "No recoverable OEP was observed within the bounded workflow.",
                "evidence": {
                    "reason": engine.get("reason"),
                    "layerReached": (engine.get("telemetry") or {}).get("layerReached"),
                    "entrySectionEntropy": engine.get("entrySectionEntropy"),
                },
            }
            if engine.get("isLikelyVirtualized")
            else None
        ),
        "logPath": LOG_PATH,
    }
    if engine.get("oepAddr"):
        _append_unpack_stage(
            stages,
            "candidate",
            "accepted",
            {
                "address": engine.get("oepAddr"),
                "section": engine.get("candidateSection"),
                "confidence": engine.get("confidence"),
                "detectedVia": engine.get("detectedVia"),
                "distanceFromEntry": engine.get("distanceFromEntry"),
            },
        )
    _log_event(
        "find_oep",
        ok=result["ok"],
        oep=result["oepAddr"],
        via=result["detectedVia"],
        reason=result.get("reason"),
    )

    detected_oep = engine.get("oepAddr")
    if detected_oep and dump_to_path:
        dump_path = os.path.abspath(str(dump_to_path))
        try:
            packed_layout = _parse_pe_layout(image_path)
        except Exception:
            packed_layout = {}
        pointer_size = 8 if layout.get("arch") == "x64" else 4
        runtime_iat_selection = _oep_select_runtime_iat_candidate(
            base_int, module_size, pointer_size
        )
        runtime_iat_resolution = _oep_resolve_runtime_iat_exports(
            runtime_iat_selection, base_int
        )
        result["runtimeIatSelection"] = runtime_iat_selection
        result["runtimeIatResolution"] = {
            key: value
            for key, value in runtime_iat_resolution.items()
            if key != "entries"
        }
        _append_unpack_stage(
            stages,
            "runtime_iat",
            (
                "resolved"
                if runtime_iat_selection.get("ok")
                and runtime_iat_resolution.get("ok")
                else "degraded"
            ),
            {
                "selection": runtime_iat_selection,
                "resolution": {
                    key: value
                    for key, value in runtime_iat_resolution.items()
                    if key != "entries"
                },
            },
        )
        if runtime_iat_selection.get("ok") and runtime_iat_resolution.get(
            "ok"
        ):
            dump_result = _dump_with_runtime_iat_rebuild(
                main,
                entrypoint=detected_oep,
                output_path=dump_path,
                source_path=image_path,
                selection=runtime_iat_selection,
                resolution=runtime_iat_resolution,
            )
        else:
            dump_result = _scylla_dump_module(
                main,
                entrypoint=detected_oep,
                output_path=dump_path,
                search_start=detected_oep,
                source_path=image_path,
                keep_raw_dump=True,
                make_runnable=True,
            )
        fixed_exists = os.path.exists(dump_path)
        verification = _oep_verify_dump(
            detected_oep, base_int, dump_path, packed_layout, dump_result
        )
        import_sanitization = None
        if verification.get("reason") in {
            "dump_iat_corrupt",
            "dump_iat_unresolved_names",
        }:
            import_sanitization = _sanitize_trailing_import_descriptors(dump_path)
            if isinstance(dump_result, dict):
                dump_result["importSanitization"] = import_sanitization
            if import_sanitization.get("ok") and import_sanitization.get("changed"):
                verification = _oep_verify_dump(
                    detected_oep, base_int, dump_path, packed_layout, dump_result
                )
        result["dumpPath"] = dump_path
        result["dumpResult"] = dump_result
        result["dumpExists"] = fixed_exists
        result["dumpSize"] = os.path.getsize(dump_path) if fixed_exists else 0
        result["rawDumpPath"] = (dump_result or {}).get("rawDumpPath")
        result["verified"] = bool(verification.get("verified"))
        result["dumpVerification"] = verification
        result["importSanitization"] = import_sanitization
        # ok now reflects a VERIFIED unpack, not mere OEP detection or file existence.
        result["ok"] = bool(verification.get("verified"))
        result["status"] = (
            "unpacked_verified" if verification.get("verified") else "dump_rejected"
        )
        _append_unpack_stage(
            stages,
            "dump",
            "written" if fixed_exists else "failed",
            {
                "path": dump_path,
                "exists": fixed_exists,
                "size": result.get("dumpSize"),
                "rawDumpPath": result.get("rawDumpPath"),
                "nativeOk": bool(isinstance(dump_result, dict) and dump_result.get("ok")),
                "iatSource": (
                    dump_result.get("iatSource")
                    if isinstance(dump_result, dict)
                    else None
                ),
                "runtimeImportRebuild": (
                    dump_result.get("runtimeImportRebuild")
                    if isinstance(dump_result, dict)
                    else None
                ),
            },
        )
        _append_unpack_stage(
            stages,
            "verification",
            "verified" if verification.get("verified") else "rejected",
            {
                "reason": verification.get("reason"),
                "iatResolved": verification.get("iatResolved"),
                "entryMatches": verification.get("entryMatches"),
                "dumpImportCount": verification.get("dumpImportCount"),
                "packedImportCount": verification.get("packedImportCount"),
                "iatSize": (verification.get("checks") or {}).get("iatSize"),
                "importDlls": (verification.get("checks") or {}).get("importDlls"),
                "importSanitization": import_sanitization,
            },
        )
        fixed_artifact = _unpack_artifact_record(dump_path, "reconstructed_pe")
        raw_artifact = _unpack_artifact_record(result.get("rawDumpPath"), "raw_memory_dump")
        result["artifacts"] = [
            item for item in (fixed_artifact, raw_artifact) if isinstance(item, dict)
        ]
        if not verification.get("verified"):
            result["reason"] = verification.get("reason") or result.get("reason")
            result["dumpHint"] = (
                "Unpacked dump did not verify; the raw memory dump was kept for manual recovery."
            )
    _append_unpack_stage(
        stages,
        "complete",
        str(result.get("status") or "failed"),
        {
            "ok": bool(result.get("ok")),
            "verified": result.get("verified"),
            "reason": result.get("reason"),
        },
    )
    result["finishedAt"] = _now_iso()
    result["confidenceScore"] = _unpack_confidence_score(
        result.get("confidence"), result.get("verified")
    )
    if timeline_to_path:
        result["timelineArtifact"] = _write_unpack_workflow_artifact(
            result, timeline_to_path
        )
    return result


@mcp.tool()
def SummarizeTraceHistory(limit: int = 20, include_breakpoints: bool = True) -> dict:
    """
    Summarize recent trace and breakpoint-capture history into a compact RE-oriented view.
    """
    safe_limit = max(1, min(int(limit), 64))
    trace_entries = list(_get_runtime_value("traceHistory", []) or [])[-safe_limit:]
    breakpoint_entries = (
        list(_get_runtime_value("breakpointCaptureHistory", []) or [])[-safe_limit:]
        if include_breakpoints
        else []
    )
    summary = _summarize_trace_entries(
        trace_entries,
        include_breakpoint_history=breakpoint_entries if include_breakpoints else None,
    )
    return {
        "ok": True,
        "limit": safe_limit,
        "traceCount": len(trace_entries),
        "breakpointCaptureCount": len(breakpoint_entries),
        "summary": summary,
        "traceEntries": trace_entries,
        "breakpointEntries": breakpoint_entries if include_breakpoints else [],
        "logPath": LOG_PATH,
    }
