"""Reproducible live child-broker acceptance matrix.

This runner exercises the public Python MCP facade against the installed x32dbg
and x64dbg plugins.  It intentionally uses only the repository's deterministic
``child_process`` fixture and records every session identity/phase in a JSON
artifact.  A pre-existing debugger is a hard failure; cleanup is PID + creation
time scoped and never falls back to an image-wide taskkill.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import sys
import time
import traceback
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_PATH = REPO_ROOT / "src" / "x64dbg.py"
FIXTURE_ROOT = REPO_ROOT / "tools" / "bin" / "e2e"
ARCHES = ("x64", "x86")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_bridge():
    spec = importlib.util.spec_from_file_location("x64dbg_child_broker_live", BRIDGE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load bridge from {BRIDGE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_live_utils():
    path = REPO_ROOT / "tools" / "run_live_release_matrix.py"
    spec = importlib.util.spec_from_file_location("x64dbg_live_utils", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load live utilities from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _fixture(arch: str) -> Path:
    path = FIXTURE_ROOT / arch / "child_process.exe"
    if not path.is_file():
        raise FileNotFoundError(path)
    return path.resolve()


def _json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return str(value)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(_json_safe(payload), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _phase_counts(sessions: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in sessions:
        state = item.get("childBrokerState") or {}
        for child in state.get("children") or []:
            phase = str(child.get("phase") or "")
            counts[phase] = counts.get(phase, 0) + 1
    return counts


def _session_summary(inventory: dict[str, Any]) -> dict[str, Any]:
    sessions = []
    for item in inventory.get("sessions") or []:
        debugger = item.get("debugger") or {}
        broker = item.get("childBroker") or {}
        state = item.get("childBrokerState") or {}
        children = []
        for child in state.get("children") or []:
            # Keep identities and diagnostics, but never copy arbitrary HTTP
            # payloads/tokens into the artifact.
            children.append(
                {
                    key: child.get(key)
                    for key in (
                        "childId",
                        "parentLaunchId",
                        "pid",
                        "tid",
                        "parentPid",
                        "creationTime100ns",
                        "architecture",
                        "phase",
                        "errorCode",
                        "identityVerified",
                        "debuggerSpawned",
                        "debuggerAttached",
                        "preEntryPaused",
                        "autoResumeSucceeded",
                        "parentBarrierReached",
                        "brokerSuspendPreviousCount",
                        "resumePreviousSuspendCount",
                        "preservedSuspensionCount",
                        "directChild",
                        "quotaReservationActive",
                        "debuggerPid",
                    )
                    if key in child
                }
            )
        sessions.append(
            {
                "sessionRef": item.get("sessionRef"),
                "bridgeInstanceId": item.get("bridgeInstanceId"),
                "debugger": {
                    "pid": debugger.get("pid"),
                    "processStartTime100ns": debugger.get("processStartTime100ns"),
                    "architecture": debugger.get("architecture"),
                },
                "childBroker": {
                    key: broker.get(key)
                    for key in (
                        "configured",
                        "policy",
                        "brokerId",
                        "rootLaunchId",
                        "rootPid",
                        "parentPid",
                        "childCount",
                    )
                    if key in broker
                },
                "brokerState": {
                    "broker": {
                        key: (state.get("broker") or {}).get(key)
                        for key in (
                            "configured",
                            "stopping",
                            "policy",
                            "rootLaunchId",
                            "rootPid",
                            "parentPid",
                            "acceptedDirectChildren",
                            "acceptedDescendants",
                            "pendingHandoffCount",
                        )
                        if key in (state.get("broker") or {})
                    },
                    "children": children,
                },
            }
        )
    return {
        "count": len(sessions),
        "phaseCounts": _phase_counts(inventory.get("sessions") or []),
        "sessions": sessions,
        "errors": list(inventory.get("errors") or []),
    }


def _launch_id(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    for key in ("launchId", "id"):
        if payload.get(key):
            return str(payload[key])
    for key in ("initResult", "init", "result", "native"):
        nested = payload.get(key)
        found = _launch_id(nested)
        if found:
            return found
    return ""


def _exit_code(payload: Any) -> Optional[int]:
    if not isinstance(payload, dict):
        return None
    for key in ("exitCode", "code"):
        value = payload.get(key)
        if isinstance(value, int):
            return value & 0xFFFFFFFF
    nested_session = payload.get("session")
    if isinstance(nested_session, dict):
        value = nested_session.get("exitCode")
        if isinstance(value, int):
            return value & 0xFFFFFFFF
    for key in ("exit", "state", "result"):
        found = _exit_code(payload.get(key))
        if found is not None:
            return found
    return None


def _error_code(payload: Any) -> str:
    """Find a structured error code through the public wrapper envelope."""

    if not isinstance(payload, dict):
        return ""
    error = payload.get("error")
    if isinstance(error, dict) and error.get("code"):
        return str(error.get("code") or "")
    for key in ("result", "data", "response", "native", "payload"):
        nested = _error_code(payload.get(key))
        if nested:
            return nested
    return str(payload.get("errorCode") or "")


def _snapshot_debuggers(live_utils: Any) -> dict[tuple[int, str, int], Any]:
    try:
        return {
            item.key: item
            for item in live_utils.debugger_processes(live_utils.snapshot_processes())
        }
    except Exception:
        return {}


def _cleanup(live_utils: Any, before: dict[tuple[int, str, int], Any]) -> dict[str, Any]:
    after = _snapshot_debuggers(live_utils)
    owned = [item for key, item in after.items() if key not in before]
    descendants = []
    try:
        snapshot = live_utils.snapshot_processes()
        descendants = live_utils.descendant_processes(snapshot, [item.pid for item in owned])
        result = live_utils.cleanup_owned_processes(owned, descendants)
    except Exception as exc:
        result = {"ok": False, "errorCode": "cleanup_exception", "error": str(exc)}
    result["ownedDebuggerCount"] = len(owned)
    result["ownedDebuggerPids"] = [item.pid for item in owned]
    result["remainingDebuggerPids"] = [item.pid for item in _snapshot_debuggers(live_utils).values()]
    return _json_safe(result)


def _wait_inventory(bridge: Any, predicate, timeout: float = 30.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {"ok": False, "sessions": [], "errors": []}
    while time.monotonic() < deadline:
        last = bridge.ListDebugSessions(include_state=True)
        try:
            if predicate(last):
                return last
        except Exception:
            pass
        time.sleep(0.15)
    return last


def _children(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for item in inventory.get("sessions") or []:
        result.extend((item.get("childBrokerState") or {}).get("children") or [])
    return result


def _run_case(bridge: Any, arch: str, name: str, policy: str, args: list[str], child_arch: Optional[str] = None) -> dict[str, Any]:
    root = _fixture(arch)
    child = _fixture(child_arch or arch)
    if name.startswith("graph") or name == "break_on_create":
        # The final argument is part of the fixture oracle and lets a root of
        # one architecture create a child of the other architecture.
        args = list(args) + [str(child)]
    started = time.monotonic()
    launch = bridge.LaunchFileUnderDebugger(
        str(root),
        arch=arch,
        restart_debugger=True,
        timeout_ms=45000,
        retries=2,
        stop_first=True,
        use_scyllahide="off",
        arguments=args,
        child_policy=policy,
        stdin={"mode": "null"},
        stdout={"mode": "pipe"},
        stderr={"mode": "pipe"},
        capture_limit_bytes=262144,
        advance_to_entry=True,
    )
    launch_id = _launch_id(launch)
    result: dict[str, Any] = {
        "name": name,
        "arch": arch,
        "childArch": child_arch or arch,
        "policy": policy,
        "launchId": launch_id,
        "launchOk": bool(isinstance(launch, dict) and launch.get("ok")),
        "launch": launch,
        "snapshots": [],
    }
    if not result["launchOk"]:
        result["ok"] = False
        result["errorCode"] = "launch_failed"
        return result

    initial = bridge.ListDebugSessions(include_state=True)
    result["snapshots"].append({"at": _now(), **_session_summary(initial)})
    root_broker = {}
    root_session_ref = ""
    for item in initial.get("sessions") or []:
        broker = item.get("childBroker") or {}
        if broker.get("rootLaunchId") == launch_id:
            root_broker = broker
            root_session_ref = str(item.get("sessionRef") or "")
            break
    root_launch = str(root_broker.get("rootLaunchId") or launch_id)

    # LaunchFileUnderDebugger intentionally leaves the root at its entrypoint.
    # Child creation cannot be observed until that exact root session is
    # resumed, so do this before polling the broker inventory.
    root_initial_run = None
    if root_session_ref:
        try:
            bridge.SelectDebugSession(session_ref=root_session_ref)
        except Exception:
            pass
    try:
        root_initial_run = bridge.DebugRun()
    except Exception as exc:
        root_initial_run = {"ok": False, "error": str(exc)}
    result["rootInitialRun"] = root_initial_run

    active_inventory: dict[str, Any] = {}
    if name == "simple_attach_first":
        observed = _wait_inventory(
            bridge,
            lambda inv: any(
                c.get("phase") == "attached_running" for c in _children(inv)
            ),
            30.0,
            )
        result["snapshots"].append({"at": _now(), **_session_summary(observed)})
        active_inventory = observed
        children = _children(observed)
        result["oracle"] = {
            "childCount": len(children),
            "allRunning": bool(children) and all(c.get("phase") == "attached_running" for c in children),
            "barrierReached": bool(children) and all(c.get("parentBarrierReached") for c in children),
            "identityVerified": bool(children) and all(c.get("identityVerified") for c in children),
        }
    else:
        expected = 2 if (name.startswith("graph") or name == "break_on_create") else 1
        if name == "break_on_create":
            selected = []
            selected_child_ids: set[str] = set()
            deadline = time.monotonic() + 60.0
            observed: dict[str, Any] = {"ok": False, "sessions": [], "errors": []}
            # The fixture creates children sequentially and waits for each
            # one.  Consequently break-on-create cannot wait for the whole
            # fanout at once: resume one paused child, then wait for the next.
            while time.monotonic() < deadline and len(selected) < expected:
                observed = bridge.ListDebugSessions(include_state=True)
                debugger_session_refs = {
                    int((session_item.get("debugger") or {}).get("pid") or 0):
                    str(session_item.get("sessionRef") or "")
                    for session_item in observed.get("sessions") or []
                }
                for item in observed.get("sessions") or []:
                    for child_state in (item.get("childBrokerState") or {}).get("children") or []:
                        child_id = str(child_state.get("childId") or "")
                        ref = debugger_session_refs.get(
                            int(child_state.get("debuggerPid") or 0), ""
                        )
                        if (
                            child_state.get("phase") != "attached_pre_entry_paused"
                            or not child_id
                            or child_id in selected_child_ids
                            or not ref
                        ):
                            continue
                        selected_child_ids.add(child_id)
                        selection = bridge.SelectDebugSession(session_ref=ref)
                        selection["run"] = bridge.DebugRun()
                        selection["childId"] = child_id
                        selected.append(selection)
                if len(selected) < expected:
                    time.sleep(0.15)
            result["snapshots"].append({"at": _now(), **_session_summary(observed)})
            result["oracle"] = {
                "pausedChildren": len(selected),
                "selectionRunsOk": len(selected) >= expected and all(bool(x.get("ok")) and bool((x.get("run") or {}).get("ok")) for x in selected),
                "selectionCount": len(selected),
            }
            result["selection"] = selected
        else:
            observed = _wait_inventory(
                bridge,
                lambda inv: len([c for c in _children(inv) if c.get("phase") == "attached_running"]) >= expected,
                60.0,
            )
            result["snapshots"].append({"at": _now(), **_session_summary(observed)})
            if name == "graph_attach_all":
                active_inventory = observed
            children = _children(observed)
            result["oracle"] = {
                "childCount": len(children),
                "expectedAtLeast": expected,
                "allRunning": len(children) >= expected and all(c.get("phase") == "attached_running" for c in children),
                "allIdentityVerified": len(children) >= expected and all(c.get("identityVerified") for c in children),
                "crossArch": child_arch is not None and len(children) >= expected and all(c.get("architecture") == child_arch for c in children),
            }

    # A self-unload request must remain inert while the child broker is
    # genuinely active.  This is a separate proof from the HTTP parser's
    # idle-session route test: the broker inventory is sampled before and
    # after the guarded command, and the bridge must still answer Hello.
    active_unload_probe: dict[str, Any] = {"skipped": True}
    if name in ("simple_attach_first", "graph_attach_all"):
        before_children = _children(active_inventory)
        before_running = bool(before_children) and all(
            child.get("phase") == "attached_running" for child in before_children
        )
        unload_request = bridge.ExecCommand("plugunload MCPx64dbg")
        after_inventory = bridge.ListDebugSessions(include_state=True)
        after_children = _children(after_inventory)
        hello_after = bridge.BridgeHello()
        after_running = bool(after_children) and all(
            child.get("phase") == "attached_running" for child in after_children
        )
        active_unload_probe = {
            "beforeRunning": before_running,
            "beforeChildCount": len(before_children),
            "request": unload_request,
            "errorCode": _error_code(unload_request),
            "afterChildCount": len(after_children),
            "afterRunning": after_running,
            "helloAfter": hello_after,
            "ok": bool(
                before_running
                and _error_code(unload_request) == "bridge_self_unload_forbidden"
                and after_running
                and isinstance(hello_after, dict)
                and hello_after.get("ok") is not False
            ),
        }
    result["activeChildBrokerUnload"] = active_unload_probe

    # Resume the root session if it is still paused at its post-launch entry.
    if root_session_ref:
        try:
            bridge.SelectDebugSession(session_ref=root_session_ref)
        except Exception:
            pass
    run_result = bridge.DebugRun()
    wait_result = bridge.WaitForExit(timeout_ms=45000, poll_ms=100)
    result["rootRun"] = run_result
    result["rootExit"] = wait_result
    result["rootExitCode"] = _exit_code(wait_result)
    streams: dict[str, Any] = {}
    for stream in ("stdout", "stderr"):
        try:
            page = bridge.ReadLaunchStream(
                launch_id, stream=stream, cursor=0, max_bytes=262144, wait_ms=0
            )
            raw = base64.b64decode(str(page.get("dataBase64") or "")) if isinstance(page, dict) else b""
            streams[stream] = {
                "ok": bool(isinstance(page, dict) and page.get("ok")),
                "byteCount": len(raw),
                "sha256": __import__("hashlib").sha256(raw).hexdigest(),
                "text": raw.decode("utf-8", "replace")[:4096],
            }
        except Exception as exc:
            streams[stream] = {"ok": False, "error": str(exc)}
    result["streams"] = streams
    stream_text = str((streams.get("stdout") or {}).get("text") or "")
    result["streamOracle"] = {
        "parentEvent": "CHILD_EVENT role=parent" in stream_text,
        "childEvent": "CHILD_EVENT role=child" in stream_text,
        "graphEvents": ("GRAPH_EVENT node=" in stream_text) if name.startswith("graph") or name == "break_on_create" else True,
        "noGraphFailure": "GRAPH_FAIL" not in stream_text and "CHILD_FAIL" not in stream_text,
    }
    result["streamOracle"]["ok"] = bool(
        result["streamOracle"]["noGraphFailure"]
        and (
            result["streamOracle"]["graphEvents"]
            if name.startswith("graph") or name == "break_on_create"
            else result["streamOracle"]["parentEvent"] and result["streamOracle"]["childEvent"]
        )
    )
    result["elapsedSeconds"] = round(time.monotonic() - started, 3)
    oracle = result.get("oracle") or {}
    result["ok"] = bool(result.get("launchOk")) and bool(
        oracle.get("allRunning") or oracle.get("selectionRunsOk")
    ) and (not child_arch or bool(oracle.get("crossArch"))) and result["rootExitCode"] in (0, 23) and bool((result.get("streamOracle") or {}).get("ok"))
    if name in ("simple_attach_first", "graph_attach_all"):
        result["ok"] = bool(result["ok"]) and bool(
            (result.get("activeChildBrokerUnload") or {}).get("ok")
        )
    if name == "break_on_create":
        result["ok"] = bool(result.get("launchOk")) and bool((result.get("oracle") or {}).get("selectionRunsOk")) and result["rootExitCode"] in (0, 23)
    return _json_safe(result)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("all", "x86", "x64"), default="all")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args(argv)
    selected_arches = ARCHES if args.arch == "all" else (args.arch,)
    cases = [
        # No arguments selects the fixture's parent mode, which creates one
        # direct child.  ``--child`` would intentionally run only the leaf and
        # therefore cannot exercise the broker.
        ("simple_attach_first", "attach-first", [], None),
        ("graph_attach_all", "attach-all", ["--graph-root", "1", "2", "1500"], None),
        ("break_on_create", "break-on-create", ["--graph-root", "1", "2", "600"], None),
        ("graph_attach_all_cross", "attach-all", ["--graph-root", "1", "2", "1500"], "opposite"),
    ]
    if args.case:
        wanted = {item.strip() for raw in args.case for item in raw.split(",") if item.strip()}
        cases = [item for item in cases if item[0] in wanted]
    if not cases:
        parser.error("case selection is empty")
    bridge = _load_bridge()
    live_utils = _load_live_utils()
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "name": "x64dbg MCP child broker live matrix",
        "startedAt": _now(),
        "repoRoot": str(REPO_ROOT),
        "cases": [],
        "ok": False,
    }
    for arch in selected_arches:
        for name, policy, case_args, child_arch in cases:
            if child_arch == arch:
                # A cross-arch case must actually cross the ABI boundary.
                continue
            effective_child_arch = (
                ("x86" if arch == "x64" else "x64")
                if child_arch == "opposite" else child_arch
            )
            before = _snapshot_debuggers(live_utils)
            if before:
                report["cases"].append({
                    "name": name,
                    "arch": arch,
                    "status": "error",
                    "errorCode": "preexisting_debugger",
                    "debuggers": [asdict(item) for item in before.values()],
                })
                continue
            try:
                outcome = _run_case(
                    bridge, arch, name, policy, case_args, effective_child_arch
                )
            except Exception as exc:
                outcome = {
                    "name": name,
                    "arch": arch,
                    "childArch": child_arch or arch,
                    "ok": False,
                    "errorCode": "runner_exception",
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                }
            outcome["cleanup"] = _cleanup(live_utils, before)
            outcome["ok"] = bool(outcome.get("ok")) and bool((outcome.get("cleanup") or {}).get("ok")) and not (outcome.get("cleanup") or {}).get("remainingDebuggerPids")
            report["cases"].append(outcome)
    report["finishedAt"] = _now()
    report["ok"] = bool(report["cases"]) and all(bool(item.get("ok")) for item in report["cases"])
    report["counts"] = {
        "total": len(report["cases"]),
        "passed": sum(1 for item in report["cases"] if item.get("ok")),
        "failed": sum(1 for item in report["cases"] if not item.get("ok")),
    }
    out = args.out or (REPO_ROOT / "tools" / "bin" / "live_release" / f"phase1b-child-broker-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json")
    _write_json(out.resolve(), report)
    print(json.dumps({"ok": report["ok"], "report": str(out.resolve()), "counts": report["counts"]}, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
