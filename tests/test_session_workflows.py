import importlib.util
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_bridge", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SessionWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def setUp(self):
        self.originals = {
            "_list_processes": self.mod._list_processes,
            "_process_exists": self.mod._process_exists,
            "_get_current_debuggee_image_name": self.mod._get_current_debuggee_image_name,
            "_infer_attached_pid_from_debugger_windows": self.mod._infer_attached_pid_from_debugger_windows,
            "_build_debug_state": self.mod._build_debug_state,
            "DisasmGetInstructionRange": self.mod.DisasmGetInstructionRange,
            "safe_get": self.mod.safe_get,
            "_log_event": self.mod._log_event,
            "LaunchFileUnderDebugger": self.mod.LaunchFileUnderDebugger,
            "RunUntil": self.mod.RunUntil,
            "DebugRun": self.mod.DebugRun,
        }
        self.mod._log_event = lambda *args, **kwargs: None
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["boundSession"] = None
            self.mod._RUNTIME_STATE["lastDebuggeePid"] = 0
            self.mod._RUNTIME_STATE["lastDebuggeeImage"] = None
            self.mod._RUNTIME_STATE["lastDebuggeePath"] = None

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(self.mod, name, value)

    def test_infer_debuggee_pid_prefers_live_bound_session(self):
        self.mod._remember_runtime(
            boundSession={
                "pid": 4242,
                "imagePath": r"C:\targets\child.exe",
                "moduleBase": "0x140000000",
                "strict": True,
            }
        )
        self.mod._process_exists = lambda pid: int(pid) == 4242
        self.mod._get_current_debuggee_image_name = lambda: ""
        self.mod._list_processes = lambda: [
            {"pid": 1000, "ppid": 0, "exe": "x64dbg.exe"},
            {"pid": 2222, "ppid": 1000, "exe": "other.exe"},
        ]
        self.mod._infer_attached_pid_from_debugger_windows = lambda debugger_pids, image_name: 0

        resolved = self.mod._infer_debuggee_pid()

        self.assertEqual(resolved, 4242)

    def test_infer_debuggee_pid_ignores_mismatched_strict_binding(self):
        self.mod._remember_runtime(
            boundSession={
                "pid": 4242,
                "imagePath": r"C:\targets\child.exe",
                "moduleBase": "0x140000000",
                "strict": True,
            }
        )
        self.mod._process_exists = lambda pid: int(pid) in (4242, 7777)
        self.mod._get_current_debuggee_image_name = lambda: "other.exe"
        self.mod._list_processes = lambda: [
            {"pid": 1000, "ppid": 0, "exe": "x64dbg.exe"},
            {"pid": 7777, "ppid": 1000, "exe": "other.exe"},
        ]
        self.mod._infer_attached_pid_from_debugger_windows = lambda debugger_pids, image_name: 0

        resolved = self.mod._infer_debuggee_pid()

        self.assertEqual(resolved, 7777)

    def test_run_until_accepts_module_rva_targets(self):
        def fake_safe_get(path, params=None, log=True):
            del log
            params = params or {}
            if path == "GetModuleList":
                return {
                    "modules": [
                        {
                            "name": "sample.exe",
                            "path": r"C:\targets\sample.exe",
                            "base": "0x400000",
                            "entry": "0x401000",
                            "size": "0x20000",
                        }
                    ]
                }
            if path == "Debug/SetBreakpoint":
                return f"set {params.get('addr')}"
            if path == "Debug/Run":
                return "running"
            if path == "Debug/WaitForPause":
                return {"timedOut": False, "state": {"eventSeq": 7}}
            if path == "Debug/SessionState":
                return {
                    "eventSeq": 7,
                    "debugging": True,
                    "running": False,
                    "paused": True,
                    "processId": 31337,
                    "imagePath": r"C:\targets\sample.exe",
                    "ip": "0x401234",
                    "state": "paused",
                }
            if path == "RegisterDump":
                return {"cip": "0x401234"}
            if path in ("Is_Debugging", "IsDebugActive"):
                return {"isDebugging": True, "isRunning": False}
            if path == "GetCallStack":
                return {"entries": []}
            if path == "GetBreakpointList":
                return {"count": 0, "breakpoints": []}
            return {}

        self.mod.safe_get = fake_safe_get

        result = self.mod.RunUntil(target="sample.exe!0x1234", timeout_ms=100, poll_ms=1)

        self.assertTrue(result["ok"])
        self.assertEqual(result["target"], "0x401234")
        self.assertEqual(result["targetRef"], "sample.exe!0x1234")

    def _run_until_exception_fixture(self, exception_module):
        phase = {"value": "exception"}
        operation_order = []
        target_addr = "0x401000"

        def session_state():
            at_target = phase["value"] == "target"
            return {
                "eventSeq": 9 if at_target else 8,
                "debugging": True,
                "running": False,
                "paused": True,
                "processId": 31337,
                "imagePath": r"C:\targets\sample.exe",
                "imageName": "sample.exe",
                "moduleBase": "0x400000",
                "ip": target_addr if at_target else (
                    "0x401234" if exception_module == "sample.exe" else "0x77001234"
                ),
                "state": "paused",
                "stopReason": "breakpoint" if at_target else "exception",
                "exceptionCode": "0x0" if at_target else "0x80000003",
                "exceptionFirstChance": False if at_target else True,
                "lastEventType": "breakpoint" if at_target else "exception",
                "sessionId": "session-run-until",
                "generation": 1,
            }

        def fake_safe_get(path, params=None, log=True):
            del log
            params = params or {}
            if path == "GetModuleList":
                return {
                    "modules": [
                        {
                            "name": "sample.exe",
                            "path": r"C:\targets\sample.exe",
                            "base": "0x400000",
                            "entry": target_addr,
                            "size": "0x20000",
                        },
                        {
                            "name": "ntdll.dll",
                            "path": r"C:\Windows\SysWOW64\ntdll.dll",
                            "base": "0x77000000",
                            "entry": "0x77001000",
                            "size": "0x200000",
                        },
                    ]
                }
            if path in ("Breakpoint/List", "GetBreakpointList"):
                return {"count": 0, "breakpoints": []}
            if path == "Debug/SetBreakpoint":
                return f"set {params.get('addr')}"
            if path == "Debug/DeleteBreakpoint":
                return "Breakpoint deleted successfully"
            if path == "Debug/Run":
                return "running"
            if path == "Debug/WaitForBreakpointDetailed":
                operation_order.append("wait")
                if phase["value"] == "target":
                    return {
                        "hit": True,
                        "matchedRequested": True,
                        "observedBreakpoint": True,
                        "timedOut": False,
                        "addr": target_addr,
                        "rip": target_addr,
                        "stopReason": "breakpoint",
                        "state": session_state(),
                    }
                return {
                    "hit": False,
                    "matchedRequested": False,
                    "observedBreakpoint": False,
                    "timedOut": False,
                    "rip": session_state()["ip"],
                    "stopReason": "exception",
                    "state": session_state(),
                }
            if path == "Debug/SessionState":
                return session_state()
            if path == "RegisterDump":
                return {"cip": session_state()["ip"]}
            if path in ("Is_Debugging", "IsDebugActive"):
                return {"isDebugging": True, "isRunning": False}
            if path == "GetCallStack":
                return {"entries": []}
            return {}

        continuations = []

        def fake_bridge_request(method, endpoint, **kwargs):
            continuations.append((method, endpoint, kwargs))
            if endpoint == "Debug/ContinueException":
                operation_order.append("continue")
                phase["value"] = "target"
            return self.mod.BridgeEnvelope(
                True,
                data={"ok": True, "windowsStatus": "DBG_CONTINUE"},
                meta={"eventSeq": 8},
            )

        self.mod.safe_get = fake_safe_get
        with mock.patch.object(
            self.mod, "_bridge_request", side_effect=fake_bridge_request
        ):
            result = self.mod.RunUntil(
                target="sample.exe!0x1000", timeout_ms=100, poll_ms=1
            )
        return result, continuations, operation_order

    def test_run_until_entry_explicitly_handles_first_chance_loader_breakpoint(self):
        result, continuations, operation_order = self._run_until_exception_fixture(
            "ntdll.dll"
        )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["target"], "0x401000")
        self.assertEqual(len(result["skippedExceptions"]), 1)
        self.assertEqual(result["skippedExceptions"][0]["code"], "0x80000003")
        self.assertEqual(result["skippedExceptions"][0]["module"], "ntdll.dll")
        dispositions = [
            item for item in continuations if item[1] == "Debug/ContinueException"
        ]
        self.assertEqual(len(dispositions), 1)
        self.assertEqual(dispositions[0][2]["params"]["disposition"], "handled")
        self.assertLess(operation_order.index("continue"), operation_order.index("wait"))

    def test_run_until_entry_preserves_breakpoint_exception_in_debuggee(self):
        result, continuations, _ = self._run_until_exception_fixture("sample.exe")

        self.assertFalse(result["ok"], result)
        self.assertEqual(result["state"]["rip"], "0x401234")
        self.assertEqual(result["state"]["module"], "sample.exe")
        self.assertEqual(result["skippedExceptions"], [])
        self.assertNotIn(
            "Debug/ContinueException", [item[1] for item in continuations]
        )

    def test_wait_for_module_load_uses_session_history_and_live_modules(self):
        call_counts = {"modules": 0, "session": 0}

        def fake_safe_get(path, params=None, log=True):
            del params, log
            if path == "GetModuleList":
                call_counts["modules"] += 1
                if call_counts["modules"] == 1:
                    return {
                        "modules": [
                        {
                            "name": "main.exe",
                            "path": r"C:\targets\main.exe",
                            "base": "0x400000",
                            "entry": "0x401000",
                            "size": "0x20000",
                        }
                    ]
                }
                return {
                    "modules": [
                        {
                            "name": "main.exe",
                            "path": r"C:\targets\main.exe",
                            "base": "0x400000",
                            "entry": "0x401000",
                            "size": "0x20000",
                        },
                        {
                            "name": "child.dll",
                            "path": r"C:\targets\child.dll",
                            "base": "0x70000000",
                            "entry": "0x70001000",
                            "size": "0x10000",
                        },
                    ]
                }
            if path == "Debug/SessionState":
                call_counts["session"] += 1
                history = []
                if call_counts["session"] >= 2:
                    history.append(
                        {
                            "eventSeq": 11,
                            "type": "load_dll",
                            "note": "Loaded DLL: child.dll",
                        }
                    )
                return {
                    "eventSeq": 10 + call_counts["session"],
                    "history": history,
                    "debugging": True,
                    "running": True,
                    "paused": False,
                }
            return {}

        self.mod.safe_get = fake_safe_get

        result = self.mod.WaitForModuleLoad(
            module_name="child.dll", timeout_ms=300, poll_ms=1, auto_run=False
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["module"]["name"], "child.dll")
        self.assertEqual(result["event"]["note"], "Loaded DLL: child.dll")

    def test_attach_failure_diagnostics_surfaces_debug_object_hint(self):
        original_query = self.mod._query_process_debug_status
        try:
            self.mod._query_process_debug_status = lambda pid=0: {
                "ok": True,
                "pid": int(pid or 1234),
                "underDebugger": True,
                "debugObjectHandle": "0xABC",
                "debugPort": "0xFFFFFFFFFFFFFFFF",
                "debugFlags": 0,
            }

            payload = self.mod._build_attach_failure_diagnostics(1234)

            self.assertIn("debug port/object", payload["hint"].lower())
            self.assertTrue(payload["processDebug"]["underDebugger"])
        finally:
            self.mod._query_process_debug_status = original_query

    def test_current_instruction_accepts_dict_payload(self):
        self.mod.DisasmGetInstructionRange = lambda addr, count=1: {
            "ok": True,
            "addr": addr,
            "count": count,
            "instructions": [
                {
                    "address": addr,
                    "instruction": "mov eax, eax",
                    "size": 2,
                }
            ],
        }

        result = self.mod._current_instruction("0x401000")

        self.assertEqual(
            result,
            {
                "address": "0x401000",
                "instruction": "mov eax, eax",
                "size": 2,
            },
        )

    def test_launch_and_open_debuggee_is_registered_alias(self):
        registry = self.mod._get_mcp_tools_registry()

        self.assertIn("LaunchAndOpenDebuggee", registry)

    def test_advance_to_entry_uses_exact_entry_breakpoint_workflow(self):
        calls = []

        def fake_run_until(**kwargs):
            calls.append(kwargs)
            return {
                "ok": True,
                "target": "0x401000",
                "targetRef": "sample.exe!0x1000",
                "state": {
                    "state": "paused",
                    "rip": "0x401000",
                    "ripRef": "sample.exe!0x1000",
                    "module": "sample.exe",
                },
                "skippedBreakpoints": [
                    {"module": "gdi32full.dll", "name": "TLS Callback 1"}
                ],
            }

        self.mod.RunUntil = fake_run_until
        self.mod.DebugRun = lambda *args, **kwargs: self.fail(
            "the compatibility one-run path must not be used when RunUntil exists"
        )

        result = self.mod._run_to_entry_point(timeout_ms=4321, poll_ms=77)

        self.assertTrue(result["ok"])
        self.assertEqual(result["rip"], "0x401000")
        self.assertEqual(result["module"], "sample.exe")
        self.assertEqual(result["mode"], "entry_breakpoint")
        self.assertEqual(len(result["skippedBreakpoints"]), 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["target"], "entry")
        self.assertEqual(calls[0]["poll_ms"], 77)
        self.assertGreaterEqual(calls[0]["timeout_ms"], 4300)
        self.assertLessEqual(calls[0]["timeout_ms"], 4321)

    def test_init_debuggee_rejects_invalid_hidemain_mode_before_launch(self):
        original_exec = self.mod.ExecCommand
        calls = []
        try:
            self.mod.ExecCommand = lambda command: calls.append(command)
            result = self.mod.InitDebuggee(
                exe_path=r"C:\targets\sample.exe",
                use_hidemain="froce",
            )
        finally:
            self.mod.ExecCommand = original_exec
        self.assertFalse(result["ok"])
        self.assertIn("Unknown HideMain mode", result["error"])
        self.assertEqual(calls, [])

    def test_direct_init_readiness_refreshes_bridge_even_with_cached_capabilities(self):
        stale_identity = {
            "bridgeInstanceId": "dead-bridge",
            "capabilities": {"launch": {"version": 2}},
        }
        hello_payload = {
            "bridgeInstanceId": "live-bridge",
            "protocolVersion": 4,
            "debugger": {"pid": 1234, "architecture": "x64"},
            "capabilities": {"launch": {"version": 2}},
        }
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"] = stale_identity
        with (
            mock.patch.object(self.mod, "_detect_pe_arch", return_value="x64"),
            mock.patch.object(
                self.mod,
                "EnsureDebugger",
                return_value={"ok": True, "requestedArch": "x64"},
            ) as ensure,
            mock.patch.object(
                self.mod,
                "_bridge_request",
                return_value=self.mod.BridgeEnvelope(True, data=hello_payload),
            ) as hello,
        ):
            result = self.mod._ensure_init_debugger_bridge(
                r"C:\targets\sample.exe", 5000
            )

        self.assertTrue(result["ok"], result)
        ensure.assert_called_once_with(arch="x64", timeout_ms=5000, restart=False)
        hello.assert_called_once()
        self.assertEqual(
            self.mod._get_cached_bridge_identity()["bridgeInstanceId"], "live-bridge"
        )

    def test_bound_state_refresh_replaces_pre_binding_snapshot(self):
        refreshed = {
            "debugging": True,
            "debuggeePid": 4242,
            "session": {"sessionId": "session-1"},
        }
        match = {"active": True, "matches": True, "reason": "matched"}
        with (
            mock.patch.object(self.mod, "_build_debug_state", return_value=refreshed),
            mock.patch.object(
                self.mod, "_describe_bound_session_match", return_value=match
            ),
        ):
            result = self.mod._refresh_state_after_session_binding(
                {"debugging": True, "binding": {"active": False}}
            )

        self.assertEqual(result["binding"], match)
        self.assertEqual(result["session"]["binding"], match)

    def test_launch_and_open_debuggee_delegates_to_launch_file_under_debugger(self):
        calls = []

        def fake_launch(**kwargs):
            calls.append(kwargs)
            return {
                "ok": True,
                "exePath": kwargs["exe_path"],
                "requestedArch": "x64",
            }

        self.mod.LaunchFileUnderDebugger = fake_launch

        result = self.mod.LaunchAndOpenDebuggee(
            exe_path=r"C:\targets\sample.exe",
            arch="x64",
            restart_debugger=True,
            timeout_ms=12345,
            retries=2,
            stop_first=False,
            use_scyllahide="force",
            scyllahide_profile="Basic",
            use_hidemain="force",
            hidemain_root=r"C:\tools\hidemain",
            hidemain_allow_system_changes=True,
            hidemain_allow_unsigned_driver=True,
            hidemain_acknowledge_kernel_risk=True,
        )

        self.assertEqual(
            calls,
            [
                {
                    "exe_path": r"C:\targets\sample.exe",
                    "arch": "x64",
                    "restart_debugger": True,
                    "timeout_ms": 12345,
                    "retries": 2,
                    "stop_first": False,
                    "use_scyllahide": "force",
                    "scyllahide_profile": "Basic",
                    "use_hidemain": "force",
                    "hidemain_root": r"C:\tools\hidemain",
                    "hidemain_allow_system_changes": True,
                    "hidemain_allow_unsigned_driver": True,
                    "hidemain_acknowledge_kernel_risk": True,
                    "advance_to_entry": True,
                }
            ],
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["entrypointTool"], "LaunchAndOpenDebuggee")
        self.assertEqual(result["legacyAlias"], "LaunchFileUnderDebugger")

    def test_launch_recovers_once_from_stale_launch_contract(self):
        stale = {
            "ok": False,
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "capability": "launch.version",
            "error": "Bridge/Hello must advertise launch contract version 2 or newer.",
            "advertised": 0,
        }
        recovered = {
            "ok": True,
            "attempts": 1,
            "state": {
                "state": "paused",
                "debuggeePid": 4242,
                "session": {"sessionId": "fresh", "generation": 1},
            },
            "binding": {
                "pid": 4242,
                "sessionId": "fresh",
                "sessionGeneration": 1,
                "debuggerArch": "x64",
            },
        }
        with mock.patch.object(
            self.mod,
            "_resolve_target_exe_path",
            return_value=r"C:\targets\fixture.exe",
        ), mock.patch.object(
            self.mod.os.path, "exists", return_value=True
        ), mock.patch.object(
            self.mod,
            "EnsureDebugger",
            return_value={"ok": True, "bridge": {"ok": True}},
        ), mock.patch.object(
            self.mod, "InitDebuggee", side_effect=[stale, recovered]
        ) as init_debuggee, mock.patch.object(
            self.mod,
            "RestartDebugger",
            return_value={"ok": True, "requestedArch": "x64"},
        ) as restart:
            result = self.mod.LaunchFileUnderDebugger(
                exe_path=r"C:\targets\fixture.exe",
                arch="x64",
                restart_debugger=False,
                advance_to_entry=False,
                detail="full",
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(init_debuggee.call_count, 2)
        restart.assert_called_once()
        self.assertEqual(result["initialInit"]["capability"], "launch.version")
        self.assertEqual(result["init"]["binding"]["sessionId"], "fresh")

    def test_launch_does_not_restart_for_non_version_capability_failure(self):
        unsupported = {
            "ok": False,
            "errorCode": "UNSUPPORTED_CAPABILITY",
            "capability": "launch.environment",
            "error": "Per-launch environment blocks are unavailable.",
        }
        with mock.patch.object(
            self.mod,
            "_resolve_target_exe_path",
            return_value=r"C:\targets\fixture.exe",
        ), mock.patch.object(
            self.mod.os.path, "exists", return_value=True
        ), mock.patch.object(
            self.mod,
            "EnsureDebugger",
            return_value={"ok": True, "bridge": {"ok": True}},
        ), mock.patch.object(
            self.mod, "InitDebuggee", return_value=unsupported
        ), mock.patch.object(
            self.mod, "RestartDebugger"
        ) as restart:
            result = self.mod.LaunchFileUnderDebugger(
                exe_path=r"C:\targets\fixture.exe",
                arch="x64",
                restart_debugger=False,
                advance_to_entry=False,
                detail="full",
            )

        self.assertFalse(result["ok"])
        restart.assert_not_called()

    def test_launch_fails_when_requested_entry_advance_does_not_complete(self):
        init = {
            "ok": True,
            "state": {"debugging": True, "paused": True},
            "scyllaHide": {"ok": True},
        }
        advance = {
            "ok": False,
            "state": {"paused": True, "exceptionCode": "0xC0000005"},
            "hint": "Target stopped on a first-chance exception.",
        }
        with mock.patch.object(
            self.mod,
            "_resolve_target_exe_path",
            return_value=r"C:\targets\fixture.exe",
        ), mock.patch.object(
            self.mod.os.path, "exists", return_value=True
        ), mock.patch.object(
            self.mod,
            "EnsureDebugger",
            return_value={"ok": True, "bridge": {"ok": True}},
        ), mock.patch.object(
            self.mod, "InitDebuggee", return_value=init
        ), mock.patch.object(
            self.mod, "_run_to_entry_point", return_value=advance
        ):
            result = self.mod.LaunchFileUnderDebugger(
                exe_path=r"C:\targets\fixture.exe",
                arch="x64",
                advance_to_entry=True,
                detail="full",
            )

        self.assertFalse(result["ok"])
        self.assertIn("advancing to its entry point failed", result["error"])
        self.assertFalse(result["init"]["scyllaHide"]["ok"])
        self.assertIn("runtimeVerification", result["init"]["scyllaHide"])


if __name__ == "__main__":
    unittest.main()
