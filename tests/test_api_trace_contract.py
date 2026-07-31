import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_api_trace_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ApiTraceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def setUp(self):
        names = (
            "GetModuleList",
            "QuerySymbols",
            "_get_current_debuggee_image_name",
            "ReadMemory",
            "DebugRun",
            "WaitForPause",
            "WaitForBreakpointDetailed",
            "_detect_debuggee_bitness",
            "_sample_api_args",
            "StackPeek",
            "_breakpoint_exists",
            "DebugSetBreakpoint",
            "DebugDeleteBreakpoint",
            "RegisterGet",
            "_api_register_value",
            "_api_trace_callstack",
            "_capture_api_out_buffers",
            "_collect_breakpoint_snapshot",
            "_enumerate_import_targets",
            "_resolve_remote_symbol_address",
            "_resolve_loaded_module_symbol",
            "_resolve_runtime_export_identity",
            "_record_native_api_entry",
            "_build_debug_state",
            "_bridge_request",
            "_finalize_native_api_trace_evidence",
            "_release_native_api_return_hooks",
            "safe_get",
            "_log_event",
            "RunApiTrace",
            "GetHeapState",
            "StopApiTrace",
            "GetApiTraceLog",
            "GetNativeApiTraceEvidence",
            "GetSessionBinding",
            "ExecCommand",
            "_read_memory_bytes",
        )
        self.originals = {name: getattr(self.mod, name) for name in names}
        self.mod._log_event = lambda *args, **kwargs: None
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"] = {}
            self.mod._RUNTIME_STATE["heapTraces"] = {}

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(self.mod, name, value)

    def test_enumerator_never_treats_iat_import_rva_as_executable_target(self):
        self.mod._get_current_debuggee_image_name = lambda: "fixture.exe"
        self.mod.GetModuleList = lambda: {
            "modules": [
                {"name": "kernelbase.dll", "base": "0x70000000"},
                {"name": "fixture.exe", "base": "0x140000000"},
            ]
        }
        self.mod.QuerySymbols = lambda **kwargs: {
            "symbols": [
                {"name": "CreateEventW", "type": "export", "rva": "0x1000"},
                {"name": "NtWaitForSingleObject", "type": "import", "rva": "0x2000"},
            ]
        }

        targets = self.mod._enumerate_import_targets(
            ["kernelbase.dll"], ["createevent", "waitforsingleobject"]
        )

        self.assertEqual(
            targets,
            [
                {
                    "module": "kernelbase.dll",
                    "func": "CreateEventW",
                    "addr": "0x70001000",
                }
            ],
        )

    def test_signature_catalog_normalizes_module_and_stdcall_decorations(self):
        signature = self.mod._api_signature(
            "kernelbase.dll!_ReadFile@20"
        )

        self.assertEqual(signature["returnType"], "BOOL")
        self.assertEqual(len(signature["args"]), 5)
        self.assertEqual(signature["args"][1]["name"], "buffer")
        self.assertEqual(signature["args"][1]["direction"], "out")

    def test_signature_catalog_covers_loader_file_sync_memory_and_network_families(self):
        cases = {
            "kernelbase.dll!LoadLibraryExW": ("HMODULE", 3, "path"),
            "kernel32.dll!CreateFileW": ("HANDLE", 7, "path"),
            "kernelbase.dll!WaitForSingleObject": ("DWORD", 2, "milliseconds"),
            "kernelbase.dll!VirtualProtect": ("BOOL", 4, "oldProtect"),
            "ws2_32.dll!recv": ("int", 4, "buffer"),
            "ntdll.dll!NtQueryInformationProcess": ("NTSTATUS", 5, "returnLength"),
        }
        for function, (return_type, count, named_arg) in cases.items():
            with self.subTest(function=function):
                signature = self.mod._api_signature(function)
                self.assertEqual(signature["returnType"], return_type)
                self.assertEqual(len(signature["args"]), count)
                self.assertIn(
                    named_arg,
                    {str(item.get("name")) for item in signature["args"]},
                )

    def test_signature_catalog_preserves_zero_argument_api_arity(self):
        signature = self.mod._api_signature("kernel32!GetCurrentProcessId")
        self.assertEqual(signature["returnType"], "DWORD")
        self.assertEqual(signature["args"], [])

    def test_module_subscription_installs_owned_targets_under_cap(self):
        trace_id = "api-module-subscription"
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"] = {
                trace_id: {
                    "traceId": trace_id,
                    "maxTargets": 3,
                    "targetMap": {
                        "0x1000": {
                            "module": "kernelbase.dll",
                            "func": "CreateEventW",
                            "addr": "0x1000",
                        }
                    },
                    "targetAddrs": ["0x1000"],
                    "ownedEntryBreakpoints": [],
                    "preexistingEntryBreakpoints": [],
                    "breakpointOwnershipPrefix": "mcp_api_trace:",
                }
            }
        commands = []
        self.mod._collect_breakpoint_snapshot = lambda **_: {"breakpoints": []}
        self.mod.DebugSetBreakpoint = (
            lambda *_: "Breakpoint set successfully"
        )
        self.mod.ExecCommand = lambda command, **_: commands.append(command) or {
            "success": True
        }

        result = self.mod._install_api_trace_subscription_targets(
            trace_id,
            [
                {
                    "module": "wininet.dll",
                    "func": "InternetOpenW",
                    "addr": "0x70001000",
                }
            ],
            "module-load-refresh",
        )
        record = self.mod._get_api_trace(trace_id)

        self.assertTrue(result["ok"])
        self.assertEqual(result["added"], 1)
        self.assertEqual(record["targetCount"], 2)
        self.assertEqual(
            record["targetMap"]["0x70001000"]["source"],
            "module-load-refresh",
        )
        self.assertEqual(record["ownedEntryBreakpoints"], ["0x70001000"])
        self.assertIn("mcp_api_trace:api-module-subscription:entry", commands[0])

    def test_getprocaddress_return_subscribes_matching_resolved_symbol(self):
        trace_id = "api-dynamic-resolver"
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"] = {
                trace_id: {
                    "traceId": trace_id,
                    "filters": ["createfile"],
                    "discoverDynamicResolvers": True,
                    "maxTargets": 4,
                    "targetMap": {},
                    "targetAddrs": [],
                    "ownedEntryBreakpoints": [],
                    "preexistingEntryBreakpoints": [],
                    "breakpointOwnershipPrefix": "mcp_api_trace:",
                }
            }
        self.mod.GetModuleList = lambda: {
            "modules": [
                {
                    "name": "kernelbase.dll",
                    "base": "0x70000000",
                    "size": "0x200000",
                }
            ]
        }
        self.mod._collect_breakpoint_snapshot = lambda **_: {"breakpoints": []}
        self.mod.DebugSetBreakpoint = (
            lambda *_: "Breakpoint set successfully"
        )
        self.mod.ExecCommand = lambda *_args, **_kwargs: {"success": True}

        result = self.mod._subscribe_dynamic_resolver_target(
            trace_id,
            {
                "seq": 9,
                "func": "GetProcAddress",
                "args": [
                    {"index": 0, "value": "0x70000000"},
                    {
                        "index": 1,
                        "value": "0x71000000",
                        "stringPreview": "CreateFileW",
                    },
                ],
            },
            "0x70001000",
        )
        record = self.mod._get_api_trace(trace_id)
        target = record["targetMap"]["0x70001000"]

        self.assertTrue(result["ok"])
        self.assertEqual(result["added"], 1)
        self.assertEqual(target["module"], "kernelbase.dll")
        self.assertEqual(target["func"], "CreateFileW")
        self.assertEqual(target["resolverCallSeq"], 9)
        self.assertEqual(target["source"], "getprocaddress-return")

    def test_custom_resolver_target_is_strict_and_resolves_symbol(self):
        self.mod.GetModuleList = lambda: {
            "modules": [
                {
                    "name": "custom_import_resolver.exe",
                    "path": r"C:\fixtures\custom_import_resolver.exe",
                    "base": "0x140000000",
                    "size": "0x8000",
                }
            ]
        }
        self.mod._resolve_loaded_module_symbol = (
            lambda *_: "0x140001000"
        )
        result = self.mod._parse_custom_api_trace_targets(
            json.dumps(
                [
                    {
                        "module": "custom_import_resolver.exe",
                        "symbol": "custom_resolve_export",
                        "kind": "import-resolver",
                        "resolver": {
                            "keyArgIndex": 1,
                            "moduleArgIndex": 0,
                            "keyEncoding": "fnv1a32",
                            "subscribeResolved": False,
                        },
                    }
                ]
            )
        )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["targets"][0]["addr"], "0x140001000")
        self.assertEqual(result["targets"][0]["targetKind"], "import-resolver")
        self.assertFalse(
            result["targets"][0]["resolverSpec"]["subscribeResolved"]
        )

        ambiguous = self.mod._parse_custom_api_trace_targets(
            json.dumps(
                [
                    {
                        "module": "custom_import_resolver.exe",
                        "symbol": "custom_resolve_export",
                        "rva": "0x1000",
                    }
                ]
            )
        )
        self.assertFalse(ambiguous["ok"])
        self.assertIn("exactly one", ambiguous["errors"][0]["error"])

    def test_custom_resolver_return_records_exact_export_without_subscription(self):
        trace_id = "api-custom-resolver"
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"] = {
                trace_id: {
                    "traceId": trace_id,
                    "filters": ["no-match"],
                    "discoverDynamicResolvers": True,
                    "targetMap": {},
                }
            }
        self.mod._resolve_runtime_export_identity = lambda address: {
            "ok": True,
            "schema": "runtime-export-identity-v1",
            "address": address,
            "module": "KERNELBASE.dll",
            "function": "GetCurrentProcessId",
            "ordinal": 0,
            "exportRva": "0x1234",
        }
        result = self.mod._subscribe_dynamic_resolver_target(
            trace_id,
            {
                "seq": 4,
                "module": "custom_import_resolver.exe",
                "func": "custom_resolve_export",
                "targetKind": "import-resolver",
                "resolverSpec": {
                    "keyArgIndex": 1,
                    "moduleArgIndex": 0,
                    "keyEncoding": "fnv1a32",
                    "subscribeResolved": False,
                    "requireExactExport": True,
                },
                "args": [
                    {"index": 0, "value": "0x70000000"},
                    {"index": 1, "value": "0x12345678"},
                ],
            },
            "0x70001234",
        )

        self.assertTrue(result["ok"], result)
        self.assertFalse(result.get("skipped", False))
        self.assertEqual(result["added"], 0)
        evidence = result["resolverEvidence"]
        self.assertTrue(evidence["exactExport"])
        self.assertEqual(evidence["requestKeyInt"], 0x12345678)
        self.assertEqual(evidence["identity"]["function"], "GetCurrentProcessId")

    def test_custom_resolver_trace_validation_requires_complete_exact_evidence(self):
        trace_id = "api-custom-validation"
        identity = {
            "ok": True,
            "module": "KERNELBASE.dll",
            "function": "GetCurrentProcessId",
            "ordinal": 0,
        }
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"] = {
                trace_id: {
                    "traceId": trace_id,
                    "label": "fixture",
                    "customTargetCount": 1,
                    "droppedCalls": 0,
                    "calls": [
                        {
                            "seq": 1,
                            "module": "custom_import_resolver.exe",
                            "func": "custom_resolve_export",
                            "targetKind": "import-resolver",
                            "returned": True,
                            "returnTrackingError": None,
                            "dynamicTargetSubscription": {
                                "resolverEvidence": {
                                    "exactExport": True,
                                    "requestKey": "0x123",
                                    "requestKeyInt": 0x123,
                                    "keyEncoding": "fnv1a32",
                                    "returnedTarget": "0x70001234",
                                    "identity": identity,
                                }
                            },
                        }
                    ],
                }
            }
        resolution = {
            "ok": True,
            "entries": [
                {
                    "index": 0,
                    "target": "0x70001234",
                    "module": "kernelbase.dll",
                    "function": "GetCurrentProcessId",
                    "ordinal": 0,
                }
            ],
        }
        valid = self.mod._validate_custom_resolver_trace(
            trace_id,
            resolution,
        )
        self.assertTrue(valid["ok"], valid)
        self.assertEqual(valid["matchedIatCount"], 1)

        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"][trace_id][
                "droppedCalls"
            ] = 1
        incomplete = self.mod._validate_custom_resolver_trace(
            trace_id,
            resolution,
        )
        self.assertFalse(incomplete["ok"])
        self.assertEqual(incomplete["droppedCalls"], 1)

    def test_late_module_refresh_discovers_new_matching_export(self):
        trace_id = "api-late-module"
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"] = {
                trace_id: {
                    "traceId": trace_id,
                    "modules": ["version.dll"],
                    "filters": ["getfileversioninfosize"],
                    "subscribeModules": True,
                    "maxTargets": 8,
                    "targetMap": {},
                    "targetAddrs": [],
                    "ownedEntryBreakpoints": [],
                    "preexistingEntryBreakpoints": [],
                    "breakpointOwnershipPrefix": "mcp_api_trace:",
                }
            }
        self.mod._enumerate_import_targets = lambda modules, filters: [
            {
                "module": "version.dll",
                "func": "GetFileVersionInfoSizeW",
                "addr": "0x72001000",
            }
        ]
        self.mod.GetModuleList = lambda: {
            "modules": [
                {
                    "name": "version.dll",
                    "base": "0x72000000",
                    "size": "0x200000",
                }
            ]
        }
        self.mod._collect_breakpoint_snapshot = lambda **_: {"breakpoints": []}
        self.mod.DebugSetBreakpoint = (
            lambda *_: "Breakpoint set successfully"
        )
        self.mod.ExecCommand = lambda *_args, **_kwargs: {"success": True}

        result = self.mod._refresh_api_trace_module_subscriptions(trace_id)
        record = self.mod._get_api_trace(trace_id)

        self.assertTrue(result["ok"])
        self.assertEqual(result["added"], 1)
        self.assertEqual(record["targetCount"], 1)
        self.assertEqual(
            record["targetMap"]["0x72001000"]["source"],
            "module-load-refresh",
        )

    def test_get_environment_out_buffer_is_captured_at_return(self):
        self.mod.ReadMemory = lambda addr, size, ty, max_chars: {
            "ok": True,
            "addr": addr,
            "sizeRead": size,
            "format": ty,
            "text": "trace-ok-7",
        }
        args = [
            {"index": 0, "value": "0x500000"},
            {"index": 1, "value": "0x600000"},
            {"index": 2, "value": "0x40"},
        ]

        captured = self.mod._capture_api_out_buffers(
            "GetEnvironmentVariableW", args, "0xa", 4096
        )

        self.assertEqual(len(captured), 1)
        self.assertTrue(captured[0]["ok"])
        self.assertEqual(captured[0]["capturedBytes"], 22)
        self.assertEqual(captured[0]["read"]["text"], "trace-ok-7")

    def test_out_buffer_read_failure_is_bounded_fault_metadata(self):
        self.mod.ReadMemory = lambda *_, **__: {
            "ok": False,
            "errorCode": "invalid_memory_range",
            "error": "unmapped output",
            "retryable": False,
        }
        args = [
            {"index": 0, "value": "0x500000"},
            {"index": 1, "value": "0x600000"},
            {"index": 2, "value": "0x20"},
        ]

        captured = self.mod._capture_api_out_buffers(
            "GetEnvironmentVariableW", args, "0x8", 4096
        )

        self.assertEqual(len(captured), 1)
        self.assertFalse(captured[0]["ok"])
        self.assertEqual(captured[0]["fault"]["code"], "invalid_memory_range")
        self.assertEqual(captured[0]["fault"]["address"], "0x600000")
        self.assertEqual(captured[0]["fault"]["requestedBytes"], 18)

    def test_common_memory_and_encoding_out_buffers_are_captured(self):
        reads = []

        def fake_read(addr, size, ty, max_chars):
            reads.append((addr, size, ty, max_chars))
            return {"ok": True, "addr": addr, "sizeRead": size, "format": ty}

        self.mod.ReadMemory = fake_read
        virtual_protect = self.mod._capture_api_out_buffers(
            "kernel32!VirtualProtect",
            [
                {"index": 0, "value": "0x100000"},
                {"index": 1, "value": "0x1000"},
                {"index": 2, "value": "0x40"},
                {"index": 3, "value": "0x600000"},
            ],
            "0x1",
            4096,
        )
        self.assertTrue(virtual_protect[0]["ok"])
        self.assertEqual(virtual_protect[0]["capturedBytes"], 4)
        self.assertEqual(reads[-1][0], "0x600000")

        converted = self.mod._capture_api_out_buffers(
            "kernel32!MultiByteToWideChar",
            [
                {"index": 0, "value": "0x4"},
                {"index": 1, "value": "0x0"},
                {"index": 2, "value": "0x700000"},
                {"index": 3, "value": "0x5"},
                {"index": 4, "value": "0x710000"},
                {"index": 5, "value": "0x20"},
            ],
            "0x6",
            4096,
        )
        self.assertTrue(converted[0]["ok"])
        self.assertEqual(converted[0]["capturedBytes"], 12)
        self.assertEqual(reads[-1][1:], (12, "utf16", 4096))

    def test_tailcall_aliases_share_one_logical_call_and_return(self):
        trace_id = "apitrace-test"
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"] = {
                trace_id: {
                    "traceId": trace_id,
                    "targetMap": {
                        "0x1000": {"module": "kernelbase.dll", "func": "WaitForSingleObject"},
                        "0x2000": {"module": "kernelbase.dll", "func": "WaitForSingleObjectEx"},
                    },
                    "argCount": 4,
                    "calls": [],
                    "nextCallSeq": 0,
                    "pendingReturns": {},
                    "ownedReturnBreakpoints": [],
                    "captureReturns": True,
                    "captureCallstack": True,
                    "maxCallstackFrames": 8,
                    "maxOutBytes": 0,
                    "stopped": False,
                }
            }
        states = [
            {"state": "paused", "rip": "0x1000", "eventSeq": 1, "stopReason": "breakpoint", "session": {"threadId": 7}},
            {"state": "paused", "rip": "0x2000", "eventSeq": 2, "stopReason": "breakpoint", "session": {"threadId": 7}},
            {"state": "paused", "rip": "0x3000", "eventSeq": 3, "stopReason": "breakpoint", "session": {"threadId": 7}},
            {"state": "exited", "rip": None, "eventSeq": 4, "session": {"threadId": 7}},
        ]
        self.mod.DebugRun = lambda: {"ok": True, "submitted": True}
        def fake_wait(**kwargs):
            state = states.pop(0)
            nested = dict(state.get("session") or {})
            nested.update(
                {
                    "state": state.get("state"),
                    "paused": state.get("state") == "paused",
                    "running": False,
                    "debugging": state.get("state") != "exited",
                    "initialized": True,
                    "ip": state.get("rip"),
                    "eventSeq": state.get("eventSeq"),
                    "stopReason": state.get("stopReason"),
                }
            )
            return {
                "timedOut": False,
                "rip": state.get("rip"),
                "eventSeq": state.get("eventSeq"),
                "threadId": nested.get("threadId"),
                "stopReason": state.get("stopReason"),
                "state": nested,
            }

        self.mod.WaitForBreakpointDetailed = fake_wait
        self.mod._detect_debuggee_bitness = lambda: 64
        self.mod._sample_api_args = lambda *_: [
            {"index": 0, "value": "0x44"},
            {"index": 1, "value": "0x0"},
        ]
        self.mod.StackPeek = lambda *_: "0x3000"
        self.mod._breakpoint_exists = lambda *_: False
        self.mod.DebugSetBreakpoint = lambda *_: "Breakpoint set successfully"
        self.mod.DebugDeleteBreakpoint = lambda *_: "Breakpoint deleted successfully"
        self.mod.RegisterGet = lambda *_: "0x102"
        self.mod._api_register_value = lambda *_: "0x102"
        self.mod._api_trace_callstack = lambda *_: []
        self.mod._capture_api_out_buffers = lambda *_: []

        result = self.mod.RunApiTrace(trace_id, timeout_ms=5000, max_calls=10)
        log = self.mod.GetApiTraceLog(trace_id, limit=10)

        self.assertTrue(result["ok"])
        self.assertEqual(result["callsRecorded"], 1)
        self.assertEqual(result["aliasesCollapsed"], 1)
        self.assertEqual(result["returnsRecorded"], 1)
        self.assertEqual(log["total"], 1)
        self.assertTrue(log["calls"][0]["returned"])
        self.assertEqual(log["calls"][0]["returnValue"], "0x102")
        self.assertEqual(log["calls"][0]["aliases"][0]["func"], "WaitForSingleObjectEx")

    def test_x86_nested_wrapper_alias_does_not_require_same_return_address(self):
        trace_id = "apitrace-x86-wrapper"
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"] = {
                trace_id: {
                    "traceId": trace_id,
                    "targetMap": {
                        "0x1000": {"module": "kernelbase.dll", "func": "WaitForSingleObject"},
                        "0x2000": {"module": "kernelbase.dll", "func": "WaitForSingleObjectEx"},
                    },
                    "argCount": 4,
                    "calls": [],
                    "nextCallSeq": 0,
                    "pendingReturns": {},
                    "ownedReturnBreakpoints": [],
                    "captureReturns": True,
                    "captureCallstack": False,
                    "maxCallstackFrames": 0,
                    "maxOutBytes": 0,
                    "stopped": False,
                }
            }
        states = [
            {"state": "paused", "rip": "0x1000", "eventSeq": 1},
            {"state": "paused", "rip": "0x2000", "eventSeq": 2},
            {"state": "paused", "rip": "0x3000", "eventSeq": 3},
            {"state": "exited", "rip": None, "eventSeq": 4},
        ]
        self.mod.DebugRun = lambda: {"ok": True, "submitted": True}

        def fake_wait(**kwargs):
            state = states.pop(0)
            nested = {
                "state": state["state"],
                "paused": state["state"] == "paused",
                "running": False,
                "debugging": state["state"] != "exited",
                "initialized": True,
                "ip": state.get("rip"),
                "eventSeq": state["eventSeq"],
                "threadId": 11,
                "stopReason": "breakpoint",
            }
            return {
                "timedOut": False,
                "rip": state.get("rip"),
                "eventSeq": state["eventSeq"],
                "threadId": 11,
                "stopReason": "breakpoint",
                "state": nested,
            }

        stack_returns = iter(("0x3000", "0x2100"))
        self.mod.WaitForBreakpointDetailed = fake_wait
        self.mod._detect_debuggee_bitness = lambda: 32
        self.mod._sample_api_args = lambda *_: [{"index": 0, "value": "0x44"}]
        self.mod.StackPeek = lambda *_: next(stack_returns)
        self.mod._breakpoint_exists = lambda *_: False
        self.mod.DebugSetBreakpoint = lambda *_: "Breakpoint set successfully"
        self.mod.DebugDeleteBreakpoint = lambda *_: "Breakpoint deleted successfully"
        self.mod._api_register_value = lambda *_: "0x102"
        self.mod._api_trace_callstack = lambda *_: []
        self.mod._capture_api_out_buffers = lambda *_: []

        result = self.mod.RunApiTrace(trace_id, timeout_ms=5000, max_calls=10)
        log = self.mod.GetApiTraceLog(trace_id, limit=10)

        self.assertTrue(result["ok"])
        self.assertEqual(result["callsRecorded"], 1)
        self.assertEqual(result["aliasesCollapsed"], 1)
        self.assertEqual(result["returnsRecorded"], 1)
        self.assertEqual(log["total"], 1)
        self.assertEqual(log["calls"][0]["aliases"][0]["kind"], "nested_wrapper")

    def test_caller_filter_runs_before_native_return_hook_scheduling(self):
        trace_id = "apitrace-filter-before-native"
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"] = {
                trace_id: {
                    "traceId": trace_id,
                    "targetMap": {
                        "0x1000": {
                            "module": "kernelbase.dll",
                            "func": "Sleep",
                        }
                    },
                    "argCount": 1,
                    "calls": [],
                    "nextCallSeq": 0,
                    "pendingReturns": {},
                    "ownedReturnBreakpoints": [],
                    "captureReturns": True,
                    "nativeReturnHooks": True,
                    "captureCallstack": True,
                    "maxCallstackFrames": 8,
                    "maxOutBytes": 0,
                    "callerFilter": "fixture.exe",
                    "stopped": False,
                }
            }
        states = [
            {
                "state": "paused",
                "rip": "0x1000",
                "eventSeq": 1,
                "debugging": True,
            },
            {
                "state": "exited",
                "rip": None,
                "eventSeq": 2,
                "debugging": False,
            },
        ]
        self.mod.DebugRun = lambda: {"ok": True, "submitted": True}

        def fake_wait(**kwargs):
            state = states.pop(0)
            nested = {
                "state": state["state"],
                "paused": state["state"] == "paused",
                "running": False,
                "debugging": state["debugging"],
                "initialized": True,
                "ip": state.get("rip"),
                "eventSeq": state["eventSeq"],
                "threadId": 13,
                "stopReason": "breakpoint",
            }
            return {
                "timedOut": False,
                "rip": state.get("rip"),
                "eventSeq": state["eventSeq"],
                "threadId": 13,
                "stopReason": "breakpoint",
                "state": nested,
            }

        native_entries = []
        self.mod.WaitForBreakpointDetailed = fake_wait
        self.mod._detect_debuggee_bitness = lambda: 64
        self.mod._sample_api_args = lambda *_: [
            {"index": 0, "value": "0x1"}
        ]
        self.mod._api_trace_callstack = lambda *_: [
            {"comment": "kernelbase.InternalCaller"}
        ]
        self.mod._record_native_api_entry = lambda *args, **kwargs: (
            native_entries.append((args, kwargs)) or {"ok": True}
        )

        result = self.mod.RunApiTrace(trace_id, timeout_ms=5000, max_calls=10)

        self.assertFalse(result["ok"])
        self.assertTrue(result["exited"])
        self.assertEqual(result["filteredEntries"], 1)
        self.assertEqual(native_entries, [])

    def test_heap_state_uses_verified_return_addresses_and_successful_frees(self):
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["heapTraces"] = {
                "heap-1": {"heapTraceId": "heap-1", "apiTraceId": "api-1"}
            }
            self.mod._RUNTIME_STATE["apiTraces"] = {
                "api-1": {
                    "calls": [
                        {
                            "seq": 1,
                            "func": "HeapAlloc",
                            "module": "kernelbase.dll",
                            "threadId": 7,
                            "timestamp": "t1",
                            "returned": True,
                            "returnValue": "0x100000",
                            "args": [
                                {"index": 0, "value": "0x1"},
                                {"index": 1, "value": "0x0"},
                                {"index": 2, "value": "0x20"},
                            ],
                        },
                        {
                            "seq": 2,
                            "func": "HeapFree",
                            "module": "kernelbase.dll",
                            "threadId": 7,
                            "timestamp": "t2",
                            "returned": True,
                            "returnValue": "0x1",
                            "args": [
                                {"index": 0, "value": "0x1"},
                                {"index": 1, "value": "0x0"},
                                {"index": 2, "value": "0x100000"},
                            ],
                        },
                    ]
                }
            }

        result = self.mod.GetHeapState("heap-1")

        self.assertTrue(result["returnTracking"])
        self.assertEqual(result["allocCount"], 1)
        self.assertEqual(result["freeCount"], 1)
        self.assertEqual(result["liveAllocations"], 0)
        self.assertEqual(result["events"][0]["addr"], "0x100000")

    def test_heap_state_tracks_realloc_lineage_and_double_free_anomaly(self):
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["heapTraces"] = {
                "heap-lineage": {
                    "heapTraceId": "heap-lineage",
                    "apiTraceId": "api-lineage",
                    "allocatorCatalog": self.mod.HEAP_RESOURCE_CATALOG,
                    "minAllocationSize": 1,
                    "maxAllocationSize": 4096,
                }
            }
            self.mod._RUNTIME_STATE["apiTraces"] = {
                "api-lineage": {
                    "calls": [
                        {
                            "seq": 1, "func": "HeapAlloc", "module": "kernelbase.dll",
                            "threadId": 7, "returned": True, "returnValue": "0x100000",
                            "args": [
                                {"index": 0, "value": "0x1"},
                                {"index": 1, "value": "0x0"},
                                {"index": 2, "value": "0x20"},
                            ],
                        },
                        {
                            "seq": 2, "func": "HeapReAlloc", "module": "kernelbase.dll",
                            "threadId": 7, "returned": True, "returnValue": "0x200000",
                            "args": [
                                {"index": 0, "value": "0x1"},
                                {"index": 1, "value": "0x0"},
                                {"index": 2, "value": "0x100000"},
                                {"index": 3, "value": "0x50"},
                            ],
                        },
                        {
                            "seq": 3, "func": "HeapFree", "module": "kernelbase.dll",
                            "threadId": 7, "returned": True, "returnValue": "0x1",
                            "args": [
                                {"index": 0, "value": "0x1"},
                                {"index": 1, "value": "0x0"},
                                {"index": 2, "value": "0x200000"},
                            ],
                        },
                        {
                            "seq": 4, "func": "HeapFree", "module": "kernelbase.dll",
                            "threadId": 7, "returned": True, "returnValue": "0x0",
                            "args": [
                                {"index": 0, "value": "0x1"},
                                {"index": 1, "value": "0x0"},
                                {"index": 2, "value": "0x200000"},
                            ],
                        },
                    ]
                }
            }

        result = self.mod.GetHeapState("heap-lineage")

        self.assertEqual(result["schema"], "heap-resource-lifecycle-v2")
        self.assertEqual(result["allocCount"], 1)
        self.assertEqual(result["reallocCount"], 1)
        self.assertEqual(result["freeCount"], 1)
        self.assertEqual(result["liveAllocations"], 0)
        self.assertEqual(result["anomalyCounts"]["double_free"], 1)
        self.assertEqual(result["recentReallocations"][0]["requestedSize"], 80)
        self.assertTrue(result["recentReallocations"][0]["parentAllocationId"])

    def test_heap_catalog_validation_supports_custom_allocator_extension(self):
        catalog, error = self.mod._normalize_heap_catalog(
            json.dumps(["crt"]),
            json.dumps(
                [
                    {
                        "module": "allocator.dll",
                        "function": "CustomAlloc",
                        "op": "alloc",
                        "sizeArgs": [1],
                        "returnSemantics": "pointer",
                    }
                ]
            ),
        )

        self.assertIsNone(error)
        self.assertIn("malloc", catalog)
        self.assertIn("allocator.dll!customalloc", catalog)
        self.assertEqual(catalog["allocator.dll!customalloc"]["sizeArgs"], [1])

    def test_api_trace_log_supports_exclusive_sequence_cursor(self):
        trace_id = "api-cursor"
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"] = {
                trace_id: {
                    "traceId": trace_id,
                    "calls": [
                        {"seq": 7, "func": "ReadFile", "returned": True},
                        {"seq": 8, "func": "WriteFile", "returned": True},
                        {"seq": 9, "func": "CloseHandle", "returned": True},
                    ],
                    "droppedCalls": 4,
                }
            }

        page = self.mod.GetApiTraceLog(trace_id, limit=10, after_seq=7)

        self.assertTrue(page["ok"])
        self.assertEqual([item["seq"] for item in page["calls"]], [8, 9])
        self.assertEqual(page["afterSeq"], 7)
        self.assertEqual(page["nextAfterSeq"], 9)
        self.assertEqual(page["oldestSeq"], 7)
        self.assertEqual(page["latestSeq"], 9)
        self.assertFalse(page["cursorTruncated"])
        self.assertEqual(page["droppedCalls"], 4)

    def test_native_api_evidence_uses_exclusive_sequence_cursor(self):
        calls = []

        def fake_request(method, endpoint, **kwargs):
            calls.append((method, endpoint, dict(kwargs.get("params") or {}), kwargs))
            return self.mod.BridgeEnvelope(
                True,
                data={"ok": True, "traceId": "api-native", "events": []},
                meta={"requestId": "test"},
            )

        self.mod._bridge_request = fake_request
        result = self.mod.GetNativeApiTraceEvidence(
            "api-native",
            after_seq=17,
            limit=23,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(calls[0][0], "GET")
        self.assertEqual(calls[0][1], "ApiTrace/Status")
        self.assertEqual(calls[0][2]["afterSeq"], "17")
        self.assertEqual(calls[0][2]["limit"], "23")

    def test_native_return_hook_configuration_uses_bridge_state_route(self):
        calls = []

        def fake_request(method, endpoint, **kwargs):
            calls.append((method, endpoint, kwargs))
            return self.mod.BridgeEnvelope(
                True,
                data={
                    "ok": True,
                    "traceId": "api-native-hooks",
                    "nativeReturnHooks": True,
                },
            )

        self.mod._bridge_request = fake_request
        result = self.mod._configure_native_api_trace(
            "api-native-hooks",
            native_return_hooks=True,
            entry_addresses=["0x70001000", "0x70002000"],
        )

        self.assertTrue(result["ok"])
        self.assertEqual(calls[0][0:2], ("POST", "ApiTrace/Configure"))
        self.assertEqual(calls[0][2]["form_data"]["nativeReturnHooks"], "true")
        self.assertEqual(
            calls[0][2]["form_data"]["entryAddresses"],
            "0x70001000,0x70002000",
        )

    def test_native_entry_evidence_uses_explicit_entry_route(self):
        calls = []

        def fake_request(method, endpoint, **kwargs):
            calls.append((method, endpoint, kwargs))
            return self.mod.BridgeEnvelope(
                True,
                data={
                    "ok": True,
                    "traceId": "api-native-entry",
                    "entrySeq": 7,
                    "callId": 3,
                    "duplicate": False,
                },
            )

        self.mod._bridge_request = fake_request
        result = self.mod._record_native_api_entry(
            "api-native-entry",
            "0x70001000",
            "user32.dll",
        )

        self.assertTrue(result["ok"])
        self.assertEqual(calls[0][0:2], ("POST", "ApiTrace/Entry"))
        self.assertEqual(calls[0][2]["form_data"]["apiAddress"], "0x70001000")
        self.assertEqual(calls[0][2]["form_data"]["module"], "user32.dll")

    def test_typed_return_decoder_preserves_raw_and_adds_semantics(self):
        resolved = self.mod._decode_api_return(
            "kernel32.dll!GetProcAddress",
            "0x7fff12345678",
        )
        self.assertEqual(resolved["raw"], "0x7fff12345678")
        self.assertEqual(resolved["resolvedAddress"], "0x7fff12345678")
        self.assertTrue(resolved["resolved"])
        self.assertEqual(resolved["classification"], "non_null")

        failed = self.mod._decode_api_return("kernel32.dll!CloseHandle", "0x0")
        self.assertFalse(failed["boolean"])
        self.assertEqual(failed["classification"], "failure")

        status = self.mod._decode_api_return(
            "ntdll.dll!NtQueryInformationProcess",
            "0xC0000005",
        )
        self.assertFalse(status["success"])
        self.assertEqual(status["signed"], -1073741819)
        self.assertEqual(status["code"], 5)

        with_fault = self.mod._decode_api_return(
            "kernel32.dll!ReadFile",
            "0x1",
            out_buffers=[
                {
                    "label": "buffer",
                    "ok": False,
                    "fault": {"code": "unreadable"},
                }
            ],
        )
        self.assertEqual(with_fault["outBufferCount"], 1)
        self.assertEqual(with_fault["outBufferFaults"], 1)
        self.assertEqual(with_fault["outBufferLabels"], ["buffer"])

    def test_stop_api_trace_cleans_and_releases_native_owned_return_hooks(self):
        trace_id = "api-native-stop"
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"] = {
                trace_id: {
                    "traceId": trace_id,
                    "createdAt": "2026-07-26T00:00:00Z",
                    "nativeReturnHooks": True,
                    "ownedEntryBreakpoints": [],
                    "ownedReturnBreakpoints": [],
                    "preexistingEntryBreakpoints": [],
                    "calls": [],
                }
            }
        deleted = []
        self.mod._finalize_native_api_trace_evidence = lambda *_: {
            "ok": True,
            "traceId": trace_id,
            "finalizedPendingCalls": 0,
            "ownedReturnBreakpoints": ["0x70001000"],
        }
        self.mod.DebugDeleteBreakpoint = (
            lambda address: deleted.append(address)
            or "Breakpoint deleted successfully"
        )
        self.mod._release_native_api_return_hooks = lambda *_: {
            "ok": True,
            "traceId": trace_id,
            "released": 1,
        }

        result = self.mod.StopApiTrace(trace_id, delete_breakpoints=True)

        self.assertTrue(result["ok"])
        self.assertEqual(deleted, ["0x70001000"])
        self.assertEqual(result["nativeOwnedReturnBreakpoints"], ["0x70001000"])
        self.assertEqual(result["nativeReturnHooksRelease"]["released"], 1)

    def test_native_api_evidence_preserves_exception_unwind_counters(self):
        self.mod._bridge_request = lambda *args, **kwargs: self.mod.BridgeEnvelope(
            True,
            data={
                "ok": True,
                "traceId": "api-exception",
                "pendingCalls": 0,
                "finalizedPendingCalls": 0,
                "exceptionUnwoundPendingCalls": 1,
                "events": [
                    {
                        "seq": 2,
                        "kind": "exception_unwind",
                        "exceptionCode": "0xe0424242",
                        "exceptionFirstChance": False,
                        "unwoundFrames": 0,
                        "managedException": True,
                        "managedRuntime": "coreclr",
                        "managedHResult": "0x80131500",
                        "managedObject": "0x70002000",
                        "exceptionParameters": ["0x80131500", "0x70002000"],
                    }
                ],
            },
        )

        result = self.mod.GetNativeApiTraceEvidence("api-exception")

        self.assertTrue(result["ok"])
        self.assertEqual(result["exceptionUnwoundPendingCalls"], 1)
        self.assertEqual(result["events"][0]["kind"], "exception_unwind")
        self.assertFalse(result["events"][0]["exceptionFirstChance"])
        self.assertTrue(result["events"][0]["managedException"])
        self.assertEqual(result["events"][0]["managedRuntime"], "coreclr")

    def test_native_api_evidence_correlates_address_with_api_target(self):
        trace_id = "api-native-map"
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"] = {
                trace_id: {
                    "traceId": trace_id,
                    "targetMap": {
                        "0x70001000": {
                            "module": "kernelbase.dll",
                            "func": "SleepEx",
                            "addr": "0x70001000",
                        }
                    },
                }
            }

        self.mod._bridge_request = lambda *args, **kwargs: self.mod.BridgeEnvelope(
            True,
            data={
                "ok": True,
                "traceId": trace_id,
                "events": [
                    {
                        "seq": 1,
                        "kind": "entry",
                        "apiAddress": "0x70001000",
                        "arguments": ["0x1", "0x0"],
                    }
                ],
            },
        )

        result = self.mod.GetNativeApiTraceEvidence(trace_id)

        self.assertTrue(result["ok"])
        self.assertEqual(result["events"][0]["apiFunction"], "SleepEx")
        self.assertEqual(
            result["events"][0]["api"],
            "kernelbase.dll!SleepEx",
        )

    def test_native_api_evidence_clear_uses_post(self):
        calls = []

        def fake_request(method, endpoint, **kwargs):
            calls.append((method, endpoint, kwargs))
            return self.mod.BridgeEnvelope(
                True,
                data={"ok": True, "traceId": "api-clear", "cleared": 3},
            )

        self.mod._bridge_request = fake_request
        result = self.mod.ClearNativeApiTraceEvidence("api-clear")

        self.assertTrue(result["ok"])
        self.assertEqual(result["cleared"], 3)
        self.assertEqual(calls[0][0:2], ("POST", "ApiTrace/Clear"))
        self.assertEqual(calls[0][2]["form_data"]["traceId"], "api-clear")

    def test_run_heap_trace_stops_on_requested_lifecycle(self):
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["heapTraces"] = {
                "heap-1": {"heapTraceId": "heap-1", "apiTraceId": "api-1"}
            }
        states = [
            {"ok": True, "allocCount": 1, "reallocCount": 0, "freeCount": 0, "liveAllocations": 1},
            {"ok": True, "allocCount": 1, "reallocCount": 1, "freeCount": 1, "liveAllocations": 0},
        ]
        self.mod.RunApiTrace = lambda *args, **kwargs: {
            "ok": True,
            "exited": False,
            "timedOut": False,
        }
        self.mod.GetHeapState = lambda *_: states.pop(0)
        self.mod.StopApiTrace = lambda *args, **kwargs: {
            "ok": True,
            "breakpointsRemoved": 3,
        }

        result = self.mod.RunHeapTrace(
            "heap-1",
            timeout_ms=5000,
            expected_allocations=1,
            expected_reallocations=1,
            expected_frees=1,
            stop_when_live_zero=True,
        )

        self.assertTrue(result["ok"])
        self.assertTrue(result["criteriaMet"])
        self.assertEqual(result["iterations"], 2)
        self.assertTrue(result["stop"]["ok"])

    def test_comparison_capture_preserves_exact_binary_operands(self):
        memory = {
            "0x1000": b"AAAAAAAAA",
            "0x2000": b"password1",
        }
        self.mod._read_memory_bytes = lambda address, size: {
            "ok": True,
            "bytes": memory[address][:size],
        }
        comparison = self.mod._capture_comparison_evidence(
            "ucrtbase.dll!strncmp",
            [
                {"index": 0, "value": "0x1000"},
                {"index": 1, "value": "0x2000"},
                {"index": 2, "value": "0x9"},
            ],
            4096,
        )

        self.assertIsNotNone(comparison)
        self.assertTrue(comparison["capturedComplete"])
        self.assertEqual(comparison["elementCount"], 9)
        self.assertEqual(comparison["operands"][0]["hex"], b"AAAAAAAAA".hex())
        self.assertEqual(comparison["operands"][1]["textPreview"], "password1")
        finalized = self.mod._finalize_comparison_evidence(
            comparison, "0xffffffff", 37
        )
        self.assertFalse(finalized["result"]["equal"])
        self.assertEqual(finalized["result"]["signed"], -1)
        self.assertEqual(finalized["result"]["returnEventSeq"], 37)

    def test_comparison_secret_recovery_handles_identity_and_xor(self):
        identity_call = {
            "seq": 1,
            "entryEventSeq": 10,
            "returnEventSeq": 11,
            "threadId": 7,
            "module": "ucrtbase.dll",
            "func": "strncmp",
            "addr": "0x70001000",
            "callStack": [{"module": "crackme01.exe", "rva": "0x1234"}],
            "comparison": {
                "encoding": "bytes",
                "result": {"equal": False},
                "operands": [
                    {"ok": True, "hex": b"AAAAAAAAA".hex()},
                    {"ok": True, "hex": b"password1".hex()},
                ],
            },
        }
        identity = self.mod._recover_candidates_from_comparison(
            identity_call, b"AAAAAAAAA", "auto", -1
        )
        self.assertEqual(len(identity), 1)
        self.assertEqual(identity[0]["candidateText"], "password1")
        self.assertEqual(identity[0]["method"], "identity-comparison")

        xor_key = 0x69
        probe = b"AAAAAAAAAA"
        encoded_probe = bytes(value ^ xor_key for value in probe) + b"\n"
        secret = b"SecretKey!"
        encoded_secret = bytes(value ^ xor_key for value in secret) + b"\n"
        xor_call = {
            **identity_call,
            "seq": 2,
            "func": "strcmp",
            "comparison": {
                "encoding": "bytes",
                "result": {"equal": False},
                "operands": [
                    {"ok": True, "hex": encoded_probe.hex()},
                    {"ok": True, "hex": encoded_secret.hex()},
                ],
            },
        }
        recovered = self.mod._recover_candidates_from_comparison(
            xor_call, probe, "auto", -1
        )
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["candidateText"], "SecretKey!")
        self.assertEqual(recovered[0]["xorKey"], xor_key)

    def test_recover_comparison_secret_writes_hashed_atomic_evidence(self):
        trace_id = "api-secret"
        call = {
            "seq": 1,
            "entryEventSeq": 20,
            "returnEventSeq": 21,
            "threadId": 9,
            "module": "ucrtbase.dll",
            "func": "strncmp",
            "addr": "0x70002000",
            "callStack": [{"module": "fixture.exe", "rva": "0x456"}],
            "comparison": {
                "encoding": "bytes",
                "result": {"equal": False, "returnEventSeq": 21},
                "operands": [
                    {"ok": True, "hex": b"AAAAAAAAA".hex()},
                    {"ok": True, "hex": b"password1".hex()},
                ],
            },
        }
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["apiTraces"] = {
                trace_id: {
                    "traceId": trace_id,
                    "label": "unit",
                    "calls": [call],
                    "droppedCalls": 0,
                }
            }
        self.mod.GetSessionBinding = lambda: {
            "ok": True,
            "active": True,
            "matches": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "recovery.json"
            result = self.mod.RecoverComparisonSecret(
                trace_id,
                probe="AAAAAAAAA",
                evidence_path=str(output),
            )
            document = json.loads(output.read_text(encoding="utf-8"))

        self.assertTrue(result["ok"])
        self.assertEqual(result["candidateCount"], 1)
        self.assertEqual(result["candidates"][0]["candidateText"], "password1")
        self.assertTrue(result["requiresIndependentValidation"])
        self.assertEqual(
            document["evidenceSha256"],
            result["evidenceWrite"]["evidenceSha256"],
        )


if __name__ == "__main__":
    unittest.main()
