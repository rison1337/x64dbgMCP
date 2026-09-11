import asyncio
import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_response_detail_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ResponseDetailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def setUp(self):
        self.originals = {
            name: getattr(self.mod, name)
            for name in (
                "safe_get",
                "GetNativeTrace",
                "TraceIntoConditional",
                "TraceOverConditional",
                "WaitNativeTrace",
                "StopNativeTrace",
            )
        }

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(self.mod, name, value)

    def test_profile_default_is_compact_only_for_compact_profile(self):
        with mock.patch.dict(os.environ, {"X64DBG_MCP_TOOL_PROFILE": "compact"}):
            self.assertEqual(self.mod._resolve_response_detail(""), ("summary", None))
        with mock.patch.dict(os.environ, {"X64DBG_MCP_TOOL_PROFILE": "full"}):
            self.assertEqual(self.mod._resolve_response_detail(""), ("full", None))
        level, error = self.mod._resolve_response_detail("verbose")
        self.assertEqual(level, "")
        self.assertEqual(error["errorCode"], "INVALID_ARGUMENT")

    def test_launch_summary_preserves_identity_and_is_bounded(self):
        full = {
            "ok": True,
            "exePath": r"C:\fixture.exe",
            "requestedArch": "x64",
            "ensureDebugger": {"ok": True, "capabilities": {"noise": ["x"] * 100}},
            "init": {
                "ok": True,
                "attempts": 2,
                "state": {
                    "state": "paused",
                    "debuggeePid": 123,
                    "rip": "0x140001000",
                    "stopReason": "entry",
                    "eventSeq": 9,
                    "session": {"sessionId": "session-1", "generation": 3},
                },
                "binding": {
                    "pid": 123,
                    "moduleBase": "0x140000000",
                    "sessionId": "session-1",
                    "sessionGeneration": 3,
                    "eventSeq": 9,
                    "debuggerArch": "x64",
                },
            },
            "advanceToEntry": {"ok": True, "rip": "0x140001000"},
        }
        summary = self.mod._compact_launch_result(full)
        self.assertEqual(summary["pid"], 123)
        self.assertEqual(summary["sessionId"], "session-1")
        self.assertEqual(summary["generation"], 3)
        self.assertEqual(summary["moduleBase"], "0x140000000")
        self.assertNotIn("init", summary)
        self.assertLess(len(json.dumps(summary)), len(json.dumps(full)))

    def test_breakpoint_summary_keeps_caller_requested_capture(self):
        payload = {
            "ok": True,
            "event": {
                "hit": True,
                "rip": "0x401000",
                "eventSeq": 7,
                "state": {
                    "exceptionCode": "0x80000003",
                    "registers": {"noise": "omitted"},
                },
            },
            "capture": {"registers": {"rax": "0x2A"}},
            "skippedBreakpoints": [{"addr": "0x1"}],
            "skippedExceptions": [],
            "resumeRepairs": [],
            "historyEntry": {"large": ["x"] * 100},
        }
        summary = self.mod._compact_breakpoint_capture_result(payload)
        self.assertEqual(summary["capture"], payload["capture"])
        self.assertEqual(summary["event"]["exceptionCode"], "0x80000003")
        self.assertEqual(summary["skippedBreakpointCount"], 1)
        self.assertNotIn("historyEntry", summary)

    def test_get_native_trace_summary_keeps_requested_page_and_cursor(self):
        self.mod.safe_get = lambda *args, **kwargs: {
            "ok": True,
            "traceId": "trace-1",
            "active": False,
            "completed": True,
            "eventCount": 3,
            "eventReturned": 2,
            "eventHasMore": True,
            "eventNextAfterSeq": 12,
            "events": [{"seq": 11}, {"seq": 12}],
            "hitReturned": 1,
            "hitHasMore": False,
            "hits": [{"ip": "0x401000", "hits": 2}],
            "captureEvents": True,
            "createdTickMs": 1,
        }
        result = self.mod.GetNativeTrace(
            "trace-1", event_limit=2, hit_limit=1, detail="summary"
        )
        self.assertEqual(len(result["events"]), 2)
        self.assertEqual(result["pageSize"], {"events": 2, "hits": 1})
        self.assertEqual(result["nextCursor"], {"eventAfterSeq": 12})
        self.assertNotIn("captureEvents", result)
        self.assertNotIn("createdTickMs", result)

    def test_run_native_trace_accepts_stepinto_and_returns_summary(self):
        replies = [
            {"ok": True, "traceId": "trace-1", "active": True, "maxSteps": 10},
            {
                "ok": True,
                "traceId": "trace-1",
                "active": False,
                "completed": True,
                "matchedSteps": 4,
                "totalSteps": 4,
                "eventCount": 4,
                "uniqueAddresses": 3,
                "stopReason": "condition",
                "hasMore": True,
                "nextCursor": {"eventAfterSeq": 4},
            },
        ]
        self.mod.GetNativeTrace = lambda *args, **kwargs: replies.pop(0)
        calls = []
        self.mod.TraceIntoConditional = lambda **kwargs: calls.append(kwargs) or {"ok": True}
        self.mod.WaitNativeTrace = lambda *args, **kwargs: {
            "ok": True,
            "active": False,
            "completed": True,
            "timedOut": False,
        }
        result = self.mod.RunNativeTrace(
            "trace-1", step_mode="stepinto", max_steps=10, detail="summary"
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["eventCount"], 4)
        self.assertEqual(result["nextCursor"], {"eventAfterSeq": 4})
        self.assertNotIn("evidence", result)
        self.assertEqual(calls[0]["max_steps"], 10)

    def test_xref_get_pages_legacy_bridge_and_adds_module_rva(self):
        def fake_get(endpoint, params=None, **kwargs):
            if endpoint == "Xref/Get":
                return {
                    "address": "0x401100",
                    "refcount": 3,
                    "references": [
                        {"addr": "0x401010", "type": "data"},
                        {"addr": "0x401020", "type": "call"},
                        {"addr": "0x401030", "type": "jmp"},
                    ],
                }
            if endpoint == "GetModuleList":
                return {
                    "modules": [
                        {
                            "name": "fixture.exe",
                            "base": "0x400000",
                            "size": "0x2000",
                        }
                    ]
                }
            raise AssertionError(endpoint)

        self.mod.safe_get = fake_get
        result = self.mod.XrefGet(
            "0x401100", offset=1, limit=1, detail="summary"
        )
        self.assertEqual(result["returned"], 1)
        self.assertTrue(result["hasMore"])
        self.assertEqual(result["nextCursor"], "2")
        self.assertEqual(result["references"][0]["rva"], "0x1020")
        self.assertEqual(result["target"]["rva"], "0x1100")

    def test_string_search_and_disassembly_are_explicitly_paginated(self):
        def fake_get(endpoint, params=None, **kwargs):
            params = params or {}
            if endpoint == "ExecCommand":
                return {
                    "success": True,
                    "refView": {
                        "rowCount": 3,
                        "rows": [
                            ["0x401010", "lea rax,[0x402000]", "0x402000", "alpha"],
                            ["0x401020", "lea rax,[0x402010]", "0x402010", "beta"],
                            ["0x401030", "lea rax,[0x402020]", "0x402020", "beta-two"],
                        ],
                    },
                }
            if endpoint == "GetModuleList":
                return {
                    "modules": [
                        {
                            "name": "fixture.exe",
                            "base": "0x400000",
                            "size": "0x4000",
                        }
                    ]
                }
            if endpoint == "Disasm/GetInstructionRange":
                start = int(str(params["addr"]), 0)
                count = int(params["count"])
                return {
                    "ok": True,
                    "instructions": [
                        {
                            "address": hex(start + index),
                            "instruction": "nop",
                            "size": 1,
                        }
                        for index in range(count)
                    ],
                }
            raise AssertionError(endpoint)

        self.mod.safe_get = fake_get
        strings = self.mod.SearchStrings(
            "beta", offset=1, limit=1, detail="summary"
        )
        self.assertEqual(strings["totalMatches"], 2)
        self.assertEqual(strings["matches"][0]["string"], "beta-two")
        self.assertIsNone(strings["nextCursor"])
        self.assertEqual(strings["matches"][0]["reference"]["rva"], "0x1030")

        first = self.mod.DisasmRange(
            "0x401000", "0x401008", max_instructions=3, detail="summary"
        )
        self.assertEqual(first["count"], 3)
        self.assertTrue(first["hasMore"])
        self.assertEqual(first["nextCursor"], "0x401003")
        second = self.mod.DisasmRange(
            "0x401000",
            "0x401008",
            max_instructions=3,
            cursor=first["nextCursor"],
            detail="summary",
        )
        self.assertEqual(second["pageStart"], "0x401003")
        self.assertEqual(second["count"], 3)

        async def public_call():
            return await self.mod.mcp._tool_manager.call_tool(
                "DisasmRange",
                {
                    "start": "0x401000",
                    "end": "0x401008",
                    "max_instructions": 3,
                    "detail": "summary",
                },
            )

        public = asyncio.run(public_call())
        self.assertTrue(public["ok"], public)
        self.assertEqual(public["data"]["nextCursor"], "0x401003")

    def test_search_strings_consumes_partial_reference_pages_without_char_truncation(self):
        rows = [
            [
                f"{0x401000 + index:08X}",
                "lea eax,[string]",
                f"{0x402000 + index:08X}",
                f"needle-{index}",
            ]
            for index in range(300)
        ]
        calls = []

        modules = {
            "modules": [
                {
                    "name": "fixture.exe",
                    "base": "0x400000",
                    "entry": "0x401000",
                    "size": "0x10000",
                }
            ]
        }
        def fake_get(endpoint, params=None, **_kwargs):
            if endpoint == "ExecCommand":
                params = params or {}
                calls.append(dict(params))
                offset = int(params["offset"])
                page = rows[offset : offset + 102]
                return {"success": True, "refView": {"rowCount": 300, "rows": page}}
            if endpoint == "GetModuleList":
                return modules
            raise AssertionError(endpoint)

        with mock.patch.object(self.mod, "safe_get", side_effect=fake_get):
            result = self.mod.SearchStrings("needle", limit=500, detail="full")

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["totalScanned"], 300)
        self.assertEqual(result["totalMatches"], 300)
        self.assertTrue(result["completeScan"])
        self.assertEqual([item["offset"] for item in calls], [0, 102, 204])
        self.assertEqual(result["matches"][0]["reference"]["rva"], "0x1000")

    def test_search_strings_scopes_named_module_to_its_entry(self):
        calls = []
        modules = {
            "modules": [
                {
                    "name": "fixture.exe",
                    "base": "0x400000",
                    "entry": "0x401234",
                    "size": "0x10000",
                }
            ]
        }

        def fake_get(endpoint, params=None, **_kwargs):
            if endpoint == "ExecCommand":
                calls.append(dict(params or {}))
                return {"success": True, "refView": {"rowCount": 0, "rows": []}}
            if endpoint == "GetModuleList":
                return modules
            raise AssertionError(endpoint)

        with mock.patch.object(self.mod, "safe_get", side_effect=fake_get):
            result = self.mod.SearchStrings("anything", module="fixture.exe")

        self.assertTrue(result["ok"], result)
        self.assertEqual(calls[0]["cmd"], "strref 0x401234")


if __name__ == "__main__":
    unittest.main()
