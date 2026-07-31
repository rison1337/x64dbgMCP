import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_native_trace_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class NativeTraceToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def setUp(self):
        self.originals = {
            name: getattr(self.mod, name)
            for name in (
                "BridgeHello",
                "safe_post",
                "safe_get",
                "_log_event",
                "GetNativeTrace",
                "WaitNativeTrace",
                "StopNativeTrace",
                "ClearNativeTrace",
                "TraceIntoConditional",
                "TraceOverConditional",
                "_build_debug_state",
                "_get_current_debuggee_module_base",
                "GetModuleList",
                "StartNativeTrace",
                "ExecCommand",
            )
        }
        self.mod._log_event = lambda *args, **kwargs: None
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["traceRecords"] = {}
            self.mod._RUNTIME_STATE["traceRecordSeq"] = 0

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(self.mod, name, value)

    @staticmethod
    def _hello():
        return {
            "ok": True,
            "identity": {"capabilities": {"nativeTrace": {"version": 1}}},
        }

    def test_start_native_trace_emits_explicit_hex_range_size(self):
        calls = []
        self.mod.BridgeHello = lambda refresh=True: self._hello()

        def fake_post(endpoint, data, **kwargs):
            calls.append((endpoint, dict(data), kwargs))
            return {"ok": True, "traceId": "native-1", "active": True}

        self.mod.safe_post = fake_post

        result = self.mod.StartNativeTrace(
            mode="both",
            range_start="0x140000000",
            range_size=0x27000,
            max_steps=1234,
            max_events=321,
            max_unique=222,
            auto_resume_exceptions=True,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(calls[0][0], "Trace/Start")
        self.assertEqual(calls[0][1]["rangeStart"], "0x140000000")
        self.assertEqual(calls[0][1]["rangeSize"], "0x27000")
        self.assertEqual(calls[0][1]["maxSteps"], "1234")
        self.assertEqual(calls[0][1]["autoResumeExceptions"], "true")

    def test_start_native_trace_rejects_partial_range_before_network(self):
        calls = []
        self.mod.BridgeHello = lambda refresh=True: calls.append("hello")
        result = self.mod.StartNativeTrace(range_start="0x401000", range_size=0)
        self.assertFalse(result["ok"])
        self.assertEqual(result["errorCode"], "INVALID_ARGUMENT")
        self.assertEqual(calls, [])

    def test_wait_native_trace_continues_across_server_slices(self):
        replies = [
            {"ok": True, "traceId": "native-1", "active": True, "completed": False},
            {
                "ok": True,
                "traceId": "native-1",
                "active": False,
                "completed": True,
                "matchedSteps": 7,
            },
        ]
        self.mod.safe_get = lambda *args, **kwargs: replies.pop(0)

        result = self.mod.WaitNativeTrace("native-1", timeout_ms=2000, poll_ms=1)

        self.assertTrue(result["ok"])
        self.assertFalse(result["timedOut"])
        self.assertEqual(result["matchedSteps"], 7)
        self.assertEqual(replies, [])

    def test_get_native_trace_sends_exclusive_event_watermark(self):
        calls = []

        def fake_get(endpoint, params, **kwargs):
            calls.append((endpoint, dict(params), kwargs))
            return {"ok": True, "traceId": "native-1", "events": []}

        self.mod.safe_get = fake_get

        result = self.mod.GetNativeTrace(
            "native-1",
            event_offset=17,
            event_limit=23,
            hit_offset=29,
            hit_limit=31,
            event_after_seq=37,
            hit_after_revision=41,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(calls[0][0], "Trace/Status")
        self.assertEqual(calls[0][1]["eventAfterSeq"], "37")
        self.assertEqual(calls[0][1]["hitAfterRevision"], "41")
        self.assertEqual(calls[0][1]["eventOffset"], "17")

    def test_clear_native_trace_requires_exact_trace_id_before_network(self):
        calls = []
        self.mod.safe_post = lambda *args, **kwargs: calls.append((args, kwargs))

        result = self.mod.ClearNativeTrace("")

        self.assertFalse(result["ok"])
        self.assertEqual(result["errorCode"], "INVALID_ARGUMENT")
        self.assertEqual(calls, [])

    def test_run_native_trace_requires_observed_callback_evidence(self):
        replies = [
            {"ok": True, "traceId": "native-1", "active": True, "maxSteps": 20},
            {
                "ok": True,
                "traceId": "native-1",
                "active": False,
                "completed": True,
                "matchedSteps": 3,
                "events": [{"seq": 1, "ip": "0x401000", "threadId": 7}],
                "hits": [{"ip": "0x401000", "hits": 3}],
            },
        ]
        self.mod.GetNativeTrace = lambda *args, **kwargs: replies.pop(0)
        self.mod.TraceIntoConditional = lambda **kwargs: {"ok": True, "args": kwargs}
        self.mod.WaitNativeTrace = lambda *args, **kwargs: {
            "ok": True,
            "active": False,
            "completed": True,
            "timedOut": False,
        }

        result = self.mod.RunNativeTrace("native-1", max_steps=20)

        self.assertTrue(result["ok"])
        self.assertTrue(result["observed"])
        self.assertEqual(result["evidence"]["matchedSteps"], 3)

    def test_trace_record_uses_native_backend_not_memory_breakpoint(self):
        self.mod._build_debug_state = lambda **kwargs: {
            "debugging": True,
            "paused": True,
        }
        self.mod._get_current_debuggee_module_base = lambda: "0x140000000"
        self.mod.GetModuleList = lambda: {
            "modules": [
                {
                    "name": "fixture.exe",
                    "base": "0x140000000",
                    "size": "0x27000",
                }
            ]
        }
        native_calls = []

        def fake_start(**kwargs):
            native_calls.append(kwargs)
            return {"ok": True, "traceId": "native-1", "active": True}

        self.mod.StartNativeTrace = fake_start
        self.mod.ExecCommand = lambda *_args, **_kwargs: self.fail(
            "legacy page-granular memory breakpoint backend must not be used"
        )

        result = self.mod.StartTraceRecord(mode="hitcount", label="fixture")

        self.assertTrue(result["ok"])
        self.assertEqual(result["backend"], "cb_traceexecute_v1")
        self.assertEqual(result["nativeTraceId"], "native-1")
        self.assertEqual(native_calls[0]["range_start"], "")
        self.assertEqual(native_calls[0]["range_size"], 0)
        self.assertIs(native_calls[0]["auto_resume_exceptions"], True)

    def test_basic_block_reconstruction_emits_stable_blocks_and_edges(self):
        events = [
            {
                "seq": 1,
                "ip": "0x1000",
                "rva": "0x0",
                "instructionSize": 5,
                "branch": True,
                "call": False,
                "isReturn": False,
                "branchTarget": "0x2000",
                "threadId": 7,
            },
            {
                "seq": 2,
                "ip": "0x2000",
                "rva": "0x1000",
                "instructionSize": 1,
                "branch": False,
                "call": False,
                "isReturn": False,
                "branchTarget": "0x0",
                "threadId": 7,
            },
        ]

        result = self.mod._reconstruct_basic_block_coverage(
            events,
            module_base=0x1000,
            module_size=0x3000,
            image_identity="sha256:test",
            limit=100,
        )

        self.assertEqual(result["coverageModel"], "basic-block-edge-v1")
        self.assertEqual(result["blockCount"], 2)
        self.assertEqual(result["edgeCount"], 1)
        self.assertEqual(result["coveredInstructions"], 2)
        self.assertEqual(result["edges"][0]["kind"], "taken")
        self.assertEqual(result["edges"][0]["branchTargets"], ["0x2000"])


if __name__ == "__main__":
    unittest.main()
