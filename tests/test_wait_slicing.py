import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_wait_slicing", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class BreakpointWaitSlicingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def setUp(self):
        self.originals = {
            name: getattr(self.mod, name)
            for name in (
                "WaitForBreakpointDetailed",
                "CaptureContext",
                "_record_breakpoint_capture",
                "DebugSetBreakpoint",
                "DebugRun",
                "_get_current_debuggee_image_name",
            )
        }

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(self.mod, name, value)

    def _install_sliced_wait(self):
        events = [
            {"timedOut": True, "hit": False, "matchedRequested": False},
            {"timedOut": True, "hit": False, "matchedRequested": False},
            {
                "timedOut": False,
                "hit": True,
                "matchedRequested": True,
                "rip": "0x401000",
                "addr": "0x401000",
                "eventSeq": 7,
            },
        ]
        calls = []

        def wait(**kwargs):
            calls.append(dict(kwargs))
            return events.pop(0)

        self.mod.WaitForBreakpointDetailed = wait
        self.mod.CaptureContext = lambda **_: {"ok": True}
        self.mod._record_breakpoint_capture = lambda *_, **__: {"ok": True}
        return calls

    def test_capture_wait_continues_after_native_slice_timeouts(self):
        calls = self._install_sliced_wait()
        result = self.mod.WaitForBreakpointCapture(
            addr="0x401000", timeout_ms=5000
        )
        self.assertTrue(result["ok"])
        self.assertEqual(len(calls), 3)

    def test_set_and_capture_continues_after_native_slice_timeouts(self):
        calls = self._install_sliced_wait()
        self.mod.DebugSetBreakpoint = lambda _: "set"
        self.mod.DebugRun = lambda: {"ok": True}
        result = self.mod.SetBreakpointWithCapture(
            "0x401000", timeout_ms=5000, resume=True
        )
        self.assertTrue(result["ok"])
        self.assertEqual(len(calls), 3)

    def test_delayed_x86_pause_after_skipped_loader_breakpoint_is_resumed_once(self):
        events = [
            {
                "timedOut": False,
                "hit": False,
                "observedBreakpoint": True,
                "matchedRequested": False,
                "eventSeq": 21,
                "addr": "0x76001000",
                "stopReason": "breakpoint",
                "breakpointName": "TLS Callback 2 (gdi32full.dll)",
                "breakpointModule": "gdi32full.dll",
            },
            {
                "timedOut": True,
                "hit": False,
                "observedBreakpoint": False,
                "matchedRequested": False,
                "eventSeq": 23,
                "lastEventType": "pause_debug",
                "stopReason": "pause",
                "breakpointName": "TLS Callback 2 (gdi32full.dll)",
                "breakpointModule": "gdi32full.dll",
                "state": {"paused": True},
            },
            {
                "timedOut": False,
                "hit": True,
                "matchedRequested": True,
                "eventSeq": 24,
                "rip": "0x401000",
                "addr": "0x401000",
            },
        ]
        run_calls = []
        self.mod.WaitForBreakpointDetailed = lambda **_: events.pop(0)
        self.mod.DebugRun = lambda: run_calls.append(True) or {"ok": True}
        self.mod.CaptureContext = lambda **_: {"ok": True}
        self.mod._record_breakpoint_capture = lambda *_, **__: {"ok": True}
        self.mod._get_current_debuggee_image_name = lambda: "fixture.exe"

        result = self.mod.WaitForBreakpointCapture(
            addr="0x401000", timeout_ms=5000
        )

        self.assertTrue(result["ok"])
        self.assertEqual(len(run_calls), 2)
        self.assertEqual(len(result["skippedBreakpoints"]), 1)
        self.assertEqual(len(result["resumeRepairs"]), 1)


if __name__ == "__main__":
    unittest.main()
