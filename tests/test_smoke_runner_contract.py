import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_tool(name: str):
    path = TOOLS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"test_{name}", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SmokeRunnerExitContractTests(unittest.TestCase):
    def test_headless_runner_returns_nonzero_for_failed_scenario(self):
        mod = _load_tool("headless_smoke")
        mod.load_bridge = lambda _: object()
        mod.SCENARIOS = {"fixture": lambda *_: {"ok": False, "error": "expected"}}
        mod._default_exe_for_scenario = lambda *_: r"C:\fixture.exe"
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "headless.json"
            argv = [
                "headless_smoke.py",
                "--scenario",
                "fixture",
                "--exe",
                r"C:\fixture.exe",
                "--out",
                str(out),
            ]
            with mock.patch.object(sys, "argv", argv):
                rc = mod.main()
            payload = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(rc, 1)
        self.assertFalse(payload["result"]["ok"])

    def test_heap_smoke_requires_an_observed_heap_event(self):
        mod = _load_tool("headless_smoke")

        class Bridge:
            @staticmethod
            def _get_active_debugger_info():
                return {"arch": "x64"}

            @staticmethod
            def AnalyzeExecutablePacking(_):
                return {"arch": "x64"}

            @staticmethod
            def InitDebuggee(*_, **__):
                return {"ok": True}

            @staticmethod
            def RunUntil(**_):
                return {"ok": True}

            @staticmethod
            def StartHeapTrace(**_):
                return {"ok": True, "apiTraceId": "api-1", "heapTraceId": "heap-1"}

            @staticmethod
            def RunApiTrace(*_, **__):
                return {"ok": True}

            @staticmethod
            def GetHeapState(_):
                return {"ok": True, "allocCount": 0, "freeCount": 0}

            @staticmethod
            def StopApiTrace(*_, **__):
                return {"ok": True}

        result = mod.scenario_heap_trace_live(Bridge(), r"C:\fixture.exe")
        self.assertFalse(result["ok"])

    def test_run_smoke_suite_returns_nonzero_and_writes_failure(self):
        mod = _load_tool("run_smoke_suite")
        with tempfile.TemporaryDirectory() as temp_dir:
            mod.load_bridge = lambda _: object()
            mod._default_exe_for_scenario = lambda *_: r"C:\fixture.exe"
            mod.SCENARIOS = {"broken": lambda *_: {"ok": False, "error": "expected"}}
            argv = ["run_smoke_suite.py", "--out-dir", temp_dir, "--scenarios", "broken"]
            with mock.patch.object(sys, "argv", argv):
                rc = mod.main()

            self.assertEqual(rc, 1)
            summary = json.loads((Path(temp_dir) / "summary.json").read_text(encoding="utf-8"))
            self.assertFalse(summary["ok"])
            self.assertFalse(summary["results"][0]["ok"])

    def test_run_smoke_suite_converts_exception_to_reported_failure(self):
        mod = _load_tool("run_smoke_suite")

        def fail(*_):
            raise RuntimeError("fixture exploded")

        with tempfile.TemporaryDirectory() as temp_dir:
            mod.load_bridge = lambda _: object()
            mod._default_exe_for_scenario = lambda *_: r"C:\fixture.exe"
            mod.SCENARIOS = {"broken": fail}
            argv = ["run_smoke_suite.py", "--out-dir", temp_dir, "--scenarios", "broken"]
            with mock.patch.object(sys, "argv", argv):
                rc = mod.main()

            self.assertEqual(rc, 1)
            detail = json.loads((Path(temp_dir) / "broken.json").read_text(encoding="utf-8"))
            self.assertEqual(detail["result"]["exceptionType"], "RuntimeError")
            self.assertIn("fixture exploded", detail["result"]["traceback"])

    def test_extended_runner_exit_code_matches_aggregate(self):
        mod = _load_tool("run_local_extended_smoke")

        class Bridge:
            @staticmethod
            def _detect_pe_arch(_):
                return "x64"

            @staticmethod
            def RestartDebugger(**_):
                return {"ok": True}

        mod.load_bridge = lambda _: Bridge()
        mod._build_cases = lambda _: [
            {"name": "fixture", "scenario": "fixture", "exe": r"C:\fixture.exe"}
        ]
        mod.SCENARIOS = {"fixture": lambda *_: {"ok": False, "error": "expected"}}
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "extended.json"
            argv = ["run_local_extended_smoke.py", "--out", str(out)]
            with mock.patch.object(sys, "argv", argv):
                rc = mod.main()
            payload = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(rc, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["okCount"], 0)

    def test_empty_crackme_corpus_is_not_success(self):
        mod = _load_tool("smoke_crackmes")
        mod._load_bridge = lambda: object()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "empty"
            root.mkdir()
            report = Path(temp_dir) / "report.json"
            rc = mod.run_smoke(root, report, include_derived=False)
            payload = json.loads(report.read_text(encoding="utf-8"))

        self.assertEqual(rc, 1)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["count"], 0)


if __name__ == "__main__":
    unittest.main()
