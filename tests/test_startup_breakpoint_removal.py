import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_bridge", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class StartupBreakpointRemovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def setUp(self):
        self.deleted = []
        self.original_collect = self.mod._collect_breakpoint_snapshot
        self.original_delete = self.mod.DebugDeleteBreakpoint
        self.original_log = self.mod._log_event
        self.mod._log_event = lambda *args, **kwargs: None

    def tearDown(self):
        self.mod._collect_breakpoint_snapshot = self.original_collect
        self.mod.DebugDeleteBreakpoint = self.original_delete
        self.mod._log_event = self.original_log

    def _install_snapshot(self, breakpoints):
        self.mod._collect_breakpoint_snapshot = (
            lambda log=False, bp_type="all": {
                "count": len(breakpoints),
                "breakpoints": list(breakpoints),
            }
        )

        def _delete(addr):
            self.deleted.append(addr)
            return f"deleted {addr}"

        self.mod.DebugDeleteBreakpoint = _delete

    def test_default_preserves_debuggee_entrypoint_breakpoint(self):
        self._install_snapshot(
            [
                {
                    "addr": "0x401000",
                    "module": "sample.exe",
                    "name": "entry point",
                    "singleshoot": True,
                    "enabled": True,
                    "active": True,
                    "hitCount": 0,
                }
            ]
        )

        removed = self.mod._remove_safe_startup_breakpoints(
            "sample.exe", current_addr="0x401000"
        )

        self.assertEqual(removed, [])
        self.assertEqual(self.deleted, [])

    def test_auto_run_removes_current_debuggee_entrypoint_breakpoint(self):
        self._install_snapshot(
            [
                {
                    "addr": "0x401000",
                    "module": "sample.exe",
                    "name": "",
                    "singleshoot": True,
                    "enabled": True,
                    "active": True,
                    "hitCount": 0,
                }
            ]
        )

        removed = self.mod._remove_safe_startup_breakpoints(
            "sample.exe",
            allow_debuggee_entrypoint=True,
            current_addr="0x401000",
        )

        self.assertEqual(removed, ["0x401000"])
        self.assertEqual(self.deleted, ["0x401000"])

    def test_auto_run_does_not_remove_non_current_debuggee_breakpoint(self):
        self._install_snapshot(
            [
                {
                    "addr": "0x401000",
                    "module": "sample.exe",
                    "name": "",
                    "singleshoot": True,
                    "enabled": True,
                    "active": True,
                    "hitCount": 0,
                }
            ]
        )

        removed = self.mod._remove_safe_startup_breakpoints(
            "sample.exe",
            allow_debuggee_entrypoint=True,
            current_addr="0x401010",
        )

        self.assertEqual(removed, [])
        self.assertEqual(self.deleted, [])

    def test_existing_foreign_singleshot_cleanup_is_preserved(self):
        self._install_snapshot(
            [
                {
                    "addr": "0x70000000",
                    "module": "ntdll.dll",
                    "name": "",
                    "singleshoot": True,
                    "enabled": True,
                    "active": True,
                    "hitCount": 0,
                }
            ]
        )

        removed = self.mod._remove_safe_startup_breakpoints("sample.exe")

        self.assertEqual(removed, ["0x70000000"])
        self.assertEqual(self.deleted, ["0x70000000"])


if __name__ == "__main__":
    unittest.main()
