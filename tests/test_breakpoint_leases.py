import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "x64dbg.py"


def _load_module():
    name = "x64dbg_breakpoint_lease_tests"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, SRC)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class BreakpointLeaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def setUp(self):
        self.mod._remember_runtime(
            breakpointLeases={},
            bridgeIdentity={
                "bridgeInstanceId": "bridge-test",
                "sessionId": "session-test",
                "sessionGeneration": 7,
                "debuggeePid": 4242,
                "imageSha256": "A" * 64,
                "session": {
                    "sessionId": "session-test",
                    "generation": 7,
                    "processId": 4242,
                    "imageSha256": "A" * 64,
                },
            },
        )

    def test_reference_count_and_compare_delete(self):
        current = {"value": None}

        def snapshot(*args, **kwargs):
            return {
                "count": 1 if current["value"] else 0,
                "breakpoints": [dict(current["value"])] if current["value"] else [],
            }

        def set_bp(*args, **kwargs):
            current["value"] = {
                "addr": "0x401000",
                "type": "normal",
                "enabled": True,
                "active": True,
            }
            return "Breakpoint set successfully"

        def delete_bp(*args, **kwargs):
            current["value"] = None
            return "Breakpoint deleted successfully"

        with mock.patch.object(self.mod, "_collect_breakpoint_snapshot", side_effect=snapshot), \
             mock.patch.object(self.mod, "DebugSetBreakpoint", side_effect=set_bp), \
             mock.patch.object(self.mod, "DebugDeleteBreakpoint", side_effect=delete_bp):
            first = self.mod.AcquireBreakpointLease(
                "0x401000", workflow_id="wf", lease_ms=30000
            )
            second = self.mod.AcquireBreakpointLease(
                "0x401000", workflow_id="wf", lease_ms=30000
            )
            self.assertTrue(first["ok"])
            self.assertEqual(second["referenceCount"], 2)
            middle = self.mod.ReleaseBreakpointLease(first["leaseId"])
            self.assertTrue(middle["ok"])
            self.assertFalse(middle["deleted"])
            self.assertIsNotNone(current["value"])
            final = self.mod.ReleaseBreakpointLease(second["leaseId"])
            self.assertTrue(final["ok"])
            self.assertTrue(final["deleted"])
            self.assertIsNone(current["value"])

    def test_preexisting_breakpoint_is_preserved(self):
        current = {
            "addr": "0x402000",
            "type": "normal",
            "enabled": True,
            "active": True,
        }

        with mock.patch.object(
            self.mod,
            "_collect_breakpoint_snapshot",
            return_value={"count": 1, "breakpoints": [current]},
        ), mock.patch.object(self.mod, "DebugDeleteBreakpoint") as delete:
            lease = self.mod.AcquireBreakpointLease("0x402000", workflow_id="wf")
            self.assertTrue(lease["ok"])
            self.assertTrue(lease["preexisting"])
            released = self.mod.ReleaseBreakpointLease(lease["leaseId"])
            self.assertTrue(released["ok"])
            self.assertFalse(released["deleted"])
            delete.assert_not_called()

    def test_compare_mismatch_preserves_user_modified_breakpoint(self):
        current = {
            "addr": "0x403000",
            "type": "normal",
            "enabled": True,
            "active": True,
        }
        state = {"current": None}
        acquired = dict(current, name="workflow-owned")

        def snapshot(*args, **kwargs):
            value = state["current"]
            return {"count": 1 if value else 0, "breakpoints": [dict(value)] if value else []}

        with mock.patch.object(self.mod, "_collect_breakpoint_snapshot", side_effect=snapshot), \
             mock.patch.object(
                 self.mod,
                 "_managed_breakpoint_set",
                 side_effect=lambda *args, **kwargs: (
                     state.update(current=dict(acquired)) or {"ok": True}
                 ),
             ), \
             mock.patch.object(self.mod, "DebugDeleteBreakpoint") as delete:
            lease = self.mod.AcquireBreakpointLease("0x403000", workflow_id="wf")
            self.assertTrue(lease["ok"])
            state["current"]["name"] = "user-owned-after-acquire"
            released = self.mod.ReleaseBreakpointLease(lease["leaseId"])
            self.assertTrue(released["ok"])
            self.assertFalse(released["deleted"])
            self.assertEqual(released["cleanup"]["status"], "preserved_compare_mismatch")
            delete.assert_not_called()

    def test_session_turnover_drops_lease_without_deleting_new_session(self):
        current = {
            "addr": "0x404000",
            "type": "normal",
            "enabled": True,
            "active": True,
        }
        with mock.patch.object(
            self.mod,
            "_collect_breakpoint_snapshot",
            return_value={"count": 0, "breakpoints": []},
        ), mock.patch.object(
            self.mod,
            "_managed_breakpoint_set",
            return_value={"ok": True},
        ):
            # The post-set verification is supplied by a second snapshot in a
            # real bridge; this unit only validates identity cleanup semantics.
            with mock.patch.object(
                self.mod,
                "_managed_breakpoint_snapshot_record",
                side_effect=[None, current],
            ):
                lease = self.mod.AcquireBreakpointLease("0x404000", workflow_id="wf")
            self.assertTrue(lease["ok"])
            self.mod._remember_runtime(
                bridgeIdentity={
                    "bridgeInstanceId": "bridge-new",
                    "sessionId": "session-new",
                    "sessionGeneration": 8,
                    "debuggeePid": 5252,
                    "imageSha256": "B" * 64,
                }
            )
            with mock.patch.object(self.mod, "DebugDeleteBreakpoint") as delete:
                listed = self.mod.ListBreakpointLeases()
                self.assertEqual(listed["count"], 0)
                delete.assert_not_called()

    def test_hardware_script_success_shape_is_normalized(self):
        with mock.patch.object(
            self.mod,
            "SetHardwareBreakpoint",
            return_value={"success": True, "address": "0x405000"},
        ):
            result = self.mod._managed_breakpoint_set(
                "0x405000", "hardware"
            )
        self.assertTrue(result["ok"])
        self.assertTrue(result["success"])


if __name__ == "__main__":
    unittest.main()
