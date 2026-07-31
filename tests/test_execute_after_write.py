import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "x64dbg_execute_after_write_tests",
        MODULE_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ExecuteAfterWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_changed_ranges_are_exact_and_coalesced(self):
        before = bytes.fromhex("0000000000000000")
        after = bytes.fromhex("6a2a58c30000007f")
        result = self.mod._execute_after_write_changed_ranges(
            before,
            after,
            0x140005000,
        )
        offsets = result.pop("_offsets")

        self.assertEqual(offsets, [0, 1, 2, 3, 7])
        self.assertEqual(result["changedByteCount"], 5)
        self.assertEqual(result["changedRangeCount"], 2)
        self.assertEqual(result["ranges"][0]["address"], "0x140005000")
        self.assertEqual(result["ranges"][0]["size"], 4)
        self.assertEqual(result["ranges"][1]["offset"], 7)

    def test_evidence_writer_is_atomic_hashed_and_overwrite_guarded(self):
        payload = {
            "schema": "execute-after-write-evidence-v1",
            "workflowId": "fixture",
            "ordering": {"strictlyOrdered": True},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            first = self.mod._write_execute_after_write_evidence(
                payload,
                str(path),
            )
            second = self.mod._write_execute_after_write_evidence(
                payload,
                str(path),
            )
            document = json.loads(path.read_text(encoding="utf-8"))

        self.assertTrue(first["ok"], first)
        self.assertEqual(len(first["evidenceSha256"]), 64)
        self.assertEqual(
            document["evidenceSha256"],
            first["evidenceSha256"],
        )
        self.assertFalse(second["ok"])
        self.assertEqual(second["reason"], "output_exists")

    def test_capture_requires_an_authoritative_paused_session(self):
        with mock.patch.object(
            self.mod,
            "_build_debug_state",
            return_value={"debugging": True, "paused": False, "state": "running"},
        ):
            result = self.mod.CaptureExecuteAfterWrite("0x1000", 16)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "paused_debug_session_required")

    def test_capture_proves_ordered_write_then_changed_byte_execution(self):
        base = 0x140005000
        before = b"\0" * 8
        generated = bytes.fromhex("6a2a58c3") + b"\0" * 4
        phases = iter(
            [
                ({"label": "before-write", "sha256": "A"}, before),
                ({"label": "after-write", "sha256": "B"}, generated),
                ({"label": "execute-hit", "sha256": "B"}, generated),
            ]
        )
        write_watch = {
            "ok": True,
            "captureResult": {
                "event": {
                    "eventSeq": 10,
                    "threadId": 2,
                    "rip": "0x140001100",
                }
            },
            "causeInstruction": {"instruction": "rep movsb"},
            "postStep": {"ok": True},
        }
        execute_capture = {
            "ok": True,
            "event": {
                "eventSeq": 12,
                "threadId": 2,
                "rip": hex(base),
            },
        }
        with (
            mock.patch.object(
                self.mod,
                "_build_debug_state",
                return_value={"debugging": True, "paused": True, "state": "paused"},
            ),
            mock.patch.object(
                self.mod,
                "BridgeHello",
                return_value={"ok": True},
            ),
            mock.patch.object(
                self.mod,
                "_resolve_expression_value",
                return_value=base,
            ),
            mock.patch.object(
                self.mod,
                "_detect_debuggee_bitness",
                return_value=64,
            ),
            mock.patch.object(
                self.mod,
                "_breakpoint_lease_identity",
                return_value={
                    "bridgeInstanceId": "bridge",
                    "sessionId": "session",
                    "sessionGeneration": 1,
                    "debuggeePid": 7,
                },
            ),
            mock.patch.object(
                self.mod,
                "_execute_after_write_phase",
                side_effect=lambda *_: next(phases),
            ),
            mock.patch.object(
                self.mod,
                "SetMemoryWatchpointWithCapture",
                return_value=write_watch,
            ),
            mock.patch.object(
                self.mod,
                "SetMemoryRangeBreakpoint",
                return_value={"ok": True},
            ),
            mock.patch.object(
                self.mod,
                "DebugRun",
                return_value={"ok": True},
            ),
            mock.patch.object(
                self.mod,
                "WaitForBreakpointCapture",
                return_value=execute_capture,
            ),
            mock.patch.object(
                self.mod,
                "DeleteMemoryBreakpoint",
                return_value={"ok": True},
            ),
            mock.patch.object(
                self.mod,
                "GetCallStack",
                return_value={"total": 1, "entries": []},
            ),
            mock.patch.object(
                self.mod,
                "_execute_after_write_address_identity",
                side_effect=lambda address: {
                    "address": str(address),
                    "module": "fixture.exe",
                    "rva": "0x5000",
                },
            ),
            mock.patch.object(
                self.mod,
                "_current_instruction",
                return_value={"instruction": "push 0x2a"},
            ),
            mock.patch.object(self.mod, "_log_event"),
        ):
            result = self.mod.CaptureExecuteAfterWrite(
                hex(base),
                8,
                capture_callstacks=True,
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["reason"], "captured")
        self.assertEqual(result["snapshotCount"], 3)
        self.assertEqual(result["finalDiff"]["changedByteCount"], 4)
        self.assertEqual(result["execute"]["offset"], 0)
        self.assertTrue(result["execute"]["pointsAtChangedByte"])
        self.assertTrue(result["ordering"]["strictlyOrdered"])


if __name__ == "__main__":
    unittest.main()
