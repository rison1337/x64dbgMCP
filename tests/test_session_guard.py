import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_bridge():
    spec = importlib.util.spec_from_file_location("x64dbg_session_guard", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SessionOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_bridge()

    def setUp(self):
        self.binding = {
            "pid": 4242,
            "imagePath": r"C:\fixtures\target.exe",
            "imageName": "target.exe",
            "moduleBase": "0x140000000",
            "bridgeInstanceId": "bridge-a",
            "sessionId": "session-a",
            "sessionGeneration": 7,
            "eventSeq": 19,
            "strict": True,
        }
        self.identity = {
            "bridgeInstanceId": "bridge-a",
            "sessionId": "session-a",
            "sessionGeneration": 7,
            "debuggeePid": 4242,
            "eventSeq": 20,
            "session": {"sessionId": "session-a", "generation": 7},
        }
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"] = dict(self.identity)
            self.mod._RUNTIME_STATE["boundSession"] = dict(self.binding)

    def _state(self, **updates):
        state = {
            "debuggeePid": 4242,
            "debuggeePath": r"C:\fixtures\target.exe",
            "debuggeeImage": "target.exe",
            "session": {"sessionId": "session-a", "generation": 7},
        }
        state.update(updates)
        return state

    def _describe(self, binding=None, state=None):
        with mock.patch.object(self.mod, "_process_exists", return_value=True), mock.patch.object(
            self.mod,
            "_current_main_module_identity",
            return_value={
                "name": "target.exe",
                "path": r"C:\fixtures\target.exe",
                "base": "0x140000000",
            },
        ):
            return self.mod._describe_bound_session_match(
                binding or self.binding, state or self._state()
            )

    def test_exact_bridge_generation_pid_and_image_match(self):
        result = self._describe()
        self.assertTrue(result["matches"])
        self.assertEqual(result["reason"], "match")

    def test_bridge_restart_same_pid_fails_closed(self):
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"] = {
                **self.identity,
                "bridgeInstanceId": "bridge-b",
            }
        result = self._describe()
        self.assertFalse(result["matches"])
        self.assertIn("bridge_id_mismatch", result["reason"])

    def test_generation_change_fails_closed(self):
        result = self._describe(
            state=self._state(
                session={"sessionId": "session-b", "generation": 8}
            )
        )
        self.assertFalse(result["matches"])
        self.assertIn("session_generation_mismatch", result["reason"])

    def test_missing_current_pid_is_not_a_wildcard(self):
        result = self._describe(
            state=self._state(debuggeePid=0, debuggeePath="", debuggeeImage="")
        )
        self.assertFalse(result["matches"])
        self.assertIn("pid_mismatch", result["reason"])

    def test_pid_reuse_with_different_image_is_rejected(self):
        result = self._describe(
            state=self._state(
                debuggeePath=r"C:\fixtures\other.exe",
                debuggeeImage="other.exe",
            )
        )
        self.assertFalse(result["matches"])
        self.assertIn("image_mismatch", result["reason"])

    def test_snapshot_owner_mismatch_blocks_restore_without_mutation(self):
        snapshot = {
            "snapshotId": "state-1",
            "owner": {**self.identity, "processId": 4242, "threadId": 11},
            "registers": {"rax": "0x1"},
            "ranges": [{"addr": "0x1000", "hex": "00", "label": "byte"}],
        }
        writes = []
        registers = []
        with mock.patch.object(self.mod, "_get_state_snapshot", return_value=snapshot), mock.patch.object(
            self.mod,
            "_snapshot_owner_match",
            return_value={"matches": False, "mismatches": ["sessionGeneration"]},
        ), mock.patch.object(
            self.mod, "MemoryWrite", side_effect=lambda *args: writes.append(args)
        ), mock.patch.object(
            self.mod, "RegisterSet", side_effect=lambda *args: registers.append(args)
        ):
            result = self.mod.RestoreState("state-1")

        self.assertFalse(result["ok"])
        self.assertEqual(result["errorCode"], "SNAPSHOT_OWNER_MISMATCH")
        self.assertEqual(writes, [])
        self.assertEqual(registers, [])

    def test_snapshot_ids_do_not_repeat_after_sequence_reset(self):
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["memorySnapshotSeq"] = 0
        first = self.mod._next_memory_snapshot_id()
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["memorySnapshotSeq"] = 0
        second = self.mod._next_memory_snapshot_id()
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("memsnap-7-1-"))

    def test_launch_spec_preserves_unicode_args_cwd_and_environment(self):
        with tempfile.TemporaryDirectory(prefix="launch_тест_") as temp_dir:
            result = self.mod._build_launch_spec(
                sys.executable,
                arguments=["", "Привет-世界-🙂", 'quote"tail', "slash\\"],
                working_directory=temp_dir,
                environment={"X64DBG_MCP_TEST": "значение-世界"},
                inherit_environment=True,
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["arguments"][1], "Привет-世界-🙂")
        self.assertIn("Привет-世界-🙂", result["commandLine"])
        self.assertEqual(result["environment"]["X64DBG_MCP_TEST"], "значение-世界")

    def test_launch_spec_rejects_relative_missing_and_case_duplicate_env(self):
        relative = self.mod._build_launch_spec("relative.exe")
        self.assertFalse(relative["ok"])
        self.assertIn("absolute", relative["error"])

        duplicate = self.mod._build_launch_spec(
            sys.executable,
            environment={"Path": "a", "PATH": "b"},
        )
        self.assertFalse(duplicate["ok"])
        self.assertIn("Duplicate case-insensitive", duplicate["error"])

    def test_bridge_launch_uses_post_and_does_not_log_environment_values(self):
        calls = []

        def fake_request(method, endpoint, **kwargs):
            calls.append((method, endpoint, kwargs))
            return self.mod.BridgeEnvelope(True, data={"ok": True}, meta={})

        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["bridgeIdentity"] = {
                **self.identity,
                "capabilities": {
                    "launch": {"args": True, "cwd": True, "environment": True}
                },
            }
        with mock.patch.object(self.mod, "_bridge_request", side_effect=fake_request):
            result = self.mod._launch_via_bridge(
                {
                    "exePath": sys.executable,
                    "arguments": ["hello"],
                    "commandLine": "hello",
                    "rawCommandLine": "",
                    "workingDirectory": os.getcwd(),
                    "environment": {"SECRET_ENV": "not-for-logs"},
                    "inheritEnvironment": True,
                },
                timeout_sec=2,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(calls[0][0:2], ("POST", "Debug/Launch"))
        form = calls[0][2]["form_data"]
        self.assertIn("not-for-logs", form["environment"])
        self.assertEqual(calls[0][2]["guard"], "bridge")

    def test_continue_exception_maps_swallow_to_handled_with_event_guard(self):
        calls = []
        with self.mod._RUNTIME_LOCK:
            self.mod._RUNTIME_STATE["lastResumeSeq"] = 0

        def fake_request(method, endpoint, **kwargs):
            calls.append((method, endpoint, kwargs))
            return self.mod.BridgeEnvelope(
                True, data={"ok": True, "windowsStatus": "DBG_CONTINUE"}, meta={}
            )

        with mock.patch.object(
            self.mod,
            "_get_debug_session_state",
            return_value={
                "paused": True,
                "exceptionCode": "0xE0424242",
                "eventSeq": 31,
            },
        ), mock.patch.object(self.mod, "_bridge_request", side_effect=fake_request):
            result = self.mod.ContinueException("swallow", expected_event_seq=31)

        self.assertTrue(result["ok"])
        self.assertEqual(calls[0][1], "Debug/ContinueException")
        self.assertEqual(calls[0][2]["params"]["disposition"], "handled")
        self.assertEqual(calls[0][2]["expected_event_seq"], 31)
        self.assertEqual(self.mod._get_runtime_value("lastResumeSeq"), 31)

    def test_wait_for_exit_uses_bounded_slices_until_overall_completion(self):
        calls = []
        payloads = [
            {"timedOut": True, "state": {"eventSeq": 20}},
            {"timedOut": True, "state": {"eventSeq": 20}},
            {"timedOut": False, "state": {"eventSeq": 24, "exited": True}},
        ]
        states = [
            {"state": "running", "debuggeePid": 4242},
            {"state": "running", "debuggeePid": 4242},
            {"state": "exited", "debuggeePid": None, "exited": True},
        ]

        def fake_get(endpoint, params=None, **_):
            calls.append((endpoint, dict(params or {})))
            return payloads.pop(0)

        with mock.patch.object(self.mod, "safe_get", side_effect=fake_get), mock.patch.object(
            self.mod, "_build_debug_state", side_effect=states
        ), mock.patch.object(self.mod, "_process_exists", return_value=True):
            result = self.mod.WaitForExit(timeout_ms=2000, poll_ms=1)

        self.assertTrue(result["exited"])
        self.assertFalse(result["timedOut"])
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(call[1]["timeoutMs"] <= 700 for call in calls))

    def test_wait_for_breakpoint_continues_after_slice_timeout(self):
        payloads = [
            {"timedOut": True, "state": {"eventSeq": 20}},
            {
                "timedOut": False,
                "hit": True,
                "state": {"eventSeq": 21, "stopReason": "breakpoint"},
            },
        ]
        states = [
            {"state": "running", "paused": False},
            {"state": "paused", "paused": True, "stopReason": "breakpoint"},
        ]
        calls = []

        def fake_get(endpoint, params=None, **_):
            calls.append(dict(params or {}))
            return payloads.pop(0)

        with mock.patch.object(self.mod, "safe_get", side_effect=fake_get), mock.patch.object(
            self.mod, "_build_debug_state", side_effect=states
        ):
            result = self.mod.WaitForBreakpoint(timeout_ms=2000, poll_ms=1)

        self.assertFalse(result["timedOut"])
        self.assertEqual(result["state"], "paused")
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(call["timeoutMs"] <= 700 for call in calls))

    def test_debug_run_blocking_composes_nonblocking_run_and_wait(self):
        with mock.patch.object(
            self.mod, "DebugRun", return_value={"ok": True, "submitted": True}
        ) as run, mock.patch.object(
            self.mod,
            "WaitForPause",
            return_value={"state": "paused", "paused": True, "timedOut": False},
        ) as wait:
            result = self.mod.DebugRunBlocking(
                exception_mode="pass", timeout_ms=4321, poll_ms=17
            )

        self.assertTrue(result["ok"])
        run.assert_called_once_with(exception_mode="pass")
        wait.assert_called_once_with(timeout_ms=4321, poll_ms=17)


if __name__ == "__main__":
    unittest.main()
