import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_bridge():
    spec = importlib.util.spec_from_file_location("x64dbg_child_broker", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ChildBrokerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_bridge()

    def _descriptor(self, pid=1001, arch="x64", bridge="bridge-a"):
        return {
            "token": "a" * 64,
            "pid": pid,
            "processStartTime100ns": 123456,
            "bridgeInstanceId": bridge,
            "port": 9000 + pid % 100,
            "arch": arch,
            "path": f"C:/tmp/bridge-{pid}.token",
            "mtimeNs": 1,
            "size": 256,
        }

    def _hello(self, descriptor, *, root="launch-a", broker="broker-a", debuggee=4242):
        return {
            "ok": True,
            "protocolVersion": 3,
            "bridgeInstanceId": descriptor["bridgeInstanceId"],
            "debugger": {
                "pid": descriptor["pid"],
                "processStartTime100ns": descriptor["processStartTime100ns"],
                "architecture": descriptor["arch"],
            },
            "http": {"boundPort": descriptor["port"], "state": "listening"},
            "childBroker": {
                "configured": True,
                "rootLaunchId": root,
                "brokerId": broker,
                "rootPid": 7000,
                "parentPid": 0,
            },
            "session": {
                "sessionId": f"session-{descriptor['pid']}",
                "generation": 1,
                "processId": debuggee,
                "paused": True,
            },
        }

    def test_extended_windows_prefixes_are_same_identity(self):
        normalize = self.mod._normalize_path_identity
        self.assertEqual(
            normalize(r"\\?\C:\Fixtures\Target.exe"),
            normalize(r"C:\fixtures\TARGET.EXE"),
        )
        self.assertEqual(
            normalize(r"\??\C:\Fixtures\Target.exe"),
            normalize(r"C:\fixtures\target.exe"),
        )
        self.assertEqual(
            normalize(r"\\?\UNC\server\Share\Target.exe"),
            normalize(r"\\server\share\target.exe"),
        )

    def test_descriptor_hello_rejects_pid_port_arch_and_id_turnover(self):
        descriptor = self._descriptor()
        hello = self._hello(descriptor)
        ok, mismatches = self.mod._validate_descriptor_hello(descriptor, hello)
        self.assertTrue(ok)
        self.assertEqual(mismatches, [])
        changed = dict(hello)
        changed["debugger"] = dict(hello["debugger"])
        changed["debugger"]["pid"] += 1
        changed["http"] = dict(hello["http"])
        changed["http"]["boundPort"] += 1
        changed["bridgeInstanceId"] = "bridge-other"
        changed["debugger"]["architecture"] = "x86"
        ok, mismatches = self.mod._validate_descriptor_hello(descriptor, changed)
        self.assertFalse(ok)
        self.assertEqual(
            set(mismatches), {"pid", "bridgeInstanceId", "port", "arch"}
        )

    def test_inventory_filters_tree_and_never_returns_tokens(self):
        first = self._descriptor(1001, "x64", "bridge-a")
        second = self._descriptor(1002, "x86", "bridge-b")
        stale = self._descriptor(1003, "x64", "bridge-stale")
        descriptors = {1001: first, 1002: second, 1003: stale}

        def fake_request(descriptor, endpoint, **_kwargs):
            if descriptor["pid"] == 1003:
                return {"ok": False, "errorCode": "bridge_instance_unreachable"}
            hello = self._hello(
                descriptor,
                root="launch-a" if descriptor["pid"] == 1001 else "launch-b",
                broker="broker-a" if descriptor["pid"] == 1001 else "broker-b",
                debuggee=4242 + descriptor["pid"],
            )
            if endpoint.startswith("Bridge/Hello"):
                return {"ok": True, "data": hello}
            return {"ok": True, "data": {"ok": True, "processId": hello["session"]["processId"]}}

        with mock.patch.dict(os.environ, {"LOCALAPPDATA": r"C:\Users\test\AppData\Local"}), \
            mock.patch.object(
                self.mod,
                "_list_processes",
                return_value=[
                    {"pid": 1001, "exe": "x64dbg.exe"},
                    {"pid": 1002, "exe": "x32dbg.exe"},
                    {"pid": 1003, "exe": "x64dbg.exe"},
                    {"pid": 9999, "exe": "notepad.exe"},
                ],
            ), \
            mock.patch.object(
                self.mod,
                "_parse_bridge_auth_file",
                side_effect=lambda path: descriptors.get(
                    int(path.stem.split("-")[-1]), {}
                ),
            ), \
            mock.patch.object(self.mod, "_request_bridge_descriptor", side_effect=fake_request):
            result = self.mod._enumerate_bridge_instances(
                root_launch_id="launch-a", broker_id="broker-a", include_state=True
            )

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["sessions"][0]["debugger"]["pid"], 1001)
        self.assertEqual(result["errors"][0]["debuggerPid"], 1003)
        self.assertNotIn("token", repr(result))
        self.assertNotIn("a" * 64, repr(result))

    def test_select_rejects_ambiguous_selector_before_global_switch(self):
        inventory = {
            "ok": True,
            "sessions": [
                {
                    "sessionRef": "ref-a",
                    "bridgeInstanceId": "bridge-a",
                    "debugger": {"pid": 1001},
                    "session": {"processId": 4242},
                },
                {
                    "sessionRef": "ref-b",
                    "bridgeInstanceId": "bridge-b",
                    "debugger": {"pid": 1002},
                    "session": {"processId": 4242},
                },
            ],
        }
        with mock.patch.object(self.mod, "_enumerate_bridge_instances", return_value=inventory), \
            mock.patch.object(self.mod, "_clear_bound_session") as clear:
            result = self.mod.SelectDebugSession(debuggee_pid=4242)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "session_selector_not_unique")
        clear.assert_not_called()

    def test_select_revalidates_identity_before_switch(self):
        descriptor = self._descriptor()
        inventory = {
            "ok": True,
            "sessions": [
                {
                    "sessionRef": "bridge-a:1001:123456",
                    "bridgeInstanceId": "bridge-a",
                    "debugger": {"pid": 1001},
                    "session": {"processId": 4242},
                }
            ],
        }
        mismatched = self._hello(descriptor)
        mismatched["bridgeInstanceId"] = "bridge-reused"
        with mock.patch.object(self.mod, "_enumerate_bridge_instances", return_value=inventory), \
            mock.patch.object(self.mod, "_parse_bridge_auth_file", return_value=descriptor), \
            mock.patch.object(
                self.mod,
                "_request_bridge_descriptor",
                return_value={"ok": True, "data": mismatched},
            ), \
            mock.patch.object(self.mod, "_clear_bound_session") as clear:
            result = self.mod.SelectDebugSession(session_ref=inventory["sessions"][0]["sessionRef"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "session_identity_changed")
        clear.assert_not_called()

    def test_select_success_updates_auth_cache_only_after_identity_check(self):
        descriptor = self._descriptor()
        hello = self._hello(descriptor)
        session_ref = "bridge-a:1001:123456"
        inventory = {
            "ok": True,
            "sessions": [
                {
                    "sessionRef": session_ref,
                    "bridgeInstanceId": "bridge-a",
                    "debugger": {"pid": 1001},
                    "session": {"processId": 4242},
                }
            ],
        }
        with mock.patch.object(self.mod, "_enumerate_bridge_instances", return_value=inventory), \
            mock.patch.object(self.mod, "_parse_bridge_auth_file", return_value=descriptor), \
            mock.patch.object(
                self.mod, "_request_bridge_descriptor", return_value={"ok": True, "data": hello}
            ), \
            mock.patch.object(self.mod, "_cache_bridge_identity", return_value={"bridgeInstanceId": "bridge-a", "debuggerPid": 1001}), \
            mock.patch.object(self.mod, "_clear_bound_session"), \
            mock.patch.object(self.mod, "_bind_debuggee_session", return_value={"ok": True}), \
            mock.patch.object(self.mod, "_remember_runtime"):
            result = self.mod.SelectDebugSession(session_ref=session_ref)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["sessionRef"], session_ref)
        self.assertTrue(self.mod.x64dbg_server_url.endswith(f":{descriptor['port']}/"))
        with self.mod._BRIDGE_AUTH_LOCK:
            self.assertEqual(self.mod._BRIDGE_AUTH_CACHE["bridgeInstanceId"], "bridge-a")
            self.assertNotIn("token", result)


if __name__ == "__main__":
    unittest.main()
