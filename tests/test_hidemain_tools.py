import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS_PATH = ROOT / "src" / "hidemain_tools.py"
SERVER_PATH = ROOT / "src" / "x64dbg.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeMcp:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def decorate(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorate


class HideMainToolsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load(TOOLS_PATH, "hidemain_tools_test")

    def setUp(self):
        self.runtime = {"lastHideMain": None}
        self.mcp = FakeMcp()

        def remember(**values):
            self.runtime.update(values)

        self.g = {
            "__name__": "x64dbg_test",
            "_remember_runtime": remember,
            "_get_runtime_value": lambda name: self.runtime.get(name),
            "_log_event": lambda *args, **kwargs: None,
            "_infer_debuggee_pid": lambda: 4242,
            "_process_exists": lambda pid: int(pid) == 4242,
            "_get_process_image_path": lambda pid: r"C:\targets\sample64.exe",
            "_detect_pe_arch": lambda path: "x64",
            "_get_active_debugger_info": lambda: {"pid": 1111, "arch": "x64"},
            "_resolve_debugger_install_dir": lambda arch: r"C:\x64dbg\x64",
        }
        self.mod.register(self.mcp, self.g)

    def test_protocol_constants_preserve_v1_and_add_v2_status(self):
        self.assertEqual(self.mod.IOCTL_HIDE_PID, 0x222000)
        self.assertEqual(self.mod.IOCTL_UNHIDE_PID, 0x222004)
        self.assertEqual(self.mod.IOCTL_QUERY_STATUS, 0x222008)
        self.assertEqual(self.mod.PROTOCOL_STATUS_V2.size, 24)

    def test_distribution_resolution_honors_explicit_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, self.mod.DRIVER_FILE).write_bytes(b"driver")
            Path(tmp, self.mod.PLUGIN_FILE).write_bytes(b"plugin")
            result = self.mod._find_distribution_root(tmp)
        self.assertTrue(result["ok"])
        self.assertEqual(Path(result["root"]), Path(tmp))

    def test_invalid_or_system_pid_never_opens_device(self):
        with mock.patch.object(self.mod, "_open_device") as open_device:
            result = self.mod._device_ioctl(4, hide=True)
        self.assertFalse(result["ok"])
        open_device.assert_not_called()

    def test_service_state_uses_language_independent_status_api(self):
        localized_sc = {
            "ok": True,
            "returncode": 0,
            "stdout": "Имя_службы: EbloDDG\nСостояние: 4 RUNNING",
            "stderr": "",
        }
        with (
            mock.patch.object(
                self.mod,
                "_query_service_status_api",
                return_value={"ok": True, "exists": True, "stateCode": 4, "pid": 0},
            ),
            mock.patch.object(self.mod, "_run_sc", return_value=localized_sc),
            mock.patch.object(
                self.mod, "_read_service_image_path", return_value=r"C:\drivers\EbloDDG.sys"
            ),
        ):
            result = self.mod._query_service()
        self.assertTrue(result["exists"])
        self.assertTrue(result["running"])
        self.assertEqual(result["state"], "running")
        self.assertEqual(result["stateCode"], 4)

    def test_service_query_falls_back_to_sc_when_status_api_fails(self):
        sc_result = {
            "ok": True,
            "returncode": 0,
            "stdout": "Имя_службы: EbloDDG\nСостояние : 4 RUNNING\nID_процесса : 0",
            "stderr": "",
        }
        with (
            mock.patch.object(
                self.mod,
                "_query_service_status_api",
                return_value={"ok": False, "exists": False, "winerror": 5},
            ),
            mock.patch.object(self.mod, "_run_sc", return_value=sc_result),
            mock.patch.object(self.mod, "_read_service_image_path", return_value=""),
        ):
            result = self.mod._query_service()
        self.assertTrue(result["exists"])
        self.assertTrue(result["running"])

    def test_mutating_driver_action_requires_explicit_confirmation(self):
        result = self.mcp.tools["ManageHideMainDriver"](action="start")
        self.assertFalse(result["ok"])
        self.assertTrue(result["requiresConfirmation"])

    def test_driver_start_blocks_legacy_even_after_acknowledgement(self):
        service = {
            "ok": True,
            "exists": True,
            "running": False,
            "state": "stopped",
            "imagePath": r"C:\drivers\EbloDDG.sys",
        }
        with (
            mock.patch.object(self.mod, "_is_admin", return_value=True),
            mock.patch.object(self.mod, "_query_service", return_value=service),
            mock.patch.object(
                self.mod,
                "_driver_load_policy",
                return_value={
                    "allowed": False,
                    "failClosed": True,
                    "reason": "Blocked legacy EbloDDG build: 0x109/arg4=0x1E.",
                },
            ),
            mock.patch.object(self.mod, "_run_sc") as run_sc,
        ):
            result = self.mcp.tools["ManageHideMainDriver"](
                action="start",
                allow_system_changes=True,
                allow_unsigned=True,
                acknowledge_kernel_risk=True,
            )
        self.assertFalse(result["ok"])
        self.assertTrue(result["blocked"])
        self.assertTrue(result["failClosed"])
        self.assertIn("0x109", result["error"])
        run_sc.assert_not_called()

    def test_driver_start_blocks_unknown_image_fail_closed(self):
        service = {
            "ok": True,
            "exists": True,
            "running": False,
            "state": "stopped",
            "imagePath": r"C:\drivers\EbloDDG.sys",
        }
        with (
            mock.patch.object(self.mod, "_is_admin", return_value=True),
            mock.patch.object(self.mod, "_query_service", return_value=service),
            mock.patch.object(
                self.mod,
                "_driver_load_policy",
                return_value={
                    "allowed": False,
                    "failClosed": True,
                    "reason": "Blocked unknown EbloDDG build: safe v2 marker is absent.",
                },
            ),
            mock.patch.object(self.mod, "_run_sc") as run_sc,
        ):
            result = self.mcp.tools["ManageHideMainDriver"](
                action="start",
                allow_system_changes=True,
                allow_unsigned=True,
                acknowledge_kernel_risk=True,
            )
        self.assertFalse(result["ok"])
        self.assertTrue(result["blocked"])
        self.assertIn("unknown", result["error"])
        run_sc.assert_not_called()

    def test_running_vbs_is_a_blocker_even_without_registry_hvci(self):
        with (
            mock.patch.object(self.mod, "_read_registry_dword", return_value=0),
            mock.patch.object(
                self.mod,
                "_device_guard_status",
                return_value={
                    "vbsRunning": True,
                    "hvciRunning": False,
                    "vbsStatus": 2,
                    "source": "cim",
                },
            ),
        ):
            status = self.mod._windows_security_status()
        self.assertTrue(status["vbsRunning"])
        self.assertTrue(status["kernelPatchingBlocked"])
        self.assertTrue(any("SECURE_KERNEL_ERROR" in b for b in status["blockers"]))

    def test_running_service_is_not_ready_when_device_is_unavailable(self):
        service = {
            "ok": True,
            "exists": True,
            "running": True,
            "state": "running",
            "imagePath": r"C:\drivers\EbloDDG.sys",
        }
        with (
            mock.patch.object(self.mod, "_is_admin", return_value=True),
            mock.patch.object(self.mod, "_query_service", return_value=service),
            mock.patch.object(
                self.mod,
                "_driver_load_policy",
                return_value={
                    "allowed": True,
                    "reason": "safe-v2",
                    "binary": {"variant": "safe-v2-no-kernel-patching"},
                },
            ),
            mock.patch.object(self.mod, "_pe_has_embedded_signature", return_value=False),
            mock.patch.object(
                self.mod,
                "_windows_security_status",
                return_value={"hvciConfigured": False, "blockers": []},
            ),
            mock.patch.object(
                self.mod,
                "_probe_device",
                return_value={"ok": False, "available": False, "error": "missing"},
            ),
        ):
            result = self.mcp.tools["ManageHideMainDriver"](
                action="start",
                allow_system_changes=True,
                allow_unsigned=True,
                acknowledge_kernel_risk=True,
            )
        self.assertFalse(result["ok"])
        self.assertTrue(result["alreadyRunning"])
        self.assertIn("cannot be opened", result["error"])

    def test_status_describes_safe_v2_without_claiming_process_cloaking(self):
        service = {
            "ok": True,
            "exists": True,
            "running": True,
            "state": "running",
            "imagePath": r"C:\drivers\EbloDDG.sys",
        }
        protocol = {
            "ok": True,
            "supported": True,
            "authoritative": True,
            "version": 2,
            "targetPid": 4242,
            "capabilities": {
                "safeKernelNoPatching": True,
                "pebBeingDebuggedSanitization": True,
            },
        }
        with (
            mock.patch.object(
                self.mod,
                "_find_distribution_root",
                return_value={"ok": False, "root": "", "assets": {}, "checked": []},
            ),
            mock.patch.object(self.mod, "_query_service", return_value=service),
            mock.patch.object(
                self.mod,
                "_driver_load_policy",
                return_value={
                    "allowed": True,
                    "reason": "safe-v2",
                    "binary": {"variant": "safe-v2-no-kernel-patching"},
                },
            ),
            mock.patch.object(
                self.mod,
                "_probe_device",
                return_value={"ok": True, "available": True},
            ),
            mock.patch.object(self.mod, "_query_driver_protocol", return_value=protocol),
            mock.patch.object(
                self.mod,
                "_windows_security_status",
                return_value={
                    "blockers": ["legacy-only compatibility warning"],
                    "hvciConfigured": False,
                },
            ),
            mock.patch.object(
                self.mod,
                "_resolve_plugin_paths",
                return_value={"pluginPath": "", "configPath": ""},
            ),
        ):
            status = self.mcp.tools["GetHideMainStatus"]()
        self.assertTrue(status["ok"])
        self.assertEqual(
            status["semantics"]["purpose"],
            "selected-target anti-debug state sanitization",
        )
        self.assertFalse(status["semantics"]["processEnumerationCloaking"])
        self.assertTrue(status["capabilities"]["safeKernelNoPatching"])
        self.assertTrue(any("safe-v2" in item for item in status["warnings"]))
        self.assertFalse(any("HideMain v1" in item for item in status["warnings"]))
        self.assertNotIn("legacy-only compatibility warning", status["warnings"])

    def test_hide_and_unhide_update_runtime_only_after_success(self):
        calls = []

        def fake_ioctl(pid, hide):
            calls.append((pid, hide))
            return {"ok": True, "pid": pid, "action": "hide" if hide else "unhide"}

        with (
            mock.patch.object(
                self.mod,
                "_query_service",
                return_value={"imagePath": r"C:\drivers\EbloDDG.sys"},
            ),
            mock.patch.object(
                self.mod,
                "_driver_load_policy",
                return_value={"allowed": True, "reason": "safe-v2"},
            ),
            mock.patch.object(
                self.mod,
                "_query_driver_protocol",
                side_effect=[
                    {"ok": True, "supported": True, "authoritative": True, "version": 2, "targetPid": 0},
                    {"ok": True, "supported": True, "authoritative": True, "version": 2, "targetPid": 4242},
                    {"ok": True, "supported": True, "authoritative": True, "version": 2, "targetPid": 0},
                ],
            ),
            mock.patch.object(self.mod, "_device_ioctl", side_effect=fake_ioctl),
            mock.patch.object(self.mod.threading, "Thread"),
        ):
            hidden = self.mcp.tools["HideDebuggeeWithHideMain"]()
            self.assertTrue(hidden["ok"])
            self.assertFalse(hidden["processEnumerationCloaking"])
            self.assertEqual(self.runtime["lastHideMain"]["pid"], 4242)
            unhidden = self.mcp.tools["UnhideDebuggeeWithHideMain"]()
        self.assertTrue(unhidden["ok"])
        self.assertIsNone(self.runtime["lastHideMain"])
        self.assertEqual(calls, [(4242, True), (4242, False)])

    def test_failed_hide_does_not_claim_runtime_protection(self):
        with (
            mock.patch.object(self.mod, "_query_service", return_value={"imagePath": r"C:\drivers\EbloDDG.sys"}),
            mock.patch.object(self.mod, "_driver_load_policy", return_value={"allowed": True}),
            mock.patch.object(
                self.mod,
                "_query_driver_protocol",
                side_effect=[
                    {"ok": True, "supported": True, "authoritative": True, "version": 2, "targetPid": 0},
                    {"ok": True, "supported": True, "authoritative": True, "version": 2, "targetPid": 4242},
                ],
            ),
            mock.patch.object(self.mod, "_device_ioctl", return_value={"ok": False, "error": "denied"}),
        ):
            result = self.mcp.tools["HideDebuggeeWithHideMain"]()
        self.assertFalse(result["ok"])
        self.assertIsNone(self.runtime["lastHideMain"])

    def test_hide_does_not_claim_process_enumeration_cloaking(self):
        with (
            mock.patch.object(self.mod, "_query_service", return_value={"imagePath": r"C:\drivers\EbloDDG.sys"}),
            mock.patch.object(self.mod, "_driver_load_policy", return_value={"allowed": True}),
            mock.patch.object(
                self.mod,
                "_query_driver_protocol",
                side_effect=[
                    {"ok": True, "supported": True, "authoritative": True, "version": 2, "targetPid": 31337},
                    {"ok": True, "supported": True, "authoritative": True, "version": 2, "targetPid": 4242},
                ],
            ),
            mock.patch.object(
                self.mod,
                "_device_ioctl",
                return_value={
                    "ok": True,
                    "pid": 4242,
                    "deviceIoControl": True,
                    "driverSuccess": True,
                },
            ),
            mock.patch.object(self.mod.threading, "Thread"),
        ):
            result = self.mcp.tools["HideDebuggeeWithHideMain"]()
        self.assertTrue(result["ok"])
        self.assertFalse(result["processEnumerationCloaking"])
        self.assertIn("PEB.BeingDebugged", result["driverSuccessMeaning"])

    def test_arbitrary_pid_is_rejected_by_default(self):
        result = self.mcp.tools["HideDebuggeeWithHideMain"](pid=9999)
        self.assertFalse(result["ok"])
        self.assertIn("not the active", result["error"])

    def test_arbitrary_pid_guard_cannot_be_disabled(self):
        with mock.patch.object(self.mod, "_device_ioctl") as ioctl:
            result = self.mcp.tools["HideDebuggeeWithHideMain"](
                pid=4242, require_active_debuggee=False
            )
        self.assertFalse(result["ok"])
        ioctl.assert_not_called()

    def test_unknown_target_architecture_fails_closed(self):
        self.g["_detect_pe_arch"] = lambda path: ""
        self.mcp = FakeMcp()
        self.mod.register(self.mcp, self.g)
        with mock.patch.object(self.mod, "_device_ioctl") as ioctl:
            result = self.mcp.tools["HideDebuggeeWithHideMain"]()
        self.assertFalse(result["ok"])
        self.assertTrue(result["unsupported"])
        ioctl.assert_not_called()

    def test_verified_session_state_overrides_stale_inferred_pid(self):
        self.g["_build_debug_state"] = lambda **kwargs: {
            "debugging": False,
            "debuggeePid": 0,
        }
        self.mcp = FakeMcp()
        self.mod.register(self.mcp, self.g)
        with mock.patch.object(self.mod, "_device_ioctl") as ioctl:
            result = self.mcp.tools["HideDebuggeeWithHideMain"]()
        self.assertFalse(result["ok"])
        self.assertEqual(result["target"]["pid"], 0)
        ioctl.assert_not_called()

    def test_stale_cleanup_rejection_does_not_wedge_new_target(self):
        self.runtime["lastHideMain"] = {"pid": 31337, "arch": "x64"}
        calls = []

        def fake_ioctl(pid, hide):
            calls.append((pid, hide))
            if not hide:
                return {
                    "ok": False,
                    "deviceIoControl": True,
                    "driverSuccess": False,
                    "error": "Driver rejected the request.",
                }
            return {
                "ok": True,
                "pid": pid,
                "deviceIoControl": True,
                "driverSuccess": True,
            }

        with (
            mock.patch.object(self.mod, "_query_service", return_value={"imagePath": r"C:\drivers\EbloDDG.sys"}),
            mock.patch.object(self.mod, "_driver_load_policy", return_value={"allowed": True}),
            mock.patch.object(
                self.mod,
                "_query_driver_protocol",
                side_effect=[
                    {"ok": True, "supported": True, "authoritative": True, "version": 2, "targetPid": 31337},
                    {"ok": True, "supported": True, "authoritative": True, "version": 2, "targetPid": 4242},
                ],
            ),
            mock.patch.object(self.mod, "_device_ioctl", side_effect=fake_ioctl),
            mock.patch.object(self.mod.threading, "Thread"),
        ):
            result = self.mcp.tools["HideDebuggeeWithHideMain"]()
        self.assertTrue(result["ok"])
        self.assertTrue(result["reconciledOwnership"])
        self.assertEqual(calls, [(31337, False), (4242, True)])
        self.assertEqual(self.runtime["lastHideMain"]["pid"], 4242)
        self.runtime["lastHideMain"] = None

    def test_hide_rolls_back_when_v2_status_does_not_confirm_target(self):
        calls = []

        def fake_ioctl(pid, hide):
            calls.append((pid, hide))
            return {
                "ok": True,
                "pid": pid,
                "deviceIoControl": True,
                "driverSuccess": True,
            }

        with (
            mock.patch.object(self.mod, "_query_service", return_value={"imagePath": r"C:\drivers\EbloDDG.sys"}),
            mock.patch.object(self.mod, "_driver_load_policy", return_value={"allowed": True}),
            mock.patch.object(
                self.mod,
                "_query_driver_protocol",
                side_effect=[
                    {"ok": True, "supported": True, "authoritative": True, "version": 2, "targetPid": 0},
                    {"ok": True, "supported": True, "authoritative": True, "version": 2, "targetPid": 0},
                ],
            ),
            mock.patch.object(self.mod, "_device_ioctl", side_effect=fake_ioctl),
        ):
            result = self.mcp.tools["HideDebuggeeWithHideMain"]()

        self.assertFalse(result["ok"])
        self.assertFalse(result["authoritativeStatus"])
        self.assertEqual(calls, [(4242, True), (4242, False)])
        self.assertIsNone(self.runtime["lastHideMain"])

    def test_auto_mode_skips_when_device_is_not_already_available(self):
        with (
            mock.patch.object(
                self.mod,
                "_find_distribution_root",
                return_value={"ok": False, "root": "", "assets": {}, "checked": []},
            ),
            mock.patch.object(
                self.mod,
                "_query_service",
                return_value={"ok": True, "exists": False, "state": "absent", "running": False},
            ),
            mock.patch.object(
                self.mod,
                "_probe_device",
                return_value={"ok": False, "available": False, "path": self.mod.DEVICE_PATH},
            ),
            mock.patch.object(
                self.mod,
                "_windows_security_status",
                return_value={"hvciConfigured": False, "blockers": []},
            ),
            mock.patch.object(
                self.mod,
                "_resolve_plugin_paths",
                return_value={"installDir": "", "pluginDir": "", "pluginPath": "", "configPath": ""},
            ),
        ):
            result = self.mcp.tools["EnsureHideMainForDebuggee"](mode="auto")
        self.assertTrue(result["ok"])
        self.assertTrue(result["skipped"])

    def test_plugin_install_is_explicit_and_writes_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp, "dist")
            debugger = Path(tmp, "x64")
            dist.mkdir()
            debugger.mkdir()
            Path(dist, self.mod.PLUGIN_FILE).write_bytes(b"plugin-v1")
            self.g["_resolve_debugger_install_dir"] = lambda arch: str(debugger)
            self.mcp = FakeMcp()
            self.mod.register(self.mcp, self.g)
            result = self.mcp.tools["ConfigureHideMainPlugin"](
                action="install", root=str(dist), enabled=False
            )
            plugin_path = debugger / "plugins" / self.mod.PLUGIN_FILE
            config_path = debugger / "plugins" / "EbloDDG.ini"
            self.assertTrue(result["ok"])
            self.assertEqual(plugin_path.read_bytes(), b"plugin-v1")
            self.assertFalse(self.mod._plugin_enabled(str(config_path)))


class HideMainServerRegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _load(SERVER_PATH, "x64dbg_hidemain_registration_test")

    def test_extension_loaded_and_tools_are_registered(self):
        self.assertTrue(
            self.server._HIDEMAIN_TOOLS_STATUS.get("loaded"),
            self.server._HIDEMAIN_TOOLS_STATUS,
        )
        registry = self.server._get_mcp_tools_registry()
        for name in (
            "GetHideMainStatus",
            "ManageHideMainDriver",
            "ConfigureHideMainPlugin",
            "HideDebuggeeWithHideMain",
            "UnhideDebuggeeWithHideMain",
            "EnsureHideMainForDebuggee",
        ):
            self.assertIn(name, registry)

    def test_workflow_off_mode_is_side_effect_free(self):
        result = self.server._prepare_hidemain_workflow(mode="off", target_arch="x64")
        self.assertTrue(result["ok"])
        self.assertTrue(result["skipped"])


if __name__ == "__main__":
    unittest.main()
