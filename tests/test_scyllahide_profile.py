import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_bridge", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ScyllaHideProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_write_profile_compacts_bloated_ini(self):
        bloated_gap = "\r\n" * 20000
        original = (
            "[SETTINGS]\r\n"
            "CurrentProfile=Disabled\r\n"
            f"{bloated_gap}"
            "[Basic]\r\n"
            "NtCloseHook=1\r\n"
            f"{bloated_gap}"
            "[Disabled]\r\n"
            "NtCloseHook=0\r\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            ini_path = Path(tmpdir) / "scylla_hide.ini"
            ini_path.write_text(original, encoding="utf-8", newline="\r\n")

            result = self.mod._write_scyllahide_profile(str(ini_path), "Basic")
            profile_info = self.mod._read_scyllahide_profile(str(ini_path))
            rewritten = ini_path.read_text(encoding="utf-8")

        self.assertTrue(result["ok"])
        self.assertEqual(result["currentProfile"], "Basic")
        self.assertTrue(result["compacted"])
        self.assertLess(result["sizeAfter"], result["sizeBefore"])
        self.assertEqual(profile_info["currentProfile"], "Basic")
        self.assertEqual(profile_info["profiles"], ["Basic", "Disabled"])
        self.assertIn("[Basic]", rewritten)
        self.assertNotIn("\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n", rewritten)

    def test_write_profile_rejects_unknown_profile(self):
        content = (
            "[SETTINGS]\r\n"
            "CurrentProfile=Disabled\r\n"
            "\r\n"
            "[Basic]\r\n"
            "NtCloseHook=1\r\n"
            "\r\n"
            "[Disabled]\r\n"
            "NtCloseHook=0\r\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            ini_path = Path(tmpdir) / "scylla_hide.ini"
            ini_path.write_text(content, encoding="utf-8", newline="\r\n")

            with self.assertRaises(RuntimeError):
                self.mod._write_scyllahide_profile(str(ini_path), "MissingProfile")

    def test_internal_restore_can_select_disabled_profile(self):
        content = (
            "[SETTINGS]\r\n"
            "CurrentProfile=Basic\r\n"
            "\r\n"
            "[Basic]\r\n"
            "NtCloseHook=1\r\n"
            "\r\n"
            "[Disabled]\r\n"
            "NtCloseHook=0\r\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            ini_path = Path(tmpdir) / "scylla_hide.ini"
            ini_path.write_text(content, encoding="utf-8", newline="\r\n")

            with self.assertRaises(RuntimeError):
                self.mod._write_scyllahide_profile(str(ini_path), "Disabled")
            result = self.mod._write_scyllahide_profile(
                str(ini_path), "Disabled", allow_disabled=True
            )
            profile_info = self.mod._read_scyllahide_profile(str(ini_path))

        self.assertTrue(result["ok"])
        self.assertEqual(result["currentProfile"], "Disabled")
        self.assertTrue(profile_info["currentProfileDisabled"])

    def test_disabled_profile_name_is_reported_as_disabled(self):
        self.assertTrue(self.mod._is_disabled_scylla_profile("Disabled"))
        self.assertTrue(self.mod._is_disabled_scylla_profile("off"))
        self.assertFalse(self.mod._is_disabled_scylla_profile("Basic"))

    def test_status_distinguishes_optional_gui_plugin_from_injection_backend(self):
        fake_paths = {
            "arch": "x64",
            "installDir": r"C:\x64dbg\x64",
            "pluginPath": r"C:\x64dbg\x64\plugins\ScyllaHideX64DBGPlugin.dp64",
            "hookPath": r"C:\x64dbg\x64\plugins\HookLibraryx64.dll",
            "configPath": r"C:\x64dbg\x64\plugins\scylla_hide.ini",
            "injectorPath": r"C:\x64dbg\ScyllaHide\InjectorCLIx64.exe",
            "testExePath": r"C:\x64dbg\ScyllaHide\ScyllaTest_x64.exe",
            "logPath": r"C:\x64dbg\ScyllaHide\scylla_hide.log",
        }
        existing = {
            fake_paths["hookPath"],
            fake_paths["configPath"],
            fake_paths["injectorPath"],
        }
        with mock.patch.object(
            self.mod, "_scyllahide_paths_for_arch", return_value=fake_paths
        ), mock.patch.object(
            self.mod.os.path, "exists", side_effect=lambda path: path in existing
        ), mock.patch.object(
            self.mod,
            "_read_scyllahide_profile",
            return_value={
                "currentProfile": "Disabled",
                "profiles": ["Basic", "Disabled"],
                "activeProfiles": ["Basic"],
                "disabledProfiles": ["Disabled"],
                "currentProfileDisabled": True,
            },
        ), mock.patch.object(
            self.mod, "_build_debug_state", return_value={"debugging": False}
        ), mock.patch.object(
            self.mod, "_get_active_debugger_info", return_value={"arch": "x64"}
        ), mock.patch.object(
            self.mod, "_read_scyllahide_log_status", return_value={}
        ):
            status = self.mod.GetScyllaHideStatus(arch="x64")

        self.assertTrue(status["installed"])
        self.assertTrue(status["integrationReady"])
        self.assertEqual(status["integrationMode"], "injector_cli")
        self.assertFalse(status["guiPluginRequired"])
        self.assertFalse(status["guiPluginPresent"])
        self.assertFalse(status["pluginPresent"])
        self.assertEqual(
            status["components"],
            {
                "injector": True,
                "hookLibrary": True,
                "profileIni": True,
                "guiPlugin": False,
            },
        )

    def test_force_mode_uses_basic_when_auto_analysis_returns_disabled(self):
        status = {
            "installed": True,
            "currentProfile": "Disabled",
            "configPath": r"C:\x64dbg\x64\plugins\scylla_hide.ini",
            "analysis": {"suggestedScyllaHideProfile": "Disabled"},
            "arch": "x64",
            "hookPath": r"C:\x64dbg\x64\plugins\HookLibraryx64.dll",
        }
        with mock.patch.object(
            self.mod, "_dismiss_scyllahide_dialog", return_value={"found": False}
        ), mock.patch.object(
            self.mod, "GetScyllaHideStatus", return_value=status
        ), mock.patch.object(
            self.mod,
            "_write_scyllahide_profile",
            return_value={"ok": True, "currentProfile": "Basic"},
        ) as write_profile, mock.patch.object(
            self.mod, "_read_scyllahide_log_status", return_value={}
        ), mock.patch.object(
            self.mod, "_remember_runtime"
        ):
            result = self.mod._prepare_scyllahide_launch(
                r"C:\targets\sample.exe", "x64", "force", ""
            )

        self.assertTrue(result["ok"])
        self.assertTrue(result["preArmed"])
        self.assertTrue(result["force"])
        self.assertEqual(result["profile"], "Basic")
        write_profile.assert_called_once_with(status["configPath"], "Basic")

    def test_force_mode_rejects_explicit_disabled_profile(self):
        status = {
            "installed": True,
            "currentProfile": "Disabled",
            "configPath": r"C:\x64dbg\x64\plugins\scylla_hide.ini",
            "analysis": {"suggestedScyllaHideProfile": "Basic"},
        }
        with mock.patch.object(
            self.mod, "_dismiss_scyllahide_dialog", return_value={"found": False}
        ), mock.patch.object(
            self.mod, "GetScyllaHideStatus", return_value=status
        ), mock.patch.object(
            self.mod, "_write_scyllahide_profile"
        ) as write_profile:
            result = self.mod._prepare_scyllahide_launch(
                r"C:\targets\sample.exe", "x64", "force", "Disabled"
            )

        self.assertFalse(result["ok"])
        self.assertIn("cannot use a disabled profile", result["reason"])
        write_profile.assert_not_called()


if __name__ == "__main__":
    unittest.main()
