import configparser
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.mcp_runtime.scylla import run_injector


class ScyllaInjectorTests(unittest.TestCase):
    def _fixture(self, root: Path):
        exe = root / "InjectorCLI.exe"
        exe.write_bytes(b"fake")
        hook = root / "ScyllaHide.dll"
        hook.write_bytes(b"fake")
        config = root / "scylla_hide.ini"
        config.write_text("[Settings]\nCurrentProfile=Other\n[Basic]\nNtContinueHook=1\n", encoding="utf-8")
        return exe, hook, config

    def test_stages_profile_and_requires_native_success(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            exe, hook, config = self._fixture(root)
            original = config.read_bytes()
            seen = {}

            def fake_run(command, **kwargs):
                seen["command"] = command
                stage_config = Path(command[0]).with_name("scylla_hide.ini")
                parser = configparser.ConfigParser()
                parser.read(stage_config, encoding="utf-16")
                seen["profile"] = parser.get("Settings", "CurrentProfile")
                seen["continue"] = parser.get("Basic", "NtContinueHook")
                seen["antiAttach"] = parser.get("Basic", "KillAntiAttach")
                seen["exists_during_run"] = stage_config.exists()
                return type("Completed", (), {"returncode": 0, "stdout": "PID\t: 1234\nHook injection successful\n", "stderr": ""})()

            with patch("src.mcp_runtime.scylla.subprocess.run", side_effect=fake_run):
                result = run_injector(injector=str(exe), hook=str(hook), config=str(config), pid=1234, profile="Basic", work_dir=str(root))

            self.assertTrue(result["ok"])
            self.assertTrue(result["hookInjected"])
            self.assertEqual(result["profile"], "Basic")
            self.assertEqual(seen["profile"], "Basic")
            self.assertEqual(seen["continue"], "0")
            self.assertEqual(seen["antiAttach"], "0")
            self.assertEqual(config.read_bytes(), original)
            self.assertTrue(seen["exists_during_run"])
            self.assertEqual(seen["command"][1:], ["pid:1234", str(hook), "nowait"])
            self.assertFalse(any(root.glob("scylla-injector-*")))

    def test_zero_exit_without_terminal_success_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            exe, hook, config = self._fixture(root)
            with patch("src.mcp_runtime.scylla.subprocess.run", return_value=type("Completed", (), {"returncode": 0, "stdout": "PID\t: 1234\n", "stderr": ""})()):
                result = run_injector(injector=str(exe), hook=str(hook), config=str(config), pid=1234, profile="Basic", work_dir=str(root))
            self.assertFalse(result["ok"])
            self.assertIn("did not confirm success", result["error"])

    def test_success_for_another_pid_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            exe, hook, config = self._fixture(root)
            completed = type("Completed", (), {"returncode": 0, "stdout": "PID: 9999\nHook injection successful\n", "stderr": ""})()
            with patch("src.mcp_runtime.scylla.subprocess.run", return_value=completed):
                result = run_injector(injector=str(exe), hook=str(hook), config=str(config), pid=1234, profile="Basic", work_dir=td)
            self.assertFalse(result["ok"])
            self.assertFalse(result["protectionApplied"])


if __name__ == "__main__":
    unittest.main()
