import configparser
import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER_PATH = ROOT / "src" / "x64dbg.py"
def _load_server():
    spec = importlib.util.spec_from_file_location("x64dbg_virtualization_exclusion", SERVER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class VirtualizationExclusionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _load_server()

    def test_deferred_profiles_are_not_auto_detected_or_registered(self):
        keys = set(self.server.SCYLLA_PROTECTOR_PROFILES)
        self.assertNotIn("vmprotect", keys)
        self.assertNotIn("vmp", keys)
        registry = set(self.server._get_mcp_tools_registry())
        self.assertFalse(any("virtualized" in name.lower() for name in registry))
        self.assertFalse(any("devirtual" in name.lower() for name in registry))

    def test_explicit_deferred_profile_fails_closed_without_touching_ini(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scylla.ini"
            parser = configparser.ConfigParser()
            parser["SETTINGS"] = {"CurrentProfile": "Basic"}
            parser["Basic"] = {"NtQueryInformationProcess": "0"}
            parser["VMProtect x86/x64"] = {"NtQueryInformationProcess": "1"}
            with path.open("w", encoding="utf-8") as handle:
                parser.write(handle)
            before = path.read_bytes()
            with self.assertRaises(RuntimeError) as ctx:
                self.server._write_scyllahide_profile(str(path), "VMProtect x86/x64")
            self.assertIn("disabled", str(ctx.exception).lower())
            self.assertEqual(path.read_bytes(), before)

    def test_deferred_experiment_archive_is_not_shipped(self):
        self.assertFalse((ROOT / "archive").exists())


if __name__ == "__main__":
    unittest.main()
