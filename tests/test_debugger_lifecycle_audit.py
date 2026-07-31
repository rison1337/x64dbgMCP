import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "run_debugger_lifecycle_audit.py"


def _load():
    spec = importlib.util.spec_from_file_location("lifecycle_audit_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DebuggerLifecycleAuditContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load()

    def test_handle_trend_is_bounded_and_deterministic(self):
        result = self.mod._trend([120, 121, 119, 123])
        self.assertEqual(result["count"], 4)
        self.assertEqual(result["first"], 120)
        self.assertEqual(result["last"], 123)
        self.assertEqual(result["delta"], 3)
        self.assertEqual(result["min"], 119)
        self.assertEqual(result["max"], 123)

    def test_empty_handle_trend_is_explicitly_unavailable(self):
        self.assertEqual(self.mod._trend([])["count"], 0)
        self.assertIsNone(self.mod._trend([])["first"])

    def test_parser_defaults_to_required_architectures_and_100_cycles(self):
        args = self.mod._parser().parse_args([])
        self.assertEqual(args.arch, "all")
        self.assertEqual(args.cycles, 100)
        self.assertEqual(args.sample_count, 5)


if __name__ == "__main__":
    unittest.main()
