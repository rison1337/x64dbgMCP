import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "tools" / "ida_evidence_coordinator.py"


def _load():
    spec = importlib.util.spec_from_file_location("ida_evidence_coordinator_tests", MODULE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class IdaEvidenceCoordinatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load()

    def _runtime(self):
        sha = "A" * 64
        return {
            "schema": "x64dbg-mcp-runtime-evidence",
            "version": 1,
            "image": {"sha256": sha, "arch": "x64", "sizeOfImage": "0x4000"},
            "staticEvidence": {
                "comments": [{"rva": "0x1200", "text": "runtime note"}],
                "labels": [{"rva": "0x1300", "text": "decoded"}],
                "functions": [{"rvaStart": "0x1000", "rvaEndInclusive": "0x1010"}],
            },
            "runtimeEvidence": {
                "coverageArtifacts": [
                    {"blocks": [{"startRva": "0x1200", "stableKey": "A:0x1200", "hits": 3}]}
                ],
                "apiTraces": [
                    {"calls": [{"callerRva": "0x1400", "module": "KERNEL32", "func": "Sleep", "seq": 7}]}
                ],
            },
        }

    def test_build_plan_uses_ida_base_and_stable_idempotency(self):
        runtime = self._runtime()
        image = {"sha256": "A" * 64, "arch": "x64", "imageBase": "0x140000000"}
        first = self.mod.build_sync_plan(runtime, image)
        second = self.mod.build_sync_plan(json.loads(json.dumps(runtime)), image)
        self.assertEqual(first["schema"], "ida-runtime-sync-plan-v1")
        self.assertEqual(first["idempotencyKey"], second["idempotencyKey"])
        self.assertTrue(any(a["tool"] == "define_func" for a in first["actions"]))
        self.assertTrue(any(a["arguments"]["items"]["addr"] == "0x140001200" for a in first["actions"]))

    def test_identity_mismatch_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "identity"):
            self.mod.build_sync_plan(self._runtime(), {"sha256": "B" * 64, "arch": "x64", "imageBase": 0x140000000})

    def test_invalid_out_of_image_items_are_skipped_deterministically(self):
        runtime = self._runtime()
        runtime["staticEvidence"]["comments"].append({"rva": "0x4000", "text": "bad"})
        plan = self.mod.build_sync_plan(
            runtime, {"sha256": "A" * 64, "arch": "x64", "imageBase": 0x140000000}
        )
        self.assertTrue(any(item["reason"] == "outside_image" for item in plan["skipped"]))


if __name__ == "__main__":
    unittest.main()
