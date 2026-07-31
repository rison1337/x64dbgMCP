import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_coverage_artifact_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CoverageArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def _artifact(self, *, block_hits=(1, 0), edge_hits=(1,)):
        return {
            "schema": "coverage-artifact-v1",
            "schemaVersion": 1,
            "coverageModel": "basic-block-edge-v1",
            "stableIdentity": "a" * 64,
            "moduleBase": "0x140000000",
            "moduleSize": "0x3000",
            "blocks": [
                {
                    "stableKey": "a" * 64 + ":0x1000",
                    "startRva": "0x1000",
                    "endRva": "0x1010",
                    "hits": block_hits[0],
                    "instructionCount": 4,
                    "threadIds": [12],
                },
                {
                    "stableKey": "a" * 64 + ":0x1020",
                    "startRva": "0x1020",
                    "endRva": "0x1030",
                    "hits": block_hits[1],
                    "instructionCount": 3,
                    "threadIds": [],
                },
            ],
            "edges": [
                {
                    "from": "a" * 64 + ":0x1000",
                    "to": "a" * 64 + ":0x1020",
                    "kind": "fallthrough",
                    "hits": edge_hits[0],
                    "branchTargets": [],
                }
            ],
            "coveredInstructions": 7,
            "executedBlockHits": sum(block_hits),
            "executedEdgeHits": edge_hits[0],
        }

    def test_normalization_and_digest_are_deterministic(self):
        body = self.mod._coverage_artifact_body(self._artifact())
        digest = self.mod._coverage_artifact_digest(body)
        self.assertEqual(body["schema"], "coverage-artifact-v1")
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, self.mod._coverage_artifact_digest(body))
        parsed, error = self.mod._coverage_artifact_input(
            json.dumps({"artifact": {**body, "artifactSha256": digest}}), "sample"
        )
        self.assertIsNone(error)
        self.assertEqual(parsed, body)

    def test_merge_sums_hits_once_and_unions_threads(self):
        first = self._artifact(block_hits=(2, 0), edge_hits=(3,))
        second = self._artifact(block_hits=(5, 4), edge_hits=(7,))
        second["blocks"][0]["threadIds"] = [13]
        result = self.mod.MergeCoverageArtifacts(json.dumps([first, second]))
        self.assertTrue(result["ok"], result)
        blocks = {item["stableKey"]: item for item in result["artifact"]["blocks"]}
        self.assertEqual(blocks[first["blocks"][0]["stableKey"]]["hits"], 7)
        self.assertEqual(blocks[first["blocks"][1]["stableKey"]]["hits"], 4)
        self.assertEqual(
            blocks[first["blocks"][0]["stableKey"]]["threadIds"], [12, 13]
        )
        self.assertEqual(result["artifact"]["edges"][0]["hits"], 10)

    def test_diff_reports_added_removed_changed_and_newly_covered(self):
        baseline = self._artifact(block_hits=(1, 0), edge_hits=(1,))
        candidate = self._artifact(block_hits=(4, 2), edge_hits=(3,))
        candidate["blocks"].append(
            {
                "stableKey": "a" * 64 + ":0x1040",
                "startRva": "0x1040",
                "endRva": "0x1050",
                "hits": 1,
                "instructionCount": 2,
                "threadIds": [12],
            }
        )
        result = self.mod.DiffCoverageArtifacts(
            json.dumps(baseline), json.dumps(candidate)
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["summary"]["addedBlocks"], 1)
        self.assertEqual(result["summary"]["changedBlocks"], 2)
        self.assertEqual(result["summary"]["newlyCoveredBlocks"], 1)
        self.assertEqual(result["summary"]["changedEdges"], 1)

    def test_export_writes_canonical_artifact(self):
        coverage = self._artifact(block_hits=(3, 1), edge_hits=(2,))
        original = self.mod.GetBasicBlockCoverage
        self.mod.GetBasicBlockCoverage = lambda trace_id, limit=100: {
            "ok": True,
            **coverage,
        }
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "coverage.json"
                result = self.mod.ExportCoverageArtifact("trace-1", str(path))
                self.assertTrue(result["ok"], result)
                payload = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(payload["artifactSha256"], result["artifactSha256"])
                self.assertEqual(payload["schema"], "coverage-artifact-v1")
        finally:
            self.mod.GetBasicBlockCoverage = original

    def test_rejects_identity_mismatch_and_tampered_digest(self):
        baseline = self._artifact()
        candidate = self._artifact()
        candidate["stableIdentity"] = "b" * 64
        mismatch = self.mod.DiffCoverageArtifacts(
            json.dumps(baseline), json.dumps(candidate)
        )
        self.assertEqual(mismatch["errorCode"], "IDENTITY_MISMATCH")
        body = self.mod._coverage_artifact_body(baseline)
        tampered = {**body, "artifactSha256": "0" * 64}
        parsed, error = self.mod._coverage_artifact_input(tampered, "tampered")
        self.assertIsNone(parsed)
        self.assertIn("does not match", error)

    def test_versioned_coverage_roundtrip_preserves_code_identity(self):
        coverage = self._artifact(block_hits=(2, 1), edge_hits=(3,))
        coverage.update(
            {
                "reconstructionSchema": "basic-block-edge-v2",
                "coveredInstructionVersions": 8,
                "executedInstructionHits": 12,
                "versionedBlockCount": 2,
                "selfModifyingRvas": ["0x1000"],
                "indirectEdgeCount": 1,
                "exceptionEdgeCount": 0,
            }
        )
        coverage["blocks"][0].update(
            {
                "baseStableKey": "a" * 64 + ":0x1000",
                "instructionHits": 8,
                "codeSha256": "b" * 64,
                "codeVersion": 1,
                "versionCountAtRva": 2,
                "selfModified": True,
            }
        )
        coverage["blocks"][1].update(
            {
                "baseStableKey": "a" * 64 + ":0x1020",
                "instructionHits": 4,
                "codeSha256": "c" * 64,
                "codeVersion": 1,
                "versionCountAtRva": 1,
                "selfModified": False,
            }
        )
        coverage["edges"][0]["indirect"] = True
        body = self.mod._coverage_artifact_body(coverage)
        self.assertEqual(body["schemaVersion"], 2)
        self.assertEqual(body["reconstructionSchema"], "basic-block-edge-v2")
        self.assertEqual(body["blocks"][0]["codeSha256"], "B" * 64)
        self.assertEqual(body["selfModifyingRvas"], ["0x1000"])
        digest = self.mod._coverage_artifact_digest(body)
        parsed, error = self.mod._coverage_artifact_input(
            {**body, "artifactSha256": digest}, "versioned"
        )
        self.assertIsNone(error)
        self.assertEqual(parsed, body)


if __name__ == "__main__":
    unittest.main()
