import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "x64dbg.py"
CPP_PATH = ROOT / "src" / "MCPx64dbg.cpp"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_evidence_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _image(sha="A" * 64):
    return {
        "name": "fixture.exe",
        "path": r"C:\fixtures\fixture.exe",
        "sha256": sha,
        "fileSize": 4096,
        "arch": "x64",
        "machine": "0x8664",
        "timeDateStamp": "0x12345678",
        "checksum": "0x0",
        "preferredImageBase": "0x140000000",
        "runtimeImageBase": "0x180000000",
        "runtimeSize": 0x4000,
        "sizeOfImage": 0x4000,
        "entryPointRva": "0x1000",
    }


def _document(evidence=None, sha="A" * 64):
    evidence = dict(evidence or {})
    for key in (
        "labels",
        "comments",
        "bookmarks",
        "functions",
        "breakpoints",
        "patches",
        "nativeTraceHits",
        "apiCallsites",
    ):
        evidence.setdefault(key, [])
    return {
        "schema": "x64dbg-mcp-evidence",
        "version": 1,
        "image": _image(sha),
        "evidence": evidence,
        "counts": {key: len(value) for key, value in evidence.items()},
    }


class EvidenceExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def _hello(self, paused=True):
        return {
            "ok": True,
            "identity": {
                "bridgeInstanceId": "bridge-a",
                "sessionId": "session-a",
                "sessionGeneration": 7,
                "debuggeePid": 4242,
                "eventSeq": 19,
            },
            "payload": {
                "build": {"id": "build-a", "sourceId": "source-a"},
                "capabilities": {"analysisEvidence": {"version": 1}},
                "session": {"paused": paused, "eventSeq": 19},
            },
        }

    def _context(self, sha="A" * 64):
        return {
            "identity": _image(sha),
            "base": 0x180000000,
            "size": 0x4000,
            "module": {"name": "fixture.exe"},
            "layout": {},
            "path": r"C:\fixtures\fixture.exe",
        }

    def _empty_current(self):
        return {"labels": {}, "comments": {}, "bookmarks": {}, "functions": []}

    def test_validator_normalizes_ida_exclusive_function_end(self):
        doc = _document(
            {
                "functions": [
                    {"rvaStart": "0x1000", "endRvaExclusive": "0x1010", "manual": True}
                ]
            }
        )
        result = self.mod._analysis_validate_document(doc)
        self.assertTrue(result["valid"], result["errors"])
        function = result["normalized"]["functions"][0]
        self.assertEqual(function["rvaEndInclusive"], 0x100F)
        self.assertEqual(function["endConvention"], "inclusive")

    def test_validator_rejects_out_of_image_rva_nul_and_oversized_label(self):
        doc = _document(
            {
                "labels": [
                    {"rva": "0x4000", "text": "outside"},
                    {"rva": "0x1000", "text": "bad\x00text"},
                    {"rva": "0x1001", "text": "x" * 256},
                    {"rva": "0x1002", "text": "Ж" * 128},
                ]
            }
        )
        result = self.mod._analysis_validate_document(doc)
        self.assertFalse(result["valid"])
        self.assertEqual(len(result["errors"]), 4)

    def test_validator_rejects_conflicting_duplicate_annotation(self):
        doc = _document(
            {
                "labels": [
                    {"rva": "0x1000", "text": "one"},
                    {"rva": "0x1000", "text": "two"},
                ]
            }
        )
        result = self.mod._analysis_validate_document(doc)
        self.assertFalse(result["valid"])
        self.assertTrue(any("Conflicting duplicate" in item["error"] for item in result["errors"]))

    def test_comment_list_rereads_truncated_text_outside_native_list_call(self):
        long_text = "x" * 400
        native = {
            "ok": True,
            "comments": [
                {"module": "fixture.exe", "rva": "0x1000", "text": "x" * 255, "manual": True}
            ],
            "count": 1,
            "hasMore": False,
        }
        with (
            mock.patch.object(self.mod, "safe_get", return_value=native),
            mock.patch.object(
                self.mod,
                "GetModuleList",
                return_value={"modules": [{"name": "fixture.exe", "base": "0x180000000"}]},
            ),
            mock.patch.object(
                self.mod, "CommentGet", return_value={"found": True, "comment": long_text}
            ) as get_comment,
        ):
            result = self.mod.CommentList("fixture.exe")
        self.assertEqual(result["comments"][0]["text"], long_text)
        self.assertTrue(result["comments"][0]["fullTextRead"])
        get_comment.assert_called_once_with("0x180001000")

    def test_dry_run_uses_runtime_base_and_performs_no_mutation(self):
        doc = _document({"labels": [{"rva": "0x1234", "text": "ida_label"}]})
        with (
            mock.patch.object(self.mod, "BridgeHello", return_value=self._hello()),
            mock.patch.object(self.mod, "_analysis_module_context", return_value=(self._context(), None)),
            mock.patch.object(
                self.mod, "_analysis_current_annotations", return_value=(self._empty_current(), None)
            ),
            mock.patch.object(self.mod, "_analysis_guarded_mutation") as mutate,
        ):
            result = self.mod.ImportAnalysisEvidence(evidence_json=json.dumps(doc))
        self.assertTrue(result["ok"])
        self.assertTrue(result["dryRun"])
        self.assertEqual(result["plan"]["actions"][0]["address"], "0x180001234")
        mutate.assert_not_called()

    def test_hash_mismatch_fails_before_annotation_enumeration(self):
        doc = _document({"labels": [{"rva": "0x1000", "text": "x"}]}, sha="B" * 64)
        current = mock.Mock()
        with (
            mock.patch.object(self.mod, "BridgeHello", return_value=self._hello()),
            mock.patch.object(
                self.mod, "_analysis_module_context", return_value=(self._context("A" * 64), None)
            ),
            mock.patch.object(self.mod, "_analysis_current_annotations", current),
        ):
            result = self.mod.ImportAnalysisEvidence(evidence_json=json.dumps(doc))
        self.assertFalse(result["ok"])
        self.assertEqual(result["errorCode"], "MODULE_IDENTITY_MISMATCH")
        current.assert_not_called()

    def test_apply_is_event_guarded_and_verified(self):
        doc = _document({"labels": [{"rva": "0x1000", "text": "pct_%41 + & Юникод"}]})
        mutations = []

        def mutate(endpoint, data, event_seq):
            mutations.append((endpoint, dict(data), event_seq))
            return True, {"success": True}, ""

        with (
            mock.patch.object(self.mod, "BridgeHello", return_value=self._hello(paused=True)),
            mock.patch.object(self.mod, "_analysis_module_context", return_value=(self._context(), None)),
            mock.patch.object(
                self.mod, "_analysis_current_annotations", return_value=(self._empty_current(), None)
            ),
            mock.patch.object(self.mod, "_analysis_guarded_mutation", side_effect=mutate),
            mock.patch.object(
                self.mod,
                "LabelGet",
                return_value={"found": True, "label": "pct_%41 + & Юникод"},
            ),
        ):
            result = self.mod.ImportAnalysisEvidence(
                evidence_json=json.dumps(doc), dry_run=False
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual(mutations[0][0], "Label/Set")
        self.assertEqual(mutations[0][1]["text"], "pct_%41 + & Юникод")
        self.assertEqual(mutations[0][2], 19)
        self.assertTrue(result["applied"][0]["verified"])

    def test_apply_requires_paused_target(self):
        doc = _document({"bookmarks": [{"rva": "0x1010"}]})
        with (
            mock.patch.object(self.mod, "BridgeHello", return_value=self._hello(paused=False)),
            mock.patch.object(self.mod, "_analysis_module_context", return_value=(self._context(), None)),
            mock.patch.object(
                self.mod, "_analysis_current_annotations", return_value=(self._empty_current(), None)
            ),
            mock.patch.object(self.mod, "_analysis_guarded_mutation") as mutate,
        ):
            result = self.mod.ImportAnalysisEvidence(
                evidence_json=json.dumps(doc), dry_run=False
            )
        self.assertEqual(result["errorCode"], "TARGET_NOT_PAUSED")
        mutate.assert_not_called()

    def test_existing_different_annotation_is_a_zero_mutation_conflict(self):
        doc = _document({"comments": [{"rva": "0x1020", "text": "new"}]})
        current = self._empty_current()
        current["comments"][0x1020] = {"rva": "0x1020", "text": "old", "manual": True}
        with (
            mock.patch.object(self.mod, "BridgeHello", return_value=self._hello()),
            mock.patch.object(self.mod, "_analysis_module_context", return_value=(self._context(), None)),
            mock.patch.object(self.mod, "_analysis_current_annotations", return_value=(current, None)),
            mock.patch.object(self.mod, "_analysis_guarded_mutation") as mutate,
        ):
            result = self.mod.ImportAnalysisEvidence(
                evidence_json=json.dumps(doc), dry_run=False
            )
        self.assertEqual(result["errorCode"], "IMPORT_CONFLICT")
        self.assertEqual(len(result["plan"]["conflicts"]), 1)
        mutate.assert_not_called()

    def test_export_converts_absolute_breakpoint_and_patch_to_rva(self):
        labels = {"count": 1, "labels": [{"module": "fixture", "rva": "0x1000", "text": "L", "manual": True}]}
        with (
            mock.patch.object(self.mod, "BridgeHello", return_value=self._hello()),
            mock.patch.object(self.mod, "_analysis_module_context", return_value=(self._context(), None)),
            mock.patch.object(self.mod, "LabelList", return_value=labels),
            mock.patch.object(
                self.mod,
                "_analysis_collect_paged",
                side_effect=[
                    ([{"module": "fixture", "rva": "0x1001", "text": "C", "manual": True}], None),
                    ([{"module": "fixture", "rva": "0x1002", "manual": True}], None),
                    ([{"module": "fixture", "rvaStart": "0x1000", "rvaEnd": "0x100F", "manual": True, "instructionCount": 4}], None),
                ],
            ),
            mock.patch.object(
                self.mod,
                "GetBreakpointList",
                return_value={"breakpoints": [{"addr": "0x180001010", "type": "normal", "enabled": True}]},
            ),
            mock.patch.object(
                self.mod,
                "GetPatchList",
                return_value={"patches": [{"address": "0x180001011", "oldByte": "0x90", "newByte": "0xCC"}]},
            ),
        ):
            result = self.mod.ExportAnalysisEvidence()
        self.assertTrue(result["ok"], result)
        evidence = result["document"]["evidence"]
        self.assertEqual(evidence["breakpoints"][0]["rva"], "0x1010")
        self.assertEqual(evidence["patches"][0]["rva"], "0x1011")
        self.assertEqual(evidence["functions"][0]["rvaEndInclusive"], "0x100F")

    def test_atomic_output_refuses_overwrite(self):
        doc = _document()
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "evidence.json"
            first = self.mod._analysis_write_json(str(output), doc, overwrite=False)
            before = output.read_bytes()
            second = self.mod._analysis_write_json(str(output), {"different": True}, overwrite=False)
            after = output.read_bytes()
        self.assertTrue(first["ok"])
        self.assertEqual(second["errorCode"], "OUTPUT_EXISTS")
        self.assertEqual(before, after)

    def test_resolve_module_rva_returns_hash_bound_location(self):
        with (
            mock.patch.object(self.mod, "_analysis_module_context", return_value=(self._context(), None)),
            mock.patch.object(self.mod, "GetSessionBinding", return_value={"sessionId": "s"}),
        ):
            result = self.mod.ResolveModuleRva(module="fixture.exe", address="0x180001234")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["rva"], "0x1234")
        self.assertEqual(result["stableKey"], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0x1234")
        self.assertEqual(result["session"]["sessionId"], "s")

    def test_runtime_export_binds_coverage_and_api_calls_to_image(self):
        artifact = self.mod._coverage_artifact_body(
            {
                "stableIdentity": "a" * 64,
                "coverageModel": "basic-block-edge-v1",
                "blocks": [{"stableKey": "a" * 64 + ":0x1000", "startRva": "0x1000", "endRva": "0x1004", "hits": 2}],
                "edges": [],
            }
        )
        with (
            mock.patch.object(self.mod, "BridgeHello", return_value=self._hello()),
            mock.patch.object(self.mod, "_analysis_module_context", return_value=(self._context(), None)),
            mock.patch.object(self.mod, "GetSessionBinding", return_value={"sessionId": "s"}),
        ):
            result = self.mod.ExportRuntimeEvidence(
                module="fixture.exe",
                include_static=False,
                coverage_artifact_json=json.dumps(artifact),
                comparison_recovery_json=json.dumps({"ok": True, "schema": "comparison-secret-recovery-v1"}),
            )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["schema"], "x64dbg-mcp-runtime-evidence")
        self.assertEqual(result["document"]["counts"]["coverageArtifacts"], 1)
        self.assertEqual(result["document"]["runtimeEvidence"]["comparisonRecoveries"][0]["schema"], "comparison-secret-recovery-v1")
        self.assertEqual(result["artifactSha256"], result["document"]["artifactSha256"])

    def test_runtime_export_rejects_coverage_for_other_image(self):
        artifact = self.mod._coverage_artifact_body(
            {"stableIdentity": "b" * 64, "blocks": [], "edges": []}
        )
        with mock.patch.object(
            self.mod, "_analysis_module_context", return_value=(self._context(), None)
        ), mock.patch.object(self.mod, "BridgeHello", return_value=self._hello()):
            result = self.mod.ExportRuntimeEvidence(
                include_static=False, coverage_artifact_json=json.dumps(artifact)
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["errorCode"], "IDENTITY_MISMATCH")

    def test_import_static_annotations_accepts_runtime_document(self):
        runtime = {
            "schema": "x64dbg-mcp-runtime-evidence",
            "version": 1,
            "image": _image(),
            "staticEvidence": {"labels": [{"rva": "0x1000", "text": "from_ida"}]},
        }
        with mock.patch.object(
            self.mod, "ImportAnalysisEvidence", return_value={"ok": True, "dryRun": True}
        ) as importer:
            result = self.mod.ImportStaticAnnotations(evidence_json=json.dumps(runtime))
        self.assertTrue(result["ok"])
        payload = json.loads(importer.call_args.kwargs["evidence_json"])
        self.assertEqual(payload["schema"], "x64dbg-mcp-evidence")
        self.assertEqual(payload["evidence"]["labels"][0]["text"], "from_ida")
        self.assertTrue(importer.call_args.kwargs["dry_run"])

    def test_sync_breakpoints_is_dry_run_by_default_and_scoped(self):
        doc = _document({"breakpoints": [{"rva": "0x1010", "type": "normal", "enabled": True}]})
        with mock.patch.object(
            self.mod, "ImportAnalysisEvidence", return_value={"ok": True, "dryRun": True}
        ) as importer:
            result = self.mod.SyncBreakpoints(evidence_json=json.dumps(doc))
        self.assertTrue(result["ok"])
        self.assertEqual(result["schema"], "breakpoint-sync-v1")
        self.assertTrue(importer.call_args.kwargs["dry_run"])
        self.assertTrue(importer.call_args.kwargs["apply_breakpoints"])
        self.assertFalse(importer.call_args.kwargs["apply_labels"])

    def test_mutation_routes_and_native_event_cas_are_pinned(self):
        self.assertEqual(self.mod._ROUTE_POLICY["/Bookmark/Set"], "session")
        self.assertEqual(self.mod._ROUTE_POLICY["/Function/Add"], "session")
        source = CPP_PATH.read_text(encoding="utf-8")
        self.assertIn('httpHeaderValue(request, "x-mcp-event-seq")', source)
        self.assertIn('"stale_event"', source)
        self.assertNotIn("text = urlDecode(text);", source)


if __name__ == "__main__":
    unittest.main()
