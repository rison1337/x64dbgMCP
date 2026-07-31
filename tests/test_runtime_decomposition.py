import ast
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
MANIFEST_PATH = SRC / "runtime_sections" / "manifest.json"
FACADE_PATH = SRC / "x64dbg.py"


class RuntimeDecompositionTests(unittest.TestCase):
    def test_manifest_sections_are_complete_ordered_and_intact(self):
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], "x64dbg-mcp-runtime-sections-v1")
        sections = manifest["sections"]
        self.assertEqual(len(sections), 8)
        self.assertEqual([item["startLine"] for item in sections], sorted(
            item["startLine"] for item in sections
        ))
        self.assertEqual(sum(item["lineCount"] for item in sections), manifest["sourceLineCount"])
        for item in sections:
            path = MANIFEST_PATH.parent / item["name"]
            payload = path.read_bytes()
            self.assertEqual(
                hashlib.sha256(payload).hexdigest().upper(),
                item["sha256"],
                item["name"],
            )
            ast.parse(payload, filename=str(path))

    def test_facade_executes_tools_from_section_namespace(self):
        spec = importlib.util.spec_from_file_location(
            "x64dbg_runtime_decomposition_test", FACADE_PATH
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        self.assertTrue(callable(module.InitDebuggee))
        self.assertTrue(callable(module.StartApiTrace))
        self.assertTrue(callable(module.ExportRuntimeEvidence))
        self.assertIn("runtime_sections", module.InitDebuggee.__code__.co_filename)
        self.assertIs(module.InitDebuggee.__globals__, module.__dict__)


if __name__ == "__main__":
    unittest.main()
