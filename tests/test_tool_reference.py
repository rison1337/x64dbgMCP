import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.generate_tool_reference import render_reference


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "tools" / "capability_map.json"
REFERENCE = ROOT / "docs" / "TOOL_REFERENCE.md"


class ToolReferenceTests(unittest.TestCase):
    def test_checked_in_reference_matches_catalog(self):
        completed = subprocess.run(
            [
                sys.executable,
                "tools/generate_tool_reference.py",
                "--check",
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_renderer_rejects_catalog_metadata_drift(self):
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        broken = copy.deepcopy(catalog)
        broken["toolMetadata"].pop(broken["tools"][0])
        with self.assertRaises(ValueError):
            render_reference(broken)

    def test_check_fails_for_stale_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "reference.md"
            output.write_text("stale\n", encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    "tools/generate_tool_reference.py",
                    "--catalog",
                    str(CATALOG),
                    "--output",
                    str(output),
                    "--check",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(completed.returncode, 1)


if __name__ == "__main__":
    unittest.main()
