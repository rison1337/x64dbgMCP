import importlib.util
import os
import struct
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_dump_pipeline_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _layout(functions=None):
    functions = list(functions or ["ExitProcess", "Sleep"])
    section = {
        "name": ".text",
        "virtualAddress": 0x1000,
        "virtualSize": 0x1000,
        "rawSize": 0x200,
        "rawPointer": 0x200,
        "executable": True,
    }
    return {
        "arch": "x64",
        "characteristics": "0x0022",
        "imageBase": "0x140000000",
        "entryPointRva": "0x1000",
        "sizeOfImage": 0x3000,
        "sizeOfHeaders": 0x200,
        "sections": [section],
        "entrySection": section,
        "imports": [{"dll": "KERNEL32.dll", "functions": functions}],
        "iatDirectory": {"rva": "0x2000", "size": 0x18, "va": "0x140002000"},
        "dynamicBase": True,
        "highEntropyVa": True,
        "dllCharacteristics": "0x0160",
    }


class DumpPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def setUp(self):
        self.originals = {
            name: getattr(self.mod, name)
            for name in (
                "_parse_pe_layout",
                "_find_missing_runtime_dependencies",
                "_sha256_file",
                "BridgeHello",
                "_infer_debuggee_pid",
                "safe_post",
            )
        }

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(self.mod, name, value)

    def _files(self):
        directory = tempfile.TemporaryDirectory()
        output = Path(directory.name) / "dump.exe"
        source = Path(directory.name) / "source.exe"
        output.write_bytes(b"MZ" + b"\x00" * 4094)
        source.write_bytes(b"MZ" + b"\x00" * 4094)
        return directory, output, source

    def test_pe_verifier_accepts_exact_entry_and_full_source_import_coverage(self):
        directory, output, source = self._files()
        self.mod._parse_pe_layout = lambda path: _layout()
        self.mod._find_missing_runtime_dependencies = lambda path: {
            "ok": True,
            "missing": [],
            "resolved": [],
        }
        self.mod._sha256_file = lambda path: "a" * 64
        try:
            result = self.mod.VerifyPEDump(
                str(output),
                source_path=str(source),
                expected_entrypoint="0x140001000",
                module_base="0x140000000",
            )
        finally:
            directory.cleanup()
        self.assertTrue(result["verified"])
        self.assertTrue(result["runnableCandidate"])
        self.assertEqual(result["checks"]["sourceComparison"]["importCoverage"], 1.0)

    def test_pe_verifier_rejects_question_mark_iat_artifacts(self):
        directory, output, source = self._files()
        corrupt = _layout()
        corrupt["imports"].append({"dll": "?", "functions": ["?"]})
        self.mod._parse_pe_layout = lambda path: corrupt if os.path.samefile(path, output) else _layout()
        self.mod._find_missing_runtime_dependencies = lambda path: {"ok": True, "missing": []}
        self.mod._sha256_file = lambda path: "b" * 64
        try:
            result = self.mod.VerifyPEDump(str(output), source_path=str(source))
        finally:
            directory.cleanup()
        self.assertFalse(result["verified"])
        self.assertIn("Import table contains invalid DLL names", result["errors"])
        self.assertIn("Import table contains unresolved function names", result["errors"])

    def test_pe_verifier_rejects_source_import_regression(self):
        directory, output, source = self._files()
        output_layout = _layout(["ExitProcess"])
        source_layout = _layout(["ExitProcess", "Sleep"])
        self.mod._parse_pe_layout = (
            lambda path: output_layout if os.path.samefile(path, output) else source_layout
        )
        self.mod._find_missing_runtime_dependencies = lambda path: {"ok": True, "missing": []}
        self.mod._sha256_file = lambda path: "c" * 64
        try:
            result = self.mod.VerifyPEDump(str(output), source_path=str(source))
        finally:
            directory.cleanup()
        self.assertFalse(result["verified"])
        self.assertIn("Dump regressed imports present in the source PE", result["errors"])
        self.assertEqual(result["checks"]["sourceComparison"]["importCoverage"], 0.5)

    def test_pe_verifier_rejects_relocated_image_with_aslr_still_enabled(self):
        directory, output, source = self._files()
        output_layout = _layout()
        output_layout["imageBase"] = "0x7ff600000000"
        source_layout = _layout()
        self.mod._parse_pe_layout = (
            lambda path: output_layout if os.path.samefile(path, output) else source_layout
        )
        self.mod._find_missing_runtime_dependencies = lambda path: {"ok": True, "missing": []}
        self.mod._sha256_file = lambda path: "d" * 64
        try:
            result = self.mod.VerifyPEDump(str(output), source_path=str(source))
        finally:
            directory.cleanup()
        self.assertFalse(result["verified"])
        self.assertTrue(any("ASLR" in error for error in result["errors"]))

    def test_make_dump_runnable_clears_aslr_and_stale_checksum(self):
        data = bytearray(b"\x00" * 512)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<H", data, 0x80 + 24 + 0x46, 0x0160)
        struct.pack_into("<I", data, 0x80 + 24 + 0x40, 0x12345678)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as handle:
            handle.write(data)
            path = handle.name
        try:
            result = self.mod._make_dump_runnable(path)
            updated = Path(path).read_bytes()
        finally:
            os.remove(path)
        self.assertTrue(result["ok"])
        self.assertEqual(struct.unpack_from("<H", updated, 0x80 + 24 + 0x46)[0], 0x0100)
        self.assertEqual(struct.unpack_from("<I", updated, 0x80 + 24 + 0x40)[0], 0)

    def test_scylla_dump_sends_exact_iat_range_via_guarded_post(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixed.exe"
            captured = {}
            self.mod.BridgeHello = lambda refresh=True: {"ok": True}
            self.mod._infer_debuggee_pid = lambda pid=0: 1234

            def fake_post(endpoint, params, **kwargs):
                captured.update({"endpoint": endpoint, "params": dict(params), "kwargs": kwargs})
                return {"ok": False, "error": "synthetic stop"}

            self.mod.safe_post = fake_post
            result = self.mod._scylla_dump_module(
                {"base": "0x140000000", "path": str(Path(directory) / "source.exe")},
                entrypoint="0x140001000",
                output_path=str(output),
                iat_start="0x140002000",
                iat_size=0x188,
            )
        self.assertFalse(result["ok"])
        self.assertEqual(captured["endpoint"], "Scylla/DumpFix")
        self.assertEqual(captured["params"]["iatStart"], "0x140002000")
        self.assertEqual(captured["params"]["iatSize"], "0x188")
        self.assertEqual(captured["params"]["dumpProcess"], "true")
        self.assertEqual(captured["params"]["overwrite"], "false")

    def test_reconstruct_imports_never_modifies_input_in_place(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as handle:
            path = handle.name
        try:
            result = self.mod.ReconstructImports(path, path)
        finally:
            os.remove(path)
        self.assertFalse(result["ok"])
        self.assertIn("different", result["error"])

    def test_tools_are_registered(self):
        names = set(getattr(self.mod.mcp, "_tool_manager")._tools.keys())
        self.assertTrue(
            {"VerifyPEDump", "ReconstructImports", "DumpLoadedModule", "DumpModule"}
            <= names
        )


if __name__ == "__main__":
    unittest.main()
