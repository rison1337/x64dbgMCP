import importlib.util
import os
import struct
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "x64dbg.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("x64dbg_minidump_tests", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _synthetic_minidump() -> bytes:
    data = bytearray(b"\x00" * (32 + 4 * 12))
    directory = []

    def add_stream(stream_type, payload):
        rva = len(data)
        data.extend(payload)
        directory.append((stream_type, len(payload), rva))
        return rva

    add_stream(7, struct.pack("<H", 9))
    add_stream(3, struct.pack("<I", 1) + b"\x00" * 48)

    name = r"C:\fixtures\sample.exe".encode("utf-16-le")
    module_payload = bytearray(struct.pack("<I", 1) + b"\x00" * 108)
    module_rva = len(data)
    name_rva = module_rva + len(module_payload)
    struct.pack_into("<QIIII", module_payload, 4, 0x140000000, 0x12000, 0, 0x12345678, name_rva)
    module_payload.extend(struct.pack("<I", len(name)) + name)
    add_stream(4, module_payload)
    add_stream(5, struct.pack("<I", 0))

    struct.pack_into(
        "<IIIIIIQ",
        data,
        0,
        0x504D444D,
        0x0000A793,
        len(directory),
        32,
        0,
        0x60000000,
        0,
    )
    for index, entry in enumerate(directory):
        struct.pack_into("<III", data, 32 + index * 12, *entry)
    return bytes(data)


class MiniDumpToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def test_profiles_have_stable_exact_masks(self):
        profiles = self.mod.GetMiniDumpProfiles()
        by_name = {item["name"]: item["flags"] for item in profiles["profiles"]}
        self.assertEqual(by_name["analysis"], "0xa3b65")
        self.assertEqual(by_name["full"], "0xf3b67")
        self.assertTrue(self.mod._resolve_minidump_type("0x1234")["ok"])
        self.assertFalse(self.mod._resolve_minidump_type("not-a-mask")["ok"])

    def test_structural_validator_reads_streams_arch_and_modules(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dmp") as handle:
            handle.write(_synthetic_minidump())
            path = handle.name
        try:
            result = self.mod.VerifyMiniDump(path, compute_sha256=True)
        finally:
            os.remove(path)
        self.assertTrue(result["valid"])
        self.assertTrue(result["analysisReady"])
        self.assertEqual(result["architecture"], "x64")
        self.assertEqual(result["threadCount"], 1)
        self.assertEqual(result["moduleCount"], 1)
        self.assertEqual(result["modules"][0]["name"], r"C:\fixtures\sample.exe")
        self.assertEqual(len(result["sha256"]), 64)

    def test_out_of_bounds_stream_fails_closed(self):
        raw = bytearray(_synthetic_minidump())
        struct.pack_into("<III", raw, 32, 7, 0x100, len(raw) - 1)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dmp") as handle:
            handle.write(raw)
            path = handle.name
        try:
            result = self.mod.VerifyMiniDump(path, compute_sha256=False)
        finally:
            os.remove(path)
        self.assertFalse(result["valid"])
        self.assertTrue(any("outside" in error.lower() for error in result["errors"]))

    def test_write_rejects_existing_file_before_bridge_mutation(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dmp") as handle:
            path = handle.name
        original = self.mod.BridgeHello
        self.mod.BridgeHello = lambda **kwargs: (_ for _ in ()).throw(AssertionError("network called"))
        try:
            result = self.mod.WriteMiniDump(path, overwrite=False)
        finally:
            self.mod.BridgeHello = original
            os.remove(path)
        self.assertFalse(result["ok"])
        self.assertIn("already exists", result["error"])

    def test_tools_are_registered(self):
        names = set(getattr(self.mod.mcp, "_tool_manager")._tools.keys())
        self.assertTrue({"WriteMiniDump", "VerifyMiniDump", "GetMiniDumpProfiles"} <= names)


if __name__ == "__main__":
    unittest.main()
